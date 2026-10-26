"""Shared helpers exercised against Requests and HTTPX2 containers."""

import hashlib
import unittest
from unittest.mock import Mock, patch

import httpx2
import requests
from http_sf.compat import Dictionary
from urllib3 import HTTPResponse
from urllib3._collections import HTTPHeaderDict

from http_message_signatures import (
    ContentDigest,
    HTTPMessageSigner,
    HTTPMessageVerifier,
    InvalidSignature,
    MappingKeyResolver,
    algorithms,
)
from http_message_signatures._messages import _HeaderFields, _Request, _Response
from http_message_signatures.httpx2 import adapt_message


def handlers():
    keys = MappingKeyResolver(public_keys={"key": b"test-secret"}, private_keys={"key": b"test-secret"})
    return (
        HTTPMessageSigner(signature_algorithm=algorithms.HMAC_SHA256, key_resolver=keys),
        HTTPMessageVerifier(signature_algorithm=algorithms.HMAC_SHA256, key_resolver=keys),
    )


class TestSharedUtilities(unittest.TestCase):
    def test_body_hashes_are_shared_across_signatures_and_components(self):
        signer, verifier = handlers()
        body = b"body" * 1024
        request = requests.Request("POST", "https://example.com/", data=body).prepare()
        request.headers["Content-Digest"] = str(
            Dictionary({"sha-256": hashlib.sha256(body).digest(), "sha-512": hashlib.sha512(body).digest()})
        )
        for label, components in (
            ("whole", ("content-digest",)),
            ("members", ('"content-digest";key="sha-256"', '"content-digest";key="sha-512"')),
        ):
            signer.sign(
                request,
                key_id="key",
                label=label,
                tag="test",
                covered_component_ids=components,
                use_existing_digest=True,
                append_if_signature_exists=True,
            )
        hashers = {name: Mock(wraps=hasher) for name, hasher in ContentDigest._hashers.items()}
        with patch.dict(ContentDigest._hashers, hashers):
            for _ in range(2):
                results = verifier.verify(request, expect_tag="test", body=body)
                self.assertEqual(len(results), 2)
                self.assertTrue(all(result.body is body for result in results))
            for hasher in hashers.values():
                self.assertEqual(sum(call.args == (body,) for call in hasher.call_args_list), 2)
            with self.assertRaisesRegex(InvalidSignature, "does not match"):
                verifier.verify(request, expect_tag="test", body=b"changed")

    def test_cached_hashes_preserve_digest_overrides_and_individual_checks(self):
        _, verifier = handlers()
        calls = []

        class CustomDigest(ContentDigest):
            @classmethod
            def verify_components(cls, covered_components, body):
                calls.append("components")
                return super().verify_components(covered_components, body)

            @classmethod
            def verify(cls, value, body, *, key=None):
                calls.append("digest")
                return super().verify(value, body, key=key)

        verifier.content_digest_class = CustomDigest
        signer, _ = handlers()
        body = b"hello"
        request = requests.Request("POST", "https://example.com/", data=body).prepare()
        signer.sign(request, key_id="key", body=body)
        result = verifier.verify(request)[0]
        bad_digest = result._replace(covered_components={'"content-digest"': ContentDigest.create(b"other")})
        no_digest = result._replace(covered_components={'"@method"': "POST"})
        with self.assertRaisesRegex(InvalidSignature, "does not match"):
            verifier.verify_body(request, [result, bad_digest], body)
        self.assertEqual(calls, ["components", "digest", "components", "digest"])
        with self.assertRaisesRegex(InvalidSignature, "requires a signed Content-Digest"):
            verifier.verify_body(request, [result, no_digest], body)
        with patch.dict(ContentDigest._hashers, {"sha-256": Mock(wraps=hashlib.sha256)}) as hashers:
            verifier.verify_body(request, [result, result], body)
            self.assertEqual(sum(call.args == (body,) for call in hashers["sha-256"].call_args_list), 1)

    def test_requests_raw_response_preserves_httpx2_signature(self):
        signer, verifier = handlers()
        request = requests.Request("GET", "https://example.com/").prepare()
        outgoing = httpx2.Response(
            200,
            request=httpx2.Request(request.method, request.url),
            content=b"hello",
            headers=[(b"Set-Cookie", b"one=1"), (b"Set-Cookie", b"two=2"), (b"Example", b"caf\xc3\xa9")],
        )
        signer.sign(
            adapt_message(outgoing),
            key_id="key",
            body=b"hello",
            covered_component_ids=("@status", '"@method";req', "set-cookie", '"example";bs'),
        )
        response = requests.Response()
        response.status_code = 200
        response.request = request
        response.raw = HTTPResponse(
            headers=HTTPHeaderDict(
                (name.decode("ascii"), value.decode("latin-1")) for name, value in outgoing.headers.raw
            )
        )
        message = _Response(
            status_code=response.status_code,
            headers=_HeaderFields(lambda: response.raw.headers.items()),
            request=_Request(method=request.method, url=request.url, headers=request.headers),
        )
        result = verifier.verify(message, body=b"hello")[0]
        self.assertIn('"set-cookie";bs', result.covered_components)
        self.assertEqual(result.body, b"hello")
        with self.assertRaisesRegex(TypeError, "read-only"):
            message.headers["Example"] = "modified"

    def test_header_view_tracks_mutations(self):
        headers = httpx2.Headers([("Example", "first"), ("Example", "second")])
        fields = _HeaderFields.from_raw(lambda: headers.raw, writable=headers)
        self.assertEqual(list(fields.items()), [("Example", "first"), ("Example", "second")])
        fields["Example"] = "replacement"
        self.assertEqual(list(fields.items()), [("Example", "replacement")])
        del fields["Example"]
        self.assertNotIn("example", fields)
        ContentDigest.add(fields, b"hello")
        ContentDigest.verify(headers["content-digest"], b"hello")
