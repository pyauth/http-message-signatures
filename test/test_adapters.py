"""Shared helpers exercised against Requests and HTTPX containers."""

import hashlib
import unittest

import httpx
import requests
from http_sf.compat import Dictionary
from urllib3 import HTTPResponse
from urllib3._collections import HTTPHeaderDict

from http_message_signatures import (
    ContentDigest,
    HTTPMessageSignaturesException,
    HTTPMessageSigner,
    HTTPMessageVerifier,
    InvalidSignature,
    MappingKeyResolver,
    algorithms,
)
from http_message_signatures.components import component_map
from http_message_signatures.httpx import adapt_message
from http_message_signatures.messages import HeaderFields, Request, Response


def handlers():
    keys = MappingKeyResolver(public_keys={"key": b"test-secret"}, private_keys={"key": b"test-secret"})
    return (
        HTTPMessageSigner(signature_algorithm=algorithms.HMAC_SHA256, key_resolver=keys),
        HTTPMessageVerifier(signature_algorithm=algorithms.HMAC_SHA256, key_resolver=keys),
    )


class TestSharedUtilities(unittest.TestCase):
    def test_component_identity_preserves_spelling_and_rejects_duplicates(self):
        original = '"content-digest";sf;key="sha-256"'
        normalized = '"content-digest";key="sha-256";sf'
        self.assertEqual(component_map((original,)), {normalized: original})
        for components in ((original, normalized), ("date", '"date"')):
            with self.assertRaisesRegex(HTTPMessageSignaturesException, "Duplicate component"):
                component_map(components)
        with self.assertRaisesRegex(HTTPMessageSignaturesException, "lowercase"):
            component_map(("Date",))

    def test_selected_digest_verification_preserves_caller_policy(self):
        signer, verifier = handlers()
        member = '"content-digest";key="sha-256"'
        value = str(
            Dictionary(
                {
                    "sha-256": hashlib.sha256(b"hello").digest(),
                    "sha-512": hashlib.sha512(b"different").digest(),
                }
            )
        )
        request = requests.Request(
            "POST", "https://example.com/", data=b"hello", headers={"Content-Digest": value}
        ).prepare()
        signer.sign(request, key_id="key", covered_component_ids=(member, "content-digest"))
        result = verifier.verify(request, require_components=(member,))[0]
        covered = component_map(tuple(result.covered_components))
        required = component_map((member,))
        selected = {covered[key]: result.covered_components[covered[key]] for key in required}
        self.assertTrue(ContentDigest.verify_components(selected, request.body))
        with self.assertRaises(InvalidSignature):
            ContentDigest.verify_components(result.covered_components, request.body)
        self.assertFalse(ContentDigest.verify_components({}, request.body))
        self.assertFalse(ContentDigest.verify_components({'"content-digest";req': value}, request.body))
        ContentDigest.verify(ContentDigest.create(b"hello").encode("ascii"), b"hello")

    def test_requests_raw_response_preserves_httpx_signature(self):
        signer, verifier = handlers()
        request = requests.Request("GET", "https://example.com/").prepare()
        outgoing = httpx.Response(
            200,
            request=httpx.Request(request.method, request.url),
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
        message = Response(
            status_code=response.status_code,
            headers=HeaderFields(lambda: response.raw.headers.items()),
            request=Request(method=request.method, url=request.url, headers=request.headers),
        )
        result = verifier.verify(message, body=b"hello")[0]
        self.assertIn('"set-cookie";bs', result.covered_components)
        self.assertEqual(result.body, b"hello")
        with self.assertRaisesRegex(TypeError, "read-only"):
            message.headers["Example"] = "modified"

    def test_header_view_tracks_mutations(self):
        headers = httpx.Headers([("Example", "first"), ("Example", "second")])
        fields = HeaderFields.from_raw(lambda: headers.raw, writable=headers)
        self.assertEqual(list(fields.items()), [("Example", "first"), ("Example", "second")])
        fields["Example"] = "replacement"
        self.assertEqual(list(fields.items()), [("Example", "replacement")])
        del fields["Example"]
        self.assertNotIn("example", fields)
        ContentDigest.add(fields, b"hello")
        ContentDigest.verify(headers["content-digest"], b"hello")
