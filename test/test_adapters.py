"""Shared helpers exercised against Requests and HTTPX2 containers."""

import unittest

import httpx2
import requests
from urllib3 import HTTPResponse
from urllib3._collections import HTTPHeaderDict

from http_message_signatures import (
    ContentDigest,
    HTTPMessageSigner,
    HTTPMessageVerifier,
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
