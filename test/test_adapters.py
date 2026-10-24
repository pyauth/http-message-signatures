"""Shared helpers exercised against Requests, HTTPX, and aiohttp containers."""

import gzip
import hashlib
import unittest

import aiohttp
import httpx
import requests
from aiohttp import web
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


class TestAiohttpViews(unittest.IsolatedAsyncioTestCase):
    async def test_middleware_with_encoded_content_repeated_headers_and_request_binding(self):
        signer, verifier = handlers()
        request_bodies = []
        verified_bodies = []
        encoded_response = gzip.compress(b"hello response")

        async def server(request):
            request_view = Request(
                method=request.method,
                url=str(request.url),
                headers=HeaderFields.from_raw(lambda: request.raw_headers),
            )
            request_bodies.append(verifier.verify(request_view, body=await request.read())[0].body)
            response = web.Response(body=encoded_response, headers={"Content-Encoding": "gzip"})
            response.headers.add("Set-Cookie", "one=1; Path=/")
            response.headers.add("Set-Cookie", "two=2; Path=/")
            signer.sign(
                Response(status_code=response.status, headers=response.headers, request=request_view),
                key_id="key",
                body=encoded_response,
                covered_component_ids=("@status", '"example";req;bs', "set-cookie"),
            )
            if request.path == "/tampered":
                response.body = gzip.compress(b"changed response")
            return response

        async def middleware(request, handler):
            # This fixture accepts finalized encoded bodies and disables later compression.
            self.assertFalse(request.compress)
            body = await request.body.as_bytes() if isinstance(request.body, aiohttp.payload.Payload) else request.body
            await request.update_body(body)
            request_view = Request(
                method=request.method,
                url=str(request.url),
                headers=HeaderFields.from_raw(
                    lambda: ((name.encode("ascii"), value.encode("utf-8")) for name, value in request.headers.items()),
                    writable=request.headers,
                ),
            )
            signer.sign(request_view, key_id="key", body=body, covered_component_ids=("@method", '"example";bs'))
            response = await handler(request)
            try:
                view = Response(
                    status_code=response.status,
                    headers=HeaderFields.from_raw(lambda: response.raw_headers),
                    request=request_view,
                )
                results = verifier.verify(view, require_components=("@status", '"set-cookie";bs'))
                verified_bodies.append(verifier.verify_body(view, results, await response.read())[0].body)
                return response
            except BaseException:
                response.close()
                raise

        app = web.Application()
        app.router.add_post("/{tail:.*}", server)
        runner = web.AppRunner(app, auto_decompress=False)
        await runner.setup()
        try:
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            url = f"http://127.0.0.1:{runner.addresses[0][1]}"
            encoded_request = gzip.compress(b"hello request")
            # unsafe=True permits cookies from the loopback IP in this test only.
            async with aiohttp.ClientSession(
                middlewares=(middleware,), auto_decompress=False, cookie_jar=aiohttp.CookieJar(unsafe=True)
            ) as session:
                async with session.post(
                    url + "/", data=encoded_request, headers={"Content-Encoding": "gzip", "Example": "caf\u00e9"}
                ) as response:
                    self.assertEqual(gzip.decompress(await response.read()), b"hello response")
                    self.assertEqual(len(response.headers.getall("Set-Cookie")), 2)
                self.assertEqual(request_bodies, [encoded_request])
                self.assertEqual(verified_bodies, [encoded_response])
                self.assertEqual(len(session.cookie_jar), 2)
                session.cookie_jar.clear()
                with self.assertRaises(InvalidSignature):
                    await session.post(url + "/tampered", data=b"hello", headers={"Example": "value"})
                self.assertEqual(len(session.cookie_jar), 0)
        finally:
            await runner.cleanup()
