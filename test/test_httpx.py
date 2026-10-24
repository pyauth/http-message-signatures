import asyncio
import gzip
import hashlib
import unittest
from datetime import datetime, timedelta, timezone
from http.client import HTTPMessage
from types import SimpleNamespace

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from http_sf.compat import Dictionary

from http_message_signatures import (
    ContentDigest,
    HTTPMessageSignaturesException,
    HTTPMessageSigner,
    HTTPMessageVerifier,
    MappingKeyResolver,
    algorithms,
)
from http_message_signatures.exceptions import InvalidSignature
from http_message_signatures.httpx import SignatureHooks, adapt_message

SECRET = b"local-tests-only-shared-secret"
ORIGIN = "https://example.com"


class SyncBody(httpx.SyncByteStream):
    def __init__(self, body):
        self.body = body
        self.closed = False
        self.reads = 0

    def __iter__(self):
        self.reads += 1
        yield self.body[:3]
        yield self.body[3:]

    def close(self):
        self.closed = True


class AsyncBody(httpx.AsyncByteStream):
    def __init__(self, body):
        self.body = body
        self.closed = False
        self.reads = 0

    async def __aiter__(self):
        self.reads += 1
        yield self.body[:3]
        await asyncio.sleep(0)
        yield self.body[3:]

    async def aclose(self):
        self.closed = True


class SignatureTestCase(unittest.TestCase):
    def setUp(self):
        self.keys = MappingKeyResolver(
            public_keys={"client": SECRET, "server": SECRET}, private_keys={"client": SECRET, "server": SECRET}
        )
        self.signer = HTTPMessageSigner(signature_algorithm=algorithms.HMAC_SHA256, key_resolver=self.keys)
        self.verifier = HTTPMessageVerifier(signature_algorithm=algorithms.HMAC_SHA256, key_resolver=self.keys)

    def hooks(self, **options):
        return SignatureHooks(
            origin=ORIGIN,
            key_id="client",
            signing_key=SECRET,
            verification_keys={"server": SECRET},
            signature_algorithm=algorithms.HMAC_SHA256,
            **options,
        )

    def response(
        self, request, body=b'{"ok":true}', *, async_mode=False, headers=(), components=("@status",), **options
    ):
        stream = AsyncBody(body) if async_mode else SyncBody(body)
        response = httpx.Response(200, request=request, headers=headers, stream=stream)
        self.signer.sign(
            adapt_message(response), key_id="server", covered_component_ids=components, body=body, **options
        )
        return response


class TestContentDigest(SignatureTestCase):
    def test_algorithms_and_empty_content(self):
        class SHA512(ContentDigest):
            algorithm = "sha-512"

        for digest_type in (ContentDigest, SHA512):
            for body in (b"", b"hello", b"\x00\xff"):
                value = digest_type.create(body)
                ContentDigest.verify(value, body)
                with self.assertRaises(InvalidSignature):
                    ContentDigest.verify(value, body + b"!")

    def test_invalid_digest_fields(self):
        valid = ContentDigest.create(b"hello")
        for value in (
            "",
            "not a dictionary",
            "sha-256=1",
            "sha-256=(1 2)",
            'sha-256="bytes"',
            "unknown=:AA==:",
            "sha-256=:AA==:",
            valid + ", " + valid,
            "sha-256=:not-base64:",
        ):
            with self.subTest(value=value), self.assertRaises(InvalidSignature):
                ContentDigest.verify(value, b"hello")

    def test_member_digest(self):
        value = str(Dictionary({"sha-256": hashlib.sha256(b"hello").digest()})["sha-256"])
        ContentDigest.verify(value, b"hello", key="sha-256")
        with self.assertRaises(InvalidSignature):
            ContentDigest.verify(value, b"other", key="sha-256")

    def test_base_body_signing_is_opt_in(self):
        request = httpx.Request("POST", ORIGIN, content=b"hello")
        message = adapt_message(request)
        self.signer.sign(message, key_id="client")
        self.assertNotIn("content-digest", request.headers)
        self.assertIsNone(self.verifier.verify(message)[0].body)
        with self.assertRaisesRegex(InvalidSignature, "signed Content-Digest"):
            self.verifier.verify(message, body=b"hello")
        self.signer.sign(message, key_id="client", body=request.content)
        result = self.verifier.verify(message, body=request.content)[0]
        self.assertEqual(result.body, b"hello")
        self.assertIn('"content-digest"', result.covered_components)
        self.assertIsNone(result.nonce)
        self.assertNotIn("expires", result.parameters)

    def test_required_components_use_semantic_parameter_identity(self):
        request = httpx.Request("POST", ORIGIN, content=b"hello")
        message = adapt_message(request)
        self.signer.sign(
            message,
            key_id="client",
            body=request.content,
            covered_component_ids=('"content-digest";sf;key="sha-256"',),
        )
        result = self.verifier.verify(
            message, body=request.content, require_components=('"content-digest";key="sha-256";sf',)
        )[0]
        self.assertEqual(result.body, request.content)
        self.assertNotIn('"content-digest"', result.covered_components)
        with self.assertRaises(InvalidSignature):
            self.verifier.verify(message, require_components=("@method",))
        with self.assertRaises(HTTPMessageSignaturesException):
            self.verifier.verify(message, require_components=("@method", '"@method"'))

    def test_response_request_digest_does_not_cover_response_body(self):
        request = httpx.Request("POST", ORIGIN, content=b"request")
        self.signer.sign(adapt_message(request), key_id="client", body=request.content)
        response = httpx.Response(200, request=request, content=b"response")
        self.signer.sign(adapt_message(response), key_id="server", covered_component_ids=('"content-digest";req',))
        with self.assertRaisesRegex(InvalidSignature, "signed Content-Digest"):
            self.verifier.verify(adapt_message(response), body=response.content)

    def test_empty_body_and_unsigned_digest(self):
        response = httpx.Response(204, request=httpx.Request("GET", ORIGIN), content=b"")
        message = adapt_message(response)
        self.signer.sign(message, key_id="server", covered_component_ids=("@status",))
        self.assertIsNone(self.verifier.verify(message, body=b"")[0].body)
        response.headers["Content-Digest"] = ContentDigest.create(b"")
        with self.assertRaises(InvalidSignature):
            self.verifier.verify(message, body=b"")

    def test_each_selected_signature_must_cover_body(self):
        response = httpx.Response(200, request=httpx.Request("GET", ORIGIN), content=b"hello")
        message = adapt_message(response)
        self.signer.sign(message, key_id="server", body=b"hello", covered_component_ids=("@status",), tag="api")
        self.signer.sign(
            message,
            key_id="server",
            covered_component_ids=("@status",),
            tag="api",
            label="second",
            append_if_signature_exists=True,
        )
        with self.assertRaises(InvalidSignature):
            self.verifier.verify(message, expect_tag="api", body=b"hello")


class TestSignatureHooks(SignatureTestCase):
    def test_roundtrip_and_verification_before_consumers(self):
        hooks = self.hooks()
        observed = []

        def server(request):
            result = self.verifier.verify(adapt_message(request), body=request.content)[0]
            self.assertEqual(result.body, b'{"hello":"world"}')
            response = self.response(request)
            observed.append(response.stream)
            return response

        def consumer(response):
            self.assertEqual(response.json(), {"ok": True})
            self.assertEqual(response.extensions["http_message_signatures"][0].body, b'{"ok":true}')

        event_hooks = hooks.event_hooks
        event_hooks["response"].append(consumer)
        with httpx.Client(transport=httpx.MockTransport(server), event_hooks=event_hooks) as client:
            response = client.post(ORIGIN, json={"hello": "world"})
        self.assertEqual(response.json(), {"ok": True})
        self.assertTrue(observed[0].closed)
        self.assertEqual(observed[0].reads, 1)

    def test_gzip_uses_encoded_digest_and_preserves_decoding(self):
        hooks = self.hooks()
        encoded = gzip.compress(b'{"ok":true}')
        with httpx.Client(
            transport=httpx.MockTransport(
                lambda request: self.response(request, encoded, headers={"Content-Encoding": "gzip"})
            ),
            event_hooks=hooks.event_hooks,
        ) as client:
            response = client.get(ORIGIN)
        self.assertEqual(response.json(), {"ok": True})
        self.assertEqual(response.extensions["http_message_signatures"][0].body, encoded)

    def test_tampered_body_closes_stream_and_skips_consumer(self):
        hooks = self.hooks()
        observed = []
        consumed = []

        def server(request):
            response = self.response(request, b"original")
            response.stream.body = b"changed"
            observed.append(response.stream)
            return response

        event_hooks = hooks.event_hooks
        event_hooks["response"].append(lambda response: consumed.append(response))
        with (
            httpx.Client(transport=httpx.MockTransport(server), event_hooks=event_hooks) as client,
            self.assertRaisesRegex(InvalidSignature, "does not match"),
        ):
            client.get(ORIGIN)
        self.assertTrue(observed[0].closed)
        self.assertFalse(consumed)

    def test_bad_headers_fail_before_reading_body(self):
        hooks = self.hooks()
        observed = []

        def server(request):
            response = self.response(request)
            response.headers["Signature"] = "bad"
            observed.append(response.stream)
            return response

        with (
            httpx.Client(transport=httpx.MockTransport(server), event_hooks=hooks.event_hooks) as client,
            self.assertRaises(InvalidSignature),
        ):
            client.get(ORIGIN)
        self.assertTrue(observed[0].closed)
        self.assertEqual(observed[0].reads, 0)

    def test_repeated_set_cookie_lines_interoperate_with_core(self):
        hooks = self.hooks()

        def server(request):
            headers = HTTPMessage()
            headers["Set-Cookie"] = "a=1; Path=/"
            headers["Set-Cookie"] = "b=2; Path=/"
            message = SimpleNamespace(status_code=200, request=adapt_message(request), headers=headers)
            self.signer.sign(message, key_id="server", covered_component_ids=("@status", "set-cookie"), body=b"hello")
            return httpx.Response(200, headers=list(headers.items()), stream=SyncBody(b"hello"))

        with httpx.Client(transport=httpx.MockTransport(server), event_hooks=hooks.event_hooks) as client:
            response = client.get(ORIGIN)
        result = response.extensions["http_message_signatures"][0]
        self.assertIn('"set-cookie";bs', result.covered_components)
        self.assertEqual(len(response.headers.get_list("set-cookie")), 2)
        self.assertEqual(response.headers["set-cookie"], "a=1; Path=/, b=2; Path=/")

    def test_raw_header_bytes_and_request_context(self):
        request = httpx.Request("GET", ORIGIN, headers=[(b"Example", b"caf\xc3\xa9"), (b"Example", b"second")])
        message = adapt_message(request)
        self.signer.sign(message, key_id="client", covered_component_ids=('"example";bs',))
        headers = HTTPMessage()
        for name, value in request.headers.raw:
            headers[name.decode("ascii")] = value.decode("latin-1")
        reference = SimpleNamespace(method=request.method, url=str(request.url), headers=headers)
        self.verifier.verify(reference)
        response = self.response(request, components=('"example";req;bs',))
        self.hooks().verify_response(response)
        self.assertIn('"example";req;bs', response.extensions["http_message_signatures"][0].covered_components)

    def test_repeated_field_normalization_and_signature_fields(self):
        request = httpx.Request("GET", ORIGIN, headers=[("Example", " one "), ("Example", "\ttwo\t")])
        message = adapt_message(request)
        self.signer.sign(message, key_id="client", covered_component_ids=("example",), tag="test")
        self.signer.sign(
            message,
            key_id="client",
            covered_component_ids=("example",),
            tag="test",
            label="second",
            append_if_signature_exists=True,
        )
        # Two dictionary members carried in separate original field lines.
        inputs = self.signer._parse_signature_dictionary(request.headers["Signature-Input"])
        signatures = self.signer._parse_signature_dictionary(request.headers["Signature"])
        request.headers = httpx.Headers(
            [
                ("Example", " one "),
                ("Example", "\ttwo\t"),
                *[("Signature-Input", str(Dictionary({name: value}))) for name, value in inputs.items()],
                *[("Signature", str(Dictionary({name: value}))) for name, value in signatures.items()],
            ]
        )
        results = self.verifier.verify(adapt_message(request), expect_tag="test")
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].covered_components['"example"'], "one, two")

    def test_redirect_resigns_method_url_and_digest(self):
        hooks = self.hooks()
        requests = []

        def server(request):
            result = self.verifier.verify(adapt_message(request), body=request.content)[0]
            requests.append((request.method, str(request.url), result.body))
            response = self.response(request)
            if len(requests) == 1:
                response.status_code = 302
                response.headers["Location"] = "/next"
                self.signer.sign(
                    adapt_message(response),
                    key_id="server",
                    covered_component_ids=("@status", "location"),
                    body=b'{"ok":true}',
                )
            return response

        with httpx.Client(
            transport=httpx.MockTransport(server), event_hooks=hooks.event_hooks, follow_redirects=True
        ) as client:
            client.post(ORIGIN, content=b"original")
        self.assertEqual(requests, [("POST", ORIGIN, b"original"), ("GET", ORIGIN + "/next", b"")])

    def test_origin_is_checked_before_reading_or_sending(self):
        hooks = self.hooks()
        stream = SyncBody(b"secret")
        with self.assertRaises(HTTPMessageSignaturesException):
            hooks.sign_request(httpx.Request("POST", "https://other.example/", stream=stream))
        self.assertEqual(stream.reads, 0)
        for destination in ("http://example.com", "https://example.com:8443"):
            with self.subTest(destination=destination), self.assertRaises(HTTPMessageSignaturesException):
                hooks.sign_request(httpx.Request("GET", destination))
        hooks.sign_request(httpx.Request("GET", "https://example.com:443/"))

    def test_streamed_upload_can_be_replayed_on_307(self):
        upload = SyncBody(b"streamed upload")
        seen = []

        def server(request):
            seen.append(self.verifier.verify(adapt_message(request), body=request.content)[0].body)
            response = self.response(request)
            if len(seen) == 1:
                response.status_code = 307
                response.headers["Location"] = "/next"
                self.signer.sign(
                    adapt_message(response), key_id="server", covered_component_ids=("@status",), body=b'{"ok":true}'
                )
            return response

        with httpx.Client(
            transport=httpx.MockTransport(server), event_hooks=self.hooks().event_hooks, follow_redirects=True
        ) as client:
            client.post(ORIGIN, content=upload)
        self.assertEqual(seen, [b"streamed upload", b"streamed upload"])
        self.assertEqual(upload.reads, 1)

    def test_cross_origin_redirect_is_not_sent(self):
        seen = []

        def server(request):
            seen.append(request.url)
            response = self.response(request)
            response.status_code = 302
            response.headers["Location"] = "https://other.example/"
            self.signer.sign(
                adapt_message(response), key_id="server", covered_component_ids=("@status",), body=b'{"ok":true}'
            )
            return response

        with (
            httpx.Client(
                transport=httpx.MockTransport(server), event_hooks=self.hooks().event_hooks, follow_redirects=True
            ) as client,
            self.assertRaises(HTTPMessageSignaturesException),
        ):
            client.get(ORIGIN)
        self.assertEqual(len(seen), 1)

    def test_configured_options_reach_base_methods(self):
        hooks = self.hooks(
            tag="api",
            label="outgoing",
            include_alg=False,
            nonce="caller-nonce",
            covered_component_ids=("@method",),
            max_age=None,
            require_components=("@status",),
        )
        request = httpx.Request("GET", ORIGIN)
        hooks.sign_request(request)
        result = self.verifier.verify(adapt_message(request), expect_tag="api")[0]
        self.assertEqual(result.label, "outgoing")
        self.assertEqual(result.nonce, "caller-nonce")
        self.assertNotIn("alg", result.parameters)
        self.assertNotIn('"@target-uri"', result.covered_components)
        response = self.response(request, tag="api", created=datetime(2020, 1, 1, tzinfo=timezone.utc))
        hooks.verify_response(response)
        with self.assertRaises(InvalidSignature):
            self.hooks(tag="api").verify_response(response)

    def test_unknown_and_hook_managed_options_are_rejected(self):
        for name in ("max_ag", "covered_components", "body"):
            with (
                self.subTest(option=name),
                self.assertRaisesRegex(TypeError, rf"Unknown signature option\(s\): {name}"),
            ):
                self.hooks(**{name: None})

    def test_unspecified_options_are_not_forwarded(self):
        hooks = self.hooks()
        self.assertEqual(hooks.signing_options, {})
        self.assertEqual(hooks.verification_options, {})
        self.assertEqual(self.hooks(tag="out", expect_tag="in").verification_options, {"expect_tag": "in"})

    def test_subclass_defaults_are_inherited(self):
        class Verifier(HTTPMessageVerifier):
            def verify(self, message, *, max_age=timedelta(seconds=1)):
                return super().verify(message, max_age=max_age)

        class Hooks(SignatureHooks):
            verifier_class = Verifier

        hooks = Hooks(
            origin=ORIGIN,
            key_id="client",
            signing_key=SECRET,
            verification_keys={"server": SECRET},
            signature_algorithm=algorithms.HMAC_SHA256,
        )
        response = self.response(
            httpx.Request("GET", ORIGIN), created=datetime.now(timezone.utc) - timedelta(minutes=1)
        )
        with self.assertRaises(InvalidSignature):
            hooks.verify_response(response)

    def test_asymmetric_keys_and_untrusted_key_id(self):
        client_key, server_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        hooks = SignatureHooks(
            origin=ORIGIN,
            key_id="client",
            signing_key=client_key,
            verification_keys={"server": server_key.public_key()},
            signature_algorithm=algorithms.ED25519,
        )
        keys = MappingKeyResolver(
            public_keys={"client": client_key.public_key()}, private_keys={"server": server_key, "unknown": server_key}
        )
        signer = HTTPMessageSigner(signature_algorithm=algorithms.ED25519, key_resolver=keys)
        verifier = HTTPMessageVerifier(signature_algorithm=algorithms.ED25519, key_resolver=keys)
        request = httpx.Request("POST", ORIGIN, content=b"hello")
        hooks.sign_request(request)
        verifier.verify(adapt_message(request), body=request.content)
        for key_id in ("server", "unknown"):
            response = httpx.Response(200, request=request, content=b"ok")
            signer.sign(adapt_message(response), key_id=key_id, body=b"ok", covered_component_ids=("@status",))
            if key_id == "server":
                hooks.verify_response(response)
            else:
                with self.assertRaises(InvalidSignature):
                    hooks.verify_response(response)

    def test_buffered_response_and_unrecoverable_encoded_response(self):
        hooks = self.hooks()
        request = httpx.Request("GET", ORIGIN)
        response = httpx.Response(200, request=request, content=b"hello")
        self.signer.sign(adapt_message(response), key_id="server", body=b"hello", covered_component_ids=("@status",))
        hooks.verify_response(response)
        encoded = gzip.compress(b"hello")
        response = httpx.Response(200, request=request, headers={"Content-Encoding": "gzip"}, content=encoded)
        self.signer.sign(adapt_message(response), key_id="server", body=encoded, covered_component_ids=("@status",))
        with self.assertRaisesRegex(InvalidSignature, "already consumed"):
            hooks.verify_response(response)

    def test_stream_api_is_buffered_before_yield(self):
        with (
            httpx.Client(
                transport=httpx.MockTransport(lambda request: self.response(request)),
                event_hooks=self.hooks().event_hooks,
            ) as client,
            client.stream("GET", ORIGIN) as response,
        ):
            self.assertTrue(response.is_stream_consumed)
            self.assertEqual(response.content, b'{"ok":true}')
            self.assertEqual(b"".join(response.iter_bytes()), response.content)

    def test_empty_responses_and_signed_errors(self):
        for method, status, body in (("HEAD", 200, b""), ("GET", 204, b""), ("GET", 304, b""), ("GET", 400, b"error")):
            with self.subTest(method=method, status=status):
                request = httpx.Request(method, ORIGIN)
                response = self.response(request, body)
                response.status_code = status
                self.signer.sign(
                    adapt_message(response), key_id="server", covered_component_ids=("@status",), body=body
                )
                self.hooks().verify_response(response)
                self.assertEqual(response.extensions["http_message_signatures"][0].body, body)

    def test_cookie_limitation_after_failure(self):
        def server(request):
            response = self.response(request, headers={"Set-Cookie": "session=unverified; Path=/"})
            response.headers["Signature"] = "bad"
            return response

        with httpx.Client(transport=httpx.MockTransport(server), event_hooks=self.hooks().event_hooks) as client:
            with self.assertRaises(InvalidSignature):
                client.get(ORIGIN)
            self.assertEqual(client.cookies.get("session"), "unverified")


class TestAsyncSignatureHooks(SignatureTestCase):
    def test_concurrent_requests_and_compressed_responses(self):
        async def run():
            hooks = self.hooks()
            streams = []

            async def server(request):
                self.verifier.verify(adapt_message(request), body=request.content)
                await asyncio.sleep(0)
                response = self.response(
                    request,
                    gzip.compress(request.content),
                    async_mode=True,
                    headers={"Content-Encoding": "gzip"},
                    components=("@status", '"content-digest";req'),
                )
                streams.append(response.stream)
                return response

            async with httpx.AsyncClient(
                transport=httpx.MockTransport(server), event_hooks=hooks.async_event_hooks
            ) as client:
                responses = await asyncio.gather(
                    *(client.post(ORIGIN, content=AsyncBody(str(i).encode())) for i in range(6))
                )
                for i, response in enumerate(responses):
                    self.assertEqual(response.content, str(i).encode())
                    self.assertEqual(
                        gzip.decompress(response.extensions["http_message_signatures"][0].body), response.content
                    )
            self.assertTrue(all(stream.closed and stream.reads == 1 for stream in streams))

        asyncio.run(run())

    def test_async_digest_failure_closes_stream(self):
        async def run():
            streams = []

            async def server(request):
                response = self.response(request, async_mode=True)
                response.stream.body = b"changed"
                streams.append(response.stream)
                return response

            async with httpx.AsyncClient(
                transport=httpx.MockTransport(server), event_hooks=self.hooks().async_event_hooks
            ) as client:
                with self.assertRaises(InvalidSignature):
                    await client.get(ORIGIN)
            self.assertTrue(streams[0].closed)

        asyncio.run(run())

    def test_cancelled_body_read_closes_stream(self):
        class CancelledBody(AsyncBody):
            async def __aiter__(self):
                yield b"partial"
                raise asyncio.CancelledError()

        async def run():
            request = httpx.Request("GET", ORIGIN)
            response = self.response(request, async_mode=True)
            stream = CancelledBody(b"")
            response.stream = stream
            with self.assertRaises(asyncio.CancelledError):
                await self.hooks().verify_response_async(response)
            self.assertTrue(stream.closed)
            self.assertNotIn("http_message_signatures", response.extensions)

        asyncio.run(run())
