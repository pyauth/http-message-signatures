import asyncio
import gzip
import io
import random
import unittest
import zlib
from types import SimpleNamespace
from unittest.mock import patch

import aiohttp
from aiohttp import web
from aiohttp.compression_utils import ZLibCompressor, ZLibDecompressor
from aiohttp.test_utils import TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from multidict import CIMultiDict
from yarl import URL

from http_message_signatures import (
    ContentDigest,
    HTTPMessageSignaturesException,
    HTTPMessageSigner,
    HTTPMessageVerifier,
    InvalidSignature,
    MappingKeyResolver,
    algorithms,
)
from http_message_signatures._messages import _HeaderFields, _Request, _Response
from http_message_signatures.aiohttp import (
    SignatureMiddleware,
    SignatureMiddlewareMode,
    _buffer_request,
    _decoded_content,
    _DecodedStream,
)

SECRET = b"local-tests-only-shared-secret"
PLAIN = b'{"verified": true}'


class AiohttpTests(unittest.IsolatedAsyncioTestCase):
    async def test_decoding_bounds_compressed_input_and_yields(self):
        body = random.Random(0).randbytes(1024 * 1024)
        decompress = ZLibDecompressor.decompress_sync
        inputs = []
        checkpoints = []

        def record(decoder, data, max_length=0):
            inputs.append(len(data) + len(decoder._decompressor.unconsumed_tail))
            return decompress(decoder, data, max_length)

        for encoding, encoded in (("gzip", gzip.compress(body)), ("deflate", zlib.compress(body))):
            with self.subTest(encoding=encoding):
                inputs.clear()
                checkpoints.clear()
                message = SimpleNamespace(
                    headers=CIMultiDict({"Content-Encoding": encoding}), content=_DecodedStream(65536, 0)
                )
                asyncio.get_running_loop().call_soon(lambda: checkpoints.append(len(inputs)))
                with patch.object(ZLibDecompressor, "decompress_sync", record):
                    content = await _decoded_content(message, encoded)
                self.assertEqual(await content.read(), body)
                self.assertLessEqual(max(inputs), 65536)
                self.assertTrue(checkpoints)
                self.assertLess(checkpoints[0], len(inputs))

    async def test_buffered_request_bytes_are_reused_on_retries(self):
        for payload in (
            aiohttp.BytesPayload(b"body" * 1024, headers={"X-Payload": "kept"}),
            aiohttp.StringPayload("hello"),
            aiohttp.JsonPayload({"hello": "world"}),
        ):
            with self.subTest(payload=type(payload).__name__):
                request = aiohttp.ClientRequest("POST", URL(self.origin), data=payload)
                self.addAsyncCleanup(request.close)
                original = await payload.as_bytes()
                for _ in range(3):
                    self.assertIs(await _buffer_request(request), original)
                    self.assertIs(request.body, payload)
                for name, value in payload.headers.items():
                    self.assertEqual(request.headers[name], value)
                request.headers["Content-Length"] = "2"
                self.assertEqual(await _buffer_request(request), original[:2])
                self.assertEqual(request.headers["Content-Length"], "2")

    async def test_mutable_payload_is_frozen_before_signing(self):
        for make_body in (bytearray, lambda value: memoryview(bytearray(value))):
            with self.subTest(make_body=make_body):
                original = make_body(b"hello")
                request = aiohttp.ClientRequest("POST", URL(self.origin), data=aiohttp.BytesPayload(original))
                self.addAsyncCleanup(request.close)
                body = await _buffer_request(request)
                original[0] = ord("x")
                self.assertEqual(body, b"hello")
                self.assertIs(await _buffer_request(request), body)

    async def asyncSetUp(self):
        self.keys = MappingKeyResolver(
            public_keys={"client": SECRET, "server": SECRET}, private_keys={"client": SECRET, "server": SECRET}
        )
        self.signer = HTTPMessageSigner(signature_algorithm=algorithms.HMAC_SHA256, key_resolver=self.keys)
        self.verifier = HTTPMessageVerifier(signature_algorithm=algorithms.HMAC_SHA256, key_resolver=self.keys)
        self.requests = []
        self.endpoint = self.signed_response
        app = web.Application()
        app.router.add_route("*", "/{path:.*}", self.dispatch)
        self.server = TestServer(app)
        await self.server.start_server(auto_decompress=False)
        self.addAsyncCleanup(self.server.close)
        self.origin = str(self.server.make_url("/")).rstrip("/")

    async def dispatch(self, request):
        body = await request.read()
        view = SimpleNamespace(
            method=request.method,
            url=str(request.url),
            headers=_HeaderFields.from_raw(lambda: request.raw_headers),
            request_target=request.raw_path,
        )
        if "Signature" in request.headers:
            self.verifier.verify(view, body=body)
        self.requests.append((request, body))
        return await self.endpoint(request)

    async def signed_response(
        self,
        request,
        body=PLAIN,
        *,
        encoding=None,
        status=200,
        headers=(),
        components=("@status", '"@method";req', '"@target-uri";req'),
    ):
        response = web.Response(body=body, status=status, headers=CIMultiDict(headers))
        response.content_type = "application/json"
        if encoding:
            response.headers["Content-Encoding"] = encoding
        request_view = SimpleNamespace(
            method=request.method,
            url=str(request.url),
            headers=_HeaderFields.from_raw(lambda: request.raw_headers),
            request_target=request.raw_path,
        )
        fields = _HeaderFields(
            lambda: ((name, value.encode("utf-8").decode("latin-1")) for name, value in response.headers.items()),
            writable=response.headers,
        )
        self.signer.sign(
            _Response(status, fields, request_view), key_id="server", body=body, covered_component_ids=components
        )
        return response

    def middleware(
        self, mode=SignatureMiddlewareMode.SIGN_REQUEST_VERIFY_RESPONSE, *, sign_options=None, verify_options=None
    ):
        options = {}
        if mode is not SignatureMiddlewareMode.VERIFY_RESPONSE:
            options["sign_options"] = {
                "origin": self.origin,
                "signature_algorithm": algorithms.HMAC_SHA256,
                "key_resolver": self.keys,
                "key_id": "client",
                **(sign_options or {}),
            }
        if mode is not SignatureMiddlewareMode.SIGN_REQUEST:
            options["verify_options"] = {
                "origin": self.origin,
                "signature_algorithm": algorithms.HMAC_SHA256,
                "key_resolver": self.keys,
                "require_components": ("@status", '"@method";req', '"@target-uri";req'),
                **(verify_options or {}),
            }
        return SignatureMiddleware(mode, **options)

    async def test_modes_with_native_session(self):
        for mode in SignatureMiddlewareMode:
            with self.subTest(mode=mode):
                middleware = self.middleware(mode)
                async with (
                    aiohttp.ClientSession(**middleware.session_kwargs) as client,
                    client.post(self.origin, json={"message": "hello"}) as response,
                ):
                    self.assertEqual(await response.json(), {"verified": True})
                    self.assertEqual(await response.text(), PLAIN.decode())
                    self.assertEqual(await response.read(), PLAIN)
                    sent, body = self.requests[-1]
                    self.assertEqual("Signature" in sent.headers, mode is not SignatureMiddlewareMode.VERIFY_RESPONSE)
                    self.assertEqual(body, b'{"message": "hello"}')
                    if mode is SignatureMiddlewareMode.SIGN_REQUEST:
                        self.assertTrue(client.auto_decompress)
                        with self.assertRaisesRegex(InvalidSignature, "has not been verified"):
                            middleware.verification_results(response)
                    else:
                        self.assertEqual(middleware.verification_results(response)[0].body, PLAIN)

    async def test_session_options_can_be_customized_without_changing_defaults(self):
        signatures = self.middleware()
        options = signatures.session_kwargs
        options["middlewares"] = ()
        options["auto_decompress"] = True
        self.assertEqual(signatures.session_kwargs, {"middlewares": (signatures,), "auto_decompress": False})

    async def test_verification_precedes_decoding_and_trace_consumers(self):
        encoded = gzip.compress(PLAIN)

        async def endpoint(request):
            return await self.signed_response(request, encoded, encoding="gzip")

        self.endpoint = endpoint
        middleware = self.middleware()
        events = []
        verify = middleware.verifier.verify_body
        decompress = ZLibDecompressor.decompress_sync

        def verified(*args):
            result = verify(*args)
            events.append("verified")
            return result

        def decoded(decoder, data, max_length=0):
            self.assertIn("verified", events)
            events.append("decoded")
            return decompress(decoder, data, max_length)

        async def received(session, context, params):
            self.assertEqual(params.chunk, PLAIN)
            events.append("trace")

        trace = aiohttp.TraceConfig()
        trace.on_response_chunk_received.append(received)
        async with aiohttp.ClientSession(**middleware.session_kwargs, trace_configs=[trace]) as client:
            with (
                patch.object(middleware.verifier, "verify_body", verified),
                patch.object(ZLibDecompressor, "decompress_sync", decoded),
            ):
                async with client.get(self.origin) as response:
                    self.assertEqual(await response.json(), {"verified": True})
                    self.assertEqual(middleware.verification_results(response)[0].body, encoded)
                    self.assertEqual(response.content.total_raw_bytes, len(encoded))
        self.assertEqual(events[0], "verified")
        self.assertEqual(events[-1], "trace")
        self.assertEqual(set(events[1:-1]), {"decoded"})

    async def test_invalid_digest_never_reaches_decoder_or_cookie_jar(self):
        async def endpoint(request):
            response = await self.signed_response(request, gzip.compress(PLAIN), encoding="gzip")
            response.body = b"invalid compressed data"
            response.set_cookie("session", "unverified")
            return response

        self.endpoint = endpoint
        middleware = self.middleware()
        async with aiohttp.ClientSession(
            **middleware.session_kwargs, cookie_jar=aiohttp.CookieJar(unsafe=True)
        ) as client:
            with (
                patch.object(
                    ZLibDecompressor, "decompress_sync", side_effect=AssertionError("Decoded unverified data")
                ),
                self.assertRaisesRegex(InvalidSignature, "does not match"),
            ):
                await client.get(self.origin)
            self.assertFalse(client.cookie_jar)

    async def test_consumed_response_cannot_verify_only_remaining_bytes(self):
        prefix = b"unsigned content"
        for consumption in ("cached", "stream", "prefix"):
            with self.subTest(consumption=consumption):
                signed_body = PLAIN if consumption == "prefix" else b""
                responses = []

                async def endpoint(request, signed_body=signed_body):
                    response = await self.signed_response(request, signed_body)
                    response.body = prefix + signed_body
                    response.set_cookie("unverified", "value")
                    return response

                async def consume(request, handler, consumption=consumption, responses=responses):
                    response = await handler(request)
                    responses.append(response)
                    if consumption == "cached":
                        await response.read()
                    elif consumption == "stream":
                        await response.content.read()
                    else:
                        self.assertEqual(await response.content.read(len(prefix)), prefix)
                    return response

                self.endpoint = endpoint
                signatures = self.middleware(SignatureMiddlewareMode.VERIFY_RESPONSE)
                options = {**signatures.session_kwargs, "middlewares": (signatures, consume)}
                async with aiohttp.ClientSession(**options, cookie_jar=aiohttp.CookieJar(unsafe=True)) as client:
                    with self.assertRaisesRegex(InvalidSignature, "consumed before verification"):
                        await client.get(self.origin)
                    self.assertFalse(client.cookie_jar)
                self.assertTrue(responses[0].closed)
                with self.assertRaises(InvalidSignature):
                    signatures.verification_results(responses[0])

    async def test_repeated_content_encoding_matches_native_aiohttp(self):
        encoded = gzip.compress(PLAIN)
        encodings = ()

        async def endpoint(request):
            return await self.signed_response(
                request,
                encoded,
                headers=[("Content-Encoding", encoding) for encoding in encodings],
                components=("@status", '"content-encoding";bs'),
            )

        self.endpoint = endpoint
        middleware = self.middleware(
            SignatureMiddlewareMode.VERIFY_RESPONSE,
            verify_options={"require_components": ("@status", '"content-encoding";bs')},
        )
        async with (
            aiohttp.ClientSession() as native,
            aiohttp.ClientSession(**middleware.session_kwargs) as verified,
        ):
            for encodings in (("identity", "gzip"), ("gzip", "identity"), ("gzip", "gzip")):
                with self.subTest(encodings=encodings):
                    async with native.get(self.origin) as response:
                        expected = await response.read()
                    async with verified.get(self.origin) as response:
                        self.assertEqual(await response.read(), expected)
                        self.assertEqual(tuple(response.headers.getall("Content-Encoding")), encodings)
                        self.assertEqual(middleware.verification_results(response)[0].body, encoded)

    async def test_decoded_streams_large_bodies_and_connection_reuse(self):
        plain = b"buffered content\n" * 100000
        for encoding, encode in ((None, lambda b: b), ("gzip", gzip.compress), ("deflate", zlib.compress)):

            async def endpoint(request, encode=encode, encoding=encoding):
                return await self.signed_response(request, encode(plain), encoding=encoding)

            self.endpoint = endpoint
            middleware = self.middleware()
            async with aiohttp.ClientSession(
                **middleware.session_kwargs, connector=aiohttp.TCPConnector(limit=1)
            ) as client:

                async def consume():
                    async with client.get(self.origin, read_bufsize=1024) as response:
                        data = b"".join([chunk async for chunk in response.content.iter_chunked(8192)])
                        self.assertEqual(data, plain)

                with self.subTest(encoding=encoding):
                    await asyncio.gather(*(consume() for _ in range(4)))

    async def test_decoding_matches_native_aiohttp(self):
        compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
        raw_deflate = compressor.compress(PLAIN) + compressor.flush()
        cases = (
            (None, PLAIN),
            ("identity", PLAIN),
            ("unknown", gzip.compress(PLAIN)),
            ("gzip, deflate", PLAIN),
            ("GZip", gzip.compress(PLAIN)),
            ("gzip", gzip.compress(PLAIN[:5]) + gzip.compress(PLAIN[5:])),
            ("gzip", b""),
            ("deflate", raw_deflate),
        )
        middleware = self.middleware(SignatureMiddlewareMode.VERIFY_RESPONSE)
        async with (
            aiohttp.ClientSession() as native,
            aiohttp.ClientSession(**middleware.session_kwargs) as verified,
        ):
            for encoding, body in cases:
                with self.subTest(encoding=encoding, empty=not body):

                    async def endpoint(request, body=body, encoding=encoding):
                        return await self.signed_response(request, body, encoding=encoding)

                    self.endpoint = endpoint
                    async with native.get(self.origin) as response:
                        expected = await response.read()
                    async with verified.get(self.origin) as response:
                        self.assertEqual(await response.read(), expected)
                        self.assertEqual(middleware.verification_results(response)[0].body, body)

    async def test_streamed_file_and_multipart_requests(self):
        async def chunks():
            yield b"streamed "
            await asyncio.sleep(0)
            yield b"request"

        middleware = self.middleware()
        async with aiohttp.ClientSession(**middleware.session_kwargs) as client:
            for compression in (None, "gzip", "deflate"):
                file = io.BytesIO(b"file content")
                self.addCleanup(file.close)
                form = aiohttp.FormData()
                form.add_field("file", io.BytesIO(b"form file"), filename="test.txt")
                for body, expected in ((chunks(), b"streamed request"), (file, b"file content"), (form, b"form file")):
                    with self.subTest(compression=compression, expected=expected):
                        async with client.post(self.origin, data=body, compress=compression) as response:
                            self.assertEqual(await response.read(), PLAIN)
                            received = self.requests[-1][1]
                            if compression:
                                received = (
                                    gzip.decompress(received) if compression == "gzip" else zlib.decompress(received)
                                )
                            self.assertIn(expected, received)

    async def test_compressed_requests_match_native_aiohttp(self):
        middleware = self.middleware(sign_options={"covered_component_ids": ("@method", "@target-uri", "content-type")})
        async with (
            aiohttp.ClientSession() as native,
            aiohttp.ClientSession(**middleware.session_kwargs) as signed,
        ):
            for compression in (True, "gzip", "deflate"):
                for options in ({"data": PLAIN * 1000}, {"json": {"message": "hello"}}, {"data": b""}):
                    with self.subTest(compression=compression, options=options.keys()):
                        for client in (native, signed):
                            async with client.post(self.origin, compress=compression, **options) as response:
                                await response.read()
                        (original, expected), (request, body) = self.requests[-2:]
                        self.assertEqual(body, expected)
                        for header in ("Content-Type", "Content-Encoding", "Content-Length", "Transfer-Encoding"):
                            self.assertEqual(request.headers.get(header), original.headers.get(header))
                        ContentDigest.verify(request.headers["Content-Digest"], body)

    async def test_explicit_content_length_matches_native_aiohttp(self):
        async def chunks():
            yield b"ab"
            yield b"cdef"

        middleware = self.middleware()
        async with (
            aiohttp.ClientSession() as native,
            aiohttp.ClientSession(**middleware.session_kwargs) as signed,
        ):
            for length in (0, 3, 6):
                for make_body in (lambda: b"abcdef", lambda: io.BytesIO(b"abcdef"), chunks):
                    with self.subTest(length=length, body=make_body):
                        for client in (native, signed):
                            async with client.post(
                                self.origin, data=make_body(), headers={"Content-Length": str(length)}
                            ) as response:
                                await response.read()
                        (original, expected), (request, body) = self.requests[-2:]
                        self.assertEqual(body, expected)
                        self.assertEqual(body, b"abcdef"[:length])
                        self.assertEqual(request.headers["Content-Length"], original.headers["Content-Length"])
                        ContentDigest.verify(request.headers["Content-Digest"], body)

    async def test_empty_compressed_stream(self):
        async def chunks():
            yield b""

        middleware = self.middleware()
        async with (
            aiohttp.ClientSession(**middleware.session_kwargs) as client,
            client.post(self.origin, data=chunks(), compress="gzip") as response,
        ):
            await response.read()
        request, body = self.requests[-1]
        self.assertEqual(request.headers["Content-Encoding"], "gzip")
        self.assertEqual(gzip.decompress(body), b"")

    async def test_multipart_part_encoding_is_preserved(self):
        writer = aiohttp.MultipartWriter("mixed")
        part = aiohttp.BytesPayload(b"part bytes", headers={"Content-Transfer-Encoding": "base64"})
        writer.append_payload(part)
        middleware = self.middleware()
        async with (
            aiohttp.ClientSession(**middleware.session_kwargs) as client,
            client.post(self.origin, data=writer) as response,
        ):
            await response.read()
        self.assertIn(b"cGFydCBieXRlcw==", self.requests[-1][1])

    async def test_repeated_and_non_ascii_headers(self):
        components = ("@status", '"x-repeat";bs', '"set-cookie";bs')

        async def endpoint(request):
            return await self.signed_response(
                request,
                headers=(("X-Repeat", " café "), ("X-Repeat", "second"), ("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")),
                components=components,
            )

        self.endpoint = endpoint
        middleware = self.middleware(
            sign_options={"covered_component_ids": ("@method", "@target-uri", '"x-repeat";bs')},
            verify_options={"require_components": components},
        )
        async with aiohttp.ClientSession(
            **middleware.session_kwargs, cookie_jar=aiohttp.CookieJar(unsafe=True)
        ) as client:
            async with client.get(self.origin, headers=[("X-Repeat", " café "), ("X-Repeat", "second")]) as response:
                results = middleware.verification_results(response)
                self.assertEqual(results[0].covered_components['"x-repeat";bs'], ":Y2Fmw6k=:, :c2Vjb25k:")
                self.assertIn('"set-cookie";bs', results[0].covered_components)
            self.assertEqual(set(client.cookie_jar.filter_cookies(self.server.make_url("/"))), {"a", "b"})

    async def test_existing_digest_requires_opt_in_and_must_match(self):
        for allowed, body in ((False, b"body"), (True, b"body"), (True, b"changed")):
            middleware = self.middleware(sign_options={"use_existing_digest": allowed})
            async with aiohttp.ClientSession(**middleware.session_kwargs) as client:

                async def send(body=body):
                    async with client.post(
                        self.origin, data=body, headers={"Content-Digest": ContentDigest.create(b"body")}
                    ) as response:
                        await response.read()

                with self.subTest(allowed=allowed, body=body):
                    if allowed and body == b"body":
                        await send()
                    else:
                        with self.assertRaises(HTTPMessageSignaturesException):
                            await send()
        self.assertEqual(len(self.requests), 1)

    async def test_retry_middleware_reuses_digest(self):
        async def retry(request, handler):
            response = await handler(request)
            response.release()
            return await handler(request)

        middleware = self.middleware()
        options = {**middleware.session_kwargs, "middlewares": (retry, middleware)}
        async with aiohttp.ClientSession(**options) as client:
            for compression in (None, "gzip", "deflate"):
                with self.subTest(compression=compression):
                    async with client.post(self.origin, data=b"retry", compress=compression) as response:
                        await response.read()
                    first, second = [body for _, body in self.requests[-2:]]
                    self.assertEqual(first, second)
                    if compression:
                        first = gzip.decompress(first) if compression == "gzip" else zlib.decompress(first)
                    self.assertEqual(first, b"retry")

        middleware = self.middleware(sign_options={"use_existing_digest": False})
        async with aiohttp.ClientSession(**{**middleware.session_kwargs, "middlewares": (retry, middleware)}) as client:
            with self.assertRaisesRegex(HTTPMessageSignaturesException, "already present"):
                await client.post(self.origin, data=b"retry", compress="gzip")

    async def test_redirects_resign_and_replay_buffered_upload(self):
        async def endpoint(request):
            if request.path == "/redirect":
                return await self.signed_response(request, status=status, headers={"Location": "/destination"})
            return await self.signed_response(request)

        async def chunks():
            yield b"redirected upload"

        self.endpoint = endpoint
        middleware = self.middleware()
        async with aiohttp.ClientSession(**middleware.session_kwargs) as client:
            for status in (301, 302, 303, 307, 308):
                for compression in (None, "gzip", "deflate"):
                    with self.subTest(status=status, compression=compression):
                        async with client.post(
                            self.origin + "/redirect", data=chunks(), compress=compression
                        ) as response:
                            self.assertEqual(response.url.path, "/destination")
                            self.assertEqual(len(response.history), 1)
                        (_, first), (request, second) = self.requests[-2:]
                        if status in (307, 308):
                            self.assertEqual(first, second)
                        else:
                            self.assertEqual(request.method, "GET")
                            self.assertNotIn("Content-Encoding", request.headers)
                            self.assertEqual(second, b"")
                        if compression:
                            first = gzip.decompress(first) if compression == "gzip" else zlib.decompress(first)
                        self.assertEqual(first, b"redirected upload")

    async def test_redirect_preserves_payload_headers(self):
        async def endpoint(request):
            if request.path == "/redirect":
                return await self.signed_response(request, status=status, headers={"Location": "/destination"})
            return await self.signed_response(request)

        def multipart():
            payload = aiohttp.MultipartWriter("mixed", boundary="test-boundary")
            payload.append(PLAIN)
            return payload

        self.endpoint = endpoint
        middleware = self.middleware(sign_options={"covered_component_ids": ("@method", "@target-uri", "content-type")})
        factories = (
            lambda: aiohttp.JsonPayload({"message": "hello"}),
            multipart,
            lambda: aiohttp.BytesPayload(PLAIN, content_type="application/custom", headers={"X-Payload": "metadata"}),
        )
        async with aiohttp.ClientSession(**middleware.session_kwargs) as client:
            for status in (307, 308):
                for compression in (None, "gzip", "deflate"):
                    for make_payload in factories:
                        payload = make_payload()
                        with self.subTest(status=status, compression=compression, content_type=payload.content_type):
                            async with client.post(
                                self.origin + "/redirect", data=payload, compress=compression
                            ) as response:
                                await response.read()
                            (first, original), (second, replayed) = self.requests[-2:]
                            self.assertEqual(original, replayed)
                            for name, value in payload.headers.items():
                                self.assertEqual(first.headers[name], value)
                                self.assertEqual(second.headers[name], value)

    async def test_forward_proxy_request_target_and_response_binding(self):
        components = ("@status", '"@request-target";req')

        async def endpoint(request):
            return await self.signed_response(request, components=components)

        self.endpoint = endpoint
        for proxy in (None, self.origin):
            origin = "http://target.example" if proxy else self.origin
            path = "/resource%2Fname?x=1&x=2"
            middleware = self.middleware(
                sign_options={"origin": origin, "covered_component_ids": ("@method", "@request-target")},
                verify_options={"origin": origin, "require_components": components},
            )
            with self.subTest(proxy=proxy):
                async with (
                    aiohttp.ClientSession(**middleware.session_kwargs) as client,
                    client.post(origin + path, data=PLAIN, proxy=proxy) as response,
                ):
                    result = middleware.verification_results(response)[0]
                    target = origin + path if proxy else path
                    self.assertEqual(self.requests[-1][0].raw_path, target)
                    self.assertEqual(result.covered_components['"@request-target";req'], target)
                    self.assertEqual(await response.read(), PLAIN)

    async def test_cross_origin_redirect_is_blocked(self):
        received = []

        async def destination(request):
            received.append(request.headers)
            return web.Response()

        app = web.Application()
        app.router.add_post("/", destination)
        async with TestServer(app) as server:

            async def endpoint(request):
                return await self.signed_response(request, status=307, headers={"Location": str(server.make_url("/"))})

            self.endpoint = endpoint
            credentials = {"Cookie": "session=private", "Authorization": "Bearer private"}
            for mode in SignatureMiddlewareMode:
                middleware = self.middleware(mode)
                async with aiohttp.ClientSession(**middleware.session_kwargs) as client:
                    for compression in (None, "gzip"):
                        for in_payload in (False, True):
                            with self.subTest(mode=mode, compression=compression, in_payload=in_payload):
                                payload = aiohttp.BytesPayload(PLAIN, headers=credentials if in_payload else {})
                                with self.assertRaisesRegex(HTTPMessageSignaturesException, "origin"):
                                    await client.post(
                                        self.origin,
                                        data=payload,
                                        compress=compression,
                                        headers={} if in_payload else credentials,
                                    )
            self.assertFalse(received)

    async def test_middleware_order_authenticates_mutations_before_consumers(self):
        middleware = self.middleware(sign_options={"covered_component_ids": ("@method", "x-added")})

        async def outer(request, handler):
            request.headers["X-Added"] = "covered"
            response = await handler(request)
            self.assertTrue(middleware.verification_results(response))
            self.assertEqual(await response.json(), {"verified": True})
            return response

        async with (
            aiohttp.ClientSession(**{**middleware.session_kwargs, "middlewares": (outer, middleware)}) as client,
            client.get(self.origin),
        ):
            pass
        self.assertIn('"x-added"', self.requests[0][0].headers["Signature-Input"])

    async def test_empty_head_and_no_content_responses(self):
        for method, status in (("HEAD", 200), ("GET", 204)):

            async def endpoint(request, status=status):
                return await self.signed_response(request, body=b"", status=status)

            self.endpoint = endpoint
            middleware = self.middleware()
            async with (
                aiohttp.ClientSession(**middleware.session_kwargs) as client,
                client.request(method, self.origin) as response,
            ):
                self.assertEqual(await response.read(), b"")
                self.assertEqual(middleware.verification_results(response)[0].body, b"")

    async def test_configuration_errors_prevent_sending(self):
        middleware = self.middleware()
        async with aiohttp.ClientSession(middlewares=(middleware,)) as client:
            with self.assertRaisesRegex(ValueError, "session_kwargs"):
                await client.get(self.origin)
        self.assertFalse(self.requests)

    async def test_compressed_existing_digest_describes_encoded_bytes(self):
        async with (
            aiohttp.ClientSession() as client,
            client.post(self.origin, data=PLAIN, compress="gzip") as response,
        ):
            await response.read()
        encoded = self.requests[-1][1]
        cases = ((False, encoded, "already present"), (True, encoded, None), (True, PLAIN, "does not match"))
        for allowed, content, error in cases:
            with self.subTest(allowed=allowed, error=error):
                middleware = self.middleware(sign_options={"use_existing_digest": allowed})
                async with aiohttp.ClientSession(**middleware.session_kwargs) as client:

                    async def send(content=content):
                        async with client.post(
                            self.origin,
                            data=PLAIN,
                            compress="gzip",
                            headers={"Content-Digest": ContentDigest.create(content)},
                        ) as response:
                            await response.read()

                    if error:
                        with self.assertRaisesRegex(HTTPMessageSignaturesException, error):
                            await send()
                    else:
                        await send()
        self.assertEqual(len(self.requests), 2)

    async def test_per_request_decompression_override_is_rejected(self):
        async def endpoint(request):
            return await self.signed_response(request, gzip.compress(PLAIN), encoding="gzip")

        self.endpoint = endpoint
        middleware = self.middleware()
        async with aiohttp.ClientSession(**middleware.session_kwargs) as client:
            with self.assertRaisesRegex(ValueError, "auto_decompress=True"):
                await client.get(self.origin, auto_decompress=True)

    async def test_precompressed_upload(self):
        body = gzip.compress(b"request content")
        middleware = self.middleware()
        async with (
            aiohttp.ClientSession(**middleware.session_kwargs) as client,
            client.post(self.origin, data=body, headers={"Content-Encoding": "gzip"}) as response,
        ):
            await response.read()
        self.assertEqual(self.requests[0][1], body)

    async def test_unknown_kwargs_reach_base_methods(self):
        for field, name in (("sign_options", "covered_component_id"), ("verify_options", "require_component")):
            middleware = self.middleware(**{field: {name: ()}})
            async with aiohttp.ClientSession(**middleware.session_kwargs) as client:
                with self.assertRaisesRegex(TypeError, name):
                    await client.get(self.origin)

    async def test_independent_algorithms_and_resolvers(self):
        private_key = Ed25519PrivateKey.generate()
        server_keys = MappingKeyResolver(
            public_keys={"server": private_key.public_key()}, private_keys={"server": private_key}
        )
        self.signer = HTTPMessageSigner(signature_algorithm=algorithms.ED25519, key_resolver=server_keys)
        middleware = self.middleware(
            verify_options={"signature_algorithm": algorithms.ED25519, "key_resolver": server_keys}
        )
        async with aiohttp.ClientSession(**middleware.session_kwargs) as client, client.get(self.origin) as response:
            self.assertIs(middleware.verification_results(response)[0].algorithm, algorithms.ED25519)

    async def test_payload_cleanup_after_buffering_and_failure(self):
        class TrackedPayload(aiohttp.BytesPayload):
            closed = False

            async def close(self):
                self.closed = True

        middleware = self.middleware()
        async with aiohttp.ClientSession(**middleware.session_kwargs) as client:
            for compression in (None, "gzip"):
                with self.subTest(compression=compression):
                    payload = TrackedPayload(b"body")
                    async with client.post(self.origin, data=payload, compress=compression):
                        self.assertTrue(payload.closed)
                    payload = TrackedPayload(b"body")
                    with self.assertRaisesRegex(HTTPMessageSignaturesException, "already present"):
                        await client.post(
                            self.origin,
                            data=payload,
                            compress=compression,
                            headers={"Content-Digest": ContentDigest.create(b"body")},
                        )
                    self.assertTrue(payload.closed)

    async def test_buffering_failure_discards_partial_body_and_closes_payload(self):
        class FailingPayload(aiohttp.BytesPayload):
            closed = False

            async def write_with_length(self, writer, content_length):
                await writer.write(b"partial content")
                raise failure

            async def close(self):
                self.closed = True

        async def check_cleanup(request, handler):
            try:
                return await handler(request)
            finally:
                # Check before ClientSession's own error cleanup can hide a leak.
                self.assertTrue(payload.closed)

        middleware = self.middleware()
        options = {**middleware.session_kwargs, "middlewares": (check_cleanup, middleware)}
        async with aiohttp.ClientSession(**options) as client:
            for compression in (None, "gzip"):
                for failure in (asyncio.CancelledError(), RuntimeError("upload failed")):
                    with self.subTest(compression=compression, failure=type(failure).__name__):
                        payload = FailingPayload(b"body")
                        with patch.object(ZLibCompressor, "flush") as flush, self.assertRaises(type(failure)):
                            await client.post(self.origin, data=payload, compress=compression)
                        flush.assert_not_called()
        self.assertFalse(self.requests)

    async def test_unsigned_responses_and_unsigned_digests_are_rejected(self):
        async def unsigned(request):
            return web.Response(body=PLAIN)

        async def unsigned_digest(request):
            response = await self.signed_response(request)
            view = _Response(
                response.status,
                _HeaderFields(lambda: response.headers.items(), writable=response.headers),
                _Request(request.method, str(request.url), _HeaderFields.from_raw(lambda: request.raw_headers)),
            )
            self.signer.sign(
                view,
                key_id="server",
                use_existing_digest=True,
                covered_component_ids=("@status", '"@method";req', '"@target-uri";req'),
            )
            return response

        for endpoint in (unsigned, unsigned_digest):
            self.endpoint = endpoint
            middleware = self.middleware()
            async with aiohttp.ClientSession(**middleware.session_kwargs) as client:
                with self.assertRaises(InvalidSignature):
                    await client.get(self.origin)

    async def test_cancellation_closes_response(self):
        middleware = self.middleware()
        received = []

        async def endpoint(request):
            return await self.signed_response(request, gzip.compress(PLAIN), encoding="gzip")

        async def record(request, handler):
            response = await handler(request)
            received.append(response)
            return response

        decompress = ZLibDecompressor.decompress_sync

        def cancel_after_decoding(decoder, data, max_length=0):
            decoded = decompress(decoder, data, max_length)
            asyncio.get_running_loop().call_soon(task.cancel)
            return decoded

        self.endpoint = endpoint
        async with aiohttp.ClientSession(
            **{**middleware.session_kwargs, "middlewares": (middleware, record)}
        ) as client:
            with (
                patch.object(ZLibDecompressor, "decompress_sync", cancel_after_decoding),
                self.assertRaises(asyncio.CancelledError),
            ):
                task = asyncio.create_task(client.get(self.origin))
                await task
        self.assertTrue(received[0].closed)
        with self.assertRaises(InvalidSignature):
            middleware.verification_results(received[0])

    async def test_chunked_response_is_verified_before_consumption(self):
        async def endpoint(request):
            encoded = gzip.compress(PLAIN)
            signed = await self.signed_response(request, encoded, encoding="gzip")
            response = web.StreamResponse(headers=signed.headers)
            await response.prepare(request)
            await response.write(encoded[:10])
            await response.write(encoded[10:])
            await response.write_eof()
            return response

        self.endpoint = endpoint
        middleware = self.middleware()
        async with (
            aiohttp.ClientSession(**middleware.session_kwargs) as client,
            client.get(self.origin) as response,
        ):
            self.assertEqual(response.headers["Transfer-Encoding"], "chunked")
            self.assertTrue(middleware.verification_results(response))
            self.assertEqual(await response.read(), PLAIN)

    async def test_invalid_authenticated_encoding_closes_response(self):
        async def endpoint(request):
            return await self.signed_response(request, b"not compressed", encoding="gzip")

        received = []

        async def record(request, handler):
            response = await handler(request)
            received.append(response)
            return response

        self.endpoint = endpoint
        middleware = self.middleware()
        async with aiohttp.ClientSession(
            **{**middleware.session_kwargs, "middlewares": (middleware, record)}
        ) as client:
            with self.assertRaises(aiohttp.ClientPayloadError):
                await client.get(self.origin)
        self.assertTrue(received[0].closed)
        with self.assertRaises(InvalidSignature):
            middleware.verification_results(received[0])
