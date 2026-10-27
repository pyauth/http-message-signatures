import asyncio
import gzip
import logging
import unittest
from unittest.mock import AsyncMock, patch

import aiohttp
from aiohttp import web
from aiohttp.compression_utils import ZLibDecompressor
from aiohttp.payload import AsyncIterablePayload, BytesPayload
from aiohttp.streams import EMPTY_PAYLOAD
from aiohttp.test_utils import TestServer, make_mocked_request
from aiohttp.web_response import ContentCoding
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from multidict import CIMultiDict
from yarl import URL

from http_message_signatures import (
    ContentDigest,
    HTTPMessageSigner,
    HTTPMessageVerifier,
    HTTPSignatureKeyResolver,
    InvalidSignature,
    MappingKeyResolver,
    algorithms,
)
from http_message_signatures._messages import _HeaderFields, _Request, _Response
from http_message_signatures.aiohttp import (
    ServerSignatureMiddleware,
    ServerSignatureMiddlewareMode,
    SignatureMiddleware,
    SignatureMiddlewareMode,
    _DecodedStream,
)

SECRET = b"local-tests-only-server-secret"
RESPONSE_COMPONENTS = ("@status", '"@method";req', '"@target-uri";req')


class AiohttpServerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        # Failure tests assert disconnection and the originating exception;
        # aiohttp also logs those expected preparation errors.
        logging_patch = patch.object(logging.getLogger("aiohttp.server"), "disabled", True)
        logging_patch.start()
        self.addCleanup(logging_patch.stop)
        self.keys = MappingKeyResolver(public_keys={"key": SECRET}, private_keys={"key": SECRET})
        self.signer = HTTPMessageSigner(signature_algorithm=algorithms.HMAC_SHA256, key_resolver=self.keys)
        self.verifier = HTTPMessageVerifier(signature_algorithm=algorithms.HMAC_SHA256, key_resolver=self.keys)
        self.errors = []
        self.seen = []

    def middleware(
        self, mode=ServerSignatureMiddlewareMode.VERIFY_REQUEST_SIGN_RESPONSE, *, sign_options=None, verify_options=None
    ):
        options = {}
        if mode is not ServerSignatureMiddlewareMode.VERIFY_REQUEST:
            options["sign_options"] = {
                "signature_algorithm": algorithms.HMAC_SHA256,
                "key_resolver": self.keys,
                "key_id": "key",
                "covered_component_ids": RESPONSE_COMPONENTS,
                **(sign_options or {}),
            }
        if mode is not ServerSignatureMiddlewareMode.SIGN_RESPONSE:
            options["verify_options"] = {
                "signature_algorithm": algorithms.HMAC_SHA256,
                "key_resolver": self.keys,
                **(verify_options or {}),
            }
        return ServerSignatureMiddleware(mode, **options)

    async def start(self, signatures, handler=None, *, before=(), prepare=(), install=True, **options):
        @web.middleware
        async def errors(request, handler):
            try:
                return await handler(request)
            except (InvalidSignature, ValueError, TypeError) as exc:
                self.errors.append(exc)
                return web.Response(status=403, text=str(exc))

        async def echo(request):
            self.seen.append(request)
            return web.Response(body=await request.read())

        app = web.Application(**{**signatures.application_kwargs, **options})
        app.middlewares[:0] = [errors, *before]
        app.router.add_route("*", "/{path:.*}", handler or echo)
        app.on_response_prepare.extend(prepare)
        if install and signatures.signer is not None:
            app.on_response_prepare.append(signatures.on_response_prepare)
        server = TestServer(app)
        await server.start_server()
        self.addAsyncCleanup(server.close)
        return server

    def client_middleware(self, server, mode=SignatureMiddlewareMode.SIGN_REQUEST_VERIFY_RESPONSE, **sign_options):
        config = {
            "origin": str(server.make_url("/")).rstrip("/"),
            "signature_algorithm": algorithms.HMAC_SHA256,
            "key_resolver": self.keys,
        }
        options = {}
        if mode is not SignatureMiddlewareMode.VERIFY_RESPONSE:
            options["sign_options"] = {**config, "key_id": "key", **sign_options}
        if mode is not SignatureMiddlewareMode.SIGN_REQUEST:
            options["verify_options"] = {**config, "require_components": RESPONSE_COMPONENTS}
        return SignatureMiddleware(mode, **options)

    async def test_modes_and_connection_reuse(self):
        for mode in ServerSignatureMiddlewareMode:
            with self.subTest(mode=mode):
                signatures = self.middleware(mode)
                server = await self.start(signatures)
                client_mode = {
                    ServerSignatureMiddlewareMode.VERIFY_REQUEST: SignatureMiddlewareMode.SIGN_REQUEST,
                    ServerSignatureMiddlewareMode.SIGN_RESPONSE: SignatureMiddlewareMode.VERIFY_RESPONSE,
                    ServerSignatureMiddlewareMode.VERIFY_REQUEST_SIGN_RESPONSE: SignatureMiddlewareMode.SIGN_REQUEST_VERIFY_RESPONSE,
                }[mode]
                client_signatures = self.client_middleware(server, client_mode)
                async with aiohttp.ClientSession(**client_signatures.session_kwargs) as client:
                    for body in (b"hello", b"", b"second body"):
                        async with client.post(server.make_url("/"), data=body) as response:
                            self.assertEqual(response.status, 200)
                            self.assertEqual(await response.read(), body)
                            request = self.seen[-1]
                            if signatures.verifier is not None:
                                self.assertEqual(signatures.verification_results(request)[0].body, body)
                            else:
                                with self.assertRaises(InvalidSignature):
                                    signatures.verification_results(request)
                    self.assertEqual(len(client.connector._conns), 1)
                if signatures.verifier is None:
                    self.assertNotIn("handler_args", signatures.application_kwargs)

    async def test_configuration_and_base_defaults(self):
        for mode in ServerSignatureMiddlewareMode:
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                ServerSignatureMiddleware(mode)
        with self.assertRaises(TypeError):
            ServerSignatureMiddleware("verify_request")
        with self.assertRaises(TypeError):
            ServerSignatureMiddleware(ServerSignatureMiddlewareMode.VERIFY_REQUEST, verify_options={})
        with self.assertRaises(ValueError):
            ServerSignatureMiddleware(ServerSignatureMiddlewareMode.VERIFY_REQUEST, sign_options={}, verify_options={})
        with self.assertRaises(ValueError):
            ServerSignatureMiddleware(ServerSignatureMiddlewareMode.SIGN_RESPONSE, sign_options={}, verify_options={})
        signatures = ServerSignatureMiddleware(
            sign_options={"signature_algorithm": algorithms.HMAC_SHA256, "key_id": "key", "key_resolver": self.keys},
            verify_options={"signature_algorithm": algorithms.HMAC_SHA256, "key_resolver": self.keys},
        )
        self.assertEqual(signatures._sign_kwargs, {"key_id": "key"})
        self.assertEqual(signatures._verify_kwargs, {})
        with patch.object(signatures.signer, "sign", wraps=signatures.signer.sign) as sign:
            server = await self.start(signatures)
            sender = self.client_middleware(server, SignatureMiddlewareMode.SIGN_REQUEST)
            async with aiohttp.ClientSession(**sender.session_kwargs) as client:
                with self.assertRaises(aiohttp.ServerDisconnectedError):
                    await client.post(server.make_url("/"))
            self.assertEqual(set(sign.call_args.kwargs), {"key_id", "body"})

    async def test_application_options_can_be_customized_without_changing_defaults(self):
        signatures = self.middleware()
        options = signatures.application_kwargs
        options["middlewares"] = ()
        options["handler_args"]["auto_decompress"] = True
        fresh = signatures.application_kwargs
        self.assertEqual(fresh["middlewares"], (signatures._middleware,))
        self.assertEqual(fresh["handler_args"], {"auto_decompress": False})

    async def test_unknown_options_reach_base_methods(self):
        signatures = self.middleware(ServerSignatureMiddlewareMode.VERIFY_REQUEST, verify_options={"typo": True})
        server = await self.start(signatures)
        async with aiohttp.ClientSession() as client, client.post(server.make_url("/")) as response:
            self.assertEqual(response.status, 403)
        self.assertIsInstance(self.errors[-1], TypeError)
        self.assertIn("typo", str(self.errors[-1]))
        signatures = self.middleware(ServerSignatureMiddlewareMode.SIGN_RESPONSE, sign_options={"typo": True})
        server = await self.start(signatures)
        with patch.object(signatures.signer, "sign", wraps=signatures.signer.sign) as sign:
            async with aiohttp.ClientSession() as client:
                with self.assertRaises(aiohttp.ServerDisconnectedError):
                    await client.post(server.make_url("/"))
        self.assertIn("typo", sign.call_args.kwargs)

    async def test_independent_algorithms_and_lazy_key_resolvers(self):
        private_key = Ed25519PrivateKey.generate()
        lookups = []

        class ServerKeys(HTTPSignatureKeyResolver):
            def resolve_private_key(self, key_id):
                lookups.append(key_id)
                return private_key

        signatures = self.middleware(
            sign_options={"signature_algorithm": algorithms.ED25519, "key_resolver": ServerKeys()}
        )
        server = await self.start(signatures)
        sender = self.client_middleware(server, SignatureMiddlewareMode.SIGN_REQUEST)
        verifier = HTTPMessageVerifier(
            signature_algorithm=algorithms.ED25519,
            key_resolver=MappingKeyResolver(public_keys={"key": private_key.public_key()}, private_keys={}),
        )
        async with (
            aiohttp.ClientSession(**sender.session_kwargs) as client,
            client.post(server.make_url("/"), data=b"hello") as response,
        ):
            view = _Response(
                response.status,
                _HeaderFields.from_raw(lambda: response.raw_headers),
                _Request("POST", str(response.url), _HeaderFields(lambda: ())),
            )
            verifier.verify(view, body=await response.read())
        self.assertEqual(lookups, ["key"])

    async def test_native_request_readers_after_compressed_verification(self):
        signatures = self.middleware()
        reader = "json"

        async def handler(request):
            self.assertIsNotNone(signatures.verification_results(request)[0].body)
            if reader == "json":
                self.assertEqual(await request.json(), {"value": "hello"})
                self.assertEqual(await request.text(), '{"value": "hello"}')
            elif reader == "post":
                self.assertEqual(dict(await request.post()), {"value": "hello"})
            elif reader == "multipart":
                multipart = await request.multipart()
                part = await multipart.next()
                self.assertEqual(await part.read(), b"hello")
                self.assertIsNone(await multipart.next())
            else:
                self.assertEqual(b"".join([chunk async for chunk in request.content.iter_chunked(2)]), b"hello")
            return web.Response(text="ok")

        server = await self.start(signatures, handler)
        client_signatures = self.client_middleware(server)
        async with aiohttp.ClientSession(**client_signatures.session_kwargs) as client:
            for reader in ("json", "post", "multipart", "content"):
                with self.subTest(reader=reader):
                    if reader == "json":
                        options = {"json": {"value": "hello"}}
                    elif reader == "post":
                        options = {"data": {"value": "hello"}}
                    elif reader == "multipart":
                        form = aiohttp.FormData()
                        form.add_field("value", b"hello", filename="value.txt")
                        options = {"data": form}
                    else:
                        options = {"data": b"hello"}
                    async with client.post(server.make_url("/"), compress="gzip", **options) as response:
                        self.assertEqual(response.status, 200)
                        self.assertEqual(await response.text(), "ok")

    async def test_tampering_rejected_before_decoding_or_handler(self):
        signatures = self.middleware()
        server = await self.start(signatures)
        url = server.make_url("/")
        headers = CIMultiDict({"Content-Encoding": "gzip"})
        self.signer.sign(_Request("POST", str(url), headers), key_id="key", body=gzip.compress(b"valid"))
        with patch.object(ZLibDecompressor, "decompress_sync", side_effect=AssertionError("decoded unverified body")):
            async with (
                aiohttp.ClientSession() as client,
                client.post(url, data=b"invalid", headers=headers) as response,
            ):
                self.assertEqual(response.status, 403)
                self.assertIn("does not match", await response.text())
                self.assertIn("Signature", response.headers)
        self.assertFalse(self.seen)

    async def test_partial_consumption_rejected_full_cached_read_allowed(self):
        partial = True

        @web.middleware
        async def consume(request, handler):
            if partial:
                await request.content.read(2)
            else:
                await request.read()
            return await handler(request)

        signatures = self.middleware()
        server = await self.start(signatures, before=(consume,))
        client_signatures = self.client_middleware(server)
        async with aiohttp.ClientSession(**client_signatures.session_kwargs) as client:
            for partial in (True, False):
                async with client.post(server.make_url("/"), data=b"hello", compress="gzip") as response:
                    self.assertEqual(response.status, 403 if partial else 200)
                    text = await response.text()
                    self.assertIn("partially consumed" if partial else "hello", text)

    async def test_early_decompression_rejected(self):
        signatures = self.middleware()
        server = await self.start(signatures, handler_args={"auto_decompress": True})
        client_signatures = self.client_middleware(server)
        async with (
            aiohttp.ClientSession(**client_signatures.session_kwargs) as client,
            client.post(server.make_url("/"), data=b"hello", compress="gzip") as response,
        ):
            self.assertEqual(response.status, 403)
            self.assertIn("auto_decompress", await response.text())
        self.assertFalse(self.seen)

    async def test_encoded_and_decoded_request_limits(self):
        signatures = self.middleware()
        server = await self.start(signatures, client_max_size=2048)
        client_signatures = self.client_middleware(server)
        with patch(
            "http_message_signatures.aiohttp._DecodedStream.feed_data",
            autospec=True,
            side_effect=_DecodedStream.feed_data,
        ) as feed:
            async with aiohttp.ClientSession(**client_signatures.session_kwargs) as client:
                for body, compress in ((b"a" * 2049, None), (b"a" * 1000000, "gzip"), (b"b" * 2048, None)):
                    async with client.post(server.make_url("/"), data=body, compress=compress) as response:
                        self.assertEqual(response.status, 413 if len(body) > 2048 else 200)
                        await response.read()
            self.assertTrue(feed.called)
            self.assertTrue(all(len(call.args[1]) < 1000000 for call in feed.call_args_list))
        self.assertEqual(len(self.seen), 1)

    async def test_unlimited_request_limit(self):
        signatures = self.middleware()
        server = await self.start(signatures, client_max_size=0)
        client_signatures = self.client_middleware(server)
        async with (
            aiohttp.ClientSession(**client_signatures.session_kwargs) as client,
            client.post(server.make_url("/"), data=b"a" * 200000, compress="gzip") as response,
        ):
            self.assertEqual(response.status, 200)
            self.assertEqual(len(await response.read()), 200000)

    async def test_final_headers_compression_and_request_snapshot(self):
        components = (
            *RESPONSE_COMPONENTS,
            '"set-cookie";bs',
            '"x-value";bs',
            "content-encoding",
            "x-late",
            '"x-value";req;bs',
            '"@request-target";req',
        )
        signatures = self.middleware(sign_options={"covered_component_ids": components})

        async def prepare(request, response):
            response.headers["X-Late"] = "prepared"

        async def handler(request):
            self.seen.append(request)
            # A later application clone must not change the request bound by the signature.
            changed = request.clone(method="DELETE", headers={"X-Value": "changed"})
            self.assertEqual(changed.method, "DELETE")
            response = web.json_response(
                {"ok": True}, headers=CIMultiDict([("X-Value", "caf\u00e9"), ("X-Value", "second")])
            )
            response.set_cookie("one", "1")
            response.set_cookie("two", "2")
            response.enable_compression(force=ContentCoding.gzip)
            return response

        server = await self.start(signatures, handler, prepare=(prepare,))
        client_signatures = self.client_middleware(
            server, covered_component_ids=("@method", "@target-uri", "@request-target", '"x-value";bs')
        )
        async with (
            aiohttp.ClientSession(**client_signatures.session_kwargs) as client,
            client.get(
                server.make_url("/a%2Fb?x=%2F"), headers=[("X-Value", "caf\u00e9"), ("X-Value", "second")]
            ) as response,
        ):
            self.assertEqual(await response.json(), {"ok": True})
            self.assertEqual(len(response.headers.getall("Set-Cookie")), 2)
            self.assertEqual(response.headers["X-Late"], "prepared")
            self.assertTrue(client_signatures.verification_results(response)[0].body.startswith(b"\x1f\x8b"))

    async def test_native_bodyless_response_semantics(self):
        for method, status in (("HEAD", 200), ("GET", 204), ("GET", 304)):
            with self.subTest(method=method, status=status):
                signatures = self.middleware(ServerSignatureMiddlewareMode.SIGN_RESPONSE)

                async def handler(request, status=status):
                    return web.Response(body=b"representation", status=status)

                server = await self.start(signatures, handler)
                client_signatures = self.client_middleware(server, SignatureMiddlewareMode.VERIFY_RESPONSE)
                async with (
                    aiohttp.ClientSession(**client_signatures.session_kwargs) as client,
                    client.request(method, server.make_url("/")) as response,
                ):
                    self.assertEqual(await response.read(), b"")
                    self.assertEqual(response.headers["Content-Digest"], ContentDigest.create(b""))

    async def test_explicit_prepare_and_payload_buffering(self):
        for payload_body in (False, True):
            with self.subTest(payload=payload_body):
                payload = BytesPayload(b"hello", headers={"X-Payload": "kept"})
                signatures = self.middleware(ServerSignatureMiddlewareMode.SIGN_RESPONSE)

                async def handler(request, payload=payload, payload_body=payload_body):
                    response = web.Response(body=payload if payload_body else b"hel", headers={"Content-Length": "3"})
                    if not payload_body:
                        await response.prepare(request)
                    return response

                server = await self.start(signatures, handler)
                client_signatures = self.client_middleware(server, SignatureMiddlewareMode.VERIFY_RESPONSE)
                with patch.object(payload, "close", wraps=payload.close) as close:
                    async with (
                        aiohttp.ClientSession(**client_signatures.session_kwargs) as client,
                        client.get(server.make_url("/")) as response,
                    ):
                        self.assertEqual(await response.read(), b"hel")
                        self.assertEqual(response.headers["Content-Length"], "3")
                        if payload_body:
                            self.assertEqual(response.headers["X-Payload"], "kept")
                    self.assertEqual(close.await_count, int(payload_body))

    async def test_existing_digest_requires_opt_in_and_matching_body(self):
        for reuse, digest_body in ((False, b"hello"), (True, b"hello"), (True, b"wrong")):
            with self.subTest(reuse=reuse, digest_body=digest_body):
                signatures = self.middleware(
                    ServerSignatureMiddlewareMode.SIGN_RESPONSE, sign_options={"use_existing_digest": reuse}
                )

                async def handler(request, digest_body=digest_body):
                    return web.Response(body=b"hello", headers={"Content-Digest": ContentDigest.create(digest_body)})

                server = await self.start(signatures, handler)
                async with aiohttp.ClientSession() as client:
                    if reuse and digest_body == b"hello":
                        async with client.post(server.make_url("/")) as response:
                            self.assertEqual(await response.read(), b"hello")
                            self.assertIn("Signature", response.headers)
                    else:
                        with self.assertRaises(aiohttp.ServerDisconnectedError):
                            await client.post(server.make_url("/"))

    async def test_unsupported_responses_fail_before_headers(self):
        for kind in ("stream", "file", "chunked-compressed", "prepared-payload", "short-length", "long-length"):
            with self.subTest(kind=kind):
                signatures = self.middleware(ServerSignatureMiddlewareMode.SIGN_RESPONSE)

                async def handler(request, kind=kind):
                    if kind == "stream":
                        return web.StreamResponse()
                    if kind == "file":
                        return web.FileResponse(__file__)
                    if kind in ("short-length", "long-length"):
                        return web.Response(
                            body=b"hello", headers={"Content-Length": "3" if kind == "short-length" else "9"}
                        )
                    response = web.Response(body=BytesPayload(b"hello") if kind == "prepared-payload" else b"hello")
                    if kind == "chunked-compressed":
                        response.enable_chunked_encoding()
                        response.enable_compression(force=ContentCoding.gzip)
                    else:
                        await response.prepare(request)
                    return response

                server = await self.start(signatures, handler)
                async with aiohttp.ClientSession() as client:
                    with self.assertRaises(aiohttp.ServerDisconnectedError):
                        await client.post(server.make_url("/"))

    async def test_missing_or_late_callback_fails_before_handler(self):
        for install in (False, True):
            signatures = self.middleware(ServerSignatureMiddlewareMode.SIGN_RESPONSE)

            async def late(request, response):
                response.headers["X-Late"] = "changed"

            callbacks = (signatures.on_response_prepare, late) if install else ()
            server = await self.start(signatures, install=False, prepare=callbacks)
            async with aiohttp.ClientSession() as client:
                with self.assertRaises(aiohttp.ServerDisconnectedError):
                    await client.post(server.make_url("/"))
        self.assertFalse(self.seen)
        self.assertTrue(all("Register on_response_prepare" in str(error) for error in self.errors))

    async def test_http_exceptions_are_signed(self):
        signatures = self.middleware()

        async def handler(request):
            raise web.HTTPNotFound(text="missing")

        server = await self.start(signatures, handler)
        client_signatures = self.client_middleware(server)
        async with (
            aiohttp.ClientSession(**client_signatures.session_kwargs) as client,
            client.get(server.make_url("/")) as response,
        ):
            self.assertEqual(response.status, 404)
            self.assertEqual(await response.text(), "missing")

    async def test_payload_cleanup_on_failure_and_cancellation(self):
        for error in (RuntimeError("payload failed"), asyncio.CancelledError()):
            with self.subTest(error=type(error)):
                signatures = self.middleware(ServerSignatureMiddlewareMode.SIGN_RESPONSE)
                request = make_mocked_request("GET", "/", app=web.Application(**signatures.application_kwargs))
                request.app.on_response_prepare.append(signatures.on_response_prepare)
                payload = BytesPayload(b"hello")
                handler = AsyncMock(return_value=web.Response(body=payload))
                with (
                    patch.object(payload, "write_with_length", side_effect=error),
                    patch.object(payload, "close", wraps=payload.close) as close,
                    self.assertRaises(type(error)),
                ):
                    await signatures._middleware(request, handler)
                close.assert_awaited_once()
                request.transport.abort.assert_called_once()

    async def test_subapplication_preparation_order(self):
        signatures = self.middleware(
            ServerSignatureMiddlewareMode.SIGN_RESPONSE, sign_options={"covered_component_ids": ("@status", "x-child")}
        )

        async def handler(request):
            return web.Response(text="child")

        async def prepare(request, response):
            response.headers["X-Child"] = "prepared"

        parent = web.Application(**signatures.application_kwargs)
        child = web.Application()
        child.router.add_post("/", handler)
        child.on_response_prepare.extend((prepare, signatures.on_response_prepare))
        parent.add_subapp("/child", child)
        server = TestServer(parent)
        await server.start_server()
        self.addAsyncCleanup(server.close)
        async with aiohttp.ClientSession() as client, client.post(server.make_url("/child/")) as response:
            view = _Response(
                response.status,
                _HeaderFields.from_raw(lambda: response.raw_headers),
                _Request("POST", str(response.url), _HeaderFields(lambda: ())),
            )
            self.verifier.verify(view, body=await response.read(), require_components=("x-child",))

    async def test_trusted_proxy_clone(self):
        @web.middleware
        async def trusted_proxy(request, handler):
            return await handler(request.clone(scheme="https", host="public.example"))

        signatures = self.middleware()
        server = await self.start(signatures, before=(trusted_proxy,))
        url = server.make_url("/a%2Fb?x=1")
        public_url = URL("https://public.example/a%2Fb?x=1", encoded=True)
        headers = CIMultiDict()
        self.signer.sign(_Request("POST", str(public_url), headers), key_id="key", body=b"hello")
        async with aiohttp.ClientSession() as client:
            for body in (b"hello", b"tampered"):
                async with client.post(url, data=body, headers=headers) as response:
                    self.assertEqual(response.status, 200 if body == b"hello" else 403)
                    view = _Response(
                        response.status,
                        _HeaderFields.from_raw(lambda: response.raw_headers),
                        _Request("POST", str(public_url), headers),
                    )
                    self.verifier.verify(view, body=await response.read())

    async def test_parent_signing_callback_cannot_precede_child_mutation(self):
        signatures = self.middleware(ServerSignatureMiddlewareMode.SIGN_RESPONSE)
        handler = AsyncMock(return_value=web.Response(text="child"))

        async def change_headers(request, response):
            response.headers["X-Child"] = "changed"

        parent = web.Application(**signatures.application_kwargs)
        parent.on_response_prepare.append(signatures.on_response_prepare)
        child = web.Application()
        child.router.add_post("/", handler)
        child.on_response_prepare.append(change_headers)
        parent.add_subapp("/child", child)
        server = TestServer(parent)
        await server.start_server()
        self.addAsyncCleanup(server.close)
        async with aiohttp.ClientSession() as client:
            with self.assertRaises(aiohttp.ServerDisconnectedError):
                await client.post(server.make_url("/child/"))
        handler.assert_not_awaited()

    async def test_invalid_signature_headers_precede_body_read(self):
        signatures = self.middleware(ServerSignatureMiddlewareMode.VERIFY_REQUEST)
        request = make_mocked_request("POST", "/", payload=EMPTY_PAYLOAD)
        handler = AsyncMock()
        with patch.object(request, "read", side_effect=AssertionError("read unauthenticated body")) as read:
            with self.assertRaises(InvalidSignature):
                await signatures._middleware(request, handler)
            read.assert_not_awaited()
        handler.assert_not_awaited()

    async def test_request_read_failure_does_not_invoke_handler_or_save_results(self):
        signatures = self.middleware(ServerSignatureMiddlewareMode.VERIFY_REQUEST)
        headers = CIMultiDict({"Host": "example.com"})
        self.signer.sign(_Request("POST", "http://example.com/", headers), key_id="key", body=b"hello")
        for error in (ConnectionResetError(), asyncio.CancelledError()):
            request = make_mocked_request("POST", "/", headers=headers, payload=EMPTY_PAYLOAD)
            handler = AsyncMock()
            with patch.object(request, "read", side_effect=error), self.assertRaises(type(error)):
                await signatures._middleware(request, handler)
            handler.assert_not_awaited()
            with self.assertRaises(InvalidSignature):
                signatures.verification_results(request)

    async def test_empty_request_without_digest_and_result_isolation(self):
        signatures = self.middleware(ServerSignatureMiddlewareMode.VERIFY_REQUEST)
        server = await self.start(signatures)
        headers = CIMultiDict()
        self.signer.sign(_Request("GET", str(server.make_url("/")), headers), key_id="key")
        async with aiohttp.ClientSession() as client, client.get(server.make_url("/"), headers=headers) as response:
            self.assertEqual(response.status, 200)
            self.assertIsNone(signatures.verification_results(self.seen[-1])[0].body)
            other = self.middleware(ServerSignatureMiddlewareMode.VERIFY_REQUEST)
            with self.assertRaises(InvalidSignature):
                other.verification_results(self.seen[-1])

    async def test_finite_payload_uses_native_response_compression(self):
        signatures = self.middleware(ServerSignatureMiddlewareMode.SIGN_RESPONSE)

        async def chunks():
            yield b"hello"
            yield b" world"

        payload = AsyncIterablePayload(chunks(), headers={"X-Payload": "kept"})

        async def handler(request):
            response = web.Response(body=payload)
            response.enable_compression()
            return response

        server = await self.start(signatures, handler)
        client_signatures = self.client_middleware(server, SignatureMiddlewareMode.VERIFY_RESPONSE)
        with patch.object(payload, "close", wraps=payload.close) as close:
            async with (
                aiohttp.ClientSession(**client_signatures.session_kwargs) as client,
                client.get(server.make_url("/"), headers={"Accept-Encoding": "gzip"}) as response,
            ):
                self.assertEqual(await response.read(), b"hello world")
                self.assertEqual(response.headers["Content-Encoding"], "gzip")
                self.assertEqual(response.headers["X-Payload"], "kept")
                self.assertTrue(client_signatures.verification_results(response)[0].body.startswith(b"\x1f\x8b"))
            close.assert_awaited_once()
