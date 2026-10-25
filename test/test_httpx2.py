import asyncio
import gzip
import hashlib
import unittest
from datetime import datetime, timedelta, timezone
from http.client import HTTPMessage
from types import SimpleNamespace
from unittest.mock import patch

import httpx2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from http_sf.compat import Dictionary

from http_message_signatures import (
    ContentDigest,
    HTTPMessageSignaturesException,
    HTTPMessageSigner,
    HTTPMessageVerifier,
    HTTPSignatureKeyResolver,
    MappingKeyResolver,
    algorithms,
)
from http_message_signatures.exceptions import InvalidSignature
from http_message_signatures.httpx2 import (
    SignatureHooks,
    SignatureHooksMode,
    SigningOptions,
    VerificationOptions,
    adapt_message,
)

SECRET = b"local-tests-only-shared-secret"
ORIGIN = "https://example.com"
SIGN_OPTIONS = SigningOptions(
    origin=ORIGIN,
    signature_algorithm=algorithms.HMAC_SHA256,
    key_id="client",
    key_resolver=MappingKeyResolver(public_keys={}, private_keys={"client": SECRET}),
)
VERIFY_OPTIONS = VerificationOptions(
    origin=ORIGIN,
    signature_algorithm=algorithms.HMAC_SHA256,
    key_resolver=MappingKeyResolver(public_keys={"server": SECRET}, private_keys={}),
)


class SyncBody(httpx2.SyncByteStream):
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


class AsyncBody(httpx2.AsyncByteStream):
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
            sign_options={**SIGN_OPTIONS, **options.pop("sign_options", {})},
            verify_options={**VERIFY_OPTIONS, **options.pop("verify_options", {})},
            **options,
        )

    def response(
        self, request, body=b'{"ok":true}', *, async_mode=False, headers=(), components=("@status",), **options
    ):
        stream = AsyncBody(body) if async_mode else SyncBody(body)
        response = httpx2.Response(200, request=request, headers=headers, stream=stream)
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

    def test_digest_generation_refuses_existing_fields_without_mutation(self):
        for header_type in (dict, HTTPMessage):
            for value in (ContentDigest.create(b"hello"), "stale or malformed", ""):
                for method in (self.signer.sign, self.signer.prepare):
                    with self.subTest(header_type=header_type, value=value, method=method.__name__):
                        headers = header_type()
                        headers["cOnTeNt-DiGeSt"] = value
                        message = SimpleNamespace(method="POST", url=ORIGIN, headers=headers)
                        before = list(headers.items())
                        with self.assertRaisesRegex(HTTPMessageSignaturesException, "already present"):
                            method(message, key_id="client", body=b"hello")
                        self.assertEqual(list(headers.items()), before)

    def test_appending_preserves_existing_digest_and_signature(self):
        class SHA512(ContentDigest):
            algorithm = "sha-512"

        class FirstSigner(HTTPMessageSigner):
            content_digest_class = SHA512

        first_signer = FirstSigner(signature_algorithm=algorithms.HMAC_SHA256, key_resolver=self.keys)
        message = SimpleNamespace(method="POST", url=ORIGIN, headers=HTTPMessage())
        first_signer.sign(message, key_id="client", body=b"hello", label="first", tag="api")
        before = list(message.headers.items())
        with self.assertRaisesRegex(HTTPMessageSignaturesException, "already present"):
            self.signer.sign(
                message, key_id="client", body=b"hello", label="second", tag="api", append_if_signature_exists=True
            )
        self.assertEqual(list(message.headers.items()), before)
        self.verifier.verify(message, expect_tag="api", body=b"hello")
        # Reuse an existing digest explicitly, without asking the signer to add one.
        self.signer.sign(
            message,
            key_id="client",
            use_existing_digest=True,
            covered_component_ids=("content-digest",),
            label="second",
            tag="api",
            append_if_signature_exists=True,
        )
        self.assertEqual(len(self.verifier.verify(message, expect_tag="api", body=b"hello")), 2)

    def test_prepare_override_receives_body_keyword(self):
        received = []

        class Signer(HTTPMessageSigner):
            def prepare(self, message, *, body, **options):
                received.append(body)
                return super().prepare(message, body=body, **options)

        signer = Signer(signature_algorithm=algorithms.HMAC_SHA256, key_resolver=self.keys)
        for body in (None, b"hello"):
            request = httpx2.Request("POST", ORIGIN, content=b"hello")
            signer.sign(adapt_message(request), key_id="client", body=body)
            self.verifier.verify(adapt_message(request), body=body)
        self.assertEqual(received, [None, b"hello"])

    def test_base_body_signing_is_opt_in(self):
        request = httpx2.Request("POST", ORIGIN, content=b"hello")
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
        request = httpx2.Request("POST", ORIGIN, content=b"hello")
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
        request = httpx2.Request("POST", ORIGIN, content=b"request")
        self.signer.sign(adapt_message(request), key_id="client", body=request.content)
        response = httpx2.Response(200, request=request, content=b"response")
        self.signer.sign(adapt_message(response), key_id="server", covered_component_ids=('"content-digest";req',))
        with self.assertRaisesRegex(InvalidSignature, "signed Content-Digest"):
            self.verifier.verify(adapt_message(response), body=response.content)

    def test_empty_body_and_unsigned_digest(self):
        response = httpx2.Response(204, request=httpx2.Request("GET", ORIGIN), content=b"")
        message = adapt_message(response)
        self.signer.sign(message, key_id="server", covered_component_ids=("@status",))
        self.assertIsNone(self.verifier.verify(message, body=b"")[0].body)
        response.headers["Content-Digest"] = ContentDigest.create(b"")
        with self.assertRaises(InvalidSignature):
            self.verifier.verify(message, body=b"")

    def test_each_selected_signature_must_cover_body(self):
        response = httpx2.Response(200, request=httpx2.Request("GET", ORIGIN), content=b"hello")
        message = adapt_message(response)
        self.signer.sign(message, key_id="server", body=b"hello", covered_component_ids=("@status",), tag="api")
        self.signer.sign(
            message,
            key_id="server",
            use_existing_digest=True,
            covered_component_ids=("@status",),
            tag="api",
            label="second",
            append_if_signature_exists=True,
        )
        with self.assertRaises(InvalidSignature):
            self.verifier.verify(message, expect_tag="api", body=b"hello")


class TestSignatureHooks(SignatureTestCase):
    def test_configuration_captures_options_but_preserves_resolvers(self):
        covered, required = ["@method"], ["@status"]
        signing = {**SIGN_OPTIONS, "covered_component_ids": covered, "tag": "out", "nonce": None}
        verification = {**VERIFY_OPTIONS, "require_components": required, "max_age": None}
        hooks = SignatureHooks(sign_options=signing, verify_options=verification)
        signing["tag"] = "changed"
        verification["max_age"] = timedelta(seconds=1)
        covered.append("missing")
        required.clear()
        self.assertIs(hooks.signer.key_resolver, signing["key_resolver"])
        self.assertIs(hooks.verifier.key_resolver, verification["key_resolver"])
        request = httpx2.Request("GET", ORIGIN)
        hooks.sign_request(request)
        result = self.verifier.verify(adapt_message(request), expect_tag="out", body=b"")[0]
        self.assertNotIn('"@target-uri"', result.covered_components)
        self.assertIsNone(result.nonce)
        hooks.verify_response(self.response(request, created=datetime(2020, 1, 1, tzinfo=timezone.utc)))
        with self.assertRaisesRegex(InvalidSignature, "Required component"):
            hooks.verify_response(self.response(request, components=()))

    def test_composed_security_hooks_persist(self):
        async def exercise(async_mode):
            hooks = self.hooks()
            observed = []

            def check(response):
                observed.append(response.extensions["http_message_signatures"][0].body)
                raise InvalidSignature("application policy")

            async def async_check(response):
                check(response)

            def server(request):
                return self.response(request, async_mode=async_mode)

            if async_mode:
                hooks.async_event_hooks["response"].append(async_check)
                async with httpx2.AsyncClient(
                    transport=httpx2.MockTransport(server), event_hooks=hooks.async_event_hooks
                ) as client:
                    with self.assertRaisesRegex(InvalidSignature, "application policy"):
                        await client.get(ORIGIN)
            else:
                hooks.event_hooks["response"].append(check)
                with (
                    httpx2.Client(transport=httpx2.MockTransport(server), event_hooks=hooks.event_hooks) as client,
                    self.assertRaisesRegex(InvalidSignature, "application policy"),
                ):
                    client.get(ORIGIN)
            self.assertEqual(observed, [b'{"ok":true}'])

        for async_mode in (False, True):
            with self.subTest(async_mode=async_mode):
                asyncio.run(exercise(async_mode))

    def test_digest_is_verified_before_decompression(self):
        async def exercise(async_mode, valid):
            body = gzip.compress(b"trusted content")
            response = self.response(
                httpx2.Request("GET", ORIGIN),
                body=body,
                async_mode=async_mode,
                headers={"Content-Encoding": "gzip"},
                components=("@status", "content-encoding"),
            )
            stream = response.stream
            if not valid:
                stream.body = gzip.compress(b"x" * 1024 * 1024)
            # The decoder must never receive any bytes from a rejected body.
            decoder = response._get_content_decoder()
            with (
                patch.object(response, "_get_content_decoder", return_value=decoder),
                patch.object(decoder, "decode", wraps=decoder.decode) as decode,
            ):
                hooks = self.hooks()
                if valid:
                    if async_mode:
                        await hooks.verify_response_async(response)
                    else:
                        hooks.verify_response(response)
                    self.assertEqual(response.content, b"trusted content")
                    self.assertEqual(response.extensions["http_message_signatures"][0].body, body)
                    decode.assert_called_once_with(body)
                else:
                    with self.assertRaisesRegex(InvalidSignature, "does not match"):
                        if async_mode:
                            await hooks.verify_response_async(response)
                        else:
                            hooks.verify_response(response)
                    decode.assert_not_called()
                    self.assertNotIn("http_message_signatures", response.extensions)
                self.assertTrue(stream.closed)

        for async_mode in (False, True):
            for valid in (False, True):
                with self.subTest(async_mode=async_mode, valid=valid):
                    asyncio.run(exercise(async_mode, valid))

    def test_custom_resolvers_are_lazy_and_follow_key_rotation(self):
        async def exercise(mode, async_mode):
            lookups = []
            current_key = None

            class SigningResolver(HTTPSignatureKeyResolver):
                def resolve_private_key(self, key_id):
                    lookups.append(("private", key_id))
                    self_test.assertEqual(key_id, "client")
                    self_test.assertIsNotNone(current_key)
                    return current_key

            class VerificationResolver(HTTPSignatureKeyResolver):
                def resolve_public_key(self, key_id):
                    lookups.append(("public", key_id))
                    self_test.assertEqual(key_id, "server")
                    self_test.assertIsNotNone(current_key)
                    return current_key

            self_test = self
            signing = mode is not SignatureHooksMode.VERIFY_RESPONSE
            verifying = mode is not SignatureHooksMode.SIGN_REQUEST
            signing_resolver = SigningResolver()
            verification_resolver = VerificationResolver()
            hooks = SignatureHooks(
                mode,
                sign_options={**SIGN_OPTIONS, "key_resolver": signing_resolver} if signing else None,
                verify_options={**VERIFY_OPTIONS, "key_resolver": verification_resolver} if verifying else None,
            )
            self.assertEqual(lookups, [])
            if signing:
                self.assertIs(hooks.signer.key_resolver, signing_resolver)
            if verifying:
                self.assertIs(hooks.verifier.key_resolver, verification_resolver)

            def server(request):
                if signing:
                    result = self.verifier.verify(adapt_message(request), body=request.content)[0]
                    self.assertEqual(result.body, b"hello")
                else:
                    self.assertNotIn("Signature", request.headers)
                if verifying:
                    return self.response(request, async_mode=async_mode)
                return httpx2.Response(200, content=b"ok")

            async def send_requests(client):
                nonlocal current_key
                for current_key in (b"first-key", b"rotated-key"):
                    self.keys.public_keys["client"] = current_key
                    self.keys.private_keys["server"] = current_key
                    if async_mode:
                        response = await client.post(ORIGIN, content=b"hello")
                    else:
                        response = client.post(ORIGIN, content=b"hello")
                    self.assertEqual(response.status_code, 200)
                    if verifying:
                        self.assertEqual(response.extensions["http_message_signatures"][0].body, b'{"ok":true}')

            if async_mode:
                async with httpx2.AsyncClient(
                    transport=httpx2.MockTransport(server), event_hooks=hooks.async_event_hooks
                ) as client:
                    await send_requests(client)
            else:
                with httpx2.Client(transport=httpx2.MockTransport(server), event_hooks=hooks.event_hooks) as client:
                    await send_requests(client)
            expected = []
            if signing:
                expected.append(("private", "client"))
            if verifying:
                expected.append(("public", "server"))
            self.assertEqual(lookups, expected * 2)

        for mode in SignatureHooksMode:
            for async_mode in (False, True):
                with self.subTest(mode=mode, async_mode=async_mode):
                    asyncio.run(exercise(mode, async_mode))

    def test_one_custom_resolver_can_serve_both_operations(self):
        lookups = []

        class Resolver(HTTPSignatureKeyResolver):
            def resolve_private_key(self, key_id):
                lookups.append(("private", key_id))
                return SECRET

            def resolve_public_key(self, key_id):
                lookups.append(("public", key_id))
                return SECRET if key_id == "server" else None

        resolver = Resolver()
        hooks = self.hooks(sign_options={"key_resolver": resolver}, verify_options={"key_resolver": resolver})
        self.assertIs(hooks.signer.key_resolver, resolver)
        self.assertIs(hooks.verifier.key_resolver, resolver)
        self.assertEqual(lookups, [])
        request = httpx2.Request("GET", ORIGIN)
        hooks.sign_request(request)
        hooks.verify_response(self.response(request))
        self.assertEqual(lookups, [("private", "client"), ("public", "server")])
        response = self.response(request)
        self.signer.sign(
            adapt_message(response),
            key_id="client",
            use_existing_digest=True,
            covered_component_ids=("@status", "content-digest"),
        )
        with self.assertRaisesRegex(InvalidSignature, "Unable to resolve verification key"):
            hooks.verify_response(response)
        self.assertEqual(lookups[-1], ("public", "client"))

    def test_custom_signing_resolver_error_is_propagated(self):
        class Resolver(HTTPSignatureKeyResolver):
            def resolve_private_key(self, key_id):
                raise LookupError(f"No signing key for {key_id}")

        hooks = self.hooks(sign_options={"key_resolver": Resolver()})
        sent = []
        with (
            httpx2.Client(transport=httpx2.MockTransport(sent.append), event_hooks=hooks.event_hooks) as client,
            self.assertRaisesRegex(LookupError, "No signing key for client"),
        ):
            client.get(ORIGIN)
        self.assertEqual(sent, [])

    def test_signing_only_accepts_unsigned_responses_without_buffering(self):
        class UnusedVerifier(HTTPMessageVerifier):
            def __init__(self, **options):
                raise AssertionError("Signing-only mode must not construct a verifier")

        class Hooks(SignatureHooks):
            verifier_class = UnusedVerifier

        hooks = Hooks(
            SignatureHooksMode.SIGN_REQUEST,
            sign_options={**SIGN_OPTIONS, "tag": "out", "include_alg": False},
        )
        stream = SyncBody(b"unverified response")

        def server(request):
            result = self.verifier.verify(adapt_message(request), body=request.content, expect_tag="out")[0]
            self.assertEqual(result.body, b"hello")
            self.assertNotIn("alg", result.parameters)
            return httpx2.Response(200, headers={"Signature": "invalid", "Content-Digest": "invalid"}, stream=stream)

        with (
            httpx2.Client(transport=httpx2.MockTransport(server), event_hooks=hooks.event_hooks) as client,
            client.stream("POST", ORIGIN, content=SyncBody(b"hello")) as response,
        ):
            self.assertFalse(response.is_stream_consumed)
            self.assertEqual(stream.reads, 0)
            self.assertNotIn("http_message_signatures", response.extensions)
            self.assertEqual(response.read(), b"unverified response")
        self.assertIsNone(hooks.verifier)
        self.assertEqual(hooks.event_hooks["response"], [])

    def test_verification_only_leaves_requests_unsigned(self):
        class UnusedSigner(HTTPMessageSigner):
            def __init__(self, **options):
                raise AssertionError("Verification-only mode must not construct a signer")

        class Hooks(SignatureHooks):
            signer_class = UnusedSigner

        hooks = Hooks(
            SignatureHooksMode.VERIFY_RESPONSE,
            verify_options={**VERIFY_OPTIONS, "expect_tag": "in", "require_components": ("@status",)},
        )
        streams = []

        def server(request):
            for name in ("Signature", "Signature-Input", "Content-Digest"):
                self.assertNotIn(name, request.headers)
            self.assertEqual(request.content, b"unsigned request")
            response = self.response(request, tag="in")
            if request.url.path == "/tampered":
                response.stream.body = b"changed"
            elif request.url.path == "/unsigned":
                del response.headers["Signature"]
            streams.append(response.stream)
            return response

        with httpx2.Client(transport=httpx2.MockTransport(server), event_hooks=hooks.event_hooks) as client:
            with client.stream("POST", ORIGIN, content=b"unsigned request") as response:
                self.assertTrue(response.is_stream_consumed)
                self.assertEqual(response.extensions["http_message_signatures"][0].body, b'{"ok":true}')
            for path in ("/tampered", "/unsigned"):
                with self.subTest(path=path), self.assertRaises(InvalidSignature):
                    client.post(ORIGIN + path, content=b"unsigned request")
        self.assertTrue(all(stream.closed for stream in streams))
        self.assertIsNone(hooks.signer)
        self.assertEqual(hooks.event_hooks["request"], [])

    def test_modes_validate_credentials_and_unused_configuration(self):
        invalid = [
            {"mode": SignatureHooksMode.SIGN_REQUEST},
            {"mode": SignatureHooksMode.VERIFY_RESPONSE},
            {},
            {"sign_options": SIGN_OPTIONS},
            {"verify_options": VERIFY_OPTIONS},
            {"mode": SignatureHooksMode.SIGN_REQUEST, "sign_options": SIGN_OPTIONS, "verify_options": {}},
            {"mode": SignatureHooksMode.VERIFY_RESPONSE, "verify_options": VERIFY_OPTIONS, "sign_options": {}},
        ]
        for options in invalid:
            with self.subTest(options=options), self.assertRaises(ValueError):
                SignatureHooks(**options)
        for mode, container, required in (
            (SignatureHooksMode.SIGN_REQUEST, "sign_options", SIGN_OPTIONS),
            (SignatureHooksMode.VERIFY_RESPONSE, "verify_options", VERIFY_OPTIONS),
        ):
            for name in required:
                incomplete = {key: value for key, value in required.items() if key != name}
                with self.subTest(mode=mode, missing=name), self.assertRaisesRegex(TypeError, name):
                    SignatureHooks(mode, **{container: incomplete})
        for mode in (None, "verify_response", 1):
            with self.subTest(mode=mode), self.assertRaisesRegex(TypeError, "SignatureHooksMode"):
                self.hooks(mode=mode)

    def test_disabled_manual_hooks_fail_before_consuming_content(self):
        sign_only = SignatureHooks(
            mode=SignatureHooksMode.SIGN_REQUEST,
            sign_options=SIGN_OPTIONS,
        )
        verify_only = SignatureHooks(
            mode=SignatureHooksMode.VERIFY_RESPONSE,
            verify_options=VERIFY_OPTIONS,
        )
        upload = SyncBody(b"hello")
        request = httpx2.Request("POST", ORIGIN, stream=upload)
        response = self.response(request)
        with self.assertRaisesRegex(HTTPMessageSignaturesException, "signing is disabled"):
            verify_only.sign_request(request)
        with self.assertRaisesRegex(HTTPMessageSignaturesException, "verification is disabled"):
            sign_only.verify_response(response)
        self.assertEqual(upload.reads, 0)
        self.assertEqual(response.stream.reads, 0)
        self.assertFalse(response.is_closed)

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
        with httpx2.Client(transport=httpx2.MockTransport(server), event_hooks=event_hooks) as client:
            response = client.post(ORIGIN, json={"hello": "world"})
        self.assertEqual(response.json(), {"ok": True})
        self.assertTrue(observed[0].closed)
        self.assertEqual(observed[0].reads, 1)

    def test_gzip_uses_encoded_digest_and_preserves_decoding(self):
        hooks = self.hooks()
        encoded = gzip.compress(b'{"ok":true}')
        with httpx2.Client(
            transport=httpx2.MockTransport(
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
            httpx2.Client(transport=httpx2.MockTransport(server), event_hooks=event_hooks) as client,
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
            httpx2.Client(transport=httpx2.MockTransport(server), event_hooks=hooks.event_hooks) as client,
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
            return httpx2.Response(200, headers=list(headers.items()), stream=SyncBody(b"hello"))

        with httpx2.Client(transport=httpx2.MockTransport(server), event_hooks=hooks.event_hooks) as client:
            response = client.get(ORIGIN)
        result = response.extensions["http_message_signatures"][0]
        self.assertIn('"set-cookie";bs', result.covered_components)
        self.assertEqual(len(response.headers.get_list("set-cookie")), 2)
        self.assertEqual(response.headers["set-cookie"], "a=1; Path=/, b=2; Path=/")

    def test_raw_header_bytes_and_request_context(self):
        request = httpx2.Request("GET", ORIGIN, headers=[(b"Example", b"caf\xc3\xa9"), (b"Example", b"second")])
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
        request = httpx2.Request("GET", ORIGIN, headers=[("Example", " one "), ("Example", "\ttwo\t")])
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
        request.headers = httpx2.Headers(
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

    def test_redirect_with_changed_body_requires_new_digest(self):
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
                    use_existing_digest=True,
                    covered_component_ids=("@status", "location", "content-digest"),
                )
            return response

        with httpx2.Client(
            transport=httpx2.MockTransport(server), event_hooks=hooks.event_hooks, follow_redirects=True
        ) as client:
            with self.assertRaisesRegex(InvalidSignature, "does not match"):
                client.post(ORIGIN, content=b"original")
            self.assertEqual(len(requests), 1)
            client.get(ORIGIN + "/next")
        self.assertEqual(requests, [("POST", ORIGIN, b"original"), ("GET", ORIGIN + "/next", b"")])

    def test_origin_is_checked_before_reading_or_sending(self):
        hooks = self.hooks()
        stream = SyncBody(b"secret")
        with self.assertRaises(HTTPMessageSignaturesException):
            hooks.sign_request(httpx2.Request("POST", "https://other.example/", stream=stream))
        self.assertEqual(stream.reads, 0)
        for destination in ("http://example.com", "https://example.com:8443"):
            with self.subTest(destination=destination), self.assertRaises(HTTPMessageSignaturesException):
                hooks.sign_request(httpx2.Request("GET", destination))
        hooks.sign_request(httpx2.Request("GET", "https://example.com:443/"))

    def test_streamed_upload_redirect_reuses_validated_digest(self):
        upload = SyncBody(b"streamed upload")
        seen = []

        def server(request):
            seen.append(self.verifier.verify(adapt_message(request), body=request.content)[0].body)
            response = self.response(request)
            if len(seen) == 1:
                response.status_code = 307
                response.headers["Location"] = "/next"
                self.signer.sign(
                    adapt_message(response),
                    key_id="server",
                    use_existing_digest=True,
                    covered_component_ids=("@status", "content-digest"),
                )
            return response

        with httpx2.Client(
            transport=httpx2.MockTransport(server), event_hooks=self.hooks().event_hooks, follow_redirects=True
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
                adapt_message(response),
                key_id="server",
                use_existing_digest=True,
                covered_component_ids=("@status", "content-digest"),
            )
            return response

        with (
            httpx2.Client(
                transport=httpx2.MockTransport(server), event_hooks=self.hooks().event_hooks, follow_redirects=True
            ) as client,
            self.assertRaises(HTTPMessageSignaturesException),
        ):
            client.get(ORIGIN)
        self.assertEqual(len(seen), 1)

    def test_configured_options_reach_base_methods(self):
        hooks = self.hooks(
            sign_options={
                "tag": "outgoing-api",
                "label": "outgoing",
                "include_alg": False,
                "nonce": "caller-nonce",
                "covered_component_ids": ("@method",),
            },
            verify_options={
                "max_age": None,
                "expect_tag": "incoming-api",
                "expect_label": "pyhms",
                "require_components": ("@status",),
            },
        )
        request = httpx2.Request("GET", ORIGIN)
        hooks.sign_request(request)
        result = self.verifier.verify(adapt_message(request), expect_tag="outgoing-api")[0]
        self.assertEqual(result.label, "outgoing")
        self.assertEqual(result.nonce, "caller-nonce")
        self.assertNotIn("alg", result.parameters)
        self.assertNotIn('"@target-uri"', result.covered_components)
        response = self.response(request, tag="incoming-api", created=datetime(2020, 1, 1, tzinfo=timezone.utc))
        hooks.verify_response(response)
        with self.assertRaises(InvalidSignature):
            self.hooks(verify_options={"expect_tag": "incoming-api"}).verify_response(response)

    def test_unknown_and_hook_managed_options_are_rejected(self):
        for name in ("unknown", "expect_tag", "body"):
            hooks = self.hooks(sign_options={name: None})
            sent = []
            with (
                self.subTest(option=name),
                httpx2.Client(transport=httpx2.MockTransport(sent.append), event_hooks=hooks.event_hooks) as client,
                self.assertRaisesRegex(TypeError, rf"HTTPMessageSigner.sign\(\).*'{name}'"),
            ):
                client.get(ORIGIN)
            self.assertFalse(sent)

    def test_verifier_rejects_unsupported_options(self):
        for name in ("unknown", "tag", "key_id"):
            with self.subTest(option=name):
                hooks = self.hooks(verify_options={name: None})
                response = self.response(httpx2.Request("GET", ORIGIN))
                stream = response.stream
                with self.assertRaisesRegex(TypeError, rf"HTTPMessageVerifier.verify\(\).*'{name}'"):
                    hooks.verify_response(response)
                self.assertEqual(stream.reads, 0)
                self.assertTrue(stream.closed)
                self.assertNotIn("http_message_signatures", response.extensions)

    def test_subclass_defaults_are_inherited(self):
        class Verifier(HTTPMessageVerifier):
            def verify(self, message, *, max_age=timedelta(seconds=1)):
                return super().verify(message, max_age=max_age)

        class Hooks(SignatureHooks):
            verifier_class = Verifier

        hooks = Hooks(sign_options=SIGN_OPTIONS, verify_options=VERIFY_OPTIONS)
        response = self.response(
            httpx2.Request("GET", ORIGIN), created=datetime.now(timezone.utc) - timedelta(minutes=1)
        )
        with self.assertRaises(InvalidSignature):
            hooks.verify_response(response)

    def test_forwarding_subclasses_accept_base_and_explicit_custom_options(self):
        observed = []

        class Signer(HTTPMessageSigner):
            def sign(self, message, *, signing_context=None, **options):
                observed.append(("sign", signing_context, options))
                return super().sign(message, **options)

        class Verifier(HTTPMessageVerifier):
            def verify(self, message, *, verification_context=None, **options):
                observed.append(("verify", verification_context, options))
                return super().verify(message, **options)

        class Hooks(SignatureHooks):
            signer_class = Signer
            verifier_class = Verifier

        hooks = Hooks(
            sign_options={**SIGN_OPTIONS, "include_alg": False, "signing_context": "out"},
            verify_options={**VERIFY_OPTIONS, "max_age": None, "verification_context": "in"},
        )
        request = httpx2.Request("GET", ORIGIN)
        hooks.sign_request(request)
        hooks.verify_response(self.response(request))
        self.assertEqual(observed[0], ("sign", "out", {"key_id": "client", "body": b"", "include_alg": False}))
        self.assertEqual(observed[1], ("verify", "in", {"max_age": None}))
        defaults = Hooks(sign_options=SIGN_OPTIONS, verify_options=VERIFY_OPTIONS)
        request = httpx2.Request("GET", ORIGIN)
        defaults.sign_request(request)
        defaults.verify_response(self.response(request))
        self.assertEqual(observed[2], ("sign", None, {"key_id": "client", "body": b""}))
        self.assertEqual(observed[3], ("verify", None, {}))
        with self.assertRaisesRegex(TypeError, r"HTTPMessageSigner.sign\(\).*'max_ag'"):
            Hooks(sign_options={**SIGN_OPTIONS, "max_ag": None}, verify_options=VERIFY_OPTIONS).sign_request(
                httpx2.Request("GET", ORIGIN)
            )

    def test_asymmetric_keys_and_untrusted_key_id(self):
        client_key, server_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        hooks = SignatureHooks(
            sign_options={
                **SIGN_OPTIONS,
                "key_resolver": MappingKeyResolver(public_keys={}, private_keys={"client": client_key}),
                "signature_algorithm": algorithms.ED25519,
            },
            verify_options={
                **VERIFY_OPTIONS,
                "key_resolver": MappingKeyResolver(public_keys={"server": server_key.public_key()}, private_keys={}),
                "signature_algorithm": algorithms.ED25519,
            },
        )
        keys = MappingKeyResolver(
            public_keys={"client": client_key.public_key()}, private_keys={"server": server_key, "unknown": server_key}
        )
        signer = HTTPMessageSigner(signature_algorithm=algorithms.ED25519, key_resolver=keys)
        verifier = HTTPMessageVerifier(signature_algorithm=algorithms.ED25519, key_resolver=keys)
        request = httpx2.Request("POST", ORIGIN, content=b"hello")
        hooks.sign_request(request)
        verifier.verify(adapt_message(request), body=request.content)
        for key_id in ("server", "unknown"):
            response = httpx2.Response(200, request=request, content=b"ok")
            signer.sign(adapt_message(response), key_id=key_id, body=b"ok", covered_component_ids=("@status",))
            if key_id == "server":
                hooks.verify_response(response)
            else:
                with self.assertRaises(InvalidSignature):
                    hooks.verify_response(response)

    def test_signing_and_verification_use_independent_algorithms(self):
        server_key = Ed25519PrivateKey.generate()
        server_signer = HTTPMessageSigner(
            signature_algorithm=algorithms.ED25519,
            key_resolver=MappingKeyResolver(public_keys={}, private_keys={"server": server_key}),
        )
        for async_mode in (False, True):
            with self.subTest(async_mode=async_mode):
                hooks = self.hooks(
                    verify_options={
                        "signature_algorithm": algorithms.ED25519,
                        "key_resolver": MappingKeyResolver(
                            public_keys={"server": server_key.public_key()}, private_keys={}
                        ),
                    }
                )

                def server(request, async_mode=async_mode):
                    result = self.verifier.verify(adapt_message(request), body=request.content)[0]
                    self.assertIs(result.algorithm, algorithms.HMAC_SHA256)
                    self.assertEqual(result.body, b"request")
                    if request.url.path == "/wrong-algorithm":
                        return self.response(request, async_mode=async_mode)
                    stream = AsyncBody(b"response") if async_mode else SyncBody(b"response")
                    response = httpx2.Response(200, request=request, stream=stream)
                    server_signer.sign(
                        adapt_message(response), key_id="server", covered_component_ids=("@status",), body=b"response"
                    )
                    return response

                if async_mode:

                    async def run(hooks, server):
                        async with httpx2.AsyncClient(
                            transport=httpx2.MockTransport(server), event_hooks=hooks.async_event_hooks
                        ) as client:
                            response = await client.post(ORIGIN, content=b"request")
                            with self.assertRaises(InvalidSignature):
                                await client.post(ORIGIN + "/wrong-algorithm", content=b"request")
                            return response

                    response = asyncio.run(run(hooks, server))
                else:
                    with httpx2.Client(transport=httpx2.MockTransport(server), event_hooks=hooks.event_hooks) as client:
                        response = client.post(ORIGIN, content=b"request")
                        with self.assertRaises(InvalidSignature):
                            client.post(ORIGIN + "/wrong-algorithm", content=b"request")
                self.assertEqual(response.content, b"response")
                self.assertIs(response.extensions["http_message_signatures"][0].algorithm, algorithms.ED25519)

    def test_each_operation_checks_its_own_origin(self):
        verification_origin = "https://other.example"
        hooks = self.hooks(verify_options={"origin": verification_origin})
        hooks.sign_request(httpx2.Request("GET", ORIGIN))
        response = self.response(httpx2.Request("GET", verification_origin))
        hooks.verify_response(response)
        self.assertIn("http_message_signatures", response.extensions)
        upload = SyncBody(b"secret")
        with self.assertRaises(HTTPMessageSignaturesException):
            hooks.sign_request(httpx2.Request("POST", verification_origin, stream=upload))
        self.assertEqual(upload.reads, 0)
        response = self.response(httpx2.Request("GET", ORIGIN))
        stream = response.stream
        with self.assertRaises(HTTPMessageSignaturesException):
            hooks.verify_response(response)
        self.assertEqual(stream.reads, 0)
        self.assertTrue(stream.closed)
        for container in ("sign_options", "verify_options"):
            for origin in ("/relative", "ftp://example.com", ORIGIN + "/path", ORIGIN + "?query=1"):
                with self.subTest(container=container, origin=origin), self.assertRaisesRegex(ValueError, "origin"):
                    self.hooks(**{container: {"origin": origin}})

    def test_buffered_response_and_unrecoverable_encoded_response(self):
        hooks = self.hooks()
        request = httpx2.Request("GET", ORIGIN)
        response = httpx2.Response(200, request=request, content=b"hello")
        self.signer.sign(adapt_message(response), key_id="server", body=b"hello", covered_component_ids=("@status",))
        hooks.verify_response(response)
        encoded = gzip.compress(b"hello")
        response = httpx2.Response(200, request=request, headers={"Content-Encoding": "gzip"}, content=encoded)
        self.signer.sign(adapt_message(response), key_id="server", body=encoded, covered_component_ids=("@status",))
        with self.assertRaisesRegex(InvalidSignature, "already consumed"):
            hooks.verify_response(response)

    def test_stream_api_is_buffered_before_yield(self):
        with (
            httpx2.Client(
                transport=httpx2.MockTransport(lambda request: self.response(request)),
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
                request = httpx2.Request(method, ORIGIN)
                response = self.response(request, body)
                response.status_code = status
                self.signer.sign(
                    adapt_message(response),
                    key_id="server",
                    use_existing_digest=True,
                    covered_component_ids=("@status", "content-digest"),
                )
                self.hooks().verify_response(response)
                self.assertEqual(response.extensions["http_message_signatures"][0].body, body)

    def test_cookie_limitation_after_failure(self):
        def server(request):
            response = self.response(request, headers={"Set-Cookie": "session=unverified; Path=/"})
            response.headers["Signature"] = "bad"
            return response

        with httpx2.Client(transport=httpx2.MockTransport(server), event_hooks=self.hooks().event_hooks) as client:
            with self.assertRaises(InvalidSignature):
                client.get(ORIGIN)
            self.assertEqual(client.cookies.get("session"), "unverified")


class TestAsyncSignatureHooks(SignatureTestCase):
    def test_single_operation_modes(self):
        async def run():
            sign_only = SignatureHooks(
                mode=SignatureHooksMode.SIGN_REQUEST,
                sign_options={**SIGN_OPTIONS, "tag": "out"},
            )
            unsigned_stream = AsyncBody(b"unsigned response")

            async def unsigned_server(request):
                result = self.verifier.verify(adapt_message(request), body=request.content, expect_tag="out")[0]
                self.assertEqual(result.body, b"hello")
                return httpx2.Response(200, stream=unsigned_stream)

            async with (
                httpx2.AsyncClient(
                    transport=httpx2.MockTransport(unsigned_server), event_hooks=sign_only.async_event_hooks
                ) as client,
                client.stream("POST", ORIGIN, content=AsyncBody(b"hello")) as response,
            ):
                self.assertEqual(unsigned_stream.reads, 0)
                self.assertNotIn("http_message_signatures", response.extensions)
                self.assertEqual(await response.aread(), b"unsigned response")

            verify_only = SignatureHooks(
                mode=SignatureHooksMode.VERIFY_RESPONSE,
                verify_options={**VERIFY_OPTIONS, "expect_tag": "in"},
            )

            async def signed_server(request):
                self.assertNotIn("Signature", request.headers)
                self.assertNotIn("Content-Digest", request.headers)
                return self.response(
                    request, gzip.compress(b"hello"), async_mode=True, headers={"Content-Encoding": "gzip"}, tag="in"
                )

            async with httpx2.AsyncClient(
                transport=httpx2.MockTransport(signed_server), event_hooks=verify_only.async_event_hooks
            ) as client:
                response = await client.get(ORIGIN)
                self.assertEqual(response.content, b"hello")
                self.assertEqual(gzip.decompress(response.extensions["http_message_signatures"][0].body), b"hello")
            upload = AsyncBody(b"unused")
            request = httpx2.Request("POST", ORIGIN, stream=upload)
            response = self.response(request, async_mode=True)
            with self.assertRaisesRegex(HTTPMessageSignaturesException, "signing is disabled"):
                await verify_only.sign_request_async(request)
            with self.assertRaisesRegex(HTTPMessageSignaturesException, "verification is disabled"):
                await sign_only.verify_response_async(response)
            self.assertEqual(upload.reads, 0)
            self.assertEqual(response.stream.reads, 0)
            self.assertFalse(response.is_closed)

        asyncio.run(run())

    def test_concurrent_requests_and_compressed_responses(self):
        async def run():
            hooks = self.hooks(sign_options={"tag": "client"}, verify_options={"expect_tag": "server"})
            streams = []

            async def server(request):
                self.verifier.verify(adapt_message(request), body=request.content, expect_tag="client")
                await asyncio.sleep(0)
                response = self.response(
                    request,
                    gzip.compress(request.content),
                    async_mode=True,
                    headers={"Content-Encoding": "gzip"},
                    components=("@status", '"content-digest";req'),
                    tag="server",
                )
                streams.append(response.stream)
                return response

            async with httpx2.AsyncClient(
                transport=httpx2.MockTransport(server), event_hooks=hooks.async_event_hooks
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

            async with httpx2.AsyncClient(
                transport=httpx2.MockTransport(server), event_hooks=self.hooks().async_event_hooks
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
            request = httpx2.Request("GET", ORIGIN)
            response = self.response(request, async_mode=True)
            stream = CancelledBody(b"")
            response.stream = stream
            with self.assertRaises(asyncio.CancelledError):
                await self.hooks().verify_response_async(response)
            self.assertTrue(stream.closed)
            self.assertNotIn("http_message_signatures", response.extensions)

        asyncio.run(run())
