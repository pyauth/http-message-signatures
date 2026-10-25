import asyncio
import hashlib
from http.client import HTTPMessage
from types import SimpleNamespace

import httpx2
from http_sf.compat import Dictionary
from test_httpx2 import ORIGIN, SIGN_OPTIONS, SignatureTestCase

from http_message_signatures import ContentDigest, HTTPMessageSignaturesException, HTTPMessageSigner, InvalidSignature
from http_message_signatures.httpx2 import SignatureHooks, SignatureHooksMode, adapt_message


class TestDigestReuse(SignatureTestCase):
    def test_signing_configuration_matrix(self):
        for method in (self.signer.sign, self.signer.prepare):
            for body in (None, b"", b"hello"):
                for existing in (False, True):
                    for options in ({}, {"use_existing_digest": False}, {"use_existing_digest": True}):
                        with self.subTest(method=method.__name__, body=body, existing=existing, options=options):
                            content = b"hello" if body is None else body
                            headers = {"Content-Digest": ContentDigest.create(content)} if existing else {}
                            message = SimpleNamespace(method="POST", url=ORIGIN, headers=headers)
                            before = headers.copy()
                            kwargs = {"key_id": "client", **options}
                            if body is not None:
                                kwargs["body"] = body
                            allowed = options.get("use_existing_digest", False)
                            if existing and not allowed:
                                error = "already present; pass use_existing_digest=True"
                            elif allowed and not existing and body is None:
                                error = "requires an existing Content-Digest or body bytes"
                            else:
                                error = None
                            if error:
                                with self.assertRaisesRegex(HTTPMessageSignaturesException, error):
                                    method(message, **kwargs)
                                self.assertEqual(headers, before)
                                continue
                            prepared = method(message, **kwargs)
                            if prepared is not None:
                                signature = self.signer.signature_algorithm(
                                    private_key=self.keys.resolve_private_key("client")
                                ).sign(prepared.signature_base)
                                self.signer.apply(message, prepared, signature)
                            result = self.verifier.verify(message, body=body)[0]
                            self.assertEqual('"content-digest"' in result.covered_components, body is not None)
                            if existing:
                                self.assertEqual(headers["Content-Digest"], before["Content-Digest"])

    def test_precomputed_digest_does_not_read_body(self):
        class Message:
            method = "POST"
            url = ORIGIN

            def __init__(self):
                self.headers = {"Content-Digest": ContentDigest.create(b"hello")}

            @property
            def body(self):
                raise AssertionError("Signing must not read content implicitly")

        message = Message()
        self.signer.sign(message, key_id="client", use_existing_digest=True, covered_component_ids=("content-digest",))
        self.assertEqual(self.verifier.verify(message, body=b"hello")[0].body, b"hello")
        with self.assertRaisesRegex(InvalidSignature, "does not match"):
            self.verifier.verify(message, body=b"different")

    def test_repeated_digest_fields_are_validated_and_preserved(self):
        for body in (None, b"hello"):
            with self.subTest(body=body):
                headers = HTTPMessage()
                headers["Content-Digest"] = " " + ContentDigest.create(b"hello") + " "
                headers["cOnTeNt-DiGeSt"] = str(Dictionary({"sha-512": hashlib.sha512(b"hello").digest()}))
                before = list(headers.items())
                message = SimpleNamespace(method="POST", url=ORIGIN, headers=headers)
                self.signer.sign(
                    message,
                    key_id="client",
                    body=body,
                    use_existing_digest=True,
                    covered_component_ids=('"content-digest";sf;key="sha-512"',),
                )
                self.assertEqual(list(headers.items())[:2], before)
                result = self.verifier.verify(message, body=b"hello")[0]
                self.assertEqual(result.body, b"hello")
                self.assertNotIn('"content-digest"', result.covered_components)

    def test_invalid_existing_digests_fail_without_mutation(self):
        valid = ContentDigest.create(b"hello")
        cases = (
            ("", "at least one digest"),
            ("not a dictionary", "Malformed Content-Digest"),
            ("sha-256=1", "byte sequences"),
            ("unknown=:AA==:", "Unsupported content digest algorithm"),
            ("sha-256=:AA==:", "Invalid sha-256 digest length"),
            (valid + ", " + valid, "Duplicate content digest algorithm"),
        )
        for method in (self.signer.sign, self.signer.prepare):
            for body in (None, b"hello"):
                for value, error in cases:
                    with self.subTest(method=method.__name__, body=body, value=value):
                        headers = {"Content-Digest": value, "Signature": "unchanged"}
                        message = SimpleNamespace(method="POST", url=ORIGIN, headers=headers)
                        before = headers.copy()
                        with self.assertRaisesRegex(InvalidSignature, error):
                            method(message, key_id="client", body=body, use_existing_digest=True)
                        self.assertEqual(headers, before)

    def test_reuse_validates_all_existing_members(self):
        for repeated in (False, True):
            headers = HTTPMessage()
            headers["Content-Digest"] = ContentDigest.create(b"hello")
            headers["content-digest"] = (
                ContentDigest.create(b"hello")
                if repeated
                else str(Dictionary({"sha-512": hashlib.sha512(b"other").digest()}))
            )
            before = list(headers.items())
            message = SimpleNamespace(method="POST", url=ORIGIN, headers=headers)
            with self.subTest(repeated=repeated), self.assertRaisesRegex(InvalidSignature, "Duplicate|does not match"):
                self.signer.sign(
                    message,
                    key_id="client",
                    body=b"hello",
                    use_existing_digest=True,
                    covered_component_ids=('"content-digest";key="sha-256"',),
                )
            self.assertEqual(list(headers.items()), before)

    def test_invalid_option_and_body_types_are_clear(self):
        for method in (self.signer.sign, self.signer.prepare):
            for flag in (None, 0, 1, "true"):
                message = SimpleNamespace(method="POST", url=ORIGIN, headers={})
                with (
                    self.subTest(flag=flag),
                    self.assertRaisesRegex(TypeError, "use_existing_digest must be True or False"),
                ):
                    method(message, key_id="client", body=b"hello", use_existing_digest=flag)
                self.assertEqual(message.headers, {})
            for body in ("hello", bytearray(b"hello")):
                message = SimpleNamespace(method="POST", url=ORIGIN, headers={})
                with (
                    self.subTest(body=body),
                    self.assertRaisesRegex(HTTPMessageSignaturesException, "body must contain bytes"),
                ):
                    method(message, key_id="client", body=body, use_existing_digest=True)
                self.assertEqual(message.headers, {})


class TestDigestRetries(SignatureTestCase):
    def test_sync_and_async_digest_auth_retries(self):
        async def exercise(async_mode):
            seen = []
            hooks = SignatureHooks(SignatureHooksMode.SIGN_REQUEST, sign_options=SIGN_OPTIONS)

            def server(request):
                result = self.verifier.verify(adapt_message(request), body=request.content)[0]
                seen.append((request.headers.get("Authorization"), result.body))
                if len(seen) == 1:
                    return httpx2.Response(
                        401,
                        headers={
                            "WWW-Authenticate": 'Digest realm="test", nonce="test-nonce", algorithm=MD5, qop="auth"'
                        },
                    )
                return httpx2.Response(200)

            options = {"transport": httpx2.MockTransport(server), "auth": httpx2.DigestAuth("user", "password")}
            if async_mode:
                async with httpx2.AsyncClient(**options, event_hooks=hooks.async_event_hooks) as client:
                    response = await client.post(ORIGIN, content=b"hello")
            else:
                with httpx2.Client(**options, event_hooks=hooks.event_hooks) as client:
                    response = client.post(ORIGIN, content=b"hello")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(len(seen), 2)
            self.assertIsNone(seen[0][0])
            self.assertTrue(seen[1][0].startswith("Digest "))
            self.assertEqual([body for _, body in seen], [b"hello", b"hello"])

        for async_mode in (False, True):
            with self.subTest(async_mode=async_mode):
                asyncio.run(exercise(async_mode))

    def test_supplied_digest_requires_explicit_configuration(self):
        request = httpx2.Request(
            "POST", ORIGIN, content=b"hello", headers={"Content-Digest": ContentDigest.create(b"hello")}
        )
        with self.assertRaisesRegex(HTTPMessageSignaturesException, "use_existing_digest=True"):
            self.hooks().sign_request(request)
        self.assertNotIn("http_message_signatures.signer", request.extensions)
        hooks = self.hooks(sign_options={"use_existing_digest": True})
        hooks.sign_request(request)
        self.assertEqual(self.verifier.verify(adapt_message(request), body=b"hello")[0].body, b"hello")

    def test_explicit_false_rejects_reuse(self):
        hooks = self.hooks(sign_options={"use_existing_digest": False})
        request = httpx2.Request("POST", ORIGIN, content=b"hello")
        hooks.sign_request(request)
        before = request.headers.raw
        with self.assertRaisesRegex(HTTPMessageSignaturesException, "use_existing_digest=True"):
            hooks.sign_request(request)
        self.assertEqual(request.headers.raw, before)

    def test_retry_permission_is_scoped_to_its_hooks(self):
        request = httpx2.Request("POST", ORIGIN, content=b"hello")
        self.hooks().sign_request(request)
        with self.assertRaisesRegex(HTTPMessageSignaturesException, "use_existing_digest=True"):
            self.hooks().sign_request(request)

    def test_failed_signing_does_not_grant_retry_permission(self):
        class FailingSigner(HTTPMessageSigner):
            def apply(self, message, prepared, signature, **options):
                raise RuntimeError("Signing failed")

        class Hooks(SignatureHooks):
            signer_class = FailingSigner

        hooks = Hooks(SignatureHooksMode.SIGN_REQUEST, sign_options=SIGN_OPTIONS)
        request = httpx2.Request("POST", ORIGIN, content=b"hello")
        with self.assertRaisesRegex(RuntimeError, "Signing failed"):
            hooks.sign_request(request)
        self.assertNotIn("http_message_signatures.signer", request.extensions)
        with self.assertRaisesRegex(HTTPMessageSignaturesException, "use_existing_digest=True"):
            hooks.sign_request(request)

    def test_retry_does_not_trust_changed_body_or_digest(self):
        hooks = self.hooks()
        original = httpx2.Request("POST", ORIGIN, content=b"hello")
        hooks.sign_request(original)
        changed = httpx2.Request(
            "POST", ORIGIN, headers=original.headers, content=b"other", extensions=original.extensions
        )
        before = changed.headers.raw
        with self.assertRaisesRegex(InvalidSignature, "does not match"):
            hooks.sign_request(changed)
        self.assertEqual(changed.headers.raw, before)
        original.headers["Content-Digest"] = ContentDigest.create(b"other")
        with self.assertRaisesRegex(InvalidSignature, "does not match"):
            hooks.sign_request(original)

    def test_retry_keyword_is_only_injected_after_success(self):
        calls = []

        class Signer(HTTPMessageSigner):
            def sign(self, message, **options):
                calls.append(options.copy())
                return super().sign(message, **options)

        class Hooks(SignatureHooks):
            signer_class = Signer

        hooks = Hooks(SignatureHooksMode.SIGN_REQUEST, sign_options=SIGN_OPTIONS)
        request = httpx2.Request("POST", ORIGIN, content=b"hello")
        hooks.sign_request(request)
        hooks.sign_request(request)
        self.assertNotIn("use_existing_digest", calls[0])
        self.assertIs(calls[1]["use_existing_digest"], True)
