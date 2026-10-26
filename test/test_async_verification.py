import asyncio
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import requests

from http_message_signatures import (
    HTTPMessageSigner,
    HTTPMessageVerifier,
    HTTPSignatureKeyResolver,
    InvalidSignature,
    MappingKeyResolver,
    algorithms,
)

SECRET = b"async-verification-test-secret"


class AsyncKeys(HTTPSignatureKeyResolver):
    def __init__(self):
        self.calls = []

    def resolve_public_key(self, key_id):
        raise AssertionError("Async verification must use the async resolver")

    async def resolve_public_key_async(self, key_id):
        await asyncio.sleep(0)
        self.calls.append(key_id)
        return SECRET if key_id == "trusted" else None


class AsyncVerificationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.keys = MappingKeyResolver(public_keys={"trusted": SECRET}, private_keys={"trusted": SECRET})
        self.signer = HTTPMessageSigner(signature_algorithm=algorithms.HMAC_SHA256, key_resolver=self.keys)
        self.async_keys = AsyncKeys()
        self.verifier = HTTPMessageVerifier(signature_algorithm=algorithms.HMAC_SHA256, key_resolver=self.async_keys)

    def request(self, **options):
        request = requests.Request("POST", "https://example.com/", data=b"hello").prepare()
        self.signer.sign(request, key_id="trusted", body=request.body, **options)
        return request

    async def test_async_lookup_and_synchronous_fallback(self):
        request = self.request()
        sync_verifier = HTTPMessageVerifier(signature_algorithm=algorithms.HMAC_SHA256, key_resolver=self.keys)
        expected = sync_verifier.verify(request, body=request.body)
        self.assertEqual(await self.verifier.verify_async(request, body=request.body), expected)
        self.assertEqual(await sync_verifier.verify_async(request, body=request.body), expected)
        self.assertEqual(self.async_keys.calls, ["trusted"])
        with self.assertRaises(InvalidSignature):
            await self.verifier.verify_async(request, body=b"tampered")
        request.url += "changed"
        with self.assertRaises(InvalidSignature):
            await self.verifier.verify_async(request)

    async def test_defaults_and_explicit_options(self):
        request = self.request(created=datetime.now(timezone.utc) - timedelta(days=2), tag="app")
        with self.assertRaisesRegex(InvalidSignature, "maximum allowable age"):
            await self.verifier.verify_async(request)
        self.assertEqual(self.async_keys.calls, [])
        result = await self.verifier.verify_async(
            request, max_age=None, expect_tag="app", expect_label="pyhms", require_components=("@method",)
        )
        self.assertEqual(result[0].parameters["tag"], "app")
        self.assertIsNone(result[0].body)
        with self.assertRaisesRegex(InvalidSignature, "Required component"):
            await self.verifier.verify_async(request, max_age=None, require_components=("content-type",))
        with self.assertRaisesRegex(InvalidSignature, "No signatures found matching"):
            await self.verifier.verify_async(request, max_age=None, expect_tag="other")
        with self.assertRaises(TypeError):
            await self.verifier.verify_async(request, unknown_option=True)

    async def test_all_selected_signatures_must_verify(self):
        request = self.request(tag="app")
        self.signer.sign(
            request,
            key_id="trusted",
            label="second",
            tag="app",
            append_if_signature_exists=True,
            body=request.body,
            use_existing_digest=True,
        )
        results = await self.verifier.verify_async(request, expect_tag="app", body=request.body)
        self.assertEqual([result.label for result in results], ["pyhms", "second"])
        self.assertEqual(self.async_keys.calls, ["trusted", "trusted"])
        with (
            patch.object(self.async_keys, "resolve_public_key_async", AsyncMock(side_effect=[SECRET, b"wrong"])),
            self.assertRaises(InvalidSignature),
        ):
            await self.verifier.verify_async(request, expect_tag="app")

    async def test_lookup_errors_and_missing_keys(self):
        request = self.request()
        for error in (KeyError("unknown key"), ValueError("key lookup failed")):
            with (
                self.subTest(error=error),
                patch.object(self.async_keys, "resolve_public_key_async", AsyncMock(side_effect=error)),
            ):
                with self.assertRaises(InvalidSignature) as caught:
                    await self.verifier.verify_async(request)
                self.assertIs(caught.exception.__cause__, error)
        with (
            patch.object(self.async_keys, "resolve_public_key_async", AsyncMock(return_value=None)),
            self.assertRaisesRegex(InvalidSignature, "Unable to resolve"),
        ):
            await self.verifier.verify_async(request)

    async def test_lookup_suspends_and_cancellation_propagates(self):
        started, cancelled = asyncio.Event(), asyncio.Event()

        async def lookup(key_id):
            started.set()
            try:
                await asyncio.Future()
            finally:
                cancelled.set()

        with patch.object(self.async_keys, "resolve_public_key_async", lookup):
            task = asyncio.create_task(self.verifier.verify_async(self.request()))
            try:
                await asyncio.wait_for(started.wait(), timeout=2)
                self.assertFalse(task.done())
            finally:
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
            self.assertTrue(cancelled.is_set())

    async def test_expiration_is_rechecked_after_lookup(self):
        initial_time = datetime.now(timezone.utc)
        request = self.request(created=initial_time, expires=initial_time + timedelta(seconds=10))

        class Clock(datetime):
            current = initial_time

            @classmethod
            def now(cls, tz=None):
                return cls.current.astimezone(tz)

        async def lookup(key_id):
            await asyncio.sleep(0)
            Clock.current = initial_time + timedelta(minutes=1)
            return SECRET

        with (
            patch("http_message_signatures.signatures.datetime.datetime", Clock),
            patch.object(self.async_keys, "resolve_public_key_async", lookup),
            self.assertRaisesRegex(InvalidSignature, "expires"),
        ):
            await self.verifier.verify_async(request)
