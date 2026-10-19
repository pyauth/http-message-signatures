#!/usr/bin/env python

import asyncio
import base64
import copy
import hashlib
import hmac
import io
import json
import os
import subprocess
import sys
import textwrap
import time
import unittest
from contextlib import contextmanager
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
from http.client import HTTPMessage
from typing import ClassVar, get_type_hints
from unittest.mock import patch
from urllib.parse import urlencode

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from http_sf.compat import Dictionary, Item

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from http_message_signatures import (  # noqa
    HTTPMessageSigner,
    HTTPMessageVerifier,
    HTTPSignatureAlgorithm,
    HTTPSignatureComponentResolver,
    HTTPSignatureKeyResolver,
    InvalidSignature,
    HTTPMessageSignaturesException,
    PreparedSignature,
    VerifyResult,
)
from http_message_signatures.algorithms import (
    ECDSA_P256_SHA256,
    ED25519,
    HMAC_SHA256,
    RSA_PSS_SHA512,
    RSA_V1_5_SHA256,
)
from http_message_signatures._url import URLParts, parse_url

test_shared_secret = base64.b64decode(
    "uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ=="
)


@contextmanager
def patch_time(dt):
    class MockDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return dt.astimezone(tz) if tz is not None else dt.astimezone().replace(tzinfo=None)

    with patch("http_message_signatures.signatures.datetime.datetime", MockDateTime):
        yield


def set_test_signature(message, signature_params, covered_lines):
    """MAC explicit fixtures without passing them through the signer's validation."""
    base = "\n".join([*covered_lines, f'"@signature-params": {signature_params}'])
    signature = HMAC_SHA256(private_key=test_shared_secret).sign(base.encode())
    message.headers["Signature-Input"] = "pyhms=" + signature_params
    message.headers["Signature"] = str(Dictionary({"pyhms": signature}))


class MyHTTPSignatureKeyResolver(HTTPSignatureKeyResolver):
    known_pem_keys: ClassVar[set[str]] = {"test-key-rsa", "test-key-rsa-pss", "test-key-ecc-p256", "test-key-ed25519"}

    def resolve_public_key(self, key_id: str):
        if key_id == "test-shared-secret":
            return test_shared_secret
        if key_id in self.known_pem_keys:
            with open(f"test/{key_id}.pem", "rb") as fh:
                return load_pem_public_key(fh.read())

    def resolve_private_key(self, key_id: str):
        if key_id == "test-shared-secret":
            return test_shared_secret
        if key_id in self.known_pem_keys:
            with open(f"test/{key_id}.key", "rb") as fh:
                return load_pem_private_key(fh.read(), password=None)


class TestURLParsing(unittest.TestCase):
    def test_components_preserve_supplied_spelling(self):
        cases = (
            (
                "HTTPS://user:p%40ss@EXAMPLE.com:00443/a%2fb/../c?q=%2f#fragment",
                URLParts("HTTPS", "EXAMPLE.com", "00443", "/a%2fb/../c", "q=%2f"),
            ),
            ("http://127.0.0.1:00080", URLParts("http", "127.0.0.1", "00080", "", None)),
            (
                "https://[2001:0DB8:0:0:0:0:0:1]:8443/",
                URLParts("https", "[2001:0DB8:0:0:0:0:0:1]", "8443", "/", None),
            ),
            ("http://[::FFFF:192.0.2.128]/", URLParts("http", "[::FFFF:192.0.2.128]", None, "/", None)),
            ("https://[v1.a:b]/", URLParts("https", "[v1.a:b]", None, "/", None)),
            ("https://[Vf.A:B]/", URLParts("https", "[Vf.A:B]", None, "/", None)),
            ("http://[fe80::1%25en%2D0]/", URLParts("http", "[fe80::1%25en%2D0]", None, "/", None)),
            ("custom+v1.2://example.com:0/a", URLParts("custom+v1.2", "example.com", "0", "/a", None)),
            ("https://%65xample.com/", URLParts("https", "%65xample.com", None, "/", None)),
            (
                "https://example.com/!$&'()*+,;=:@/_~-.?a=/?:@!$&'()*+,;=_~-.#/?fragment",
                URLParts("https", "example.com", None, "/!$&'()*+,;=:@/_~-.", "a=/?:@!$&'()*+,;=_~-."),
            ),
        )
        for url, expected in cases:
            with self.subTest(url=url):
                self.assertEqual(parse_url(url), expected)

    def test_empty_and_absent_components(self):
        cases = (
            ("https://example.com", None, "", None),
            ("https://example.com?", None, "", ""),
            ("https://example.com#", None, "", None),
            ("https://example.com?#", None, "", ""),
            ("https://@example.com:/?#", "", "/", ""),
            ("https://example.com/#?", None, "/", None),
        )
        for url, port, path, query in cases:
            with self.subTest(url=url):
                self.assertEqual(parse_url(url), URLParts("https", "example.com", port, path, query))

    def test_percent_escapes_are_preserved_without_decoding(self):
        for spelling in ("02x", "02X"):
            encoded = "".join("%" + format(octet, spelling) for octet in range(256))
            url = f"https://{encoded}@example.com/{encoded}?{encoded}#{encoded}"
            self.assertEqual(parse_url(url), URLParts("https", "example.com", None, "/" + encoded, encoded))

    def test_invalid_url_syntax(self):
        urls = (
            "",
            "/resource",
            "//example.com/",
            "https:example.com/",
            "mailto:user@example.com",
            "1http://example.com/",
            "https:///resource",
            "https://?query",
            "https://user@/",
            "https://example.com:abc/",
            "https://example.com:-1/",
            "https://example.com:+80/",
            "https://example.com:８０/",
            "https://example.com:80:90/",
            "https://a@b@example.com/",
            "https://[::1",
            "https://::1/",
            "https://[]/",
            "https://[127.0.0.1]/",
            "https://[:::]/",
            "https://[1:2:3:4:5:6:7]/",
            "https://[1:2:3:4:5:6:7:8:9]/",
            "https://[::ffff:256.1.1.1]/",
            "https://[::1]extra/",
            "https://[v1.]/",
            "https://[vG.test]/",
            "https://[v1.%41]/",
            "https://[fe80::1%eth0]/",
            "https://[fe80::1%25]/",
            "https://example.com/path#one#two",
            "https://example.com/[path]",
            "https://example.com/?q=[value]",
        )
        for url in urls:
            with self.subTest(url=url), self.assertRaisesRegex(HTTPMessageSignaturesException, "Invalid URL"):
                parse_url(url)

    def test_invalid_characters_and_escapes_in_each_component(self):
        templates = (
            "https://user{}@example.com/",
            "https://ex{}zample.com/",
            "https://example.com/a{}z",
            "https://example.com/?q=a{}z",
            "https://example.com/#a{}z",
            "https://[fe80::1%25en{}z]/",
        )
        invalid = [chr(code) for code in range(33)] + [chr(127), "é", "K", "\\", '"', "<", ">", "^", "`", "{", "|", "}"]
        invalid += ["%", "%2", "%GG", "%2g", "%41%ZZ", "%41%2"]
        for template in templates:
            for value in invalid:
                url = template.format(value)
                with self.subTest(url=url), self.assertRaisesRegex(HTTPMessageSignaturesException, "Invalid URL"):
                    parse_url(url)
        for value in invalid:
            with self.subTest(prefix=value), self.assertRaisesRegex(HTTPMessageSignaturesException, "Invalid URL"):
                parse_url(value + "https://example.com/")

    def test_long_invalid_inputs_finish_promptly(self):
        script = textwrap.dedent("""
            from http_message_signatures._url import parse_url
            from http_message_signatures.exceptions import HTTPMessageSignaturesException

            for template in (
                "https://{}^/", "https://{}^@example.com/", "https://example.com/{}^",
                "https://example.com/?{}^", "https://example.com/#{}^", "https://example.com:{}x/",
            ):
                try:
                    parse_url(template.format("1" * 100_000))
                except HTTPMessageSignaturesException:
                    pass
                else:
                    raise AssertionError("Invalid URL accepted")
        """)
        result = subprocess.run([sys.executable, "-c", script], check=False, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)


class TestHTTPMessageSignatures(unittest.TestCase):
    def setUp(self):
        request = requests.Request("POST", "https://example.com/foo?param=Value&Pet=dog", json={"hello": "world"})
        self.test_request = request.prepare()
        self.test_request.headers["Date"] = "Tue, 20 Apr 2021 02:07:55 GMT"
        self.test_request.headers["Content-Digest"] = (
            "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"
        )
        self.test_response = requests.Response()
        self.test_response.request = self.test_request
        self.test_response.status_code = 200
        self.test_response.headers = {
            "Date": "Tue, 20 Apr 2021 02:07:56 GMT",
            "Content-Type": "application/json",
            "Content-Digest": (
                "sha-512=:JlEy2bfUz7WrWIjc1qV6KVLpdr/7L5/L4h7Sxvh6sNHpDQWDCL+GauFQWcZBvVDhiyOnAQsxzZFYwi0wDH+1pw==:"
            ),
            "Content-Length": "23",
        }
        self.test_response.raw = io.BytesIO(json.dumps({"message": "good dog"}).encode())
        self.key_resolver = MyHTTPSignatureKeyResolver()
        self.max_age = timedelta(weeks=90000)

    def verify(self, verifier, message, max_age=None, expect_tag=None, expect_label=None):
        if max_age is None:
            max_age = self.max_age
        m = copy.deepcopy(message)
        m.headers["Signature"] = m.headers["Signature"][:8] + m.headers["Signature"][8:].upper()
        with self.assertRaises(InvalidSignature):
            verifier.verify(m, max_age=max_age, expect_tag=expect_tag, expect_label=expect_label)
        m.headers["Signature"] = m.headers["Signature"].upper()
        with self.assertRaisesRegex(InvalidSignature, "Malformed structured header field"):
            verifier.verify(m, max_age=max_age, expect_tag=expect_tag, expect_label=expect_label)
        del m.headers["Signature"]
        with self.assertRaisesRegex(InvalidSignature, 'Expected "Signature" header field to be present'):
            verifier.verify(m, max_age=max_age, expect_tag=expect_tag, expect_label=expect_label)
        return verifier.verify(message, max_age=max_age, expect_tag=expect_tag, expect_label=expect_label)

    def test_prepare_signature_base_and_metadata(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256)
        created = datetime.fromtimestamp(1618884473, timezone.utc)
        original_headers = dict(self.test_request.headers)
        prepared = signer.prepare(
            self.test_request,
            key_id="test-shared-secret",
            created=created,
            expires=created + timedelta(seconds=60),
            nonce='quote"\\',
            label="sig1",
            tag="remote",
            covered_component_ids=("@method", "date"),
        )
        expected_params = (
            '("@method" "date");created=1618884473;keyid="test-shared-secret";alg="hmac-sha256";'
            'expires=1618884533;nonce="quote\\"\\\\";tag="remote"'
        )
        self.assertIsInstance(prepared, PreparedSignature)
        self.assertEqual(prepared.signature_params, expected_params)
        self.assertEqual(
            prepared.signature_base,
            (
                '"@method": POST\n"date": Tue, 20 Apr 2021 02:07:55 GMT\n"@signature-params": ' + expected_params
            ).encode(),
        )
        self.assertEqual(prepared.label, "sig1")
        self.assertEqual(prepared.algorithm_id, "hmac-sha256")
        self.assertEqual(dict(self.test_request.headers), original_headers)
        with self.assertRaises(FrozenInstanceError):
            prepared.label = "other"

    def test_remote_signing_all_algorithms(self):
        for algorithm, key_id in (
            (HMAC_SHA256, "test-shared-secret"),
            (ECDSA_P256_SHA256, "test-key-ecc-p256"),
            (ED25519, "test-key-ed25519"),
            (RSA_PSS_SHA512, "test-key-rsa-pss"),
            (RSA_V1_5_SHA256, "test-key-rsa"),
        ):
            with self.subTest(algorithm=algorithm.algorithm_id):
                message = copy.deepcopy(self.test_request)
                local_message = copy.deepcopy(message)
                created = datetime.now(timezone.utc)
                key = self.key_resolver.resolve_private_key(key_id)
                signer = HTTPMessageSigner(signature_algorithm=algorithm, key_resolver=self.key_resolver)
                with (
                    patch.object(
                        self.key_resolver, "resolve_private_key", side_effect=AssertionError("local key read")
                    ),
                    patch.object(self.key_resolver, "resolve_public_key", side_effect=AssertionError("local key read")),
                ):
                    prepared = signer.prepare(message, key_id=key_id, created=created)
                    signature = algorithm(private_key=key).sign(prepared.signature_base)
                    signer.apply(message, prepared, signature)
                verifier = HTTPMessageVerifier(signature_algorithm=algorithm, key_resolver=self.key_resolver)
                self.assertEqual(len(verifier.verify(message)), 1)
                signer.sign(local_message, key_id=key_id, created=created)
                self.assertEqual(message.headers["Signature-Input"], local_message.headers["Signature-Input"])
                if algorithm in (HMAC_SHA256, ED25519, RSA_V1_5_SHA256):
                    self.assertEqual(message.headers["Signature"], local_message.headers["Signature"])

    def test_async_remote_signing_without_key_resolver(self):
        async def remote_sign(base):
            await asyncio.sleep(0)
            return HMAC_SHA256(shared_secret=test_shared_secret).sign(base)

        async def sign_request():
            signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256)
            prepared = signer.prepare(self.test_request, key_id="test-shared-secret", include_alg=False)
            signature = await remote_sign(prepared.signature_base)
            signer.apply(self.test_request, prepared, signature)

        asyncio.run(sign_request())
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        result = verifier.verify(self.test_request)[0]
        self.assertNotIn("alg", result.parameters)
        self.assertEqual(result.label, "pyhms")

    def test_local_signing_requires_key_resolver(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256)
        with self.assertRaisesRegex(HTTPMessageSignaturesException, "key_resolver is required"):
            signer.sign(self.test_request, key_id="test-shared-secret")

    def test_prepare_rejects_invalid_label_before_signing(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        for label in ("", "Sig1", "sig 1", "sig1,evil", "sig1\r\nx-evil"):
            with (
                self.subTest(label=label),
                patch.object(self.key_resolver, "resolve_private_key", side_effect=AssertionError("local key read")),
                self.assertRaisesRegex(HTTPMessageSignaturesException, "Invalid signature label"),
            ):
                signer.sign(self.test_request, key_id="test-shared-secret", label=label)
        self.assertNotIn("Signature", self.test_request.headers)

    def test_apply_rejects_changed_covered_values(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256)
        prepared = signer.prepare(
            self.test_request, key_id="test-shared-secret", covered_component_ids=("@method", "date")
        )
        signature = HMAC_SHA256(shared_secret=test_shared_secret).sign(prepared.signature_base)
        for field, value in (("method", "DELETE"), ("date", "Wed, 21 Apr 2021 02:07:55 GMT")):
            with self.subTest(field=field):
                message = copy.deepcopy(self.test_request)
                if field == "method":
                    message.method = value
                else:
                    message.headers["Date"] = value
                message.headers["Signature-Input"] = "existing-input"
                message.headers["Signature"] = "existing-signature"
                original_headers = dict(message.headers)
                with self.assertRaisesRegex(HTTPMessageSignaturesException, "changed after prepare"):
                    signer.apply(message, prepared, signature)
                self.assertEqual(dict(message.headers), original_headers)

    def test_apply_allows_copied_message_and_equivalent_values(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256)
        prepared = signer.prepare(self.test_request, key_id="test-shared-secret", covered_component_ids=("date",))
        signature = HMAC_SHA256(shared_secret=test_shared_secret).sign(prepared.signature_base)
        message = copy.deepcopy(self.test_request)
        message.headers["Date"] = "\t" + message.headers["Date"] + " "
        message.headers["X-Uncovered"] = "new value"
        signer.apply(message, prepared, signature)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        self.assertEqual(len(verifier.verify(message)), 1)
        self.assertNotIn("Signature", self.test_request.headers)

    def test_apply_rejects_inconsistent_prepared_input(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256)
        prepared = signer.prepare(self.test_request, key_id="test-shared-secret")
        signature = HMAC_SHA256(shared_secret=test_shared_secret).sign(prepared.signature_base)
        original_headers = dict(self.test_request.headers)
        for changed in (
            None,
            replace(prepared, signature_base=prepared.signature_base + b"\n"),
            replace(prepared, signature_params=prepared.signature_params + ';nonce="other"'),
            replace(prepared, signature_params=prepared.signature_params + ", injected=()"),
            replace(prepared, signature_params=prepared.signature_params + " trailing garbage"),
            replace(prepared, signature_params='"not an inner list"'),
            replace(prepared, signature_params=prepared.signature_params.replace("hmac-sha256", "ed25519")),
            replace(prepared, label="sig1, injected"),
            replace(prepared, algorithm_id="ed25519"),
        ):
            with self.subTest(prepared=changed), self.assertRaises(HTTPMessageSignaturesException):
                signer.apply(self.test_request, changed, signature)
            self.assertEqual(dict(self.test_request.headers), original_headers)

    def test_apply_binds_algorithm_when_alg_omitted(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256)
        prepared = signer.prepare(self.test_request, key_id="test-shared-secret", include_alg=False)
        other_signer = HTTPMessageSigner(signature_algorithm=ED25519)
        with self.assertRaisesRegex(HTTPMessageSignaturesException, "different algorithm"):
            other_signer.apply(self.test_request, prepared, b"signature")

    def test_apply_requires_raw_nonempty_bytes(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256)
        prepared = signer.prepare(self.test_request, key_id="test-shared-secret")
        for signature in (None, "YWJjZA==", b"", bytearray(b"signature")):
            with self.subTest(signature=signature), self.assertRaisesRegex(HTTPMessageSignaturesException, "raw bytes"):
                signer.apply(self.test_request, prepared, signature)
        self.assertNotIn("Signature", self.test_request.headers)

    def test_apply_does_not_claim_to_verify_signature(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256)
        prepared = signer.prepare(self.test_request, key_id="test-shared-secret")
        signer.apply(self.test_request, prepared, bytes(32))
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        with self.assertRaises(InvalidSignature):
            verifier.verify(self.test_request)

    def test_remote_signature_append_and_replace(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        prepared = signer.prepare(self.test_request, key_id="test-shared-secret", label="remote", tag="remote")
        signature = HMAC_SHA256(shared_secret=test_shared_secret).sign(prepared.signature_base)
        # Another signature can arrive while the remote signature is pending.
        signer.sign(self.test_request, key_id="test-shared-secret", label="local", tag="local")
        old_signature = Dictionary()
        old_signature.parse(self.test_request.headers["Signature"].encode())
        signer.apply(self.test_request, prepared, signature, append_if_signature_exists=True)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        for tag in ("local", "remote"):
            self.assertEqual(verifier.verify(self.test_request, expect_tag=tag)[0].label, tag)
        signatures = Dictionary()
        signatures.parse(self.test_request.headers["Signature"].encode())
        self.assertEqual(signatures["local"].value, old_signature["local"].value)
        headers = dict(self.test_request.headers)
        with self.assertRaisesRegex(HTTPMessageSignaturesException, "already present"):
            signer.apply(self.test_request, prepared, signature, append_if_signature_exists=True)
        self.assertEqual(dict(self.test_request.headers), headers)
        signer.apply(self.test_request, prepared, signature)
        self.assertEqual(verifier.verify(self.test_request)[0].label, "remote")

    def test_prepare_apply_custom_component_resolver(self):
        class Resolver(HTTPSignatureComponentResolver):
            def get_method(self):
                return "CUSTOM"

        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, component_resolver_class=Resolver)
        prepared = signer.prepare(self.test_request, key_id="test-shared-secret", covered_component_ids=("@method",))
        self.assertTrue(prepared.signature_base.startswith(b'"@method": CUSTOM\n'))
        signature = HMAC_SHA256(shared_secret=test_shared_secret).sign(prepared.signature_base)
        signer.apply(self.test_request, prepared, signature)
        verifier = HTTPMessageVerifier(
            signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver, component_resolver_class=Resolver
        )
        self.assertEqual(len(verifier.verify(self.test_request)), 1)
        other_signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256)
        with self.assertRaisesRegex(HTTPMessageSignaturesException, "changed after prepare"):
            other_signer.apply(self.test_request, prepared, signature)

    def test_prepare_response_with_request_components(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256)
        prepared = signer.prepare(
            self.test_response, key_id="test-shared-secret", covered_component_ids=("@status", '"@method";req')
        )
        signature = HMAC_SHA256(shared_secret=test_shared_secret).sign(prepared.signature_base)
        self.test_response.request.method = "DELETE"
        with self.assertRaisesRegex(HTTPMessageSignaturesException, "changed after prepare"):
            signer.apply(self.test_response, prepared, signature)
        self.test_response.request.method = "POST"
        signer.apply(self.test_response, prepared, signature)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        self.assertEqual(len(verifier.verify(self.test_response)), 1)

    def test_prepare_preserves_creation_time_across_delay(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256)
        created = datetime.now(timezone.utc)
        with patch_time(created):
            prepared = signer.prepare(
                self.test_request, key_id="test-shared-secret", expires=created + timedelta(seconds=10)
            )
        signature = HMAC_SHA256(shared_secret=test_shared_secret).sign(prepared.signature_base)
        with patch_time(created + timedelta(minutes=1)):
            signer.apply(self.test_request, prepared, signature)
            verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
            with self.assertRaisesRegex(InvalidSignature, '"expires" parameter is set to a time in the past'):
                verifier.verify(self.test_request)
        self.assertIn(f"created={int(created.timestamp())}", self.test_request.headers["Signature-Input"])

    def test_ecdsa_remote_der_conversion(self):
        signer = HTTPMessageSigner(signature_algorithm=ECDSA_P256_SHA256)
        prepared = signer.prepare(self.test_request, key_id="test-key-ecc-p256")
        key = self.key_resolver.resolve_private_key("test-key-ecc-p256")
        der = key.sign(prepared.signature_base, ec.ECDSA(hashes.SHA256()))
        signature = ECDSA_P256_SHA256.signature_from_der(der)
        self.assertEqual(len(signature), 64)
        signer.apply(self.test_request, prepared, signature)
        verifier = HTTPMessageVerifier(signature_algorithm=ECDSA_P256_SHA256, key_resolver=self.key_resolver)
        self.assertEqual(len(verifier.verify(self.test_request)), 1)

    def test_ecdsa_der_conversion_padding_and_invalid_input(self):
        signature = ECDSA_P256_SHA256.signature_from_der(encode_dss_signature(1, 2**255))
        self.assertEqual(signature, bytes(31) + b"\x01\x80" + bytes(31))
        for der in (b"not DER", bytes(64), encode_dss_signature(2**256, 1), encode_dss_signature(1, 2**256)):
            with self.subTest(der=der), self.assertRaisesRegex(HTTPMessageSignaturesException, "Invalid DER"):
                ECDSA_P256_SHA256.signature_from_der(der)

    def test_reject_scalar_covered_components(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        self.test_request.headers.update({"d": "one", "a": "two", "t": "three", "e": "four"})
        original_headers = dict(self.test_request.headers)
        for components in ("date", b"date", bytearray(b"date"), ""):
            with self.subTest(components=components):
                with self.assertRaisesRegex(HTTPMessageSignaturesException, "sequence of component strings"):
                    signer.sign(self.test_request, key_id="test-shared-secret", covered_component_ids=components)
                self.assertEqual(dict(self.test_request.headers), original_headers)

    def test_single_component_sequences_cover_the_header(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        for components in (("date",), ["date"]):
            with self.subTest(components=components):
                message = copy.deepcopy(self.test_request)
                signer.sign(message, key_id="test-shared-secret", covered_component_ids=components)
                self.assertEqual(verifier.verify(message)[0].covered_components['"date"'], message.headers["Date"])
                message.headers["Date"] = "Wed, 21 Apr 2021 02:07:55 GMT"
                with self.assertRaises(InvalidSignature):
                    verifier.verify(message)

    def test_hmac_key_arguments(self):
        message = b"message"
        for secret in (b"secret", b""):
            expected = hmac.digest(secret, message, hashlib.sha256)
            for keys in (
                {"shared_secret": secret},
                {"public_key": secret},
                {"private_key": secret},
                {"public_key": secret, "private_key": secret},
                {"public_key": secret, "shared_secret": secret},
                {"private_key": secret, "shared_secret": secret},
                {"public_key": secret, "private_key": secret, "shared_secret": secret},
            ):
                with self.subTest(keys=keys):
                    algorithm = HMAC_SHA256(**keys)
                    self.assertEqual(algorithm.sign(message), expected)
                    algorithm.verify(signature=expected, message=message)

    def test_hmac_rejects_conflicting_keys(self):
        for keys in (
            {"public_key": b"first", "private_key": b"second"},
            {"public_key": b"first", "shared_secret": b"second"},
            {"private_key": b"first", "shared_secret": b"second"},
            {"public_key": b"first", "private_key": b"first", "shared_secret": b"second"},
            {"public_key": b"", "private_key": b"second"},
            {"private_key": b"first", "shared_secret": b""},
        ):
            with self.subTest(keys=keys), self.assertRaisesRegex(HTTPMessageSignaturesException, "must be the same"):
                HMAC_SHA256(**keys)

    def test_hmac_requires_a_key(self):
        with self.assertRaisesRegex(HTTPMessageSignaturesException, "HMAC key must be supplied"):
            HMAC_SHA256()

    def test_configured_algorithm_subclass(self):
        class CustomHMAC(HMAC_SHA256):
            pass

        signer = HTTPMessageSigner(signature_algorithm=CustomHMAC, key_resolver=self.key_resolver)
        verifier = HTTPMessageVerifier(signature_algorithm=CustomHMAC, key_resolver=self.key_resolver)
        for include_alg in (True, False):
            with self.subTest(include_alg=include_alg):
                message = copy.deepcopy(self.test_request)
                signer.sign(message, key_id="test-shared-secret", include_alg=include_alg)
                result = verifier.verify(message)[0]
                self.assertIs(result.algorithm, CustomHMAC)
                self.assertEqual("alg" in result.parameters, include_alg)
                message.method = "DELETE"
                with self.assertRaises(InvalidSignature):
                    verifier.verify(message)

    def test_configured_algorithm_rejects_other_algorithm_ids(self):
        class CustomHMAC(HMAC_SHA256):
            algorithm_id = "app-hmac-sha256"

        for signing_algorithm, verifying_algorithm in ((CustomHMAC, HMAC_SHA256), (HMAC_SHA256, CustomHMAC)):
            with self.subTest(algorithm=signing_algorithm.algorithm_id):
                signer = HTTPMessageSigner(signature_algorithm=signing_algorithm, key_resolver=self.key_resolver)
                signer.sign(self.test_request, key_id="test-shared-secret")
                verifier = HTTPMessageVerifier(signature_algorithm=verifying_algorithm, key_resolver=self.key_resolver)
                with (
                    patch.object(self.key_resolver, "resolve_public_key", side_effect=AssertionError("key read")),
                    self.assertRaisesRegex(InvalidSignature, "Unexpected algorithm"),
                ):
                    verifier.verify(self.test_request)
                prepared = signer.prepare(self.test_request, key_id="test-shared-secret", include_alg=False)
                other_signer = HTTPMessageSigner(signature_algorithm=verifying_algorithm)
                with self.assertRaisesRegex(HTTPMessageSignaturesException, "different algorithm"):
                    other_signer.apply(self.test_request, prepared, b"signature")

    def test_invalid_algorithm_configuration(self):
        for algorithm in (None, "hmac-sha256", object, HTTPSignatureAlgorithm, HMAC_SHA256(shared_secret=b"secret")):
            for handler in (HTTPMessageSigner, HTTPMessageVerifier):
                with (
                    self.subTest(algorithm=algorithm, handler=handler),
                    self.assertRaisesRegex(HTTPMessageSignaturesException, "HTTPSignatureAlgorithm subclass"),
                ):
                    handler(signature_algorithm=algorithm, key_resolver=self.key_resolver)

    def test_public_api_typing(self):
        self.assertEqual(get_type_hints(VerifyResult)["algorithm"], type[HTTPSignatureAlgorithm])
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "mypy",
                "--strict",
                "--follow-imports=silent",
                "--no-incremental",
                "test/typing_api.py",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_custom_derived_component_mapping(self):
        class CustomResolver(HTTPSignatureComponentResolver):
            derived_component_resolvers: ClassVar[dict] = {
                **HTTPSignatureComponentResolver.derived_component_resolvers,
                "@custom": lambda resolver, **params: resolver.get_custom(**params),
            }

            def get_custom(self, *, name):
                return self.headers[name]

        signer = HTTPMessageSigner(
            signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver, component_resolver_class=CustomResolver
        )
        verifier = HTTPMessageVerifier(
            signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver, component_resolver_class=CustomResolver
        )
        self.test_request.headers["Example"] = "custom-value"
        for message, component in (
            (self.test_request, '"@custom";name="example"'),
            (self.test_response, '"@custom";name="example";req'),
        ):
            with self.subTest(component=component):
                signer.sign(message, key_id="test-shared-secret", covered_component_ids=(component,))
                self.assertEqual(verifier.verify(message)[0].covered_components[component], "custom-value")
        self.test_request.headers["Example"] = "changed"
        for message in (self.test_request, self.test_response):
            with self.assertRaises(InvalidSignature):
                verifier.verify(message)
        self.assertNotIn("@custom", HTTPSignatureComponentResolver.derived_component_resolvers)

    def test_derived_mapping_preserves_method_overrides(self):
        class CustomResolver(HTTPSignatureComponentResolver):
            def get_path(self):
                return "/custom-path"

        resolver = CustomResolver(self.test_request)
        self.assertEqual(resolver.resolve(Item("@path")), "/custom-path")
        self.assertEqual(resolver.resolve(Item("@target-uri")), "https://example.com/custom-path?param=Value&Pet=dog")
        self.assertEqual(HTTPSignatureComponentResolver(self.test_request).resolve(Item("@path")), "/foo")

    def test_obsolete_request_response_component_is_rejected(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        component = '"@request-response";key="sig1"'
        created = int(datetime.now(timezone.utc).timestamp())
        params = f'({component});created={created};keyid="test-shared-secret";alg="hmac-sha256"'
        for message in (self.test_request, self.test_response):
            with self.subTest(message=type(message).__name__):
                with self.assertRaisesRegex(HTTPMessageSignaturesException, "Unknown covered derived component"):
                    signer.sign(message, key_id="test-shared-secret", covered_component_ids=(component,))
                set_test_signature(message, params, [f"{component}: value"])
                with self.assertRaisesRegex(InvalidSignature, "Unknown covered derived component"):
                    verifier.verify(message)

    def test_http_message_signatures_B21(self):
        signer = HTTPMessageSigner(signature_algorithm=RSA_PSS_SHA512, key_resolver=self.key_resolver)
        signer.sign(
            self.test_request,
            key_id="test-key-rsa-pss",
            covered_component_ids=(),
            created=datetime.fromtimestamp(1618884473),
            label="sig-b21",
            nonce="b3k2pp5k7z-50gnwp.yemd",
            include_alg=False,
        )
        self.assertEqual(
            self.test_request.headers["Signature-Input"],
            'sig-b21=();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"',
        )
        verifier = HTTPMessageVerifier(signature_algorithm=RSA_PSS_SHA512, key_resolver=self.key_resolver)
        self.verify(verifier, self.test_request)  # Non-deterministic signing algorithm
        self.test_request.headers["Signature"] = (
            "sig-b21=:d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopem"
            "LJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG"
            "52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx"
            "2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6"
            "UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3"
            "+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==:"
        )
        self.verify(verifier, self.test_request)

    def test_http_message_signatures_B22(self):
        signer = HTTPMessageSigner(signature_algorithm=RSA_PSS_SHA512, key_resolver=self.key_resolver)
        signer.sign(
            self.test_request,
            key_id="test-key-rsa-pss",
            covered_component_ids=("@authority", "content-digest", '"@query-param";name="Pet"'),
            created=datetime.fromtimestamp(1618884473),
            label="sig-b22",
            tag="header-example",
            include_alg=False,
        )
        self.assertEqual(
            self.test_request.headers["Signature-Input"],
            'sig-b22=("@authority" "content-digest" "@query-param";name="Pet");'
            'created=1618884473;keyid="test-key-rsa-pss";tag="header-example"',
        )
        verifier = HTTPMessageVerifier(signature_algorithm=RSA_PSS_SHA512, key_resolver=self.key_resolver)
        self.verify(verifier, self.test_request)  # Non-deterministic signing algorithm
        self.test_request.headers["Signature"] = (
            "sig-b22=:LjbtqUbfmvjj5C5kr1Ugj4PmLYvx9wVjZvD9GsTT4F7GrcQ"
            "EdJzgI9qHxICagShLRiLMlAJjtq6N4CDfKtjvuJyE5qH7KT8UCMkSowOB4+ECxCmT"
            "8rtAmj/0PIXxi0A0nxKyB09RNrCQibbUjsLS/2YyFYXEu4TRJQzRw1rLEuEfY17SA"
            "RYhpTlaqwZVtR8NV7+4UKkjqpcAoFqWFQh62s7Cl+H2fjBSpqfZUJcsIk4N6wiKYd"
            "4je2U/lankenQ99PZfB4jY3I5rSV2DSBVkSFsURIjYErOs0tFTQosMTAoxk//0RoK"
            "UqiYY8Bh0aaUEb0rQl3/XaVe4bXTugEjHSw==:"
        )
        self.verify(verifier, self.test_request)

    def test_http_message_signatures_B23(self):
        signer = HTTPMessageSigner(signature_algorithm=RSA_PSS_SHA512, key_resolver=self.key_resolver)
        signer.sign(
            self.test_request,
            key_id="test-key-rsa-pss",
            covered_component_ids=(
                "date",
                "@method",
                "@path",
                "@query",
                "@authority",
                "content-type",
                "content-digest",
                "content-length",
            ),
            created=datetime.fromtimestamp(1618884473),
            label="sig-b23",
            include_alg=False,
        )
        self.assertEqual(
            self.test_request.headers["Signature-Input"],
            (
                "sig-b23="
                '("date" "@method" "@path" "@query" "@authority" "content-type" "content-digest" "content-length")'
                ';created=1618884473;keyid="test-key-rsa-pss"'
            ),
        )
        verifier = HTTPMessageVerifier(signature_algorithm=RSA_PSS_SHA512, key_resolver=self.key_resolver)
        self.verify(verifier, self.test_request)
        self.test_request.headers["Signature"] = (
            "sig-b23=:bbN8oArOxYoyylQQUU6QYwrTuaxLwjAC9fbY2F6SVWvh0yB"
            "iMIRGOnMYwZ/5MR6fb0Kh1rIRASVxFkeGt683+qRpRRU5p2voTp768ZrCUb38K0fU"
            "xN0O0iC59DzYx8DFll5GmydPxSmme9v6ULbMFkl+V5B1TP/yPViV7KsLNmvKiLJH1"
            "pFkh/aYA2HXXZzNBXmIkoQoLd7YfW91kE9o/CCoC1xMy7JA1ipwvKvfrs65ldmlu9"
            "bpG6A9BmzhuzF8Eim5f8ui9eH8LZH896+QIF61ka39VBrohr9iyMUJpvRX2Zbhl5Z"
            "JzSRxpJyoEZAFL2FUo5fTIztsDZKEgM4cUA==:"
        )
        self.verify(verifier, self.test_request)

    def test_http_message_signatures_B24(self):
        signer = HTTPMessageSigner(signature_algorithm=ECDSA_P256_SHA256, key_resolver=self.key_resolver)
        signer.sign(
            self.test_response,
            key_id="test-key-ecc-p256",
            covered_component_ids=("@status", "content-type", "content-digest", "content-length"),
            created=datetime.fromtimestamp(1618884473),
            label="sig-b24",
            include_alg=False,
        )
        self.assertEqual(
            self.test_response.headers["Signature-Input"],
            (
                'sig-b24=("@status" "content-type" "content-digest" "content-length");'
                'created=1618884473;keyid="test-key-ecc-p256"'
            ),
        )
        # Non-deterministic signing algorithm
        self.assertTrue(self.test_response.headers["Signature"].startswith("sig-b24="))
        verifier = HTTPMessageVerifier(signature_algorithm=ECDSA_P256_SHA256, key_resolver=self.key_resolver)
        self.verify(verifier, self.test_response)
        self.test_response.headers["Signature"] = (
            "sig-b24=:0Ry6HsvzS5VmA6HlfBYS/fYYeNs7fYuA7s0tAdxfUlPGv0CSVuwrrzBOjcCFHTxVRJ01wjvSzM2BetJauj8dsw==:"
        )
        self.verify(verifier, self.test_response)

    def test_http_message_signatures_B25(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        signer.sign(
            self.test_request,
            key_id="test-shared-secret",
            covered_component_ids=("date", "@authority", "content-type"),
            created=datetime.fromtimestamp(1618884473),
            label="sig-b25",
            include_alg=False,
        )
        self.assertEqual(
            self.test_request.headers["Signature-Input"],
            'sig-b25=("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"',
        )
        self.assertEqual(
            self.test_request.headers["Signature"], "sig-b25=:pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=:"
        )
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        self.verify(verifier, self.test_request)

    def test_http_message_signatures_B26(self):
        signer = HTTPMessageSigner(signature_algorithm=ED25519, key_resolver=self.key_resolver)
        signer.sign(
            self.test_request,
            key_id="test-key-ed25519",
            covered_component_ids=("date", "@method", "@path", "@authority", "content-type", "content-length"),
            created=datetime.fromtimestamp(1618884473),
            label="sig-b26",
            include_alg=False,
        )
        self.assertEqual(
            self.test_request.headers["Signature-Input"],
            (
                'sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");'
                'created=1618884473;keyid="test-key-ed25519"'
            ),
        )
        signature = "sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:"
        self.assertEqual(self.test_request.headers["Signature"], signature)
        verifier = HTTPMessageVerifier(signature_algorithm=ED25519, key_resolver=self.key_resolver)
        result = self.verify(verifier, self.test_request)[0]

        self.assertEqual(result.parameters["keyid"], "test-key-ed25519")
        self.assertIn("created", result.parameters)
        self.assertEqual(result.label, "sig-b26")

        self.test_request.headers["Signature"] = "sig-b26=:pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=:"
        with self.assertRaises(InvalidSignature):
            verifier.verify(self.test_request, max_age=self.max_age)
        self.test_request.headers["Signature"] = signature[::-1]
        with self.assertRaises(InvalidSignature):
            verifier.verify(self.test_request, max_age=self.max_age)

    def test_http_message_signatures_B27(self):
        signer = HTTPMessageSigner(signature_algorithm=ED25519, key_resolver=self.key_resolver)
        signer.sign(
            self.test_request,
            key_id="test-key-ed25519",
            covered_component_ids=("date", "@method", "@path", "@authority", "content-type", "content-length"),
            created=datetime.fromtimestamp(1618884473),
            label="sig-b27",
            tag="tag-b27",
            include_alg=False,
        )
        self.assertEqual(
            self.test_request.headers["Signature-Input"],
            (
                'sig-b27=("date" "@method" "@path" "@authority" "content-type" "content-length");'
                'created=1618884473;keyid="test-key-ed25519";tag="tag-b27"'
            ),
        )
        signature = "sig-b27=:pDPhW4vxi28JZfogrM4NLeYhZKW+TYDko8KtzCFoTOFeGCCSivD0iVcIuT9gqM6AtGfgzqQU/GaoLqh8sC6bCg==:"
        self.assertEqual(self.test_request.headers["Signature"], signature)
        verifier = HTTPMessageVerifier(signature_algorithm=ED25519, key_resolver=self.key_resolver)
        result = self.verify(verifier, self.test_request)[0]

        self.assertEqual(result.parameters["keyid"], "test-key-ed25519")
        self.assertEqual(result.parameters["tag"], "tag-b27")
        self.assertIn("created", result.parameters)
        self.assertEqual(result.label, "sig-b27")

        self.test_request.headers["Signature"] = "sig-b26=:pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=:"
        with self.assertRaises(InvalidSignature):
            verifier.verify(self.test_request, max_age=self.max_age)
        self.test_request.headers["Signature"] = signature[::-1]
        with self.assertRaises(InvalidSignature):
            verifier.verify(self.test_request, max_age=self.max_age)

    def test_multiple_signatures(self):
        # The example below (and its signature test vectors) is from section 4.3 of the RFC, but it does not follow the
        # RFC's own guidance about not trusting labels. We emit a warning if the user specifies a label when verifying
        signer = HTTPMessageSigner(signature_algorithm=ECDSA_P256_SHA256, key_resolver=self.key_resolver)
        signer.sign(
            self.test_request,
            key_id="test-key-ecc-p256",
            covered_component_ids=(
                "@method",
                "@authority",
                "@path",
                "content-digest",
                "content-type",
                "content-length",
            ),
            created=datetime.fromtimestamp(1618884475),
            label="sig1",
            include_alg=False,
        )
        # Non-deterministic signing algorithm
        self.assertTrue(self.test_request.headers["Signature"].startswith("sig1="))
        verifier = HTTPMessageVerifier(signature_algorithm=ECDSA_P256_SHA256, key_resolver=self.key_resolver)
        self.verify(verifier, self.test_request)
        self.test_request.headers["Signature"] = (
            "sig1=:X5spyd6CFnAG5QnDyHfqoSNICd+BUP4LYMz2Q0JXlb//4Ijpzp+kve2w4NIyqeAuM7jTDX+sNalzA8ESSaHD3A==:"
        )
        self.verify(verifier, self.test_request)

        self.test_request.url = "https://origin.host.internal.example/foo?param=Value&Pet=dog"
        self.test_request.headers["Forwarded"] = "for=192.0.2.123;host=example.com;proto=https"
        signer2_args = {
            "key_id": "test-key-rsa",
            "covered_component_ids": (
                "@method",
                "@authority",
                "@path",
                "content-digest",
                "content-type",
                "content-length",
                "forwarded",
            ),
            "created": datetime.fromtimestamp(1618884480),
            "expires": datetime.fromtimestamp(1618884540),
            "label": "proxy_sig",
            "tag": None,
            "append_if_signature_exists": False,
        }
        signer2 = HTTPMessageSigner(signature_algorithm=RSA_V1_5_SHA256, key_resolver=self.key_resolver)
        req_for_overwrite = copy.deepcopy(self.test_request)
        signer2.sign(req_for_overwrite, **signer2_args)
        self.assertNotIn("sig1", req_for_overwrite.headers["Signature"])
        self.assertNotIn("sig1", req_for_overwrite.headers["Signature-Input"])
        signer2_args["append_if_signature_exists"] = True
        signer2.sign(self.test_request, **signer2_args)
        self.assertEqual(
            self.test_request.headers["Signature-Input"],
            'sig1=("@method" "@authority" "@path" "content-digest" "content-type" "content-length");created=1618884475;keyid="test-key-ecc-p256", proxy_sig=("@method" "@authority" "@path" "content-digest" "content-type" "content-length" "forwarded");created=1618884480;keyid="test-key-rsa";alg="rsa-v1_5-sha256";expires=1618884540',
        )
        self.assertEqual(
            self.test_request.headers["Signature"],
            "sig1=:X5spyd6CFnAG5QnDyHfqoSNICd+BUP4LYMz2Q0JXlb//4Ijpzp+kve2w4NIyqeAuM7jTDX+sNalzA8ESSaHD3A==:, proxy_sig=:S6ZzPXSdAMOPjN/6KXfXWNO/f7V6cHm7BXYUh3YD/fRad4BCaRZxP+JH+8XY1I6+8Cy+CM5g92iHgxtRPz+MjniOaYmdkDcnL9cCpXJleXsOckpURl49GwiyUpZ10KHgOEe11sx3G2gxI8S0jnxQB+Pu68U9vVcasqOWAEObtNKKZd8tSFu7LB5YAv0RAGhB8tmpv7sFnIm9y+7X5kXQfi8NMaZaA8i2ZHwpBdg7a6CMfwnnrtflzvZdXAsD3LH2TwevU+/PBPv0B6NMNk93wUs/vfJvye+YuI87HU38lZHowtznbLVdp770I6VHR6WfgS9ddzirrswsE1w5o0LV/g==:",
        )
        self.assertIn("sig1", self.test_request.headers["Signature-Input"])
        with self.assertRaisesRegex(InvalidSignature, "Multiple signatures found and no tag or label specified"):
            verifier.verify(self.test_request)
        verifier2 = HTTPMessageVerifier(signature_algorithm=RSA_V1_5_SHA256, key_resolver=self.key_resolver)
        with self.assertRaisesRegex(HTTPMessageSignaturesException, "expect_tag must be set if expect_label is set"):
            self.verify(verifier2, self.test_request, expect_label="proxy_sig")
        verifier2.allow_label_only_selection = True
        with self.assertRaisesRegex(InvalidSignature, 'Signature "expires" parameter is set to a time in the past'):
            self.verify(verifier2, self.test_request, expect_label="proxy_sig")

        with patch_time(datetime.fromtimestamp(1618884500)):
            res = self.verify(verifier2, self.test_request, expect_label="proxy_sig")
            self.assertEqual(len(res), 1)
            self.assertEqual(res[0].label, "proxy_sig")

        signer2_args.update(label="my-label", tag="my-tag")
        signer2.sign(self.test_request, **signer2_args)
        with self.assertRaisesRegex(InvalidSignature, "No signatures found matching the expected tag or label"):
            self.verify(verifier2, self.test_request, expect_tag="test")
        with patch_time(datetime.fromtimestamp(1618884500)):
            res = self.verify(verifier2, self.test_request, expect_tag="my-tag")
            self.assertEqual(len(res), 1)
            self.assertEqual(res[0].label, "my-label")
            self.assertEqual(res[0].parameters["tag"], "my-tag")

    def _verify_rfc_signature(self, message, *, algorithm, label, params, signature, components):
        # The signature bytes are published RFC fixtures, never generated by this helper.
        message.headers["Signature-Input"] = f"{label}={params}"
        message.headers["Signature"] = f"{label}=:{signature}:"
        verifier = HTTPMessageVerifier(signature_algorithm=algorithm, key_resolver=self.key_resolver)
        result = verifier.verify(message, max_age=self.max_age)[0]
        self.assertEqual(result.label, label)
        self.assertEqual(
            list(result.covered_components.items()),
            list(components.items()) + [('"@signature-params"', params)],
        )

    def _rfc_service_unavailable_response(self):
        self.test_response.status_code = 503
        self.test_response.headers["Content-Length"] = "62"
        self.test_response.headers["Content-Digest"] = (
            "sha-512=:0Y6iCBzGg5rZtoXS95Ijz03mslf6KAMCloESHObfwnHJDbkkWWQz6PhhU9kxsTbARtY2PTBOzq24uJFpHsMuAg==:"
        )
        self.test_response.raw = io.BytesIO(b'{"busy": true, "message": "Your call is very important to us"}')
        return self.test_response

    def _set_rfc_signed_request(self):
        # RFC 9421 section 2.4, the request preceding the second signed response.
        self.test_request.headers["Signature-Input"] = (
            'sig1=("@method" "@authority" "@path" "@query" "content-digest" "content-type" "content-length");'
            'created=1618884475;keyid="test-key-rsa-pss"'
        )
        self.test_request.headers["Signature"] = (
            "sig1=:e8UJ5wMiRaonlth5ERtE8GIiEH7Akcr493nQ07VPNo6y3qvjdK"
            "t0fo8VHO8xXDjmtYoatGYBGJVlMfIp06eVMEyNW2I4vN7XDAz7m5v1108vGzaDljr"
            "d0H8+SJ28g7bzn6h2xeL/8q+qUwahWA/JmC8aOC9iVnwbOKCc0WSrLgWQwTY6VLp4"
            "2Qt7jjhYT5W7/wCvfK9A1VmHH1lJXsV873Z6hpxesd50PSmO+xaNeYvDLvVdZlhtw"
            "5PCtUYzKjHqwmaQ6DEuM8udRjYsoNqp2xZKcuCO1nKc0V3RjpqMZLuuyVbHDAbCzr"
            "0pg2d2VM/OC33JAU7meEjjaNz+d7LWPg==:"
        )

    def test_rfc9421_section_2_4_signed_request(self):
        self._set_rfc_signed_request()
        verifier = HTTPMessageVerifier(signature_algorithm=RSA_PSS_SHA512, key_resolver=self.key_resolver)
        result = verifier.verify(self.test_request, max_age=self.max_age)[0]
        self.assertEqual(
            list(result.covered_components.items()),
            [
                ('"@method"', "POST"),
                ('"@authority"', "example.com"),
                ('"@path"', "/foo"),
                ('"@query"', "?param=Value&Pet=dog"),
                ('"content-digest"', self.test_request.headers["Content-Digest"]),
                ('"content-type"', "application/json"),
                ('"content-length"', "18"),
                (
                    '"@signature-params"',
                    (
                        '("@method" "@authority" "@path" "@query" "content-digest" "content-type" "content-length");'
                        'created=1618884475;keyid="test-key-rsa-pss"'
                    ),
                ),
            ],
        )

    def test_rfc9421_section_2_4_response_to_unsigned_request(self):
        response = self._rfc_service_unavailable_response()
        self._verify_rfc_signature(
            response,
            algorithm=ECDSA_P256_SHA256,
            label="reqres",
            params=(
                '("@status" "content-digest" "content-type" "@authority";req "@method";req "@path";req '
                '"content-digest";req);created=1618884479;keyid="test-key-ecc-p256"'
            ),
            signature="dMT/A/76ehrdBTD/2Xx8QuKV6FoyzEP/I9hdzKN8LQJLNgzU4W767HK05rx1i8meNQQgQPgQp8wq2ive3tV5Ag==",
            components={
                '"@status"': "503",
                '"content-digest"': response.headers["Content-Digest"],
                '"content-type"': "application/json",
                '"@authority";req': "example.com",
                '"@method";req': "POST",
                '"@path";req': "/foo",
                '"content-digest";req': self.test_request.headers["Content-Digest"],
            },
        )

    def test_rfc9421_section_2_4_response_to_signed_request(self):
        self._set_rfc_signed_request()
        response = self._rfc_service_unavailable_response()
        self._verify_rfc_signature(
            response,
            algorithm=ECDSA_P256_SHA256,
            label="reqres",
            params=(
                '("@status" "content-digest" "content-type" "@authority";req "@method";req "@path";req '
                '"@query";req "content-digest";req "content-type";req "content-length";req);'
                'created=1618884479;keyid="test-key-ecc-p256"'
            ),
            signature="C73J41GVKc+TYXbSobvZf0CmNcptRiWN+NY1Or0A36ISg6ymdRN6ZgR2QfrtopFNzqAyv+CeWrMsNbcV2Ojsgg==",
            components={
                '"@status"': "503",
                '"content-digest"': response.headers["Content-Digest"],
                '"content-type"': "application/json",
                '"@authority";req': "example.com",
                '"@method";req': "POST",
                '"@path";req': "/foo",
                '"@query";req': "?param=Value&Pet=dog",
                '"content-digest";req': self.test_request.headers["Content-Digest"],
                '"content-type";req': "application/json",
                '"content-length";req': "18",
            },
        )

    def test_rfc9421_sections_2_5_through_3_2_rsa_pss(self):
        # Sections 2.5, 3.1, and 3.2 share this base and published signature.
        self._verify_rfc_signature(
            self.test_request,
            algorithm=RSA_PSS_SHA512,
            label="sig1",
            params=(
                '("@method" "@authority" "@path" "content-digest" "content-length" "content-type");'
                'created=1618884473;keyid="test-key-rsa-pss"'
            ),
            signature=(
                "HIbjHC5rS0BYaa9v4QfD4193TORw7u9edguPh0AW3dMq9WImrlFrCGUDih47vAxi4L2"
                "YRZ3XMJc1uOKk/J0ZmZ+wcta4nKIgBkKq0rM9hs3CQyxXGxHLMCy8uqK488o+9jrptQ"
                "+xFPHK7a9sRL1IXNaagCNN3ZxJsYapFj+JXbmaI5rtAdSfSvzPuBCh+ARHBmWuNo1Uz"
                "VVdHXrl8ePL4cccqlazIJdC4QEjrF+Sn4IxBQzTZsL9y9TP5FsZYzHvDqbInkTNigBc"
                "E9cKOYNFCn4D/WM7F6TNuZO9EgtzepLWcjTymlHzK7aXq6Am6sfOrpIC49yXjj3ae6H"
                "RalVc/g=="
            ),
            components={
                '"@method"': "POST",
                '"@authority"': "example.com",
                '"@path"': "/foo",
                '"content-digest"': self.test_request.headers["Content-Digest"],
                '"content-length"': "18",
                '"content-type"': "application/json",
            },
        )

    def test_rfc9421_B24_published_response(self):
        # The earlier B24 test retains a different digest/signature pair.
        self.test_response.headers["Content-Digest"] = (
            "sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:"
        )
        self._verify_rfc_signature(
            self.test_response,
            algorithm=ECDSA_P256_SHA256,
            label="sig-b24",
            params=(
                '("@status" "content-type" "content-digest" "content-length");'
                'created=1618884473;keyid="test-key-ecc-p256"'
            ),
            signature="wNmSUAhwb5LxtOtOpNa6W5xj067m5hFrj0XQ4fvpaCLx0NKocgPquLgyahnzDnDAUy5eCdlYUEkLIj+32oiasw==",
            components={
                '"@status"': "200",
                '"content-type"': "application/json",
                '"content-digest"': self.test_response.headers["Content-Digest"],
                '"content-length"': "23",
            },
        )

    def test_rfc9421_B3_client_certificate_proxy(self):
        self.test_request.url = "https://service.internal.example/foo?param=Value&Pet=dog"
        self.test_request.headers["Host"] = "service.internal.example"
        del self.test_request.headers["Content-Digest"]
        self.test_request.headers["Client-Cert"] = (
            ":MIIBqDCCAU6gAwIBAgIBBzAKBggqhkjOPQQDAjA6MRswGQYDVQQKD"
            "BJMZXQncyBBdXRoZW50aWNhdGUxGzAZBgNVBAMMEkxBIEludGVybWVkaWF0ZSBDQT"
            "AeFw0yMDAxMTQyMjU1MzNaFw0yMTAxMjMyMjU1MzNaMA0xCzAJBgNVBAMMAkJDMFk"
            "wEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8YnXXfaUgmnMtOXU/IncWalRhebrXmck"
            "C8vdgJ1p5Be5F/3YC8OthxM4+k1M6aEAEFcGzkJiNy6J84y7uzo9M6NyMHAwCQYDV"
            "R0TBAIwADAfBgNVHSMEGDAWgBRm3WjLa38lbEYCuiCPct0ZaSED2DAOBgNVHQ8BAf"
            "8EBAMCBsAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwHQYDVR0RAQH/BBMwEYEPYmRjQGV"
            "4YW1wbGUuY29tMAoGCCqGSM49BAMCA0gAMEUCIBHda/r1vaL6G3VliL4/Di6YK0Q6"
            "bMjeSkC3dFCOOB8TAiEAx/kHSB4urmiZ0NX5r5XarmPk0wmuydBVoU4hBVZ1yhk=:"
        )
        self._verify_rfc_signature(
            self.test_request,
            algorithm=ECDSA_P256_SHA256,
            label="ttrp",
            params=(
                '("@path" "@query" "@method" "@authority" "client-cert");created=1618884473;keyid="test-key-ecc-p256"'
            ),
            signature="xVMHVpawaAC/0SbHrKRs9i8I3eOs5RtTMGCWXm/9nvZzoHsIg6Mce9315T6xoklyy0yzhD9ah4JHRwMLOgmizw==",
            components={
                '"@path"': "/foo",
                '"@query"': "?param=Value&Pet=dog",
                '"@method"': "POST",
                '"@authority"': "service.internal.example",
                '"client-cert"': self.test_request.headers["Client-Cert"],
            },
        )

    def _rfc_transformation_request(
        self, *, method="GET", authority="example.org", query="name1=Value1&Name2=value2", fields=None
    ):
        message = requests.Request(method, f"https://{authority}/demo?{query}").prepare()
        message.headers = HTTPMessage()
        if fields is None:
            fields = (
                ("Host", authority),
                ("Date", "Fri, 15 Jul 2022 14:24:55 GMT"),
                ("Accept", "application/json"),
                ("Accept", "*/*"),
            )
        for name, value in fields:
            message.headers[name] = value
        return message

    def _verify_rfc_transformation(self, message):
        # Appendix B.4 uses this same published signature for all six messages.
        self._verify_rfc_signature(
            message,
            algorithm=ED25519,
            label="transform",
            params='("@method" "@path" "@authority" "accept");created=1618884473;keyid="test-key-ed25519"',
            signature="ZT1kooQsEHpZ0I1IjCqtQppOmIqlJPeo7DHR3SoMn0s5JZ1eRGS0A+vyYP9t/LXlh5QMFFQ6cpLt2m0pmj3NDA==",
            components={
                '"@method"': "GET",
                '"@path"': "/demo",
                '"@authority"': "example.org",
                '"accept"': "application/json, */*",
            },
        )

    def test_rfc9421_B4_original_request(self):
        message = self._rfc_transformation_request()
        self._verify_rfc_transformation(message)
        expected_signature = message.headers["Signature"]
        signer = HTTPMessageSigner(signature_algorithm=ED25519, key_resolver=self.key_resolver)
        signer.sign(
            message,
            key_id="test-key-ed25519",
            covered_component_ids=("@method", "@path", "@authority", "accept"),
            created=datetime.fromtimestamp(1618884473, timezone.utc),
            label="transform",
            include_alg=False,
        )
        self.assertEqual(message.headers["Signature"], expected_signature)

    def test_rfc9421_B4_added_uncovered_fields(self):
        message = self._rfc_transformation_request(query="name1=Value1&Name2=value2&param=added")
        message.headers["Accept-Language"] = "en-US,en;q=0.5"
        self._verify_rfc_transformation(message)

    def test_rfc9421_B4_combined_accept_fields(self):
        message = self._rfc_transformation_request(
            fields=(
                ("Host", "example.org"),
                ("Referer", "https://developer.example.org/demo"),
                ("Accept", "application/json, */*"),
            )
        )
        self._verify_rfc_transformation(message)

    def test_rfc9421_B4_reordered_field_names(self):
        message = self._rfc_transformation_request(
            fields=(
                ("Accept", "application/json"),
                ("Accept", "*/*"),
                ("Date", "Fri, 15 Jul 2022 14:24:55 GMT"),
                ("Host", "example.org"),
            )
        )
        self._verify_rfc_transformation(message)

    def test_rfc9421_B4_changed_method_and_authority(self):
        message = self._rfc_transformation_request(method="POST", authority="example.com")
        with self.assertRaises(InvalidSignature):
            self._verify_rfc_transformation(message)

    def test_rfc9421_B4_reordered_accept_values(self):
        message = self._rfc_transformation_request(
            fields=(
                ("Host", "example.org"),
                ("Date", "Fri, 15 Jul 2022 14:24:55 GMT"),
                ("Accept", "*/*"),
                ("Accept", "application/json"),
            )
        )
        with self.assertRaises(InvalidSignature):
            self._verify_rfc_transformation(message)

    def test_uppercase_method_signature_fixture(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        for message, component in ((self.test_request, '"@method"'), (self.test_response, '"@method";req')):
            for method in ("GET", "FETCH"):
                with self.subTest(component=component, method=method):
                    self.test_request.method = method
                    params = f'({component});created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'
                    set_test_signature(message, params, [f"{component}: {method}"])
                    expected_signature = message.headers["Signature"]
                    result = verifier.verify(message, max_age=self.max_age)[0]
                    self.assertEqual(result.covered_components[component], method)
                    signer.sign(
                        message,
                        key_id="test-shared-secret",
                        covered_component_ids=(component,),
                        created=datetime.fromtimestamp(1618884473, timezone.utc),
                    )
                    self.assertEqual(message.headers["Signature"], expected_signature)

    def test_method_case_rejected_on_ingestion(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        for message, components in (
            (self.test_request, ('"@method"', '"@path"')),
            (self.test_response, ('"@method";req', '"@status"')),
        ):
            for component in components:
                for method in ("get", "Get", "Fetch"):
                    with self.subTest(component=component, method=method):
                        self.test_request.method = method.upper()
                        signer.sign(message, key_id="test-shared-secret", covered_component_ids=(component,))
                        self.test_request.method = method
                        with self.assertRaisesRegex(InvalidSignature, "method must be an uppercase string"):
                            verifier.verify(message)
                        with self.assertRaisesRegex(
                            HTTPMessageSignaturesException, "method must be an uppercase string"
                        ):
                            signer.sign(message, key_id="test-shared-secret", covered_component_ids=(component,))

    def test_query_parameters(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        signer.sign(
            self.test_request,
            key_id="test-shared-secret",
            covered_component_ids=("date", "@authority", "content-type", '"@query-param";name="Pet"'),
            created=datetime.fromtimestamp(1618884473),
        )
        self.assertEqual(
            self.test_request.headers["Signature-Input"],
            (
                'pyhms=("date" "@authority" "content-type" "@query-param";name="Pet");'
                'created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'
            ),
        )
        self.assertEqual(self.test_request.headers["Signature"], "pyhms=:Z9vQKeWMcZ9MyiiiN0X9p64FlcJ73F2QjV4X6QlrOYE=:")
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        self.verify(verifier, self.test_request)

    def test_query_param_signature_fixtures(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        for message, suffix in ((self.test_request, ""), (self.test_response, ";req")):
            component = f'"@query-param";name="Pet"{suffix}'
            with self.subTest(component=component):
                self.test_request.url = "https://example.com/pets?Pet=dog&count=2"
                params = f'({component});created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'
                set_test_signature(message, params, [f"{component}: dog"])
                expected_signature = message.headers["Signature"]
                result = verifier.verify(message, max_age=self.max_age)[0]
                self.assertEqual(result.covered_components[component], "dog")
                signer.sign(
                    message,
                    key_id="test-shared-secret",
                    covered_component_ids=(component,),
                    created=datetime.fromtimestamp(1618884473, timezone.utc),
                )
                self.assertEqual(message.headers["Signature-Input"], "pyhms=" + params)
                self.assertEqual(message.headers["Signature"], expected_signature)
                self.test_request.url = "https://example.com/pets?Pet=dog&count=3"
                verifier.verify(message, max_age=self.max_age)
                self.test_request.url = "https://example.com/pets?Pet=cat&count=3"
                with self.assertRaises(InvalidSignature):
                    verifier.verify(message, max_age=self.max_age)

    def test_plural_query_component_is_not_supported(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        component = '"@query-params";name="Pet"'
        params = f'({component});created=1618884473;keyid="test-shared-secret"'
        set_test_signature(self.test_request, params, [f"{component}: dog"])
        with self.assertRaisesRegex(InvalidSignature, "Unknown covered derived component name @query-params"):
            verifier.verify(self.test_request, max_age=self.max_age)
        with self.assertRaisesRegex(
            HTTPMessageSignaturesException, "Unknown covered derived component name @query-params"
        ):
            signer.sign(self.test_request, key_id="test-shared-secret", covered_component_ids=(component,))

    def test_created_expires(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        signer.sign(self.test_request, key_id="test-shared-secret", created=datetime.fromtimestamp(1))
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        self.verify(verifier, self.test_request)
        with self.assertRaisesRegex(InvalidSignature, "Signature age exceeds maximum allowable age"):
            verifier.verify(self.test_request)
        signer.sign(self.test_request, key_id="test-shared-secret", created=datetime.now() + self.max_age)
        with self.assertRaisesRegex(InvalidSignature, 'Signature "created" parameter is set to a time in the future'):
            verifier.verify(self.test_request)
        signer.sign(self.test_request, key_id="test-shared-secret", expires=datetime.fromtimestamp(1))
        with self.assertRaisesRegex(InvalidSignature, 'Signature "expires" parameter is set to a time in the past'):
            verifier.verify(self.test_request)

    def test_query_parameter_canonicalization(self):
        self.test_request.url = (
            "https://example.com/parameters?var=this%20is%20a%20big%0Amultiline%20value"
            "&bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something&empty=&symbols=%2B%2F%26%3D*~"
        )
        resolver = HTTPSignatureComponentResolver(self.test_request)
        for name, expected in (
            ("var", "this%20is%20a%20big%0Amultiline%20value"),
            ("bar", "with%20plus%20whitespace"),
            ("fa%C3%A7ade%22%3A%20", "something"),
            ("empty", ""),
            ("symbols", "%2B%2F%26%3D*%7E"),
        ):
            with self.subTest(name=name):
                component = Item("@query-param")
                component.params["name"] = name
                self.assertEqual(resolver.resolve(component), expected)

    def test_query_parameter_newline_collision(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        for message, suffix in ((self.test_request, ""), (self.test_response, ";req")):
            with self.subTest(suffix=suffix):
                components = (f'"@query-param";name="a"{suffix}', f'"@query-param";name="b"{suffix}')
                delimiter = f"\n{components[1]}: "
                original = {"a": "safe" + delimiter + "injected", "b": "tail"}
                changed = {"a": "safe", "b": "injected" + delimiter + "tail"}
                self.test_request.url = "https://example.com/?" + urlencode(original)
                signer.sign(message, key_id="test-shared-secret", covered_component_ids=components)
                result = verifier.verify(message)[0]
                self.assertNotIn("\n", result.covered_components[components[0]])
                self.test_request.url = "https://example.com/?" + urlencode(changed)
                with self.assertRaises(InvalidSignature):
                    verifier.verify(message)

    def test_header_value_normalization(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        self.test_request.headers["Example"] = "Obsolete line folding."
        signer.sign(self.test_request, key_id="test-shared-secret", covered_component_ids=("example",))
        self.test_request.headers["Example"] = " \tObsolete\r\n\t  line folding.\t "
        self.assertEqual(
            verifier.verify(self.test_request)[0].covered_components['"example"'], "Obsolete line folding."
        )
        for invalid in ("Obsolete\nline folding.", "Obsolete\rline folding.", "Obsolete\r\nline folding.", "caf\u00e9"):
            with self.subTest(invalid=invalid):
                self.test_request.headers["Example"] = invalid
                with self.assertRaises(InvalidSignature):
                    verifier.verify(self.test_request)
                with self.assertRaises(HTTPMessageSignaturesException):
                    signer.sign(self.test_request, key_id="test-shared-secret", covered_component_ids=("example",))

    def test_obsolete_fold_includes_preceding_whitespace(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        self.test_request.headers["Example"] = "a b"
        signer.sign(self.test_request, key_id="test-shared-secret", covered_component_ids=("example",))
        for folded in ("a \t\r\n b", "a  \r\n\t  b", "a\r\n b"):
            with self.subTest(folded=folded):
                self.test_request.headers["Example"] = folded
                result = verifier.verify(self.test_request)[0]
                self.assertEqual(result.covered_components['"example"'], "a b")
        for distinct in ("a \t b", "a\nb", "a\rb", "a\r\nb"):
            with self.subTest(distinct=distinct):
                self.test_request.headers["Example"] = distinct
                with self.assertRaises(InvalidSignature):
                    verifier.verify(self.test_request)

    def test_header_normalization_long_whitespace(self):
        # Bound runtime in a child process so a quadratic-regex regression
        # fails promptly instead of hanging the suite. No signature is needed.
        script = textwrap.dedent(
            """
            from types import SimpleNamespace
            from http_message_signatures import HTTPMessageVerifier, HTTPSignatureKeyResolver, InvalidSignature
            from http_message_signatures.algorithms import HMAC_SHA256
            from http_message_signatures.structures import normalize_header_value

            padding = " \\t" * 131072
            values = ("a" + padding + "b", "a\\r\\n b" + padding + "c", "a" + padding + "\\r\\nb")
            expected = (values[0], "a b" + padding + "c", values[2])
            for value, normalized in zip(values, expected):
                assert normalize_header_value(value) == normalized
            message = SimpleNamespace(method="GET", url="https://example.com/", headers={"X-Padding": values[0]})
            verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=HTTPSignatureKeyResolver())
            try:
                verifier.verify(message)
            except InvalidSignature as error:
                assert 'Expected "Signature-Input"' in str(error)
            else:
                raise AssertionError("Unsigned request was accepted")
            """
        )
        result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=5, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_adjacent_obsolete_folds(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        self.test_request.headers["Example"] = "a  b"
        signer.sign(self.test_request, key_id="test-shared-secret", covered_component_ids=("example",))
        for folded in ("a\r\n \r\n b", "a \t\r\n \t\r\n\t b"):
            with self.subTest(folded=folded):
                self.test_request.headers["Example"] = folded
                result = verifier.verify(self.test_request)[0]
                self.assertEqual(result.covered_components['"example"'], "a  b")

    def test_structured_header_folding(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        self.test_request.headers["Example-Dict"] = "a=1,\r\n\t b=2"
        component = '"example-dict";key="b"'
        signer.sign(self.test_request, key_id="test-shared-secret", covered_component_ids=(component,), tag="folding")
        signature_input = self.test_request.headers["Signature-Input"]
        self.test_request.headers["Signature-Input"] = signature_input.replace(";created", ";\r\n created")
        self.test_request.headers["Signature"] = "\t" + self.test_request.headers["Signature"] + " "
        self.assertEqual(verifier.verify(self.test_request)[0].covered_components[component], "2")
        signer.sign(
            self.test_request,
            key_id="test-shared-secret",
            label="second",
            tag="folding",
            append_if_signature_exists=True,
        )
        self.assertEqual(len(verifier.verify(self.test_request, expect_tag="folding")), 2)

    def test_multiple_header_lines(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        for header_type in (dict, HTTPMessage):
            with self.subTest(header_type=header_type):
                headers = header_type()
                headers["Example"] = " first\t"
                headers["eXaMpLe"] = " second "
                self.test_request.headers = headers
                signer.sign(self.test_request, key_id="test-shared-secret", covered_component_ids=("example",))
                result = verifier.verify(self.test_request)[0]
                self.assertEqual(result.covered_components['"example"'], "first, second")
                headers["EXAMPLE"] = "third"
                with self.assertRaises(InvalidSignature):
                    verifier.verify(self.test_request)

    def test_dictionary_member_multiple_header_lines(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        headers = HTTPMessage()
        headers["Example-Dict"] = "a=1"
        headers["Example-Dict"] = "b=2"
        self.test_request.headers = headers
        component = '"example-dict";key="b"'
        signer.sign(self.test_request, key_id="test-shared-secret", covered_component_ids=(component,))
        self.assertEqual(verifier.verify(self.test_request)[0].covered_components[component], "2")
        headers["example-dict"] = "a=9"
        verifier.verify(self.test_request)
        headers["example-dict"] = "b=3"
        with self.assertRaises(InvalidSignature):
            verifier.verify(self.test_request)

    def test_multiple_signature_header_lines(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        signer.sign(self.test_request, key_id="test-shared-secret", label="first", tag="multi")
        signer.sign(
            self.test_request, key_id="test-shared-secret", label="second", tag="multi", append_if_signature_exists=True
        )
        headers = HTTPMessage()
        for name, value in self.test_request.headers.items():
            if name in ("Signature-Input", "Signature"):
                dictionary = Dictionary()
                dictionary.parse(value.encode())
                for label, item in dictionary.items():
                    headers[name.lower()] = str(Dictionary({label: item}))
            else:
                headers[name] = value
        self.test_request.headers = headers
        self.assertEqual(len(verifier.verify(self.test_request, expect_tag="multi")), 2)
        with self.assertRaisesRegex(InvalidSignature, "Multiple signatures found"):
            verifier.verify(self.test_request)
        tampered = copy.deepcopy(self.test_request)
        del tampered.headers["Signature"]
        tampered.headers["Signature"] = headers.get_all("Signature")[0]
        tampered.headers["Signature"] = str(Dictionary({"second": b"\x00" * 32}))
        with self.assertRaises(InvalidSignature):
            verifier.verify(tampered, expect_tag="multi")
        signer.sign(
            self.test_request, key_id="test-shared-secret", label="third", tag="multi", append_if_signature_exists=True
        )
        self.assertEqual(len(verifier.verify(self.test_request, expect_tag="multi")), 3)
        for name in ("Signature-Input", "Signature"):
            self.assertEqual(len(headers.get_all(name)), 1)
        signer.sign(self.test_request, key_id="test-shared-secret", label="single")
        self.assertEqual(verifier.verify(self.test_request)[0].label, "single")
        for name in ("Signature-Input", "Signature"):
            self.assertEqual(len(headers.get_all(name)), 1)

    def test_append_rejects_unpaired_signature_headers(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        cases = (
            {"Signature": "old=:AAAA:"},
            {"Signature-Input": 'old=("@method")'},
            {"Signature-Input": 'old=("@method")', "Signature": "other=:AAAA:"},
            {"Signature-Input": 'old=("@method"), other=("@path")', "Signature": "old=:AAAA:"},
            {"Signature-Input": 'old=("@method")', "Signature": "old=:AAAA:, other=:AAAA:"},
            {"Signature-Input": "invalid(", "Signature": "old=:AAAA:"},
        )
        for existing in cases:
            with self.subTest(existing=existing):
                headers = HTTPMessage()
                for name, value in existing.items():
                    headers[name.lower()] = value
                self.test_request.headers = headers
                before = list(headers.items())
                with self.assertRaises(HTTPMessageSignaturesException):
                    signer.sign(
                        self.test_request, key_id="test-shared-secret", label="new", append_if_signature_exists=True
                    )
                self.assertEqual(list(headers.items()), before)

        self.test_request.headers = HTTPMessage()
        for label in ("first", "second"):
            signer.sign(
                self.test_request,
                key_id="test-shared-secret",
                label=label,
                tag="append",
                append_if_signature_exists=True,
            )
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        self.assertEqual(len(verifier.verify(self.test_request, expect_tag="append")), 2)
        before = list(self.test_request.headers.items())
        with self.assertRaisesRegex(HTTPMessageSignaturesException, "already present"):
            signer.sign(self.test_request, key_id="test-shared-secret", label="first", append_if_signature_exists=True)
        self.assertEqual(list(self.test_request.headers.items()), before)

    def test_verification_error_boundary(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        timestamp = int(datetime.now().timestamp())
        set_test_signature(self.test_request, f'("@method");created={timestamp}', ['"@method": POST'])
        with self.assertRaisesRegex(InvalidSignature, 'missing a required "keyid"'):
            verifier.verify(self.test_request)
        signer.sign(self.test_request, key_id="test-shared-secret")
        for error in (KeyError("unknown key"), ValueError("invalid key")):
            with (
                self.subTest(error=error),
                patch.object(self.key_resolver, "resolve_public_key", side_effect=error),
                self.assertRaises(InvalidSignature) as caught,
            ):
                verifier.verify(self.test_request)
            self.assertIs(caught.exception.__cause__, error)
        with (
            patch.object(self.key_resolver, "resolve_public_key", return_value=None),
            self.assertRaisesRegex(InvalidSignature, "Unable to resolve verification key"),
        ):
            verifier.verify(self.test_request)
        rsa_verifier = HTTPMessageVerifier(signature_algorithm=RSA_PSS_SHA512, key_resolver=self.key_resolver)
        signer.sign(self.test_request, key_id="test-shared-secret", include_alg=False)
        with (
            patch.object(self.key_resolver, "resolve_public_key", return_value=b"invalid PEM"),
            self.assertRaises(InvalidSignature) as caught,
        ):
            rsa_verifier.verify(self.test_request)
        self.assertIsInstance(caught.exception.__cause__, ValueError)

    def test_optional_created_requires_disabling_age_limit(self):
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        params = '("@method");keyid="test-shared-secret"'
        set_test_signature(self.test_request, params, ['"@method": POST'])
        with self.assertRaisesRegex(InvalidSignature, 'missing a required "created"'):
            verifier.verify(self.test_request, max_age=None)
        verifier.require_created = False
        with self.assertRaisesRegex(InvalidSignature, 'missing a required "created"'):
            verifier.verify(self.test_request)
        verifier.verify(self.test_request, max_age=None)
        expired = int((datetime.now() - timedelta(minutes=1)).timestamp())
        set_test_signature(self.test_request, params + f";expires={expired}", ['"@method": POST'])
        with self.assertRaisesRegex(InvalidSignature, "past"):
            verifier.verify(self.test_request, max_age=None)

    def test_signature_metadata_types(self):
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        timestamp = int(datetime.now().timestamp())
        wrong_integers = (f'"{timestamp}"', f"{timestamp}.5", "?1", ":MTIz:", f"@{timestamp}")
        for name in ("created", "expires"):
            for value in wrong_integers:
                with self.subTest(name=name, value=value):
                    params = {"created": str(timestamp), "keyid": '"test-shared-secret"', name: value}
                    signature_params = '("@method")' + "".join(f";{key}={item}" for key, item in params.items())
                    set_test_signature(self.test_request, signature_params, ['"@method": POST'])
                    with self.assertRaisesRegex(InvalidSignature, f'"{name}" must be a Structured Field Integer'):
                        verifier.verify(self.test_request)
        for name, value in (
            ("keyid", "test-shared-secret"),
            ("alg", "hmac-sha256"),
            ("nonce", "7"),
            ("tag", "example"),
        ):
            with self.subTest(name=name, value=value):
                params = {"created": str(timestamp), "keyid": '"test-shared-secret"', name: value}
                signature_params = '("@method")' + "".join(f";{key}={item}" for key, item in params.items())
                set_test_signature(self.test_request, signature_params, ['"@method": POST'])
                with self.assertRaisesRegex(InvalidSignature, f'"{name}" must be a Structured Field String'):
                    verifier.verify(self.test_request)

    def test_component_names_must_be_strings(self):
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        self.test_request.headers["example"] = "value"
        self.test_request.headers["123"] = "value"
        timestamp = int(datetime.now().timestamp())
        for component in ("example", "123", '%"example"'):
            with self.subTest(component=component):
                params = f'({component});created={timestamp};keyid="test-shared-secret"'
                set_test_signature(self.test_request, params, [f"{component}: value"])
                with self.assertRaisesRegex(InvalidSignature, "Component names must be Structured Field Strings"):
                    verifier.verify(self.test_request)

    def test_signature_dictionary_member_types(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        signer.sign(self.test_request, key_id="test-shared-secret")
        for value in ('"text"', "(:AAAA:)", "?1"):
            self.test_request.headers["Signature"] = "pyhms=" + value
            with self.assertRaisesRegex(InvalidSignature, "must be a Byte Sequence"):
                verifier.verify(self.test_request)
        self.test_request.headers["Signature"] = "pyhms=:AAAA:"
        self.test_request.headers["Signature-Input"] = 'pyhms="@method"'
        with self.assertRaisesRegex(InvalidSignature, "must be an Inner List"):
            verifier.verify(self.test_request)

    def test_derived_value_character_validation(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        timestamp = int(datetime.now().timestamp())
        params = f'("@method");created={timestamp};keyid="test-shared-secret"'
        for method in ("GET\t", " GET", "GET ", "GE\x00T", "GET\x7f"):
            with self.subTest(method=method):
                self.test_request.method = method
                with self.assertRaisesRegex(HTTPMessageSignaturesException, "must be printable"):
                    signer.sign(self.test_request, key_id="test-shared-secret")
                set_test_signature(self.test_request, params, [f'"@method": {method}'])
                with self.assertRaisesRegex(InvalidSignature, "must be printable"):
                    verifier.verify(self.test_request)

    def test_covered_header_control_characters(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        timestamp = int(datetime.now().timestamp())
        controls = [codepoint for codepoint in range(32) if codepoint != 9] + [127]
        for message, component in ((self.test_request, '"example"'), (self.test_response, '"example";req')):
            params = f'({component});created={timestamp};keyid="test-shared-secret"'
            for codepoint in controls:
                with self.subTest(component=component, codepoint=codepoint):
                    value = "a" + chr(codepoint) + "b"
                    self.test_request.headers["Example"] = value
                    # Matching MACs isolate character validation from signature mismatch.
                    set_test_signature(message, params, [f"{component}: {value}"])
                    with self.assertRaisesRegex(InvalidSignature, "control|newline"):
                        verifier.verify(message)
                    with self.assertRaisesRegex(HTTPMessageSignaturesException, "control|newline"):
                        signer.sign(message, key_id="test-shared-secret", covered_component_ids=(component,))

    def test_covered_header_internal_tabs(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        created = datetime.now(timezone.utc).replace(microsecond=0)
        value = "a\t" + "".join(chr(codepoint) for codepoint in range(32, 127)) + "\tb"
        self.test_request.headers["Example"] = value
        for message, component in ((self.test_request, '"example"'), (self.test_response, '"example";req')):
            with self.subTest(component=component):
                params = f'({component});created={int(created.timestamp())};keyid="test-shared-secret"'
                set_test_signature(message, params, [f"{component}: {value}"])
                signature = message.headers["Signature"]
                self.assertEqual(verifier.verify(message)[0].covered_components[component], value)
                signer.sign(
                    message,
                    key_id="test-shared-secret",
                    created=created,
                    include_alg=False,
                    covered_component_ids=(component,),
                )
                self.assertEqual(message.headers["Signature"], signature)

    def test_signer_metadata_types_and_empty_strings(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        for kwargs in ({"nonce": 7}, {"nonce": False}, {"tag": b""}, {"key_id": 7}):
            with (
                self.subTest(kwargs=kwargs),
                self.assertRaisesRegex(HTTPMessageSignaturesException, "must be a Structured Field String"),
            ):
                signer.sign(self.test_request, **({"key_id": "test-shared-secret"} | kwargs))
        signer.sign(self.test_request, key_id="test-shared-secret", nonce="", tag="")
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        result = verifier.verify(self.test_request, expect_tag="")[0]
        self.assertEqual(result.nonce, "")
        self.assertEqual(result.parameters["tag"], "")

    def test_duplicate_signature_labels(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        signer.sign(self.test_request, key_id="test-shared-secret")
        originals = self.test_request.headers.copy()
        for name, invalid in (("Signature", "pyhms=:AAAA:"), ("Signature-Input", 'pyhms=("@status")')):
            for repeated_lines in (False, True):
                for first in (invalid, originals[name]):
                    with self.subTest(name=name, repeated_lines=repeated_lines, first=first):
                        headers = HTTPMessage() if repeated_lines else originals.copy()
                        if repeated_lines:
                            for other, value in originals.items():
                                if other != name:
                                    headers[other] = value
                            headers[name.lower()] = first
                            headers[name.upper()] = originals[name]
                        else:
                            headers[name] = first + ", " + originals[name]
                        self.test_request.headers = headers
                        with self.assertRaisesRegex(InvalidSignature, "Malformed structured header"):
                            verifier.verify(self.test_request)
                        with self.assertRaisesRegex(HTTPMessageSignaturesException, "Duplicate signature label"):
                            signer.sign(
                                self.test_request,
                                key_id="test-shared-secret",
                                label="new",
                                append_if_signature_exists=True,
                            )

    def test_duplicate_components(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        self.test_request.headers["Example-Dict"] = "a=1"
        for components in (
            ('"@status"', '"@status"'),
            ('"example-dict";req;key="a"', '"example-dict";key="a";req'),
        ):
            with self.subTest(components=components):
                with self.assertRaisesRegex(HTTPMessageSignaturesException, "appeared multiple times"):
                    signer.sign(self.test_response, key_id="test-shared-secret", covered_component_ids=components)
                signer.sign(self.test_response, key_id="test-shared-secret", covered_component_ids=components[:1])
                sig_inputs = Dictionary()
                sig_inputs.parse(self.test_response.headers["Signature-Input"].encode())
                duplicate = Item()
                duplicate.parse(components[1].encode())
                sig_inputs["pyhms"].append(duplicate)
                self.test_response.headers["Signature-Input"] = str(sig_inputs)
                with self.assertRaisesRegex(InvalidSignature, "appeared multiple times"):
                    verifier.verify(self.test_response)

    def test_distinct_component_parameters(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        self.test_request.headers["Example-Dict"] = "a=1, b=2"
        self.test_response.headers["Example-Dict"] = "a=3"
        components = ('"example-dict";req;key="a"', '"example-dict";key="b";req', '"example-dict";key="a"')
        signer.sign(self.test_response, key_id="test-shared-secret", covered_component_ids=components)
        result = verifier.verify(self.test_response)[0]
        for component, value in zip(components, ("1", "2", "3")):
            self.assertEqual(result.covered_components[component], value)
            self.assertIn(component, self.test_response.headers["Signature-Input"])

    @unittest.skipUnless(hasattr(time, "tzset"), "Requires POSIX timezone switching")
    def test_timestamps_across_dst_fallback(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        cases = (
            # UTC hours/minutes during New York's repeated local hour, November 1, 2026.
            ((6, 15), None, (5, 45), "future"),
            ((5, 15), None, (6, 45), "maximum allowable age"),
            ((5, 40), (5, 50), (6, 20), "past"),
            ((5, 45), None, (6, 15), None),
        )
        try:
            with patch.dict(os.environ, {"TZ": "America/New_York"}):
                time.tzset()
                for created, expires, now, error in cases:
                    with self.subTest(created=created, expires=expires, now=now):
                        signer.sign(
                            self.test_request,
                            key_id="test-shared-secret",
                            created=datetime(2026, 11, 1, *created, tzinfo=timezone.utc),
                            expires=datetime(2026, 11, 1, *expires, tzinfo=timezone.utc) if expires else None,
                        )
                        with patch_time(datetime(2026, 11, 1, *now, tzinfo=timezone.utc)):
                            if error:
                                with self.assertRaisesRegex(InvalidSignature, error):
                                    verifier.verify(self.test_request, max_age=timedelta(hours=1))
                            else:
                                verifier.verify(self.test_request, max_age=timedelta(hours=1))
        finally:
            time.tzset()

    def test_tolerate_clock_skew(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        signer.sign(self.test_request, key_id="test-shared-secret", created=datetime.fromtimestamp(1))
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        signer.sign(self.test_request, key_id="test-shared-secret", created=datetime.now() + timedelta(seconds=9))
        verifier.max_clock_skew = timedelta(seconds=10)
        verifier.verify(self.test_request)
        verifier.max_clock_skew = timedelta(seconds=0)
        with self.assertRaisesRegex(InvalidSignature, 'Signature "created" parameter is set to a time in the future'):
            verifier.verify(self.test_request)

    def test_has_nonce(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        nonce = "random-nonce"
        signer.sign(self.test_request, key_id="test-shared-secret", nonce=nonce)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        result = verifier.verify(self.test_request)
        self.assertEqual(result[0].nonce, nonce)

    def test_has_no_nonce(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        signer.sign(self.test_request, key_id="test-shared-secret", nonce=None)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        result = verifier.verify(self.test_request)
        self.assertEqual(result[0].nonce, None)

    def test_dictionary_member_key_parameter(self):
        # RFC 9421 section 2.1.2, the Example-Dict field and its four member components.
        self.test_request.headers["Example-Dict"] = " a=1,    b=2;x=1;y=2,   c=(a   b   c), d"
        resolver = HTTPSignatureComponentResolver(self.test_request)

        def resolve(component_id):
            node = Item()
            node.parse(component_id.encode())
            return resolver.resolve(node)

        self.assertEqual(resolve('"example-dict";key="a"'), "1")
        self.assertEqual(resolve('"example-dict";key="d"'), "?1")
        self.assertEqual(resolve('"example-dict";key="b"'), "2;x=1;y=2")
        self.assertEqual(resolve('"example-dict";key="c"'), "(a b c)")
        with self.assertRaisesRegex(HTTPMessageSignaturesException, 'has no member "e"'):
            resolve('"example-dict";key="e"')
        with self.assertRaisesRegex(HTTPMessageSignaturesException, "not a Dictionary"):
            resolve('"date";key="a"')
        for flag in ("sf", "bs", "tr"):
            with self.assertRaisesRegex(HTTPMessageSignaturesException, "not supported"):
                resolve(f'"example-dict";{flag}')
        with self.assertRaisesRegex(HTTPMessageSignaturesException, "Unknown parameter"):
            resolve('"example-dict";foo="bar"')
        for key in ("a", "1", "?1"):  # Token, Integer, Boolean: the key must be a String
            with self.assertRaisesRegex(HTTPMessageSignaturesException, "must be a string"):
                resolve(f'"example-dict";key={key}')

    def test_dictionary_member_key_and_sf_signature_fixtures(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        self.test_request.headers["Example-Dict"] = "a=1, b=2;x=1;y=2, c=(a   b    c), d"
        for message, suffix in ((self.test_request, ""), (self.test_response, ";req")):
            for key, value in (("a", "1"), ("b", "2;x=1;y=2"), ("c", "(a b c)"), ("d", "?1")):
                for parameters in (f'key="{key}";sf', f'sf;key="{key}"'):
                    component = f'"example-dict";{parameters}{suffix}'
                    with self.subTest(component=component):
                        params = f'({component});created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'
                        set_test_signature(message, params, [f"{component}: {value}"])
                        expected_signature = message.headers["Signature"]
                        result = verifier.verify(message, max_age=self.max_age)[0]
                        self.assertEqual(result.covered_components[component], value)
                        signer.sign(
                            message,
                            key_id="test-shared-secret",
                            covered_component_ids=(component,),
                            created=datetime.fromtimestamp(1618884473, timezone.utc),
                        )
                        self.assertEqual(message.headers["Signature-Input"], "pyhms=" + params)
                        self.assertEqual(message.headers["Signature"], expected_signature)
                        # Keeping the member value but dropping a signed flag must invalidate the MAC.
                        message.headers["Signature-Input"] = message.headers["Signature-Input"].replace(";sf", "")
                        with self.assertRaises(InvalidSignature):
                            verifier.verify(message, max_age=self.max_age)

    def test_dictionary_member_rejects_invalid_parameter_combinations(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        self.test_request.headers["Example-Dict"] = "b=2"
        for parameters, error in (
            ("bs", "cannot be combined"),
            ("tr", "cannot be combined"),
            ("sf;bs", "cannot be combined"),
            ("sf;tr", "cannot be combined"),
            ("sf=?0", "must be a Boolean flag"),
            ("sf=1", "must be a Boolean flag"),
            ('sf="yes"', "must be a Boolean flag"),
        ):
            with self.subTest(parameters=parameters):
                component = f'"example-dict";key="b";{parameters}'
                params = f'({component});created=1618884473;keyid="test-shared-secret"'
                set_test_signature(self.test_request, params, [f"{component}: 2"])
                with self.assertRaisesRegex(InvalidSignature, error):
                    verifier.verify(self.test_request, max_age=self.max_age)
                with self.assertRaisesRegex(HTTPMessageSignaturesException, error):
                    signer.sign(self.test_request, key_id="test-shared-secret", covered_component_ids=(component,))

    def test_dictionary_member_key_parameter_round_trip(self):
        # Section 2.1.2: a signature over one member survives a change to another member
        # and fails on a change to the covered one.
        self.test_request.headers["Example-Dict"] = "a=1, b=2;x=1;y=2, c=(a b c), d"
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        signer.sign(
            self.test_request,
            key_id="test-shared-secret",
            covered_component_ids=("@method", "@authority", '"example-dict";key="b"'),
        )
        self.assertIn('"example-dict";key="b"', self.test_request.headers["Signature-Input"])
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        result = self.verify(verifier, self.test_request)
        self.assertEqual(result[0].covered_components['"example-dict";key="b"'], "2;x=1;y=2")

        other_member_changed = copy.deepcopy(self.test_request)
        other_member_changed.headers["Example-Dict"] = "a=9, b=2;x=1;y=2, c=(x y z)"
        verifier.verify(other_member_changed, max_age=self.max_age)

        covered_member_changed = copy.deepcopy(self.test_request)
        covered_member_changed.headers["Example-Dict"] = "a=1, b=3;x=1;y=2, c=(a b c), d"
        with self.assertRaises(InvalidSignature):
            verifier.verify(covered_member_changed, max_age=self.max_age)

    def test_dictionary_display_string_serialization(self):
        # A one-digit percent escape must not consume the following literal digit.
        # Exercise every location a display string can occupy in a Dictionary member.
        templates = ("a={}", "a=1;x={}", "a=({})", "a=(1);x={}", "a=(1;x={})")
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        component = '"example-dict";key="a"'
        for template in templates:
            with self.subTest(template=template):
                field_value = template.format('%"%010"')
                self.test_request.headers["Example-Dict"] = field_value
                signer.sign(self.test_request, key_id="test-shared-secret", covered_component_ids=(component,))
                result = verifier.verify(self.test_request)[0]
                self.assertEqual(result.covered_components[component], field_value.removeprefix("a="))
                self.test_request.headers["Example-Dict"] = template.format('%"%10"')
                with self.assertRaises(InvalidSignature):
                    verifier.verify(self.test_request)

        # All control bytes, DEL, quotes, percent signs, and UTF-8 use the same
        # strict serializer, including the boundaries previously left unescaped.
        value = '%"' + "".join(f"%{byte:02x}" for byte in range(32)) + '%7f%22%25%c3%a9"'
        self.test_request.headers["Example-Dict"] = f"a={value}"
        signer.sign(self.test_request, key_id="test-shared-secret", covered_component_ids=(component,))
        self.assertEqual(verifier.verify(self.test_request)[0].covered_components[component], value)

    def test_signing_rejects_invalid_urls(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        invalid_urls = (
            "https://example.com/files/%41%",
            "https://example.com/files/%41%2",
            "https://example.com/files/%41%ZZ",
            "https://example.com/?role=%61dmin&x=%",
            "https://example.com/?role=%61dmin&x=%2",
            "https://example.com/?role=%61dmin&x=%ZZ",
            "https://example.com/a b",
            "https://example.com/?q=a b",
            "https://example.com/café",
            "https://example.com/?q=café",
            "https://example.com/a\nb",
            "https://example.com/?q=a\tb",
            "https://ex ample.com/",
            "https://user%ZZ@example.com/",
            "https://example.com/#%ZZ",
            "https://[:::]/",
            "https://example.com:abc/",
            "/resource",
        )
        headers = dict(self.test_request.headers)
        for url in invalid_urls:
            for operation in (signer.prepare, signer.sign):
                with (
                    self.subTest(url=url, operation=operation.__name__),
                    patch.object(
                        self.key_resolver, "resolve_private_key", side_effect=AssertionError("local key read")
                    ),
                    self.assertRaisesRegex(HTTPMessageSignaturesException, "Invalid URL"),
                ):
                    self.test_request.url = url
                    operation(self.test_request, key_id="test-shared-secret")
                self.assertEqual(dict(self.test_request.headers), headers)

    def test_verification_rejects_url_repair_collisions(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        cases = (
            (
                "https://example.com/files/%2541%25ZZ",
                "https://example.com/files/%41%ZZ",
                (("@method", "@authority", "@target-uri"), ("@path",), ("@request-target",)),
            ),
            (
                "https://example.com/?role=%2561dmin&x=%25ZZ",
                "https://example.com/?role=%61dmin&x=%ZZ",
                (("@method", "@authority", "@target-uri"), ("@query",), ('"@query-param";name="role"',)),
            ),
        )
        for original, changed, component_lists in cases:
            for components in component_lists:
                for message, suffix in ((self.test_request, ""), (self.test_response, ";req")):
                    with self.subTest(url=changed, components=components, suffix=suffix):
                        covered = tuple(
                            (component if component.startswith('"') else f'"{component}"') + suffix
                            for component in components
                        )
                        self.test_request.url = original
                        signer.sign(message, key_id="test-shared-secret", covered_component_ids=covered)
                        verifier.verify(message)
                        self.test_request.url = changed
                        with self.assertRaisesRegex(InvalidSignature, "Invalid URL"):
                            verifier.verify(message)

    def test_apply_rejects_url_repair_collisions(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256)
        for original, changed in (
            ("https://example.com/files/%2541%25ZZ", "https://example.com/files/%41%ZZ"),
            ("https://example.com/?role=%2561dmin&x=%25ZZ", "https://example.com/?role=%61dmin&x=%ZZ"),
        ):
            for message, component in ((self.test_request, "@target-uri"), (self.test_response, '"@target-uri";req')):
                with self.subTest(url=changed, component=component):
                    self.test_request.url = original
                    prepared = signer.prepare(message, key_id="test-shared-secret", covered_component_ids=(component,))
                    signature = HMAC_SHA256(shared_secret=test_shared_secret).sign(prepared.signature_base)
                    signer.apply(message, prepared, signature)
                    headers = dict(message.headers)
                    self.test_request.url = changed
                    for append in (False, True):
                        with self.assertRaisesRegex(HTTPMessageSignaturesException, "Invalid URL"):
                            signer.apply(message, prepared, signature, append_if_signature_exists=append)
                        self.assertEqual(dict(message.headers), headers)

    def test_encoded_urls_preserve_signature_components(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        for url, target in (
            (
                "https://example.com/files/%2541%25ZZ?role=%2561dmin&x=%25ZZ",
                "https://example.com/files/%2541%25ZZ?role=%2561dmin&x=%25ZZ",
            ),
            (
                "https://example.com/a%2fb/../caf%C3%A9?q=%20%2f%FF&plus=+",
                "https://example.com/a%2fb/../caf%C3%A9?q=%20%2f%FF&plus=+",
            ),
            ("https://example.com/resource?", "https://example.com/resource?"),
            ("https://user:pass@[2001:DB8::1]:443/resource?#fragment", "https://[2001:DB8::1]:443/resource?"),
        ):
            with self.subTest(url=url):
                self.test_request.url = url
                resolver = HTTPSignatureComponentResolver(self.test_request)
                self.assertEqual(resolver.get_target_uri(), target)
                signer.sign(self.test_request, key_id="test-shared-secret")
                verifier.verify(self.test_request)

    def test_url_formatting_is_specific_to_each_signature_component(self):
        self.test_request.url = "HTTPS://user:p%40ss@EXAMPLE.com:00443/a%2fb/../c?q=%2f#fragment"
        covered = (
            ("@scheme", "https"),
            ("@authority", "example.com"),
            ("@target-uri", "HTTPS://EXAMPLE.com:00443/a%2fb/../c?q=%2f"),
            ("@request-target", "/a%2fb/../c?q=%2f"),
            ("@path", "/a%2fb/../c"),
            ("@query", "?q=%2f"),
        )
        created = datetime.now(timezone.utc).replace(microsecond=0)
        components = " ".join(f'"{name}"' for name, value in covered)
        params = f'({components});created={int(created.timestamp())};keyid="test-shared-secret"'
        set_test_signature(self.test_request, params, [f'"{name}": {value}' for name, value in covered])
        expected_signature = self.test_request.headers["Signature"]
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        result = verifier.verify(self.test_request)[0]
        for name, value in covered:
            self.assertEqual(result.covered_components[f'"{name}"'], value)
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        signer.sign(
            self.test_request,
            key_id="test-shared-secret",
            covered_component_ids=tuple(name for name, value in covered),
            created=created,
            include_alg=False,
        )
        self.assertEqual(self.test_request.headers["Signature"], expected_signature)

    def test_empty_port_and_zero_padded_ports(self):
        for port, authority in (
            ("", "example.com"),
            ("00443", "example.com"),
            ("00000", "example.com:00000"),
            ("08443", "example.com:08443"),
            ("0" * 10_000 + "443", "example.com"),
        ):
            with self.subTest(port=port[:20]):
                self.test_request.url = f"https://example.com:{port}/?"
                resolver = HTTPSignatureComponentResolver(self.test_request)
                self.assertEqual(resolver.get_authority(), authority)
                self.assertEqual(resolver.get_target_uri(), self.test_request.url)
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        self.test_request.url = "https://example.com:/"
        signer.sign(self.test_request, key_id="test-shared-secret")
        self.test_request.url = "https://example.com/"
        with self.assertRaises(InvalidSignature):
            verifier.verify(self.test_request)

    def test_response_uses_the_associated_request_url(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        del self.test_response.url
        signer.sign(
            self.test_response, key_id="test-shared-secret", covered_component_ids=("@status", '"@target-uri";req')
        )
        result = verifier.verify(self.test_response)[0]
        self.assertEqual(result.covered_components['"@target-uri";req'], self.test_request.url)
        self.test_response.url = "https://unrelated.example/%ZZ"
        verifier.verify(self.test_response)
        self.test_request.url = "https://example.com/%ZZ"
        with self.assertRaisesRegex(InvalidSignature, "Invalid URL"):
            verifier.verify(self.test_response)

    def test_url_component_canonicalization(self):
        cases = (
            ("https://EXAMPLE.com:443", "example.com", "/", "/", "https://EXAMPLE.com:443/"),
            ("http://example.com:80/a", "example.com", "/a", "/a", "http://example.com:80/a"),
            ("https://[2001:DB8::1]:443/a?", "[2001:db8::1]", "/a", "/a?", "https://[2001:DB8::1]:443/a?"),
            (
                "https://user:pass@example.com:8443/a#fragment",
                "example.com:8443",
                "/a",
                "/a",
                "https://example.com:8443/a",
            ),
            (
                "https://example.com/a%2fb/../c?q=%2f",
                "example.com",
                "/a%2fb/../c",
                "/a%2fb/../c?q=%2f",
                "https://example.com/a%2fb/../c?q=%2f",
            ),
        )
        for url, authority, path, target, target_url in cases:
            with self.subTest(url=url):
                self.test_request.url = url
                resolver = HTTPSignatureComponentResolver(self.test_request)
                self.assertEqual(resolver.get_authority(), authority)
                self.assertEqual(resolver.get_path(), path)
                self.assertEqual(resolver.get_request_target(), target)
                self.assertEqual(resolver.get_target_uri(), target_url)

    def test_options_target_uri_preserves_empty_path(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        created = datetime.now(timezone.utc).replace(microsecond=0)
        params = f'("@method" "@authority" "@target-uri");created={int(created.timestamp())};keyid="test-shared-secret"'
        self.test_request.method = "OPTIONS"
        # RFC 9112 section 3.3: asterisk-form has an empty target-URI path.
        for url, authority in (("https://example.com", "example.com"), ("http://example.com:8080", "example.com:8080")):
            for target in (None, "*", url):
                with self.subTest(url=url, target=target):
                    self.test_request.url = url
                    if target is not None:
                        self.test_request.request_target = target
                    elif hasattr(self.test_request, "request_target"):
                        del self.test_request.request_target
                    set_test_signature(
                        self.test_request,
                        params,
                        ['"@method": OPTIONS', f'"@authority": {authority}', f'"@target-uri": {url}'],
                    )
                    signature = self.test_request.headers["Signature"]
                    self.assertEqual(verifier.verify(self.test_request)[0].covered_components['"@target-uri"'], url)
                    signer.sign(self.test_request, key_id="test-shared-secret", created=created, include_alg=False)
                    self.assertEqual(self.test_request.headers["Signature"], signature)
                    self.assertEqual(HTTPSignatureComponentResolver(self.test_request).get_path(), "/")

    def test_options_signature_cannot_move_between_server_and_root(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        self.test_request.method = "OPTIONS"
        for message, suffix in ((self.test_request, ""), (self.test_response, ";req")):
            for original, changed in (("", "/"), ("/", "")):
                with self.subTest(suffix=suffix, original=original):
                    self.test_request.url = "https://example.com" + original
                    self.test_request.request_target = original or "*"
                    components = tuple(f'"{name}"{suffix}' for name in ("@method", "@authority", "@target-uri"))
                    signer.sign(message, key_id="test-shared-secret", covered_component_ids=components)
                    verifier.verify(message)
                    self.test_request.url = "https://example.com" + changed
                    self.test_request.request_target = changed or "*"
                    with self.assertRaises(InvalidSignature):
                        verifier.verify(message)

    def test_request_target_forms_and_empty_query(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        self.test_request.url = "https://example.com/resource"
        signer.sign(self.test_request, key_id="test-shared-secret", covered_component_ids=("@request-target",))
        self.test_request.url += "?"
        with self.assertRaises(InvalidSignature):
            verifier.verify(self.test_request)
        for method, target in (
            ("GET", "/resource?"),
            ("GET", "https://example.com/resource?"),
            ("CONNECT", "example.com:443"),
            ("OPTIONS", "*"),
        ):
            with self.subTest(target=target):
                self.test_request.method = method
                self.test_request.request_target = target
                signer.sign(self.test_request, key_id="test-shared-secret", covered_component_ids=("@request-target",))
                result = verifier.verify(self.test_request)[0]
                self.assertEqual(result.covered_components['"@request-target"'], target)
                self.test_request.request_target += "x"
                with self.assertRaises(InvalidSignature):
                    verifier.verify(self.test_request)
        del self.test_request.request_target
        self.test_request.method = "CONNECT"
        self.test_request.url = "https://example.com:443"
        self.assertEqual(HTTPSignatureComponentResolver(self.test_request).get_request_target(), "example.com:443")

    def test_target_uri_omits_client_only_components(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        self.test_request.url = "https://user:pass@example.com/resource?#fragment"
        signer.sign(self.test_request, key_id="test-shared-secret")
        self.test_request.url = "https://example.com/resource?"
        verifier.verify(self.test_request)
        self.test_request.url = "https://example.com/resource"
        with self.assertRaises(InvalidSignature):
            verifier.verify(self.test_request)

    def test_response_requires_req_for_request_components(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        signer.sign(self.test_request, key_id="test-shared-secret")
        self.test_response.url = self.test_request.url
        self.test_response.headers = self.test_request.headers.copy()
        with self.assertRaisesRegex(InvalidSignature, 'requires "req"'):
            verifier.verify(self.test_response)

        components = (
            "@method",
            "@target-uri",
            "@authority",
            "@scheme",
            "@request-target",
            "@path",
            "@query",
            '"@query-param";name="Pet"',
        )
        for component in components:
            with self.subTest(component=component):
                with self.assertRaisesRegex(HTTPMessageSignaturesException, 'requires "req"'):
                    signer.sign(self.test_response, key_id="test-shared-secret", covered_component_ids=(component,))
                qualified = component if component.startswith('"') else f'"{component}"'
                signer.sign(
                    self.test_response,
                    key_id="test-shared-secret",
                    covered_component_ids=("@status", qualified + ";req"),
                )
                verifier.verify(self.test_response)

    def test_req_parameter_binds_request_components_to_a_response(self):
        # RFC 9421 section 2.4: "@authority";req in a response signature is the request's authority.
        resolver = HTTPSignatureComponentResolver(self.test_response)
        node = Item()
        node.parse(b'"@authority";req')
        self.assertEqual(resolver.resolve(node), "example.com")
        node.parse(b'"content-digest";req')
        self.assertEqual(resolver.resolve(node), self.test_request.headers["Content-Digest"])
        self.test_request.headers["Example-Dict"] = "a=1, b=2;x=1;y=2"
        node.parse(b'"example-dict";req;key="b"')  # section 2.4: req combines with key
        self.assertEqual(resolver.resolve(node), "2;x=1;y=2")
        node.parse(b'"@query-param";name="Pet";req')
        self.assertEqual(resolver.resolve(node), "dog")
        with self.assertRaisesRegex(HTTPMessageSignaturesException, "only valid in a response signature"):
            HTTPSignatureComponentResolver(self.test_request).resolve(node)
        node.parse(b'"@authority";req=?0')
        with self.assertRaisesRegex(HTTPMessageSignaturesException, "must be a Boolean flag"):
            resolver.resolve(node)

        signer = HTTPMessageSigner(signature_algorithm=ED25519, key_resolver=self.key_resolver)
        signer.sign(
            self.test_response,
            key_id="test-key-ed25519",
            covered_component_ids=("@status", '"@authority";req', "content-digest"),
        )
        verifier = HTTPMessageVerifier(signature_algorithm=ED25519, key_resolver=self.key_resolver)
        result = self.verify(verifier, self.test_response)
        self.assertEqual(result[0].covered_components['"@authority";req'], "example.com")


if __name__ == "__main__":
    unittest.main()
