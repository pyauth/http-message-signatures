#!/usr/bin/env python

import base64
import copy
import io
import json
import os
import sys
import time
import unittest
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.client import HTTPMessage
from typing import ClassVar
from unittest.mock import patch
from urllib.parse import urlencode

import requests
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from http_sf.compat import Dictionary, Item

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from http_message_signatures import (  # noqa
    HTTPMessageSigner,
    HTTPMessageVerifier,
    HTTPSignatureComponentResolver,
    HTTPSignatureKeyResolver,
    InvalidSignature,
    HTTPMessageSignaturesException,
)
from http_message_signatures.algorithms import (
    ECDSA_P256_SHA256,
    ED25519,
    HMAC_SHA256,
    RSA_PSS_SHA512,
    RSA_V1_5_SHA256,
)

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
            covered_component_ids=("@authority", "content-digest"),
            created=datetime.fromtimestamp(1618884473),
            label="sig-b22",
            include_alg=False,
        )
        self.assertEqual(
            self.test_request.headers["Signature-Input"],
            'sig-b22=("@authority" "content-digest");created=1618884473;keyid="test-key-rsa-pss"',
        )
        verifier = HTTPMessageVerifier(signature_algorithm=RSA_PSS_SHA512, key_resolver=self.key_resolver)
        self.verify(verifier, self.test_request)  # Non-deterministic signing algorithm
        self.test_request.headers["Signature"] = (
            "sig-b22=:Fee1uy9YGZq5UUwwYU6vz4dZNvfw3GYrFl1L6YlVIyUMuWs"
            "wWDNSvql4dVtSeidYjYZUm7SBCENIb5KYy2ByoC3bI+7gydd2i4OAT5lyDtmeapnA"
            "a8uP/b9xUpg+VSPElbBs6JWBIQsd+nMdHDe+ls/IwVMwXktC37SqsnbNyhNp6kcvc"
            "WpevjzFcD2VqdZleUz4jN7P+W5A3wHiMGfIjIWn36KXNB+RKyrlGnIS8yaBBrom5r"
            "cZWLrLbtg6VlrH1+/07RV+kgTh/l10h8qgpl9zQHu7mWbDKTq0tJ8K4ywcPoC4s2I"
            "4rU88jzDKDGdTTQFZoTVZxZmuTM1FvHfzIw==:"
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

    def test_query_parameters(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        signer.sign(
            self.test_request,
            key_id="test-shared-secret",
            covered_component_ids=("date", "@authority", "content-type", '"@query-params";name="Pet"'),
            created=datetime.fromtimestamp(1618884473),
        )
        self.assertEqual(
            self.test_request.headers["Signature-Input"],
            (
                'pyhms=("date" "@authority" "content-type" "@query-params";name="Pet");'
                'created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'
            ),
        )
        self.assertEqual(self.test_request.headers["Signature"], "pyhms=:LOYhEJpBn34v3KohQBFl5qSy93haFd3+Ka9wwOmKeN0=:")
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        self.verify(verifier, self.test_request)

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
                self.assertEqual(resolver.get_query_params(name=name), expected)

    def test_query_parameter_newline_collision(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        for message, suffix in ((self.test_request, ""), (self.test_response, ";req")):
            with self.subTest(suffix=suffix):
                components = (f'"@query-params";name="a"{suffix}', f'"@query-params";name="b"{suffix}')
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

    def test_uri_component_canonicalization(self):
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
        for url, authority, path, target, uri in cases:
            with self.subTest(url=url):
                self.test_request.url = url
                resolver = HTTPSignatureComponentResolver(self.test_request)
                self.assertEqual(resolver.get_authority(), authority)
                self.assertEqual(resolver.get_path(), path)
                self.assertEqual(resolver.get_request_target(), target)
                self.assertEqual(resolver.get_target_uri(), uri)

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
            '"@query-params";name="Pet"',
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
        node.parse(b'"@query-params";name="Pet";req')
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
