#!/usr/bin/env python

import os, sys, unittest, io, base64, json

from datetime import datetime, timedelta

import requests
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from http_message_signatures import (HTTPSignatureComponentResolver, HTTPSignatureKeyResolver,  # noqa
                                     HTTPMessageSigner, HTTPMessageVerifier, InvalidSignature)
from http_message_signatures.algorithms import HMAC_SHA256, ED25519, ECDSA_P256_SHA256, RSA_PSS_SHA512  # noqa

test_shared_secret = base64.b64decode("uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasj"
                                      "lTMtDQ==")


class MyHTTPSignatureKeyResolver(HTTPSignatureKeyResolver):
    known_pem_keys = {"test-key-rsa-pss", "test-key-ecc-p256", "test-key-ed25519"}

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
        request = requests.Request('POST', 'https://example.com/foo?param=Value&Pet=dog', json={"hello": "world"})
        self.test_request = request.prepare()
        self.test_request.headers["Date"] = "Tue, 20 Apr 2021 02:07:55 GMT"
        self.test_request.headers["Content-Digest"] = ("sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+"
                                                       "AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:")
        self.test_response = requests.Response()
        self.test_response.request = self.test_request
        self.test_response.status_code = 200
        self.test_response.headers = {
            "Date": "Tue, 20 Apr 2021 02:07:56 GMT",
            "Content-Type": "application/json",
            "Content-Digest": ("sha-512=:JlEy2bfUz7WrWIjc1qV6KVLpdr/7L5/L4h7Sxvh6sNHpDQWDCL+"
                               "GauFQWcZBvVDhiyOnAQsxzZFYwi0wDH+1pw==:"),
            "Content-Length": "23"
        }
        self.test_response.raw = io.BytesIO(json.dumps({"message": "good dog"}).encode())
        self.key_resolver = MyHTTPSignatureKeyResolver()
        self.max_age = timedelta(weeks=90000)

    def test_http_message_signatures_B21(self):
        self.test_request.headers["Signature-Input"] = ('sig-b21=();created=1618884473;keyid="test-key-rsa-pss";'
                                                        'nonce="b3k2pp5k7z-50gnwp.yemd"')
        self.test_request.headers["Signature"] = ('sig-b21=:d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopem'
                                                  'LJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG'
                                                  '52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx'
                                                  '2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6'
                                                  'UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3'
                                                  '+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==:')
        verifier = HTTPMessageVerifier(signature_algorithm=RSA_PSS_SHA512, key_resolver=self.key_resolver)
        verifier.verify(self.test_request, max_age=self.max_age)

    def test_http_message_signatures_B22(self):
        self.test_request.headers["Signature-Input"] = ('sig-b22=("@authority" "content-digest");'
                                                        'created=1618884473;keyid="test-key-rsa-pss"')
        self.test_request.headers["Signature"] = ('sig-b22=:Fee1uy9YGZq5UUwwYU6vz4dZNvfw3GYrFl1L6YlVIyUMuWs'
                                                  'wWDNSvql4dVtSeidYjYZUm7SBCENIb5KYy2ByoC3bI+7gydd2i4OAT5lyDtmeapnA'
                                                  'a8uP/b9xUpg+VSPElbBs6JWBIQsd+nMdHDe+ls/IwVMwXktC37SqsnbNyhNp6kcvc'
                                                  'WpevjzFcD2VqdZleUz4jN7P+W5A3wHiMGfIjIWn36KXNB+RKyrlGnIS8yaBBrom5r'
                                                  'cZWLrLbtg6VlrH1+/07RV+kgTh/l10h8qgpl9zQHu7mWbDKTq0tJ8K4ywcPoC4s2I'
                                                  '4rU88jzDKDGdTTQFZoTVZxZmuTM1FvHfzIw==:')
        verifier = HTTPMessageVerifier(signature_algorithm=RSA_PSS_SHA512, key_resolver=self.key_resolver)
        verifier.verify(self.test_request, max_age=self.max_age)

    def test_http_message_signatures_B23(self):
        self.test_request.headers["Signature-Input"] = ('sig-b23=("date" "@method" "@path" "@query" "@authority" '
                                                        '"content-type" "content-digest" "content-length");'
                                                        'created=1618884473;keyid="test-key-rsa-pss"')
        self.test_request.headers["Signature"] = ('sig-b23=:bbN8oArOxYoyylQQUU6QYwrTuaxLwjAC9fbY2F6SVWvh0yB'
                                                  'iMIRGOnMYwZ/5MR6fb0Kh1rIRASVxFkeGt683+qRpRRU5p2voTp768ZrCUb38K0fU'
                                                  'xN0O0iC59DzYx8DFll5GmydPxSmme9v6ULbMFkl+V5B1TP/yPViV7KsLNmvKiLJH1'
                                                  'pFkh/aYA2HXXZzNBXmIkoQoLd7YfW91kE9o/CCoC1xMy7JA1ipwvKvfrs65ldmlu9'
                                                  'bpG6A9BmzhuzF8Eim5f8ui9eH8LZH896+QIF61ka39VBrohr9iyMUJpvRX2Zbhl5Z'
                                                  'JzSRxpJyoEZAFL2FUo5fTIztsDZKEgM4cUA==:')
        verifier = HTTPMessageVerifier(signature_algorithm=RSA_PSS_SHA512, key_resolver=self.key_resolver)
        verifier.verify(self.test_request, max_age=self.max_age)

    def test_http_message_signatures_B24(self):
        signer = HTTPMessageSigner(signature_algorithm=ECDSA_P256_SHA256, key_resolver=self.key_resolver)
        signer.sign(self.test_response,
                    key_id="test-key-ecc-p256",
                    covered_component_ids=("@status", "content-type", "content-digest", "content-length"),
                    created=datetime.fromtimestamp(1618884473),
                    label="sig-b24",
                    include_alg=False)
        self.assertEqual(self.test_response.headers["Signature-Input"],
                         ('sig-b24=("@status" "content-type" "content-digest" "content-length");'
                          'created=1618884473;keyid="test-key-ecc-p256"'))
        # Non-deterministic signing algorithm
        self.assertTrue(self.test_response.headers["Signature"].startswith('sig-b24='))
        verifier = HTTPMessageVerifier(signature_algorithm=ECDSA_P256_SHA256, key_resolver=self.key_resolver)
        verifier.verify(self.test_response, max_age=self.max_age)
        self.test_response.headers["Signature"] = ("sig-b24=:0Ry6HsvzS5VmA6HlfBYS/fYYeNs7fYuA7s0tAdxfUlPGv0CSVuwrrzBOjc"
                                                   "CFHTxVRJ01wjvSzM2BetJauj8dsw==:")
        verifier.verify(self.test_response, max_age=self.max_age)

    def test_http_message_signatures_B25(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        signer.sign(self.test_request,
                    key_id="test-shared-secret",
                    covered_component_ids=("date", "@authority", "content-type"),
                    created=datetime.fromtimestamp(1618884473),
                    label="sig-b25",
                    include_alg=False)
        self.assertEqual(self.test_request.headers["Signature-Input"],
                         'sig-b25=("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"')
        self.assertEqual(self.test_request.headers["Signature"],
                         'sig-b25=:pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=:')
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        verifier.verify(self.test_request, max_age=self.max_age)

    def test_http_message_signatures_B26(self):
        signer = HTTPMessageSigner(signature_algorithm=ED25519, key_resolver=self.key_resolver)
        signer.sign(self.test_request,
                    key_id="test-key-ed25519",
                    covered_component_ids=("date", "@method", "@path", "@authority", "content-type", "content-length"),
                    created=datetime.fromtimestamp(1618884473),
                    label="sig-b26",
                    include_alg=False)
        self.assertEqual(self.test_request.headers["Signature-Input"],
                         ('sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");'
                          'created=1618884473;keyid="test-key-ed25519"'))
        signature = 'sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:'
        self.assertEqual(self.test_request.headers["Signature"], signature)
        verifier = HTTPMessageVerifier(signature_algorithm=ED25519, key_resolver=self.key_resolver)
        result = verifier.verify(self.test_request, max_age=self.max_age)[0]

        self.assertEqual(result.parameters["keyid"], "test-key-ed25519")
        self.assertIn("created", result.parameters)
        self.assertEqual(result.label, "sig-b26")

        self.test_request.headers["Signature"] = 'sig-b26=:pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=:'
        with self.assertRaises(InvalidSignature):
            verifier.verify(self.test_request, max_age=self.max_age)
        self.test_request.headers["Signature"] = signature[::-1]
        with self.assertRaises(InvalidSignature):
            verifier.verify(self.test_request, max_age=self.max_age)

    def test_query_parameters(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        signer.sign(self.test_request,
                    key_id="test-shared-secret",
                    covered_component_ids=("date", "@authority", "content-type", '"@query-params";name="Pet"'),
                    created=datetime.fromtimestamp(1618884473))
        self.assertEqual(self.test_request.headers["Signature-Input"],
                         ('pyhms=("date" "@authority" "content-type" "@query-params";name="Pet");'
                          'created=1618884473;keyid="test-shared-secret";alg="hmac-sha256"'))
        self.assertEqual(self.test_request.headers["Signature"],
                         'pyhms=:LOYhEJpBn34v3KohQBFl5qSy93haFd3+Ka9wwOmKeN0=:')
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        verifier.verify(self.test_request, max_age=self.max_age)

    def test_created_expires(self):
        signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        signer.sign(self.test_request, key_id="test-shared-secret", created=datetime.fromtimestamp(1))
        verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=self.key_resolver)
        verifier.verify(self.test_request, max_age=self.max_age)
        with self.assertRaisesRegex(InvalidSignature, "Signature age exceeds maximum allowable age"):
            verifier.verify(self.test_request)
        signer.sign(self.test_request, key_id="test-shared-secret", created=datetime.now() + self.max_age)
        with self.assertRaisesRegex(InvalidSignature, 'Signature "created" parameter is set to a time in the future'):
            verifier.verify(self.test_request)
        signer.sign(self.test_request, key_id="test-shared-secret", expires=datetime.fromtimestamp(1))
        with self.assertRaisesRegex(InvalidSignature, 'Signature "expires" parameter is set to a time in the past'):
            verifier.verify(self.test_request)


if __name__ == '__main__':
    unittest.main()
