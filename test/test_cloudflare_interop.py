"""Interoperability with Cloudflare's published Web Bot Auth fixtures."""

import json
import unittest
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import requests
from http_sf.compat import Dictionary

from http_message_signatures import HTTPMessageSigner, HTTPMessageVerifier, InvalidSignature, MappingKeyResolver
from http_message_signatures.algorithms import ED25519, RSA_PSS_SHA512

_TEST_DIR = Path(__file__).parent
_FIXTURE_DIR = _TEST_DIR / "fixtures" / "cloudflare-web-bot-auth"
_ALGORITHMS = {
    "ed25519": (ED25519, "test-key-ed25519"),
    "rsa-pss-sha512": (RSA_PSS_SHA512, "test-key-rsa-pss"),
}


def _load_vectors(filename):
    return json.loads((_FIXTURE_DIR / filename).read_text(encoding="utf-8"))


def _request_vectors():
    for version in (1, 2):
        filename = f"web_bot_auth_architecture_v{version}.json"
        for vector in _load_vectors(filename):
            yield filename, vector


@contextmanager
def _at_time(timestamp):
    instant = datetime.fromtimestamp(timestamp, tz=timezone.utc)

    class _DateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return instant.astimezone(tz) if tz is not None else instant.astimezone().replace(tzinfo=None)

    with patch("http_message_signatures.signatures.datetime.datetime", _DateTime):
        yield


def _handlers(signature_input, label=None):
    parsed = Dictionary()
    parsed.parse(signature_input.encode("ascii"))
    if label is None:
        label = next(iter(parsed))
    node = parsed[label]
    algorithm, key_name = _ALGORITHMS[node.params["alg"]]
    key_id = node.params["keyid"]
    # Cloudflare uses the RFC 9421 keys already present in this test suite.
    keys = MappingKeyResolver(
        public_keys={key_id: (_TEST_DIR / f"{key_name}.pem").read_bytes()},
        private_keys={key_id: (_TEST_DIR / f"{key_name}.key").read_bytes()},
    )
    signer = HTTPMessageSigner(signature_algorithm=algorithm, key_resolver=keys)
    verifier = HTTPMessageVerifier(signature_algorithm=algorithm, key_resolver=keys)
    options = {
        "key_id": key_id,
        "label": label,
        "created": datetime.fromtimestamp(node.params["created"], tz=timezone.utc),
        "expires": datetime.fromtimestamp(node.params["expires"], tz=timezone.utc),
        "nonce": node.params.get("nonce"),
        "tag": node.params["tag"],
        "covered_component_ids": tuple(str(component) for component in node),
    }
    return signer, verifier, options


def _request(vector):
    headers = {"Signature-Input": vector["signature_input"], "Signature": vector["signature"]}
    if "signature_agent" in vector:
        headers["Signature-Agent"] = vector["signature_agent"]
    return requests.Request("GET", vector["target_url"], headers=headers).prepare()


class _TestCloudflareInterop(unittest.TestCase):
    def test_verify_published_requests(self):
        for filename, vector in _request_vectors():
            with self.subTest(file=filename, label=vector["label"], key=vector["key"]["kid"]):
                request = _request(vector)
                _, verifier, options = _handlers(vector["signature_input"], vector["label"])
                with _at_time(vector["created_ms"] / 1000):
                    results = verifier.verify(request, expect_tag="web-bot-auth")
                    self.assertEqual(len(results), 1)
                    self.assertEqual(results[0].label, vector["label"])
                    self.assertEqual(results[0].parameters["keyid"], options["key_id"])
                    self.assertEqual(results[0].covered_components['"@authority"'], "example.com")

                    request.url = "https://changed.example/path/to/resource"
                    with self.assertRaises(InvalidSignature):
                        verifier.verify(request, expect_tag="web-bot-auth")

    def test_sign_requests(self):
        for filename, vector in _request_vectors():
            with self.subTest(file=filename, label=vector["label"], key=vector["key"]["kid"]):
                request = _request(vector)
                del request.headers["Signature"]
                del request.headers["Signature-Input"]
                signer, verifier, options = _handlers(vector["signature_input"], vector["label"])
                signer.sign(request, **options)
                self.assertEqual(request.headers["Signature-Input"], vector["signature_input"])
                if signer.signature_algorithm is ED25519:
                    self.assertEqual(request.headers["Signature"], vector["signature"])
                # RSA-PSS is randomized; compare its inputs and verify the output.
                with _at_time(vector["created_ms"] / 1000):
                    verifier.verify(request, expect_tag="web-bot-auth")

    def test_directory_response(self):
        for vector in _load_vectors("web_bot_auth_directory_response_v1.json"):
            with self.subTest(name=vector["name"]):
                request = vector["request"]
                response = requests.Response()
                response.request = requests.Request(
                    request["method"], request["target_url"], headers=request["headers"]
                ).prepare()
                response.status_code = vector["response"]["status"]
                response.headers.update(vector["response"]["headers"])
                body = vector["response"]["body"].encode("utf-8")
                signature_input = response.headers["Signature-Input"]
                signer, verifier, options = _handlers(signature_input)
                with _at_time(options["created"].timestamp()):
                    results = verifier.verify(response, expect_tag="http-message-signatures-directory", body=body)
                    self.assertEqual(len(results), 1)
                    result = results[0]
                    self.assertEqual(result.label, options["label"])
                    self.assertEqual(result.body, body)
                    self.assertEqual(
                        "\n".join(f"{key}: {value}" for key, value in result.covered_components.items()),
                        vector["signature_base"],
                    )
                    with self.assertRaises(InvalidSignature):
                        verifier.verify(response, body=body + b" ")
                    original_url = response.request.url
                    response.request.url = "https://changed.example/.well-known/http-message-signatures-directory"
                    with self.assertRaises(InvalidSignature):
                        verifier.verify(response, body=body)
                    response.request.url = original_url

                prepared = signer.prepare(response, body=body, use_existing_digest=True, **options)
                self.assertEqual(prepared.signature_base, vector["signature_base"].encode("utf-8"))
                signer.sign(response, body=body, use_existing_digest=True, **options)
                self.assertEqual(response.headers["Signature-Input"], signature_input)
                self.assertEqual(response.headers["Signature"], vector["response"]["headers"]["Signature"])
