#!/usr/bin/env python

import base64
import hashlib
import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
from cryptography.exceptions import InvalidSignature as CryptographyInvalidSignature
from cryptography.hazmat.primitives.asymmetric.mldsa import (
    MLDSA44PrivateKey,
    MLDSA44PublicKey,
    MLDSA65PrivateKey,
    MLDSA65PublicKey,
    MLDSA87PrivateKey,
    MLDSA87PublicKey,
)
from http_sf.compat import Dictionary

from http_message_signatures import (
    HTTPMessageSignaturesException,
    HTTPMessageSigner,
    HTTPMessageVerifier,
    HTTPSignatureKeyResolver,
    InvalidSignature,
)
from http_message_signatures.algorithms import ML_DSA_44, ML_DSA_65, ML_DSA_87

ALGORITHMS = {
    "ml-dsa-44": (ML_DSA_44, MLDSA44PrivateKey),
    "ml-dsa-65": (ML_DSA_65, MLDSA65PrivateKey),
    "ml-dsa-87": (ML_DSA_87, MLDSA87PrivateKey),
}

PUBLIC_KEY_CLASSES = {
    "ml-dsa-44": MLDSA44PublicKey,
    "ml-dsa-65": MLDSA65PublicKey,
    "ml-dsa-87": MLDSA87PublicKey,
}

TEST_DIR = Path(__file__).parent
TEST_VECTORS_PATH = TEST_DIR / "test-vectors-mldsa.json"


class VectorKeyResolver(HTTPSignatureKeyResolver):
    def __init__(self, private_key):
        self.private_key = private_key

    def resolve_public_key(self, key_id: str):
        return self.private_key.public_key()

    def resolve_private_key(self, key_id: str):
        return self.private_key


class TestMLDSAConformanceVectors(unittest.TestCase):
    def setUp(self):
        with open(TEST_VECTORS_PATH) as fh:
            self.vectors = json.load(fh)["vectors"]
        self.max_age = timedelta(weeks=90000)

    def test_vectors_cover_all_algorithms(self):
        self.assertEqual(sorted(v["algorithm"] for v in self.vectors), sorted(ALGORITHMS))

    def test_conformance_vectors(self):
        for vector in self.vectors:
            with self.subTest(vector=vector["id"]):
                algorithm, private_key_class = ALGORITHMS[vector["algorithm"]]
                private_key = private_key_class.from_seed_bytes(bytes.fromhex(vector["private_key_seed_hex"]))
                self.assertEqual(
                    private_key.public_key().public_bytes_raw(),
                    base64.b64decode(vector["public_key_base64"]),
                )
                expected_base = base64.b64decode(vector["signature_base_base64"])
                self.assertEqual(len(expected_base), vector["signature_base_length"])
                self.assertEqual(
                    hashlib.sha256(expected_base).hexdigest(),
                    vector["signature_base_sha256"],
                )
                field_name, _, signature_input = vector["serialized_signature_input"].partition(": ")
                self.assertEqual(field_name, "Signature-Input")
                label, _, params = signature_input.partition("=")
                sig_inputs = Dictionary()
                sig_inputs.parse(signature_input.encode())
                key_id = sig_inputs[label].params["keyid"]
                created = sig_inputs[label].params["created"]
                covered = dict(line.split(": ", 1) for line in expected_base.decode().split("\n"))
                self.assertFalse(any(item.params for item in sig_inputs[label]))
                component_ids = [item.value for item in sig_inputs[label]]
                field_names = [c for c in component_ids if not c.startswith("@")]
                self.assertTrue(field_names)

                request = requests.Request(covered['"@method"'], covered['"@target-uri"']).prepare()
                for name in field_names:
                    request.headers[name] = covered[f'"{name}"']
                key_resolver = VectorKeyResolver(private_key)
                signer = HTTPMessageSigner(signature_algorithm=algorithm, key_resolver=key_resolver)
                prepared = signer.prepare(
                    request,
                    key_id=key_id,
                    created=datetime.fromtimestamp(created, timezone.utc),
                    label=label,
                    covered_component_ids=component_ids,
                )
                self.assertEqual(prepared.signature_base, expected_base)
                self.assertEqual(prepared.signature_params, params)

                # ML-DSA signing is hedged, so a fresh signature differs from the deterministic fixture.
                signer.apply(
                    request,
                    prepared,
                    algorithm(private_key=private_key).sign(prepared.signature_base),
                )
                self.assertEqual(request.headers["Signature-Input"], signature_input)
                verifier = HTTPMessageVerifier(signature_algorithm=algorithm, key_resolver=key_resolver)
                self.assertEqual(len(verifier.verify(request, max_age=self.max_age)), 1)

                request.headers["Signature"] = f"{label}=:{vector['deterministic_signature_base64']}:"
                result = verifier.verify(request, max_age=self.max_age)[0]
                self.assertEqual(result.label, label)
                self.assertEqual(result.parameters["keyid"], key_id)
                self.assertEqual(result.parameters["alg"], vector["algorithm"])
                self.assertEqual(dict(result.covered_components), covered)
                request.headers[field_names[0]] += "x"
                with self.assertRaises(InvalidSignature):
                    verifier.verify(request, max_age=self.max_age)


class TestMLDSAKeyMaterial(unittest.TestCase):
    def test_seed_private_key_accepted(self):
        ML_DSA_44(private_key=(TEST_DIR / "test-key-mldsa44.key").read_bytes())

    def test_expanded_private_key_rejected(self):
        # PKCS#8 (RFC 9881) carrying only the 2560-octet skEncode of test-key-mldsa44, without the seed.
        # httpsig-pq requires the 32-octet seed and forbids accepting the expanded form in its place.
        with self.assertRaises(ValueError):
            ML_DSA_44(private_key=(TEST_DIR / "test-key-mldsa44-expanded.key").read_bytes())

    def test_seed_length(self):
        for algorithm_id, (_, private_key_class) in ALGORITHMS.items():
            for length in (31, 33, 64):
                with self.subTest(algorithm=algorithm_id, length=length), self.assertRaises(ValueError):
                    private_key_class.from_seed_bytes(bytes(length))


class TestMLDSANegativeVectors(unittest.TestCase):
    """Negative tests from c2sp.org/httpsig-pq@v1.0.1, applied to each vector while retaining its signature."""

    def setUp(self):
        with open(TEST_VECTORS_PATH) as fh:
            self.vectors = json.load(fh)["vectors"]

    def vector_inputs(self, vector):
        algorithm, _ = ALGORITHMS[vector["algorithm"]]
        public_key_bytes = base64.b64decode(vector["public_key_base64"])
        public_key = PUBLIC_KEY_CLASSES[vector["algorithm"]].from_public_bytes(public_key_bytes)
        signature_base = base64.b64decode(vector["signature_base_base64"])
        signature = base64.b64decode(vector["deterministic_signature_base64"])
        return algorithm, public_key, signature_base, signature

    def assertRejected(self, algorithm, public_key, signature, message):
        with self.assertRaises(CryptographyInvalidSignature):
            algorithm(public_key=public_key).verify(signature=signature, message=message)

    def test_vectors_verify(self):
        for vector in self.vectors:
            with self.subTest(vector=vector["id"]):
                algorithm, public_key, signature_base, signature = self.vector_inputs(vector)
                algorithm(public_key=public_key).verify(signature=signature, message=signature_base)

    def test_modified_signature_base(self):
        for vector in self.vectors:
            algorithm, public_key, signature_base, signature = self.vector_inputs(vector)
            lines = signature_base.split(b"\n")
            modified = {
                "changed component value": signature_base.replace(b'"host": example.com', b'"host": example.org'),
                "removed component line": b"\n".join(line for line in lines if not line.startswith(b'"date"')),
                "LF to CRLF": signature_base.replace(b"\n", b"\r\n"),
                "terminal LF": signature_base + b"\n",
            }
            for other_id in ALGORITHMS:
                if other_id != vector["algorithm"]:
                    alg = f'alg="{vector["algorithm"]}"'.encode()
                    modified[f"alg {other_id}"] = signature_base.replace(alg, f'alg="{other_id}"'.encode())
            for name, message in modified.items():
                with self.subTest(vector=vector["id"], modification=name):
                    self.assertNotEqual(message, signature_base)
                    self.assertRejected(algorithm, public_key, signature, message)

    def test_modified_signature(self):
        for vector in self.vectors:
            algorithm, public_key, signature_base, signature = self.vector_inputs(vector)
            flipped = bytearray(signature)
            flipped[len(flipped) // 2] ^= 0x01
            modified = {
                "flipped bit": bytes(flipped),
                "removed octet": signature[:-1],
                "appended octet": signature + b"\x00",
                "empty": b"",
            }
            for name, modified_signature in modified.items():
                with self.subTest(vector=vector["id"], modification=name):
                    self.assertRejected(algorithm, public_key, modified_signature, signature_base)

    def test_other_public_key_same_parameter_set(self):
        for vector in self.vectors:
            with self.subTest(vector=vector["id"]):
                algorithm, private_key_class = ALGORITHMS[vector["algorithm"]]
                _, _, signature_base, signature = self.vector_inputs(vector)
                other_public_key = private_key_class.generate().public_key()
                self.assertRejected(algorithm, other_public_key, signature, signature_base)

    def test_other_parameter_set(self):
        for vector in self.vectors:
            algorithm, _ = ALGORITHMS[vector["algorithm"]]
            for other_id, (other_algorithm, other_private_key_class) in ALGORITHMS.items():
                if other_id == vector["algorithm"]:
                    continue
                with self.subTest(vector=vector["id"], key=other_id):
                    other_private_key = other_private_key_class.generate()
                    with self.assertRaises(HTTPMessageSignaturesException):
                        algorithm(public_key=other_private_key.public_key())
                    with self.assertRaises(HTTPMessageSignaturesException):
                        algorithm(private_key=other_private_key)
                with self.subTest(vector=vector["id"], algorithm=other_id):
                    _, public_key, _, _ = self.vector_inputs(vector)
                    with self.assertRaises(HTTPMessageSignaturesException):
                        other_algorithm(public_key=public_key)

    def test_public_key_length(self):
        for vector in self.vectors:
            public_key_bytes = base64.b64decode(vector["public_key_base64"])
            for name, modified in {
                "removed octet": public_key_bytes[:-1],
                "appended octet": public_key_bytes + b"\x00",
            }.items():
                with self.subTest(vector=vector["id"], modification=name), self.assertRaises(ValueError):
                    PUBLIC_KEY_CLASSES[vector["algorithm"]].from_public_bytes(modified)

    def test_context_and_prehash(self):
        for vector in self.vectors:
            with self.subTest(vector=vector["id"]):
                _, public_key, signature_base, signature = self.vector_inputs(vector)
                with self.assertRaises(CryptographyInvalidSignature):
                    public_key.verify(signature, signature_base, context=b"ctx")
                with self.assertRaises(CryptographyInvalidSignature):
                    public_key.verify(signature, hashlib.sha256(signature_base).digest())
                with self.assertRaises(CryptographyInvalidSignature):
                    public_key.verify(signature, hashlib.sha512(signature_base).digest())


class TestMLDSAAlgorithmBinding(unittest.TestCase):
    """Algorithm binding through HTTPMessageVerifier, using each vector's message and deterministic signature."""

    def setUp(self):
        with open(TEST_VECTORS_PATH) as fh:
            self.vectors = json.load(fh)["vectors"]

    def signed_request(self, vector, signature_input=None):
        signature_base = base64.b64decode(vector["signature_base_base64"]).decode()
        covered = dict(line.split(": ", 1) for line in signature_base.split("\n"))
        request = requests.Request(covered['"@method"'], covered['"@target-uri"']).prepare()
        request.headers["Host"] = covered['"host"']
        request.headers["Date"] = covered['"date"']
        _, _, vector_signature_input = vector["serialized_signature_input"].partition(": ")
        request.headers["Signature-Input"] = signature_input or vector_signature_input
        request.headers["Signature"] = f"sig1=:{vector['deterministic_signature_base64']}:"
        return request

    def verifier(self, algorithm, public_key):
        class KeyResolver(HTTPSignatureKeyResolver):
            def resolve_public_key(self, key_id: str):
                return public_key

        return HTTPMessageVerifier(signature_algorithm=algorithm, key_resolver=KeyResolver())

    def test_vector_messages_verify(self):
        for vector in self.vectors:
            with self.subTest(vector=vector["id"]):
                algorithm, private_key_class = ALGORITHMS[vector["algorithm"]]
                public_key = private_key_class.from_seed_bytes(
                    bytes.fromhex(vector["private_key_seed_hex"])
                ).public_key()
                self.verifier(algorithm, public_key).verify(self.signed_request(vector), max_age=None)

    def test_alg_mismatch(self):
        for vector in self.vectors:
            _, private_key_class = ALGORITHMS[vector["algorithm"]]
            public_key = private_key_class.from_seed_bytes(bytes.fromhex(vector["private_key_seed_hex"])).public_key()
            request = self.signed_request(vector)
            for other_id, (other_algorithm, _) in ALGORITHMS.items():
                if other_id == vector["algorithm"]:
                    continue
                with (
                    self.subTest(vector=vector["id"], alg=other_id),
                    self.assertRaisesRegex(InvalidSignature, "Unexpected algorithm"),
                ):
                    self.verifier(other_algorithm, public_key).verify(request, max_age=None)

    def test_substituted_alg_parameter(self):
        for vector in self.vectors:
            algorithm, private_key_class = ALGORITHMS[vector["algorithm"]]
            public_key = private_key_class.from_seed_bytes(bytes.fromhex(vector["private_key_seed_hex"])).public_key()
            _, _, signature_input = vector["serialized_signature_input"].partition(": ")
            for other_id in ALGORITHMS:
                if other_id == vector["algorithm"]:
                    continue
                request = self.signed_request(
                    vector,
                    signature_input.replace(f'alg="{vector["algorithm"]}"', f'alg="{other_id}"'),
                )
                with self.subTest(vector=vector["id"], alg=other_id), self.assertRaises(InvalidSignature):
                    self.verifier(algorithm, public_key).verify(request, max_age=None)

    def test_key_parameter_set_mismatch_without_alg(self):
        for vector in self.vectors:
            _, private_key_class = ALGORITHMS[vector["algorithm"]]
            public_key = private_key_class.from_seed_bytes(bytes.fromhex(vector["private_key_seed_hex"])).public_key()
            _, _, signature_input = vector["serialized_signature_input"].partition(": ")
            request = self.signed_request(vector, signature_input.replace(f';alg="{vector["algorithm"]}"', ""))
            for other_id, (other_algorithm, _) in ALGORITHMS.items():
                if other_id == vector["algorithm"]:
                    continue
                with self.subTest(vector=vector["id"], algorithm=other_id), self.assertRaises(InvalidSignature):
                    self.verifier(other_algorithm, public_key).verify(request, max_age=None)

    def test_other_public_key(self):
        for vector in self.vectors:
            with self.subTest(vector=vector["id"]):
                algorithm, private_key_class = ALGORITHMS[vector["algorithm"]]
                other_public_key = private_key_class.generate().public_key()
                with self.assertRaises(InvalidSignature):
                    self.verifier(algorithm, other_public_key).verify(self.signed_request(vector), max_age=None)


if __name__ == "__main__":
    unittest.main()
