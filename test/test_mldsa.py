import base64
import hashlib
import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
from cryptography.hazmat.primitives.asymmetric.mldsa import (
    MLDSA44PrivateKey,
    MLDSA65PrivateKey,
    MLDSA87PrivateKey,
)
from http_sf.compat import Dictionary

from http_message_signatures import (
    HTTPMessageSigner,
    HTTPMessageVerifier,
    HTTPSignatureKeyResolver,
    InvalidSignature,
)
from http_message_signatures.algorithms import MLDSA44, MLDSA65, MLDSA87

ALGORITHMS = {
    "ml-dsa-44": (MLDSA44, MLDSA44PrivateKey),
    "ml-dsa-65": (MLDSA65, MLDSA65PrivateKey),
    "ml-dsa-87": (MLDSA87, MLDSA87PrivateKey),
}

TEST_VECTORS_PATH = Path(__file__).parent / "test-vectors-mldsa.json"


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


if __name__ == "__main__":
    unittest.main()
