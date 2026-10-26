import unittest

import requests
from cryptography.exceptions import InvalidSignature as CryptoInvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from http_message_signatures import HTTPMessageSigner, HTTPMessageVerifier, MappingKeyResolver
from http_message_signatures.algorithms import ECDSA_P256_SHA256, ECDSA_P384_SHA384
from http_message_signatures.exceptions import HTTPMessageSignaturesException, InvalidSignature


class TestECDSA(unittest.TestCase):
    profiles = (
        (ECDSA_P256_SHA256, ec.SECP256R1, hashes.SHA256, 32),
        (ECDSA_P384_SHA384, ec.SECP384R1, hashes.SHA384, 48),
    )

    def test_cryptography_interoperability(self):
        message = b"HTTP message signature base"
        for algorithm, curve, hash_type, size in self.profiles:
            with self.subTest(algorithm=algorithm.algorithm_id):
                key = ec.generate_private_key(curve())
                signer = algorithm(private_key=key)
                verifier = algorithm(public_key=key.public_key())
                raw = signer.sign(message)
                self.assertEqual(len(raw), 2 * size)
                r, s = int.from_bytes(raw[:size], "big"), int.from_bytes(raw[size:], "big")
                key.public_key().verify(encode_dss_signature(r, s), message, ec.ECDSA(hash_type()))

                der = key.sign(message, ec.ECDSA(hash_type()))
                r, s = decode_dss_signature(der)
                raw = r.to_bytes(size, "big") + s.to_bytes(size, "big")
                verifier.verify(raw, message)
                self.assertEqual(algorithm.signature_from_der(der), raw)
                with self.assertRaises(CryptoInvalidSignature):
                    verifier.verify(raw, message + b"changed")
                for malformed in (b"", raw[:-1], raw + b"\0", der):
                    with self.assertRaisesRegex(HTTPMessageSignaturesException, "signature length"):
                        verifier.verify(malformed, message)

    def test_der_padding_and_invalid_integers(self):
        for algorithm, _, _, size in self.profiles:
            with self.subTest(algorithm=algorithm.algorithm_id):
                raw = algorithm.signature_from_der(encode_dss_signature(1, 2))
                self.assertEqual(raw, (b"\0" * (size - 1) + b"\1") + (b"\0" * (size - 1) + b"\2"))
                for der in (b"bad DER", encode_dss_signature(1, 2 ** (size * 8))):
                    with self.assertRaisesRegex(HTTPMessageSignaturesException, "Invalid DER"):
                        algorithm.signature_from_der(der)

    def test_rejects_wrong_keys(self):
        for algorithm, curve, _, _ in self.profiles:
            other_curve = ec.SECP384R1 if curve is ec.SECP256R1 else ec.SECP256R1
            for key in (ec.generate_private_key(other_curve()), ed25519.Ed25519PrivateKey.generate()):
                with self.subTest(algorithm=algorithm.algorithm_id, key=type(key)):
                    with self.assertRaises(HTTPMessageSignaturesException):
                        algorithm(private_key=key)
                    with self.assertRaises(HTTPMessageSignaturesException):
                        algorithm(public_key=key.public_key())

    def test_p384_message_signing_with_pem_keys(self):
        key = ec.generate_private_key(ec.SECP384R1())
        private_pem = key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        public_pem = key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        keys = MappingKeyResolver(public_keys={"p384": public_pem}, private_keys={"p384": private_pem})
        signer = HTTPMessageSigner(signature_algorithm=ECDSA_P384_SHA384, key_resolver=keys)
        verifier = HTTPMessageVerifier(signature_algorithm=ECDSA_P384_SHA384, key_resolver=keys)
        request = requests.Request("POST", "https://example.com/", data=b"hello").prepare()
        signer.sign(request, key_id="p384", body=request.body)
        result = verifier.verify(request, body=request.body)[0]
        self.assertEqual(result.algorithm, ECDSA_P384_SHA384)
        self.assertEqual(result.parameters["alg"], "ecdsa-p384-sha384")
        self.assertEqual(result.body, b"hello")
        with self.assertRaises(InvalidSignature):
            verifier.verify(request, body=b"tampered")

        prepared = signer.prepare(request, key_id="p384", use_existing_digest=True)
        der = key.sign(prepared.signature_base, ec.ECDSA(hashes.SHA384()))
        signer.apply(request, prepared, ECDSA_P384_SHA384.signature_from_der(der))
        verifier.verify(request)
