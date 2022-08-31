from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)

from .exceptions import HTTPMessageSignaturesException


class HTTPSignatureAlgorithm:
    algorithm_id: str

    def __init__(self, public_key=None, private_key=None):
        raise NotImplementedError("This method must be implemented by a subclass.")

    def sign(self, message: bytes):
        raise NotImplementedError("This method must be implemented by a subclass.")

    def verify(self, signature: bytes, message: bytes):
        raise NotImplementedError("This method must be implemented by a subclass.")


class PEMKeyLoader:
    def load_pem_keys(self, public_key=None, private_key=None, password=None):
        self.public_key, self.private_key = public_key, private_key
        if isinstance(public_key, bytes):
            self.public_key = load_pem_public_key(public_key)
        if isinstance(private_key, bytes):
            self.private_key = load_pem_private_key(private_key, password=password)


class RSA_PSS_SHA512(HTTPSignatureAlgorithm, PEMKeyLoader):
    algorithm_id = "rsa-pss-sha512"

    def __init__(self, public_key=None, private_key=None, password=None):
        self.load_pem_keys(public_key=public_key, private_key=private_key, password=password)
        if self.public_key and not isinstance(self.public_key, rsa.RSAPublicKey):
            raise HTTPMessageSignaturesException("Unexpected public key type")
        if self.private_key and not isinstance(self.private_key, rsa.RSAPrivateKey):
            raise HTTPMessageSignaturesException("Unexpected private key type")
        self.padding: padding.AsymmetricPadding = padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=64)
        self.hash_algorithm: hashes.HashAlgorithm = hashes.SHA512()

    def sign(self, message: bytes):
        return self.private_key.sign(data=message, padding=self.padding, algorithm=self.hash_algorithm)

    def verify(self, signature: bytes, message: bytes):
        self.public_key.verify(signature=signature, data=message, padding=self.padding, algorithm=self.hash_algorithm)


class RSA_V1_5_SHA256(RSA_PSS_SHA512):
    algorithm_id = "rsa-v1_5-sha256"

    def __init__(self, public_key=None, private_key=None, password=None):
        super().__init__(public_key=public_key, private_key=private_key, password=password)
        self.padding = padding.PKCS1v15()
        self.hash_algorithm = hashes.SHA256()


class HMAC_SHA256(HTTPSignatureAlgorithm):
    algorithm_id = "hmac-sha256"

    def __init__(self, public_key=None, private_key=None, shared_secret=None):
        if public_key and private_key and public_key != private_key:
            raise HTTPMessageSignaturesException("HMAC public and private key must be the same")
        self.shared_secret = public_key if public_key is not None else private_key
        self.hash_algorithm = hashes.SHA256()

    def sign(self, message: bytes):
        hasher = hmac.HMAC(self.shared_secret, algorithm=self.hash_algorithm)
        hasher.update(message)
        return hasher.finalize()

    def verify(self, signature: bytes, message: bytes):
        hasher = hmac.HMAC(self.shared_secret, algorithm=self.hash_algorithm)
        hasher.update(message)
        hasher.verify(signature)


class ECDSA_P256_SHA256(HTTPSignatureAlgorithm, PEMKeyLoader):
    algorithm_id = "ecdsa-p256-sha256"

    def __init__(self, public_key=None, private_key=None, password=None):
        self.load_pem_keys(public_key=public_key, private_key=private_key, password=password)
        if self.public_key and not isinstance(self.public_key, ec.EllipticCurvePublicKey):
            raise HTTPMessageSignaturesException("Unexpected public key type")
        if self.private_key and not isinstance(self.private_key, ec.EllipticCurvePrivateKey):
            raise HTTPMessageSignaturesException("Unexpected private key type")
        if self.public_key and type(self.public_key.curve) != ec.SECP256R1:
            raise HTTPMessageSignaturesException("Unexpected elliptic curve type in public key")
        if self.private_key and type(self.private_key.curve) != ec.SECP256R1:
            raise HTTPMessageSignaturesException("Unexpected elliptic curve type in private key")
        self.signature_algorithm = ec.ECDSA(hashes.SHA256())

    def sign(self, message: bytes):
        der_sig = self.private_key.sign(message, signature_algorithm=self.signature_algorithm)
        r, s = decode_dss_signature(der_sig)
        return r.to_bytes(32, byteorder="big") + s.to_bytes(32, byteorder="big")

    def verify(self, signature: bytes, message: bytes):
        if len(signature) != 64:
            raise HTTPMessageSignaturesException("Unexpected signature length")
        r = int.from_bytes(signature[:32], byteorder="big")
        s = int.from_bytes(signature[32:], byteorder="big")
        der_sig = encode_dss_signature(r, s)
        self.public_key.verify(signature=der_sig, data=message, signature_algorithm=self.signature_algorithm)


class ED25519(HTTPSignatureAlgorithm, PEMKeyLoader):
    algorithm_id = "ed25519"

    def __init__(self, public_key=None, private_key=None, password=None):
        self.load_pem_keys(public_key=public_key, private_key=private_key, password=password)
        if self.public_key and not isinstance(self.public_key, ed25519.Ed25519PublicKey):
            raise HTTPMessageSignaturesException("Unexpected public key type")
        if self.private_key and not isinstance(self.private_key, ed25519.Ed25519PrivateKey):
            raise HTTPMessageSignaturesException("Unexpected private key type")

    def sign(self, message: bytes):
        return self.private_key.sign(message)

    def verify(self, signature: bytes, message: bytes):
        self.public_key.verify(signature=signature, data=message)


signature_algorithms = {}
for signature_algorithm_class in list(globals().values()):
    if isinstance(signature_algorithm_class, type):
        if issubclass(signature_algorithm_class, HTTPSignatureAlgorithm):
            if signature_algorithm_class != HTTPSignatureAlgorithm:
                signature_algorithms[signature_algorithm_class.algorithm_id] = signature_algorithm_class
