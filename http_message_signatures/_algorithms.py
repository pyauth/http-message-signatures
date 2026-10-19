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
    """Interface for explicitly configured signature algorithm implementations.

    Subclasses define ``algorithm_id`` and implement initialization, ``sign()``,
    and ``verify()``. Pass the subclass as ``signature_algorithm`` when creating
    a signer or verifier; no registration is required. The configured class is
    used regardless of whether the signature includes an ``alg`` parameter.
    When present, ``alg`` must match the class's ``algorithm_id``.
    """

    algorithm_id: str

    def __init__(self, public_key=None, private_key=None):
        raise NotImplementedError("This method must be implemented by a subclass.")

    def sign(self, message: bytes):
        """Return signature bytes for the supplied message bytes."""
        raise NotImplementedError("This method must be implemented by a subclass.")

    def verify(self, signature: bytes, message: bytes):
        """Return None for a valid signature or raise if verification fails."""
        raise NotImplementedError("This method must be implemented by a subclass.")


class PEMKeyLoader:
    def load_pem_keys(self, public_key=None, private_key=None, password=None):
        self.public_key, self.private_key = public_key, private_key
        if isinstance(public_key, bytes):
            self.public_key = load_pem_public_key(public_key)
        if isinstance(private_key, bytes):
            self.private_key = load_pem_private_key(private_key, password=password)


class RSA_PSS_SHA512(HTTPSignatureAlgorithm, PEMKeyLoader):
    """RSA-PSS with SHA-512. Keys may be PEM bytes or cryptography RSA key objects.

    ``password`` decrypts an encrypted PEM private key when provided.
    """

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
    """RSA PKCS#1 v1.5 with SHA-256; accepts the same key arguments as RSA-PSS."""

    algorithm_id = "rsa-v1_5-sha256"

    def __init__(self, public_key=None, private_key=None, password=None):
        super().__init__(public_key=public_key, private_key=private_key, password=password)
        self.padding = padding.PKCS1v15()
        self.hash_algorithm = hashes.SHA256()


class HMAC_SHA256(HTTPSignatureAlgorithm):
    """HMAC with SHA-256 using secret bytes.

    Supply ``shared_secret``, ``public_key``, or ``private_key``. At least one is
    required, and all supplied values must agree. The key resolver integration
    uses ``private_key`` for signing and ``public_key`` for verification.
    """

    algorithm_id = "hmac-sha256"

    def __init__(self, public_key=None, private_key=None, shared_secret=None):
        keys = [key for key in (public_key, private_key, shared_secret) if key is not None]
        if not keys:
            raise HTTPMessageSignaturesException("An HMAC key must be supplied")
        if any(key != keys[0] for key in keys[1:]):
            raise HTTPMessageSignaturesException("HMAC public key, private key, and shared secret must be the same")
        self.shared_secret = keys[0]
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
    """ECDSA P-256 with SHA-256, using PEM bytes or cryptography EC key objects.

    ``password`` decrypts an encrypted PEM private key when provided.
    """

    algorithm_id = "ecdsa-p256-sha256"

    def __init__(self, public_key=None, private_key=None, password=None):
        self.load_pem_keys(public_key=public_key, private_key=private_key, password=password)
        if self.public_key and not isinstance(self.public_key, ec.EllipticCurvePublicKey):
            raise HTTPMessageSignaturesException("Unexpected public key type")
        if self.private_key and not isinstance(self.private_key, ec.EllipticCurvePrivateKey):
            raise HTTPMessageSignaturesException("Unexpected private key type")
        if self.public_key and not isinstance(self.public_key.curve, ec.SECP256R1):
            raise HTTPMessageSignaturesException("Unexpected elliptic curve type in public key")
        if self.private_key and not isinstance(self.private_key.curve, ec.SECP256R1):
            raise HTTPMessageSignaturesException("Unexpected elliptic curve type in private key")
        self.signature_algorithm = ec.ECDSA(hashes.SHA256())

    def sign(self, message: bytes):
        der_sig = self.private_key.sign(message, signature_algorithm=self.signature_algorithm)
        return self.signature_from_der(der_sig)

    @staticmethod
    def signature_from_der(signature: bytes) -> bytes:
        """Convert a DER-encoded ECDSA P-256 signature to RFC 9421 signature bytes.

        Returns the 64-byte concatenation of unsigned, big-endian ``r`` and ``s``,
        each padded to 32 bytes (RFC 9421 section 3.3.4). Use this for a remote
        signer's DER output before calling ``HTTPMessageSigner.apply()``.
        Malformed DER or integers that do not fit raise
        :class:`~http_message_signatures.HTTPMessageSignaturesException`.
        Conversion does not verify the signature or the signer's choice of curve.
        """
        try:
            r, s = decode_dss_signature(signature)
            return r.to_bytes(32, byteorder="big") + s.to_bytes(32, byteorder="big")
        except (ValueError, TypeError, OverflowError) as e:
            raise HTTPMessageSignaturesException("Invalid DER-encoded ECDSA P-256 signature") from e

    def verify(self, signature: bytes, message: bytes):
        if len(signature) != 64:
            raise HTTPMessageSignaturesException("Unexpected signature length")
        r = int.from_bytes(signature[:32], byteorder="big")
        s = int.from_bytes(signature[32:], byteorder="big")
        der_sig = encode_dss_signature(r, s)
        self.public_key.verify(signature=der_sig, data=message, signature_algorithm=self.signature_algorithm)


class ED25519(HTTPSignatureAlgorithm, PEMKeyLoader):
    """Ed25519 using PEM bytes or cryptography Ed25519 key objects.

    ``password`` decrypts an encrypted PEM private key when provided.
    """

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
