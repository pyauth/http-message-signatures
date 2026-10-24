"""Public imports and result fields must retain their types for strict consumers."""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from typing_extensions import assert_type

from http_message_signatures import (
    ContentDigest,
    HTTPMessageSignaturesException,
    HTTPMessageSigner,
    HTTPMessageVerifier,
    HTTPSignatureAlgorithm,
    HTTPSignatureComponentResolver,
    HTTPSignatureKeyResolver,
    InvalidSignature,
    MappingKeyResolver,
    PreparedSignature,
    SigningKey,
    VerificationKey,
    VerifyResult,
    algorithms,
)
from http_message_signatures.algorithms import (
    ECDSA_P256_SHA256,
    ED25519,
    HMAC_SHA256,
    RSA_PSS_SHA512,
    RSA_V1_5_SHA256,
)
from http_message_signatures.httpx import SignatureHooks


def make_handlers(keys: HTTPSignatureKeyResolver) -> tuple[HTTPMessageSigner, HTTPMessageVerifier]:
    return (
        HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=keys),
        HTTPMessageVerifier(signature_algorithm=algorithms.HMAC_SHA256, key_resolver=keys),
    )


def read_result(result: VerifyResult) -> None:
    assert_type(result.label, str)
    assert_type(result.algorithm, type[HTTPSignatureAlgorithm])
    assert_type(result.covered_components, dict[str, str])
    assert_type(result.parameters, dict[str, int | str])
    assert_type(result.body, bytes | None)
    assert_type(result.nonce, str | None)
    label: str = result.label
    algorithm: type[HTTPSignatureAlgorithm] = result.algorithm
    components: dict[str, str] = result.covered_components
    parameters: dict[str, int | str] = result.parameters
    body: bytes | None = result.body
    nonce: str | None = result.nonce
    rebuilt = VerifyResult(label, algorithm, components, parameters, body, nonce)
    assert rebuilt == result


def prepare_remote_signature(message: object) -> PreparedSignature:
    signer = HTTPMessageSigner(signature_algorithm=ECDSA_P256_SHA256)
    prepared = signer.prepare(message, key_id="remote-key")
    assert_type(prepared, PreparedSignature)
    assert_type(prepared.signature_base, bytes)
    assert_type(prepared.signature_params, str)
    assert_type(prepared.label, str)
    assert_type(prepared.algorithm_id, str)
    return prepared


def apply_remote_signature(message: object, prepared: PreparedSignature, der_signature: bytes) -> None:
    signer = HTTPMessageSigner(signature_algorithm=ECDSA_P256_SHA256)
    signature = ECDSA_P256_SHA256.signature_from_der(der_signature)
    assert_type(signature, bytes)
    signer.apply(message, prepared, signature, append_if_signature_exists=True)


supported_algorithms: tuple[type[HTTPSignatureAlgorithm], ...] = (
    ECDSA_P256_SHA256,
    ED25519,
    HMAC_SHA256,
    RSA_PSS_SHA512,
    RSA_V1_5_SHA256,
)
resolver_class: type[HTTPSignatureComponentResolver] = HTTPSignatureComponentResolver
exception_class: type[HTTPMessageSignaturesException] = InvalidSignature


def configure_httpx(secret: bytes) -> SignatureHooks:
    keys = MappingKeyResolver(public_keys={"server": secret}, private_keys={"client": secret})
    assert_type(keys.resolve_private_key("client"), SigningKey)
    assert_type(keys.resolve_public_key("server"), VerificationKey | None)
    make_handlers(keys)
    assert_type(ContentDigest.create(b"hello"), str)
    hooks = SignatureHooks(
        origin="https://example.com",
        key_id="client",
        signing_key=secret,
        verification_keys={"server": secret},
        signature_algorithm=HMAC_SHA256,
    )
    assert_type(hooks.signer, HTTPMessageSigner)
    assert_type(hooks.verifier, HTTPMessageVerifier)
    return hooks


def configure_httpx_keys(signing_key: SigningKey, verification_key: VerificationKey) -> SignatureHooks:
    return SignatureHooks(
        origin="https://example.com",
        key_id="client",
        signing_key=signing_key,
        verification_keys={"server": verification_key},
        signature_algorithm=ED25519,
    )


def reject_invalid_httpx_keys(private_key: Ed25519PrivateKey, public_key: Ed25519PublicKey) -> None:
    # Strict mypy rejects unused ignores, so these check that invalid keys remain errors.
    SignatureHooks(
        origin="https://example.com",
        key_id="client",
        signing_key=public_key,  # type: ignore[arg-type]
        verification_keys={"server": private_key},  # type: ignore[dict-item]
        signature_algorithm=ED25519,
    )
    SignatureHooks(
        origin="https://example.com",
        key_id="client",
        signing_key="secret",  # type: ignore[arg-type]
        verification_keys={"server": 123},  # type: ignore[dict-item]
        signature_algorithm=HMAC_SHA256,
    )
