"""Downstream imports and result access must work without implicit reexports or Any."""

from typing_extensions import assert_type

from http_message_signatures import (
    HTTPMessageSignaturesException,
    HTTPMessageSigner,
    HTTPMessageVerifier,
    HTTPSignatureAlgorithm,
    HTTPSignatureComponentResolver,
    HTTPSignatureKeyResolver,
    InvalidSignature,
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


supported_algorithms: tuple[type[HTTPSignatureAlgorithm], ...] = (
    ECDSA_P256_SHA256,
    ED25519,
    HMAC_SHA256,
    RSA_PSS_SHA512,
    RSA_V1_5_SHA256,
)
resolver_class: type[HTTPSignatureComponentResolver] = HTTPSignatureComponentResolver
exception_class: type[HTTPMessageSignaturesException] = InvalidSignature
