"""Public imports and result fields must retain their types for strict consumers."""

import aiohttp
import httpx2
from aiohttp import web
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
from http_message_signatures.aiohttp import (
    ServerSignatureMiddleware,
    ServerSignatureMiddlewareMode,
    ServerSigningOptions,
    ServerVerificationOptions,
    SignatureMiddleware,
    SignatureMiddlewareMode,
)
from http_message_signatures.aiohttp import SigningOptions as AiohttpSigningOptions
from http_message_signatures.aiohttp import VerificationOptions as AiohttpVerificationOptions
from http_message_signatures.algorithms import (
    ECDSA_P256_SHA256,
    ED25519,
    HMAC_SHA256,
    RSA_PSS_SHA512,
    RSA_V1_5_SHA256,
)
from http_message_signatures.httpx2 import (
    SignatureHooks,
    SignatureHooksMode,
    SigningOptions,
    VerificationOptions,
    adapt_message,
)


async def aiohttp_example(keys: HTTPSignatureKeyResolver) -> list[VerifyResult]:
    signatures = SignatureMiddleware(
        SignatureMiddlewareMode.VERIFY_RESPONSE,
        verify_options=AiohttpVerificationOptions(
            origin="https://example.com", signature_algorithm=HMAC_SHA256, key_resolver=keys
        ),
    )
    async with (
        aiohttp.ClientSession(**signatures.session_kwargs) as client,
        client.get("https://example.com") as response,
    ):
        assert_type(await response.read(), bytes)
        assert_type(signatures.mode, SignatureMiddlewareMode)
        return signatures.verification_results(response)


def aiohttp_server_example(keys: HTTPSignatureKeyResolver) -> web.Application:
    signatures = ServerSignatureMiddleware(
        ServerSignatureMiddlewareMode.VERIFY_REQUEST_SIGN_RESPONSE,
        sign_options=ServerSigningOptions(
            signature_algorithm=HMAC_SHA256,
            key_id="server",
            key_resolver=keys,
            covered_component_ids=("@status",),
        ),
        verify_options=ServerVerificationOptions(signature_algorithm=HMAC_SHA256, key_resolver=keys),
    )
    assert_type(signatures.mode, ServerSignatureMiddlewareMode)

    async def handler(request: web.Request) -> web.Response:
        assert_type(signatures.verification_results(request), list[VerifyResult])
        return web.Response(body=await request.read())

    options = signatures.application_kwargs
    options["handler_args"]["keepalive_timeout"] = 30.0
    app = web.Application(**options)
    app.router.add_post("/", handler)
    app.on_response_prepare.append(signatures.on_response_prepare)
    return app


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


def configure_httpx2(secret: bytes) -> SignatureHooks:
    keys = MappingKeyResolver(public_keys={"server": secret}, private_keys={"client": secret})
    assert_type(keys.resolve_private_key("client"), SigningKey)
    assert_type(keys.resolve_public_key("server"), VerificationKey | None)
    make_handlers(keys)
    assert_type(ContentDigest.create(b"hello"), str)
    hooks = SignatureHooks(
        sign_options={
            "origin": "https://example.com",
            "signature_algorithm": HMAC_SHA256,
            "key_id": "client",
            "key_resolver": keys,
            "tag": "out",
            "include_alg": False,
            "use_existing_digest": True,
        },
        verify_options={
            "origin": "https://example.com",
            "signature_algorithm": HMAC_SHA256,
            "key_resolver": keys,
            "expect_tag": "in",
            "max_age": None,
        },
    )
    assert_type(hooks.mode, SignatureHooksMode)
    assert_type(hooks.signer, HTTPMessageSigner | None)
    assert_type(hooks.verifier, HTTPMessageVerifier | None)
    return hooks


def configure_single_operation_modes(secret: bytes) -> tuple[SignatureHooks, SignatureHooks]:
    keys = MappingKeyResolver(public_keys={"server": secret}, private_keys={"client": secret})
    signing = SignatureHooks(
        SignatureHooksMode.SIGN_REQUEST,
        sign_options=SigningOptions(
            origin="https://example.com",
            signature_algorithm=HMAC_SHA256,
            key_id="client",
            key_resolver=keys,
            tag="out",
        ),
    )
    verification = SignatureHooks(
        SignatureHooksMode.VERIFY_RESPONSE,
        verify_options=VerificationOptions(
            origin="https://example.com",
            signature_algorithm=HMAC_SHA256,
            key_resolver=keys,
            expect_tag="in",
        ),
    )
    return signing, verification


class CustomSigningOptions(SigningOptions, total=False):
    signing_context: str


class CustomVerificationOptions(VerificationOptions, total=False):
    verification_context: str


def configure_subclass_options(secret: bytes, hooks_class: type[SignatureHooks]) -> SignatureHooks:
    keys = MappingKeyResolver(public_keys={"server": secret}, private_keys={"client": secret})
    signing = CustomSigningOptions(
        origin="https://example.com",
        key_id="client",
        key_resolver=keys,
        signature_algorithm=HMAC_SHA256,
        signing_context="out",
    )
    verification = CustomVerificationOptions(
        origin="https://example.com",
        key_resolver=keys,
        signature_algorithm=HMAC_SHA256,
        verification_context="in",
    )
    return hooks_class(sign_options=signing, verify_options=verification)


def reject_invalid_options(secret: bytes) -> None:
    # Strict mypy rejects unused ignores, so these exercise the container types.
    keys = MappingKeyResolver(public_keys={"server": secret}, private_keys={"client": secret})
    signing = SigningOptions(
        origin="https://example.com",
        signature_algorithm=HMAC_SHA256,
        key_id="client",
        key_resolver=keys,
    )
    verification = VerificationOptions(
        origin="https://example.com",
        signature_algorithm=HMAC_SHA256,
        key_resolver=keys,
    )
    signing["expect_tag"] = "in"  # type: ignore[typeddict-unknown-key]
    verification["tag"] = "out"  # type: ignore[typeddict-unknown-key]
    signing["include_alg"] = "yes"  # type: ignore[typeddict-item]
    signing["use_existing_digest"] = "yes"  # type: ignore[typeddict-item]
    verification["max_age"] = 60  # type: ignore[typeddict-item]
    signing["body"] = b"managed"  # type: ignore[typeddict-unknown-key]
    verification["body"] = b"managed"  # type: ignore[typeddict-unknown-key]
    verification["key_id"] = "client"  # type: ignore[typeddict-unknown-key]
    signing["signature_algorithm"] = "hmac-sha256"  # type: ignore[typeddict-item]
    verification["signature_algorithm"] = "hmac-sha256"  # type: ignore[typeddict-item]
    SigningOptions(tag="out")  # type: ignore[typeddict-item]
    VerificationOptions(expect_tag="in")  # type: ignore[typeddict-item]
    SignatureHooks("sign_request", sign_options=signing)  # type: ignore[arg-type]
    SignatureHooks(sign_options={"tag": "out"}, verify_options={"expect_tag": "in"})  # type: ignore[arg-type]


def configure_httpx2_resolvers(
    signing_resolver: HTTPSignatureKeyResolver, verification_resolver: HTTPSignatureKeyResolver
) -> SignatureHooks:
    return SignatureHooks(
        sign_options={
            "origin": "https://example.com",
            "signature_algorithm": ED25519,
            "key_id": "client",
            "key_resolver": signing_resolver,
        },
        verify_options={
            "origin": "https://example.com",
            "signature_algorithm": ED25519,
            "key_resolver": verification_resolver,
        },
    )


def use_adapted_messages(request: httpx2.Request, response: httpx2.Response) -> None:
    view = adapt_message(request)
    assert_type(view.method, str)
    assert_type(adapt_message(response).status_code, int)
    ContentDigest.add(view.headers, b"hello")
    assert_type(ContentDigest.verify_components({}, b"hello"), bool)


def configure_aiohttp_signing(keys: HTTPSignatureKeyResolver) -> SignatureMiddleware:
    return SignatureMiddleware(
        SignatureMiddlewareMode.SIGN_REQUEST,
        sign_options=AiohttpSigningOptions(
            origin="https://example.com", signature_algorithm=HMAC_SHA256, key_id="client", key_resolver=keys
        ),
    )


def reject_invalid_httpx2_resolvers(private_key: Ed25519PrivateKey, public_key: Ed25519PublicKey) -> None:
    # Strict mypy rejects unused ignores, so these check that keys cannot replace resolvers.
    keys = MappingKeyResolver(public_keys={"server": public_key}, private_keys={"client": private_key})
    signing = SigningOptions(
        origin="https://example.com",
        key_id="client",
        key_resolver=keys,
        signature_algorithm=ED25519,
    )
    verification = VerificationOptions(
        origin="https://example.com",
        key_resolver=keys,
        signature_algorithm=ED25519,
    )
    signing["key_resolver"] = private_key  # type: ignore[typeddict-item]
    verification["key_resolver"] = {"server": public_key}  # type: ignore[typeddict-item]
    signing["key_resolver"] = "secret"  # type: ignore[typeddict-item]
    verification["key_resolver"] = None  # type: ignore[typeddict-item]
