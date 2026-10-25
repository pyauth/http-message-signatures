"""Configuration shared by client adapters; base methods own signature defaults."""

from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import Any, TypedDict

from .algorithms import HTTPSignatureAlgorithm
from .resolvers import HTTPSignatureKeyResolver
from .signatures import HTTPMessageSigner, HTTPMessageVerifier


class _SigningConfiguration(TypedDict):
    origin: str
    signature_algorithm: type[HTTPSignatureAlgorithm]
    key_id: str
    key_resolver: HTTPSignatureKeyResolver


class SigningOptions(_SigningConfiguration, total=False):
    """Request signing configuration and optional base signer keywords.

    ``origin``, ``signature_algorithm``, ``key_id``, and ``key_resolver`` are
    required. The adapters supply ``body``; the base signer supplies defaults for
    omitted signing options.
    """

    created: datetime | None
    expires: datetime | None
    nonce: str | None
    label: str | None
    tag: str | None
    include_alg: bool
    covered_component_ids: Sequence[str]
    append_if_signature_exists: bool
    use_existing_digest: bool


class _VerificationConfiguration(TypedDict):
    origin: str
    signature_algorithm: type[HTTPSignatureAlgorithm]
    key_resolver: HTTPSignatureKeyResolver


class VerificationOptions(_VerificationConfiguration, total=False):
    """Response verification configuration and optional base verifier keywords.

    ``origin``, ``signature_algorithm``, and ``key_resolver`` are required.
    The adapters supply ``body``; the base verifier supplies defaults for omitted
    verification options. The adapters do not infer these options from SigningOptions.
    """

    max_age: timedelta | None
    expect_tag: str | None
    expect_label: str | None
    require_components: Sequence[str]


class SignatureAdapter:
    signer_class: type[HTTPMessageSigner] = HTTPMessageSigner
    verifier_class: type[HTTPMessageVerifier] = HTTPMessageVerifier

    def __init__(
        self,
        *,
        sign_requests: bool,
        verify_responses: bool,
        sign_options: SigningOptions | None,
        verify_options: VerificationOptions | None,
    ) -> None:
        if sign_requests and sign_options is None:
            raise ValueError("sign_options is required when signing requests")
        if not sign_requests and sign_options is not None:
            raise ValueError("Signing configuration is not allowed in VERIFY_RESPONSE mode")
        if verify_responses and verify_options is None:
            raise ValueError("verify_options is required when verifying responses")
        if not verify_responses and verify_options is not None:
            raise ValueError("Verification configuration is not allowed in SIGN_REQUEST mode")
        self.signer: HTTPMessageSigner | None = None
        self.verifier: HTTPMessageVerifier | None = None
        self._sign_origin: tuple[str, str, int | None] | None = None
        self._verify_origin: tuple[str, str, int | None] | None = None
        self._sign_kwargs: dict[str, Any] = {}
        self._verify_kwargs: dict[str, Any] = {}
        if sign_options is not None:
            self._configure_signing(**sign_options)
        if verify_options is not None:
            self._configure_verification(**verify_options)

    @staticmethod
    def _parse_origin(origin: str) -> tuple[str, str, int | None]:
        raise NotImplementedError

    def _configure_signing(
        self,
        *,
        origin: str,
        signature_algorithm: type[HTTPSignatureAlgorithm],
        key_id: str,
        key_resolver: HTTPSignatureKeyResolver,
        **options: Any,
    ) -> None:
        self._sign_origin = self._parse_origin(origin)
        self.signer = self.signer_class(signature_algorithm=signature_algorithm, key_resolver=key_resolver)
        if "covered_component_ids" in options and not isinstance(options["covered_component_ids"], (str, bytes)):
            options["covered_component_ids"] = tuple(options["covered_component_ids"])
        self._sign_kwargs = {"key_id": key_id, **options}

    def _configure_verification(
        self,
        *,
        origin: str,
        signature_algorithm: type[HTTPSignatureAlgorithm],
        key_resolver: HTTPSignatureKeyResolver,
        **options: Any,
    ) -> None:
        self._verify_origin = self._parse_origin(origin)
        self.verifier = self.verifier_class(signature_algorithm=signature_algorithm, key_resolver=key_resolver)
        if "require_components" in options and not isinstance(options["require_components"], (str, bytes)):
            options["require_components"] = tuple(options["require_components"])
        self._verify_kwargs = options
