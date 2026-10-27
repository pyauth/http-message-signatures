"""Adapter configuration; HTTPMessageSigner and HTTPMessageVerifier supply signature defaults."""

from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import Any, TypedDict, cast

from .algorithms import HTTPSignatureAlgorithm
from .resolvers import HTTPSignatureKeyResolver
from .signatures import HTTPMessageSigner, HTTPMessageVerifier


class _SigningConfiguration(TypedDict):
    signature_algorithm: type[HTTPSignatureAlgorithm]
    key_id: str
    key_resolver: HTTPSignatureKeyResolver


class _BaseSigningOptions(_SigningConfiguration, total=False):
    """Signer configuration shared by client and server adapters."""

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
    signature_algorithm: type[HTTPSignatureAlgorithm]
    key_resolver: HTTPSignatureKeyResolver


class _BaseVerificationOptions(_VerificationConfiguration, total=False):
    """Verifier configuration shared by client and server adapters."""

    max_age: timedelta | None
    expect_tag: str | None
    expect_label: str | None
    require_components: Sequence[str]


class _SigningOptions(_BaseSigningOptions):
    origin: str


class _VerificationOptions(_BaseVerificationOptions):
    origin: str


class _SignatureConfiguration:
    signer_class: type[HTTPMessageSigner] = HTTPMessageSigner
    verifier_class: type[HTTPMessageVerifier] = HTTPMessageVerifier

    def __init__(
        self,
        *,
        sign_options: _BaseSigningOptions | None,
        verify_options: _BaseVerificationOptions | None,
    ) -> None:
        self.signer: HTTPMessageSigner | None = None
        self.verifier: HTTPMessageVerifier | None = None
        self._sign_kwargs: dict[str, Any] = {}
        self._verify_kwargs: dict[str, Any] = {}
        if sign_options is not None:
            self._configure_signing(**sign_options)
        if verify_options is not None:
            self._configure_verification(**verify_options)

    def _configure_signing(
        self,
        *,
        signature_algorithm: type[HTTPSignatureAlgorithm],
        key_id: str,
        key_resolver: HTTPSignatureKeyResolver,
        **options: Any,
    ) -> None:
        self.signer = self.signer_class(signature_algorithm=signature_algorithm, key_resolver=key_resolver)
        if "covered_component_ids" in options and not isinstance(options["covered_component_ids"], (str, bytes)):
            options["covered_component_ids"] = tuple(options["covered_component_ids"])
        self._sign_kwargs = {"key_id": key_id, **options}

    def _configure_verification(
        self,
        *,
        signature_algorithm: type[HTTPSignatureAlgorithm],
        key_resolver: HTTPSignatureKeyResolver,
        **options: Any,
    ) -> None:
        self.verifier = self.verifier_class(signature_algorithm=signature_algorithm, key_resolver=key_resolver)
        if "require_components" in options and not isinstance(options["require_components"], (str, bytes)):
            options["require_components"] = tuple(options["require_components"])
        self._verify_kwargs = options


class _SignatureAdapter(_SignatureConfiguration):
    def __init__(
        self,
        *,
        sign_requests: bool,
        verify_responses: bool,
        sign_options: _SigningOptions | None,
        verify_options: _VerificationOptions | None,
    ) -> None:
        if sign_requests and sign_options is None:
            raise ValueError("sign_options is required when signing requests")
        if not sign_requests and sign_options is not None:
            raise ValueError("Signing configuration is not allowed in VERIFY_RESPONSE mode")
        if verify_responses and verify_options is None:
            raise ValueError("verify_options is required when verifying responses")
        if not verify_responses and verify_options is not None:
            raise ValueError("Verification configuration is not allowed in SIGN_REQUEST mode")
        self._sign_origin: tuple[str, str, int | None] | None = None
        self._verify_origin: tuple[str, str, int | None] | None = None
        signing = verification = None
        if sign_options is not None:
            self._sign_origin, signing = self._client_options(**sign_options)
        if verify_options is not None:
            self._verify_origin, verification = self._client_options(**verify_options)
        super().__init__(
            sign_options=cast(_BaseSigningOptions | None, signing),
            verify_options=cast(_BaseVerificationOptions | None, verification),
        )

    @staticmethod
    def _parse_origin(origin: str) -> tuple[str, str, int | None]:
        raise NotImplementedError

    def _client_options(self, *, origin: str, **options: Any) -> tuple[tuple[str, str, int | None], dict[str, Any]]:
        return self._parse_origin(origin), options
