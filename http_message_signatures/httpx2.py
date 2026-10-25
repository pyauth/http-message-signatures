"""Buffered request signing and response verification for HTTPX2."""

from collections.abc import Awaitable, Callable, Sequence
from datetime import datetime, timedelta
from enum import Enum
from functools import cached_property
from io import BytesIO
from typing import Any, TypedDict, overload

import httpx2

from .algorithms import HTTPSignatureAlgorithm
from .exceptions import HTTPMessageSignaturesException, InvalidSignature
from .messages import HeaderFields, Request, Response
from .resolvers import HTTPSignatureKeyResolver
from .signatures import HTTPMessageSigner, HTTPMessageVerifier
from .structures import VerifyResult


class SignatureHooksMode(Enum):
    """Operations installed by the synchronous and asynchronous hook collections."""

    SIGN_REQUEST = "sign_request"
    VERIFY_RESPONSE = "verify_response"
    SIGN_REQUEST_VERIFY_RESPONSE = "sign_request_verify_response"


class _SigningConfiguration(TypedDict):
    origin: str
    signature_algorithm: type[HTTPSignatureAlgorithm]
    key_id: str
    key_resolver: HTTPSignatureKeyResolver


class SigningOptions(_SigningConfiguration, total=False):
    """Request signing configuration and optional base signer keywords.

    ``origin``, ``signature_algorithm``, ``key_id``, and ``key_resolver`` are
    required. The hooks manage ``body``; omitted signing options use base defaults.
    """

    created: datetime | None
    expires: datetime | None
    nonce: str | None
    label: str | None
    tag: str | None
    include_alg: bool
    covered_component_ids: Sequence[str]
    append_if_signature_exists: bool
    allow_existing_digest: bool


class _VerificationConfiguration(TypedDict):
    origin: str
    signature_algorithm: type[HTTPSignatureAlgorithm]
    key_resolver: HTTPSignatureKeyResolver


class VerificationOptions(_VerificationConfiguration, total=False):
    """Response verification configuration and optional base verifier keywords.

    ``origin``, ``signature_algorithm``, and ``key_resolver`` are required.
    The hooks manage ``body``; omitted verification options use base defaults.
    No configuration is inferred from SigningOptions.
    """

    max_age: timedelta | None
    expect_tag: str | None
    expect_label: str | None
    require_components: Sequence[str]


@overload
def adapt_message(message: httpx2.Request) -> Request: ...


@overload
def adapt_message(message: httpx2.Response) -> Response: ...


def adapt_message(message: httpx2.Request | httpx2.Response) -> Request | Response:
    """Expose original header lines to the base signer/verifier.

    Header writes reach the original message. Response request components use
    the same adapter. Use this for direct base-API calls on HTTPX2 objects;
    SignatureHooks applies it automatically. A response must have a request.
    """
    headers = HeaderFields.from_raw(lambda: message.headers.raw, writable=message.headers)
    if isinstance(message, httpx2.Request):
        return Request(method=message.method, url=str(message.url), headers=headers)
    return Response(status_code=message.status_code, headers=headers, request=adapt_message(message.request))


class _SyncVerifiedStream(httpx2.SyncByteStream):
    def __init__(self, stream: httpx2.SyncByteStream, verify: Callable[[bytes], list[VerifyResult]]):
        self.stream = stream
        self.verify = verify
        self.results: list[VerifyResult] = []

    def __iter__(self):
        with BytesIO() as content:
            for chunk in self.stream:
                content.write(chunk)
            body = content.getvalue()
        self.results = self.verify(body)
        yield body

    def close(self):
        self.stream.close()


class _AsyncVerifiedStream(httpx2.AsyncByteStream):
    def __init__(self, stream: httpx2.AsyncByteStream, verify: Callable[[bytes], list[VerifyResult]]):
        self.stream = stream
        self.verify = verify
        self.results: list[VerifyResult] = []

    async def __aiter__(self):
        with BytesIO() as content:
            async for chunk in self.stream:
                content.write(chunk)
            body = content.getvalue()
        self.results = self.verify(body)
        yield body

    async def aclose(self):
        await self.stream.aclose()


class SignatureHooks:
    """Sign requests, verify responses, or both through HTTPX2 event hooks.

    :param mode: Operations to enable; defaults to signing and verification.
    :param sign_options: SigningOptions containing ``origin``,
        ``signature_algorithm``, ``key_id``, and ``key_resolver``, plus optional
        ``HTTPMessageSigner.sign()`` keywords. Required when signing requests.
    :param verify_options: VerificationOptions containing ``origin``,
        ``signature_algorithm``, and ``key_resolver``, plus optional
        ``HTTPMessageVerifier.verify()`` keywords. Required when verifying responses.

    Each origin is an HTTP origin including its scheme and port. Signing checks
    its origin before sending; verification checks its origin when the response
    arrives. Algorithms and key resolvers are independent. Each resolver is passed
    unchanged to the underlying signer or verifier. Keys are resolved when each
    message is signed or verified, using the base HTTPSignatureKeyResolver interface.
    Key loading, caching, and trust policy belong to the supplied resolver.

    Options are captured at construction; component sequences are copied.
    Signature keywords are forwarded independently. Omitted signature options use
    the underlying method defaults; explicit ``None`` is passed through.
    Set ``expect_tag`` separately from the signing ``tag``. Unknown
    keywords raise ``TypeError`` from the underlying method when its hook runs.
    Missing containers or containers for a disabled operation raise ``ValueError``.
    Missing required entries raise ``TypeError`` at construction. Disabled handlers
    are not constructed. The hooks manage ``body`` for both operations.

    Install ``event_hooks`` on Client or ``async_event_hooks`` on AsyncClient.
    Each collection installs only the operations enabled by ``mode``.
    Signing belongs after request-mutating hooks; verification belongs before
    response consumers. Signing buffers requests and verification buffers responses,
    even with stream().
    Signing rejects a supplied Content-Digest unless ``allow_existing_digest=True``
    is configured. Requests previously signed by these hooks may reuse their digest
    on retries and redirects, unless that option is explicitly False. Reused digests
    are validated against the current body; changed content requires a new digest.
    Response content is buffered and verified before decoding; normal
    HTTPX2 content decoding is preserved. Successful verification results are
    stored in ``response.extensions["http_message_signatures"]``.

    When verifying, nonempty responses and responses with Content-Digest require signed digest
    coverage. Other coverage is controlled by the base ``require_components``
    option. No nonce, expiration, status, or request-binding policy is added.

    HTTPX2 stores cookies before response hooks. Failed verification does not undo
    cookie changes, so these hooks do not authenticate the client's cookie jar.
    """

    signer_class: type[HTTPMessageSigner] = HTTPMessageSigner
    verifier_class: type[HTTPMessageVerifier] = HTTPMessageVerifier

    def __init__(
        self,
        mode: SignatureHooksMode = SignatureHooksMode.SIGN_REQUEST_VERIFY_RESPONSE,
        *,
        sign_options: SigningOptions | None = None,
        verify_options: VerificationOptions | None = None,
    ) -> None:
        if not isinstance(mode, SignatureHooksMode):
            raise TypeError("mode must be a SignatureHooksMode")
        if mode is SignatureHooksMode.VERIFY_RESPONSE:
            if sign_options is not None:
                raise ValueError("Signing configuration is not allowed in VERIFY_RESPONSE mode")
        elif sign_options is None:
            raise ValueError("sign_options is required when signing requests")
        if mode is SignatureHooksMode.SIGN_REQUEST:
            if verify_options is not None:
                raise ValueError("Verification configuration is not allowed in SIGN_REQUEST mode")
        elif verify_options is None:
            raise ValueError("verify_options is required when verifying responses")
        self.mode = mode
        self.signer: HTTPMessageSigner | None = None
        self.verifier: HTTPMessageVerifier | None = None
        self._sign_origin: tuple[str, str, int | None] | None = None
        self._verify_origin: tuple[str, str, int | None] | None = None
        self._sign_kwargs: dict[str, Any] = {}
        self._verify_kwargs: dict[str, Any] = {}
        self._signing_marker = object()
        if sign_options is not None:
            self._configure_signing(**sign_options)
        if verify_options is not None:
            self._configure_verification(**verify_options)

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

    @staticmethod
    def _parse_origin(origin: str) -> tuple[str, str, int | None]:
        url = httpx2.URL(origin)
        if (
            not url.is_absolute_url
            or url.scheme not in {"http", "https"}
            or url.path != "/"
            or url.query
            or url.fragment
            or url.userinfo
        ):
            raise ValueError("origin must be an HTTP origin without a path, query, fragment, or credentials")
        return url.scheme, url.host, url.port

    @cached_property
    def event_hooks(self) -> dict[str, list[Callable[..., None]]]:
        """Mutable hook lists for ``httpx2.Client``."""
        return {
            "request": [self.sign_request] if self.signer is not None else [],
            "response": [self.verify_response] if self.verifier is not None else [],
        }

    @cached_property
    def async_event_hooks(self) -> dict[str, list[Callable[..., Awaitable[None]]]]:
        """Mutable async hook lists for ``httpx2.AsyncClient``."""
        return {
            "request": [self.sign_request_async] if self.signer is not None else [],
            "response": [self.verify_response_async] if self.verifier is not None else [],
        }

    @staticmethod
    def _check_origin(request: httpx2.Request, origin: tuple[str, str, int | None] | None) -> None:
        url = request.url
        if (url.scheme, url.host, url.port) != origin:
            raise HTTPMessageSignaturesException("Request origin is not authorized for these signature keys")

    def sign_request(self, request: httpx2.Request) -> None:
        """Buffer and sign a prepared request, including its current body."""
        if self.signer is None:
            raise HTTPMessageSignaturesException("Request signing is disabled in this mode")
        self._check_origin(request, self._sign_origin)
        body = request.read()
        self._sign(request, body, self.signer)

    async def sign_request_async(self, request: httpx2.Request) -> None:
        """Async request hook; await body consumption before signing."""
        if self.signer is None:
            raise HTTPMessageSignaturesException("Request signing is disabled in this mode")
        self._check_origin(request, self._sign_origin)
        body = await request.aread()
        self._sign(request, body, self.signer)

    def _sign(self, request: httpx2.Request, body: bytes, signer: HTTPMessageSigner) -> None:
        options = self._sign_kwargs
        if request.extensions.get("http_message_signatures.signer") is self._signing_marker:
            options = {"allow_existing_digest": True, **options}
        signer.sign(adapt_message(request), body=body, **options)
        request.extensions["http_message_signatures.signer"] = self._signing_marker

    def _verify_headers(self, response: httpx2.Response, verifier: HTTPMessageVerifier):
        response.extensions.pop("http_message_signatures", None)
        self._check_origin(response.request, self._verify_origin)
        message = adapt_message(response)
        return message, verifier.verify(message, **self._verify_kwargs)

    @staticmethod
    def _buffered_body(response: httpx2.Response) -> bytes:
        if response.headers.get("content-encoding", "identity").strip().lower() != "identity":
            raise InvalidSignature("Encoded response was already consumed; verify before reading or decoding its body")
        return response.content

    def verify_response(self, response: httpx2.Response) -> None:
        """Authenticate headers and the complete encoded body before returning."""
        verifier = self.verifier
        if verifier is None:
            raise HTTPMessageSignaturesException("Response verification is disabled in this mode")
        try:
            message, results = self._verify_headers(response, verifier)
            if response.is_stream_consumed:
                verified = verifier.verify_body(message, results, self._buffered_body(response))
            else:
                if not isinstance(response.stream, httpx2.SyncByteStream):
                    raise TypeError("Use async_event_hooks with an asynchronous response stream")
                stream = _SyncVerifiedStream(response.stream, lambda body: verifier.verify_body(message, results, body))
                response.stream = stream
                response.read()
                verified = stream.results
            response.extensions["http_message_signatures"] = verified
        except BaseException:
            response.close()
            raise

    async def verify_response_async(self, response: httpx2.Response) -> None:
        """Async response hook with the same buffering and verification contract."""
        verifier = self.verifier
        if verifier is None:
            raise HTTPMessageSignaturesException("Response verification is disabled in this mode")
        try:
            message, results = self._verify_headers(response, verifier)
            if response.is_stream_consumed:
                verified = verifier.verify_body(message, results, self._buffered_body(response))
            else:
                if not isinstance(response.stream, httpx2.AsyncByteStream):
                    raise TypeError("Use event_hooks with a synchronous response stream")
                stream = _AsyncVerifiedStream(
                    response.stream, lambda body: verifier.verify_body(message, results, body)
                )
                response.stream = stream
                await response.aread()
                verified = stream.results
            response.extensions["http_message_signatures"] = verified
        except BaseException:
            await response.aclose()
            raise
