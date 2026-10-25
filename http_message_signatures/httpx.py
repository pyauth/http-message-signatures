"""Buffered request signing and response verification for HTTPX."""

from collections.abc import Awaitable, Callable, Mapping, Sequence
from datetime import datetime, timedelta
from enum import Enum
from io import BytesIO
from typing import TypedDict, overload

import httpx

from .algorithms import HTTPSignatureAlgorithm
from .exceptions import HTTPMessageSignaturesException, InvalidSignature
from .messages import HeaderFields, Request, Response
from .resolvers import MappingKeyResolver, SigningKey, VerificationKey
from .signatures import HTTPMessageSigner, HTTPMessageVerifier


class SignatureHooksMode(Enum):
    """Operations installed by the synchronous and asynchronous hook collections."""

    SIGN_REQUEST = "sign_request"
    VERIFY_RESPONSE = "verify_response"
    SIGN_REQUEST_VERIFY_RESPONSE = "sign_request_verify_response"


class SigningOptions(TypedDict, total=False):
    """Optional keywords for request signing; omitted keys use signer defaults.

    ``key_id`` is supplied separately to SignatureHooks, which manages ``body``.
    """

    created: datetime | None
    expires: datetime | None
    nonce: str | None
    label: str | None
    tag: str | None
    include_alg: bool
    covered_component_ids: Sequence[str]
    append_if_signature_exists: bool


class VerificationOptions(TypedDict, total=False):
    """Optional keywords for response verification; omitted keys use verifier defaults.

    SignatureHooks manages ``body``. No options are inferred from SigningOptions.
    """

    max_age: timedelta | None
    expect_tag: str | None
    expect_label: str | None
    require_components: Sequence[str]


@overload
def adapt_message(message: httpx.Request) -> Request: ...


@overload
def adapt_message(message: httpx.Response) -> Response: ...


def adapt_message(message: httpx.Request | httpx.Response) -> Request | Response:
    """Expose original header lines to the base signer/verifier.

    Header writes reach the original message. Response request components use
    the same adapter. Use this for direct base-API calls on HTTPX objects;
    SignatureHooks applies it automatically. A response must have a request.
    """
    headers = HeaderFields.from_raw(lambda: message.headers.raw, writable=message.headers)
    if isinstance(message, httpx.Request):
        return Request(method=message.method, url=str(message.url), headers=headers)
    return Response(status_code=message.status_code, headers=headers, request=adapt_message(message.request))


class _SyncCapture(httpx.SyncByteStream):
    def __init__(self, stream: httpx.SyncByteStream, content: BytesIO):
        self.stream = stream
        self.content = content

    def __iter__(self):
        for chunk in self.stream:
            self.content.write(chunk)
            yield chunk

    def close(self):
        self.stream.close()


class _AsyncCapture(httpx.AsyncByteStream):
    def __init__(self, stream: httpx.AsyncByteStream, content: BytesIO):
        self.stream = stream
        self.content = content

    async def __aiter__(self):
        async for chunk in self.stream:
            self.content.write(chunk)
            yield chunk

    async def aclose(self):
        await self.stream.aclose()


class SignatureHooks:
    """Sign requests, verify responses, or both through HTTPX event hooks.

    :param mode: Operations to enable; defaults to signing and verification.
    :param origin: HTTP origin allowed to use these keys, including its scheme
        and port. Signing checks it before sending; verification checks it when
        the response arrives.
    :param key_id: Signing key ID, required only when signing requests.
    :param signing_key: PEM bytes, a cryptography private key, or HMAC secret bytes;
        required only when signing requests.
    :param verification_keys: Mapping of trusted response key IDs to public keys
        or HMAC secrets. No key is inferred from the signing key or fetched remotely.
        Required only when verifying responses.
    :param signature_algorithm: Algorithm class, required as in the base API.
    :param sign_options: Dictionary of optional ``HTTPMessageSigner.sign()``
        keywords, typed by SigningOptions. ``key_id`` and ``body`` are managed
        by the hooks.
    :param verify_options: Dictionary of optional ``HTTPMessageVerifier.verify()``
        keywords, typed by VerificationOptions. ``body`` is managed by the hooks.

    The option dictionaries are shallow-copied and forwarded independently.
    Omitted keys use the underlying method defaults; explicit ``None`` is passed
    through. Set ``expect_tag`` separately from the signing ``tag``. Unknown
    keywords raise ``TypeError`` from the underlying method when its hook runs.
    Missing credentials or configuration for a disabled operation raise
    ``ValueError`` at construction. Disabled handlers are not constructed.

    Install ``event_hooks`` on Client or ``async_event_hooks`` on AsyncClient.
    Each collection installs only the operations enabled by ``mode``.
    Signing belongs after request-mutating hooks; verification belongs before
    response consumers. Signing buffers requests and verification buffers responses,
    even with stream().
    Signing rejects requests with an existing Content-Digest, including redirected
    requests that inherit that field. Build a fresh request to follow a redirect.
    Response content is captured before decoding for digest validation; normal
    HTTPX content decoding is preserved. Successful verification results are
    stored in ``response.extensions["http_message_signatures"]``.

    When verifying, nonempty responses and responses with Content-Digest require signed digest
    coverage. Other coverage is controlled by the base ``require_components``
    option. No nonce, expiration, status, or request-binding policy is added.

    HTTPX stores cookies before response hooks. Failed verification does not undo
    cookie changes, so these hooks do not authenticate the client's cookie jar.
    """

    signer_class: type[HTTPMessageSigner] = HTTPMessageSigner
    verifier_class: type[HTTPMessageVerifier] = HTTPMessageVerifier

    def __init__(
        self,
        mode: SignatureHooksMode = SignatureHooksMode.SIGN_REQUEST_VERIFY_RESPONSE,
        *,
        origin: str,
        signature_algorithm: type[HTTPSignatureAlgorithm],
        key_id: str | None = None,
        signing_key: SigningKey | None = None,
        verification_keys: Mapping[str, VerificationKey] | None = None,
        sign_options: SigningOptions | None = None,
        verify_options: VerificationOptions | None = None,
    ) -> None:
        if not isinstance(mode, SignatureHooksMode):
            raise TypeError("mode must be a SignatureHooksMode")
        if mode is SignatureHooksMode.VERIFY_RESPONSE:
            if key_id is not None or signing_key is not None or sign_options is not None:
                raise ValueError("Signing configuration is not allowed in VERIFY_RESPONSE mode")
        elif key_id is None or signing_key is None:
            raise ValueError("key_id and signing_key are required when signing requests")
        if mode is SignatureHooksMode.SIGN_REQUEST:
            if verification_keys is not None or verify_options is not None:
                raise ValueError("Verification configuration is not allowed in SIGN_REQUEST mode")
        elif verification_keys is None:
            raise ValueError("verification_keys is required when verifying responses")
        url = httpx.URL(origin)
        if (
            not url.is_absolute_url
            or url.scheme not in {"http", "https"}
            or url.path != "/"
            or url.query
            or url.fragment
            or url.userinfo
        ):
            raise ValueError("origin must be an HTTP origin without a path, query, fragment, or credentials")
        self.origin = (url.scheme, url.host, url.port)
        self.mode = mode
        self.key_id = key_id
        self.signer: HTTPMessageSigner | None = None
        self.verifier: HTTPMessageVerifier | None = None
        if key_id is not None and signing_key is not None:
            keys = MappingKeyResolver(public_keys={}, private_keys={key_id: signing_key})
            self.signer = self.signer_class(signature_algorithm=signature_algorithm, key_resolver=keys)
        if verification_keys is not None:
            keys = MappingKeyResolver(public_keys=verification_keys, private_keys={})
            self.verifier = self.verifier_class(signature_algorithm=signature_algorithm, key_resolver=keys)
        self.sign_options: SigningOptions = sign_options.copy() if sign_options is not None else {}
        self.verify_options: VerificationOptions = verify_options.copy() if verify_options is not None else {}

    @property
    def event_hooks(self) -> dict[str, list[Callable[..., None]]]:
        """Fresh hook lists for ``httpx.Client``."""
        return {
            "request": [self.sign_request] if self.signer is not None else [],
            "response": [self.verify_response] if self.verifier is not None else [],
        }

    @property
    def async_event_hooks(self) -> dict[str, list[Callable[..., Awaitable[None]]]]:
        """Fresh async hook lists for ``httpx.AsyncClient``."""
        return {
            "request": [self.sign_request_async] if self.signer is not None else [],
            "response": [self.verify_response_async] if self.verifier is not None else [],
        }

    def _check_origin(self, request: httpx.Request) -> None:
        url = request.url
        if (url.scheme, url.host, url.port) != self.origin:
            raise HTTPMessageSignaturesException("Request origin is not authorized for these signature keys")

    def sign_request(self, request: httpx.Request) -> None:
        """Buffer and sign a prepared request, including its current body."""
        if self.signer is None or self.key_id is None:
            raise HTTPMessageSignaturesException("Request signing is disabled in this mode")
        self._check_origin(request)
        body = request.read()
        self.signer.sign(adapt_message(request), key_id=self.key_id, body=body, **self.sign_options)

    async def sign_request_async(self, request: httpx.Request) -> None:
        """Async request hook; await body consumption before signing."""
        if self.signer is None or self.key_id is None:
            raise HTTPMessageSignaturesException("Request signing is disabled in this mode")
        self._check_origin(request)
        body = await request.aread()
        self.signer.sign(adapt_message(request), key_id=self.key_id, body=body, **self.sign_options)

    def _verify_headers(self, response: httpx.Response, verifier: HTTPMessageVerifier):
        response.extensions.pop("http_message_signatures", None)
        self._check_origin(response.request)
        message = adapt_message(response)
        return message, verifier.verify(message, **self.verify_options)

    @staticmethod
    def _buffered_body(response: httpx.Response) -> bytes:
        if response.headers.get("content-encoding", "identity").strip().lower() != "identity":
            raise InvalidSignature("Encoded response was already consumed; verify before reading or decoding its body")
        return response.content

    def verify_response(self, response: httpx.Response) -> None:
        """Authenticate headers and the complete encoded body before returning."""
        if self.verifier is None:
            raise HTTPMessageSignaturesException("Response verification is disabled in this mode")
        try:
            message, results = self._verify_headers(response, self.verifier)
            if response.is_stream_consumed:
                body = self._buffered_body(response)
            else:
                if not isinstance(response.stream, httpx.SyncByteStream):
                    raise TypeError("Use async_event_hooks with an asynchronous response stream")
                with BytesIO() as content:
                    response.stream = _SyncCapture(response.stream, content)
                    response.read()
                    body = content.getvalue()
            response.extensions["http_message_signatures"] = self.verifier.verify_body(message, results, body)
        except BaseException:
            response.close()
            raise

    async def verify_response_async(self, response: httpx.Response) -> None:
        """Async response hook with the same buffering and verification contract."""
        if self.verifier is None:
            raise HTTPMessageSignaturesException("Response verification is disabled in this mode")
        try:
            message, results = self._verify_headers(response, self.verifier)
            if response.is_stream_consumed:
                body = self._buffered_body(response)
            else:
                if not isinstance(response.stream, httpx.AsyncByteStream):
                    raise TypeError("Use event_hooks with a synchronous response stream")
                with BytesIO() as content:
                    response.stream = _AsyncCapture(response.stream, content)
                    await response.aread()
                    body = content.getvalue()
            response.extensions["http_message_signatures"] = self.verifier.verify_body(message, results, body)
        except BaseException:
            await response.aclose()
            raise
