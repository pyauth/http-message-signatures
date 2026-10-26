"""Buffered request signing and response verification for HTTPX2."""

from collections.abc import Awaitable, Callable
from enum import Enum
from functools import cached_property
from io import BytesIO
from typing import overload

import httpx2

from ._integrations import _SignatureAdapter, _SigningOptions, _VerificationOptions
from ._messages import _HeaderFields, _Request, _Response
from .exceptions import HTTPMessageSignaturesException, InvalidSignature
from .signatures import HTTPMessageSigner, HTTPMessageVerifier
from .structures import VerifyResult


class SigningOptions(_SigningOptions):
    """Configuration for request signing with SignatureHooks.

    ``origin``, ``signature_algorithm``, ``key_id``, and ``key_resolver`` are
    required. Other entries are optional ``HTTPMessageSigner.sign()`` keywords.
    SignatureHooks supplies ``body``; ``HTTPMessageSigner.sign()`` supplies defaults for omitted options.
    """


class VerificationOptions(_VerificationOptions):
    """Configuration for response verification with SignatureHooks.

    ``origin``, ``signature_algorithm``, and ``key_resolver`` are required.
    Other entries are optional ``HTTPMessageVerifier.verify()`` keywords.
    SignatureHooks supplies ``body``; ``HTTPMessageVerifier.verify()`` supplies defaults for omitted options.
    """


class SignatureHooksMode(Enum):
    """Operations installed by the synchronous and asynchronous hook collections."""

    SIGN_REQUEST = "sign_request"
    VERIFY_RESPONSE = "verify_response"
    SIGN_REQUEST_VERIFY_RESPONSE = "sign_request_verify_response"


@overload
def adapt_message(message: httpx2.Request) -> _Request: ...


@overload
def adapt_message(message: httpx2.Response) -> _Response: ...


def adapt_message(message: httpx2.Request | httpx2.Response) -> _Request | _Response:
    """This function exposes original header lines to the base signer/verifier.

    Header writes reach the original message. Response request components use
    the same adapter. Use this for direct base-API calls on HTTPX2 objects;
    SignatureHooks applies it automatically. A response must have a request.
    """
    headers = _HeaderFields.from_raw(lambda: message.headers.raw, writable=message.headers)
    if isinstance(message, httpx2.Request):
        return _Request(method=message.method, url=str(message.url), headers=headers)
    return _Response(status_code=message.status_code, headers=headers, request=adapt_message(message.request))


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


class SignatureHooks(_SignatureAdapter):
    """Sign requests, verify responses, or both through HTTPX2 event hooks.

    :param mode: Operations to enable; defaults to signing and verification.
    :param sign_options: SigningOptions containing ``origin``,
        ``signature_algorithm``, ``key_id``, and ``key_resolver``, plus optional
        ``HTTPMessageSigner.sign()`` keywords. Required when signing requests.
    :param verify_options: VerificationOptions containing ``origin``,
        ``signature_algorithm``, and ``key_resolver``, plus optional
        ``HTTPMessageVerifier.verify()`` keywords. Required when verifying responses.
    :ivar signer: Configured HTTPMessageSigner, or None when signing is disabled.
    :ivar verifier: Configured HTTPMessageVerifier, or None when verification is disabled.
    :cvar signer_class: Subclasses may override the HTTPMessageSigner class used by the hooks.
    :cvar verifier_class: Subclasses may override the HTTPMessageVerifier class used by the hooks.

    Each origin is an HTTP origin including its scheme and port. The signing hook
    checks the request's origin before HTTPX2 sends it; the verification hook checks
    it when the response arrives. The hooks pass each configured algorithm and key
    resolver to the corresponding signer or verifier. The signer and verifier look
    up keys when processing each message, using the HTTPSignatureKeyResolver interface.
    Key loading, caching, and trust policy belong to the supplied resolver.

    The constructor copies the option dictionaries and their component sequences.
    The hooks forward supplied options, including explicit ``None``, to the
    corresponding base methods. Those methods supply defaults for omitted options
    and raise ``TypeError`` for unknown keywords when the hook runs.
    Set ``expect_tag`` separately from the signing ``tag``.
    The constructor raises ``ValueError`` for missing option dictionaries or
    dictionaries for disabled operations, and ``TypeError`` for missing required
    entries. It constructs only enabled handlers. The hooks supply ``body`` for
    both operations.

    Pass ``event_hooks`` to Client or ``async_event_hooks`` to AsyncClient.
    Each collection contains only the operations enabled by ``mode``.
    Place the signing hook after hooks that modify requests, and the verification
    hook before hooks that consume responses. The signing hook buffers requests;
    the verification hook buffers responses, even when you use ``stream()``.
    The signing hook rejects a supplied Content-Digest unless you configure
    ``use_existing_digest=True``. It allows digest reuse on retries and redirects
    for requests previously signed by the same hooks, unless you explicitly set
    that option to ``False``. It validates reused digests against the current body.
    If you change the body, remove or replace its existing digest before signing again.
    The verification hook buffers and verifies response content before HTTPX2 decodes
    it, preserving normal HTTPX2 content decoding. The hook stores successful results
    in ``response.extensions["http_message_signatures"]``.

    The verification hook requires signed digest coverage for nonempty responses
    and responses with Content-Digest. Use ``require_components`` to require other
    coverage. The hooks add no nonce, expiration, status, or request-binding policy
    beyond the base verifier's checks and your configuration.

    HTTPX2 stores cookies before response hooks. Failed verification does not undo
    cookie changes, so these hooks do not authenticate the client's cookie jar.
    """

    def __init__(
        self,
        mode: SignatureHooksMode = SignatureHooksMode.SIGN_REQUEST_VERIFY_RESPONSE,
        *,
        sign_options: SigningOptions | None = None,
        verify_options: VerificationOptions | None = None,
    ) -> None:
        if not isinstance(mode, SignatureHooksMode):
            raise TypeError("mode must be a SignatureHooksMode")
        super().__init__(
            sign_requests=mode is not SignatureHooksMode.VERIFY_RESPONSE,
            verify_responses=mode is not SignatureHooksMode.SIGN_REQUEST,
            sign_options=sign_options,
            verify_options=verify_options,
        )
        self.mode = mode
        self._signing_marker = object()

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
        """This hook buffers and signs a prepared request, including its current body."""
        if self.signer is None:
            raise HTTPMessageSignaturesException("Request signing is disabled in this mode")
        self._check_origin(request, self._sign_origin)
        body = request.read()
        self._sign(request, body, self.signer)

    async def sign_request_async(self, request: httpx2.Request) -> None:
        """This async hook reads the complete request body before signing the request."""
        if self.signer is None:
            raise HTTPMessageSignaturesException("Request signing is disabled in this mode")
        self._check_origin(request, self._sign_origin)
        body = await request.aread()
        self._sign(request, body, self.signer)

    def _sign(self, request: httpx2.Request, body: bytes, signer: HTTPMessageSigner) -> None:
        options = self._sign_kwargs
        if request.extensions.get("http_message_signatures.signer") is self._signing_marker:
            options = {"use_existing_digest": True, **options}
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
        """This hook verifies headers and the complete encoded body before returning."""
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
