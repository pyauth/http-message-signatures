"""Buffered request signing and response verification for HTTPX."""

from collections.abc import Awaitable, Callable, Mapping
from inspect import Parameter, signature
from io import BytesIO
from typing import Any, overload

import httpx

from .algorithms import HTTPSignatureAlgorithm
from .exceptions import HTTPMessageSignaturesException, InvalidSignature
from .messages import HeaderFields, Request, Response
from .resolvers import MappingKeyResolver, SigningKey, VerificationKey
from .signatures import HTTPMessageSigner, HTTPMessageVerifier


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
    """Sign requests and verify responses through paired HTTPX event hooks.

    :param origin: HTTP origin allowed to use these keys, including its scheme
        and port. Other destinations, including redirects, fail before sending.
    :param key_id: Signing key ID, passed to the base signer.
    :param signing_key: PEM bytes, a cryptography private key, or HMAC secret bytes.
    :param verification_keys: Mapping of trusted response key IDs to public keys
        or HMAC secrets. No key is inferred from the signing key or fetched remotely.
    :param signature_algorithm: Algorithm class, required as in the base API.
    :param options: Keyword options of ``HTTPMessageSigner.sign()`` or
        ``HTTPMessageVerifier.verify()``. Unspecified options are not forwarded;
        the base methods own their defaults. ``tag`` also supplies ``expect_tag``
        unless the latter is explicitly provided. ``body`` is managed by the hooks.
        Unknown options raise ``TypeError`` during construction.

    Install ``event_hooks`` on Client or ``async_event_hooks`` on AsyncClient.
    Signing belongs after request-mutating hooks; verification belongs before
    response consumers. Requests and responses are buffered, even with stream().
    Requests with an existing Content-Digest are rejected, including redirected
    requests that inherit that field. Build a fresh request to follow a redirect.
    Response content is captured before decoding for digest validation; normal
    HTTPX content decoding is preserved. Successful verification results are
    stored in ``response.extensions["http_message_signatures"]``.

    Nonempty responses and responses with Content-Digest require signed digest
    coverage. Other coverage is controlled by the base ``require_components``
    option. No nonce, expiration, status, or request-binding policy is added.

    HTTPX stores cookies before response hooks. Failed verification does not undo
    cookie changes, so these hooks do not authenticate the client's cookie jar.
    """

    signer_class: type[HTTPMessageSigner] = HTTPMessageSigner
    verifier_class: type[HTTPMessageVerifier] = HTTPMessageVerifier

    def __init__(
        self,
        *,
        origin: str,
        key_id: str,
        signing_key: SigningKey,
        verification_keys: Mapping[str, VerificationKey],
        signature_algorithm: type[HTTPSignatureAlgorithm],
        **options: Any,
    ) -> None:
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
        self.key_id = key_id
        keys = MappingKeyResolver(public_keys=verification_keys, private_keys={key_id: signing_key})
        self.signer = self.signer_class(signature_algorithm=signature_algorithm, key_resolver=keys)
        self.verifier = self.verifier_class(signature_algorithm=signature_algorithm, key_resolver=keys)
        # Use the base methods' keyword names, never copy their default values.
        signing_names = self._option_names(self.signer.sign, HTTPMessageSigner.sign) - {"body", "key_id"}
        verifying_names = self._option_names(self.verifier.verify, HTTPMessageVerifier.verify) - {"body"}
        unknown = options.keys() - (signing_names | verifying_names)
        if unknown:
            raise TypeError(f"Unknown signature option(s): {', '.join(sorted(unknown))}")
        self.signing_options = {name: value for name, value in options.items() if name in signing_names}
        self.verification_options = {name: value for name, value in options.items() if name in verifying_names}
        if "tag" in options and "expect_tag" not in options:
            self.verification_options["expect_tag"] = options["tag"]

    @staticmethod
    def _option_names(method: Callable[..., Any], base_method: Callable[..., Any]) -> set[str]:
        parameters = signature(method).parameters
        names = {name for name, parameter in parameters.items() if parameter.kind == Parameter.KEYWORD_ONLY}
        if any(parameter.kind == Parameter.VAR_KEYWORD for parameter in parameters.values()):
            names.update(
                name
                for name, parameter in signature(base_method).parameters.items()
                if parameter.kind == Parameter.KEYWORD_ONLY
            )
        return names

    @property
    def event_hooks(self) -> dict[str, list[Callable[..., None]]]:
        """Fresh hook lists for ``httpx.Client``."""
        return {"request": [self.sign_request], "response": [self.verify_response]}

    @property
    def async_event_hooks(self) -> dict[str, list[Callable[..., Awaitable[None]]]]:
        """Fresh async hook lists for ``httpx.AsyncClient``."""
        return {"request": [self.sign_request_async], "response": [self.verify_response_async]}

    def _check_origin(self, request: httpx.Request) -> None:
        url = request.url
        if (url.scheme, url.host, url.port) != self.origin:
            raise HTTPMessageSignaturesException("Request origin is not authorized for these signature keys")

    def sign_request(self, request: httpx.Request) -> None:
        """Buffer and sign a prepared request, including its current body."""
        self._check_origin(request)
        body = request.read()
        self.signer.sign(adapt_message(request), key_id=self.key_id, body=body, **self.signing_options)

    async def sign_request_async(self, request: httpx.Request) -> None:
        """Async request hook; await body consumption before signing."""
        self._check_origin(request)
        body = await request.aread()
        self.signer.sign(adapt_message(request), key_id=self.key_id, body=body, **self.signing_options)

    def _verify_headers(self, response: httpx.Response):
        response.extensions.pop("http_message_signatures", None)
        self._check_origin(response.request)
        message = adapt_message(response)
        return message, self.verifier.verify(message, **self.verification_options)

    @staticmethod
    def _buffered_body(response: httpx.Response) -> bytes:
        if response.headers.get("content-encoding", "identity").strip().lower() != "identity":
            raise InvalidSignature("Encoded response was already consumed; verify before reading or decoding its body")
        return response.content

    def verify_response(self, response: httpx.Response) -> None:
        """Authenticate headers and the complete encoded body before returning."""
        try:
            message, results = self._verify_headers(response)
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
        try:
            message, results = self._verify_headers(response)
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
