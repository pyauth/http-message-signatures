"""Buffered HTTP message signatures for aiohttp clients and servers."""

import asyncio
from contextvars import ContextVar
from dataclasses import dataclass
from enum import Enum
from io import BytesIO
from typing import Any, TypedDict, cast
from weakref import WeakKeyDictionary, WeakSet

import aiohttp
from aiohttp import web
from aiohttp.abc import AbstractStreamWriter
from aiohttp.base_protocol import BaseProtocol
from aiohttp.compression_utils import ZLibCompressor
from aiohttp.helpers import must_be_empty_body
from aiohttp.http_exceptions import ContentEncodingError
from aiohttp.http_parser import HeadersParser, HttpPayloadParser, HttpResponseParser, HttpResponseParserPy
from aiohttp.payload import BytesPayload, JsonPayload, Payload, StringPayload
from aiohttp.streams import EmptyStreamReader
from aiohttp.typedefs import Handler, Middleware
from multidict import CIMultiDict
from yarl import URL

from ._integrations import (
    _BaseSigningOptions,
    _BaseVerificationOptions,
    _SignatureAdapter,
    _SignatureConfiguration,
    _SigningOptions,
    _VerificationOptions,
)
from ._messages import _HeaderFields, _Request, _Response
from .exceptions import HTTPMessageSignaturesException, InvalidSignature
from .structures import VerifyResult


class SigningOptions(_SigningOptions):
    """Configuration for request signing with SignatureMiddleware.

    ``origin``, ``signature_algorithm``, ``key_id``, and ``key_resolver`` are
    required. Other entries are optional ``HTTPMessageSigner.sign()`` keywords.
    SignatureMiddleware supplies ``body``; ``HTTPMessageSigner.sign()`` supplies defaults for omitted options.
    """


class VerificationOptions(_VerificationOptions):
    """Configuration for response verification with SignatureMiddleware.

    ``origin``, ``signature_algorithm``, and ``key_resolver`` are required.
    Other entries are optional ``HTTPMessageVerifier.verify()`` keywords.
    SignatureMiddleware supplies ``body``; ``HTTPMessageVerifier.verify()`` supplies defaults for omitted options.
    """


class SignatureMiddlewareMode(Enum):
    """Operations that SignatureMiddleware performs for each request and response."""

    SIGN_REQUEST = "sign_request"
    VERIFY_RESPONSE = "verify_response"
    SIGN_REQUEST_VERIFY_RESPONSE = "sign_request_verify_response"


class _SessionOptions(TypedDict, total=False):
    middlewares: tuple[aiohttp.ClientMiddlewareType, ...]
    auto_decompress: bool


class _BodyWriter(AbstractStreamWriter):
    def __init__(self, content: BytesIO, compressor: ZLibCompressor | None = None):
        self.content = content
        self.compressor = compressor

    async def write(self, chunk: bytes | bytearray | memoryview) -> None:
        if self.compressor is not None:
            chunk = await self.compressor.compress(chunk)
        self.content.write(chunk)

    async def write_eof(self, chunk: bytes = b"") -> None:
        await self.write(chunk)

    async def drain(self) -> None:
        pass

    def enable_compression(self, encoding: str = "deflate", strategy: int | None = None) -> None:
        raise HTTPMessageSignaturesException("Payloads must apply content encoding before signing")

    def enable_chunking(self) -> None:
        raise HTTPMessageSignaturesException("Payloads must leave HTTP framing to aiohttp")

    async def write_headers(self, status_line: str, headers: CIMultiDict[str]) -> None:
        raise HTTPMessageSignaturesException("Payloads must leave HTTP headers to aiohttp")


class _CompressedPayload(BytesPayload):
    def __init__(self, body: bytes, content_encoding: str, headers: CIMultiDict[str]):
        super().__init__(body, headers=headers)
        self.content_encoding = content_encoding


async def _buffer_request(request: aiohttp.ClientRequest) -> bytes:
    payload = request.body
    if isinstance(payload, _CompressedPayload):
        # Redirects reuse the payload but reapply the original compress argument.
        # Keep the encoded bytes and disable compression on the new request too.
        request.compress = None
        request.headers["Content-Encoding"] = payload.content_encoding
        return await payload.as_bytes()

    # aiohttp resolves compress=True to an encoding name before middleware runs.
    encoding = cast(str, request.compress) if request.compress else None
    compressor = ZLibCompressor(encoding=encoding) if encoding else None
    # Use aiohttp's validation and the same limit as ClientRequest.write_bytes().
    content_length = request._get_content_length()
    if not encoding and type(payload) in (BytesPayload, StringPayload, JsonPayload):
        # These native payloads write their stored bytes, limited by Content-Length.
        # Custom payloads must still run their writer; mutable inputs must be copied.
        body = await cast(BytesPayload, payload).as_bytes()
        if isinstance(body, bytes):
            return body if content_length is None else body[:content_length]
    with BytesIO() as content:
        writer = _BodyWriter(content, compressor)
        if isinstance(payload, Payload):
            await payload.write_with_length(writer, content_length)
        else:
            await writer.write(payload)
        if compressor is not None:
            # Flush only after successful writes; cancellation discards this compressor.
            content.write(compressor.flush())
        body = content.getvalue()

    if encoding:
        headers = payload.headers if isinstance(payload, Payload) else CIMultiDict()
        await request.update_body(_CompressedPayload(body, encoding, headers))
        request.compress = None
    elif isinstance(payload, Payload):
        await request.update_body(BytesPayload(body, headers=payload.headers))
        if content_length is not None:
            request.headers["Content-Length"] = str(content_length)
    return body


class _BufferedProtocol(BaseProtocol):
    # Replaying buffered content must not pause or resume the original connection,
    # which aiohttp may already have returned to the pool.
    def pause_reading(self) -> None:
        pass

    def resume_reading(self, resume_parser: bool = True) -> None:
        pass


class _DecodedStream(aiohttp.StreamReader):
    def __init__(self, limit: int, max_size: int):
        loop = asyncio.get_running_loop()
        super().__init__(_BufferedProtocol(loop), limit, loop=loop)
        self._max_size = max_size

    def feed_data(self, data: bytes, size: int = 0) -> bool:
        size = self.total_bytes + len(data)
        if self._max_size and size > self._max_size:
            raise web.HTTPRequestEntityTooLarge(max_size=self._max_size, actual_size=size)
        return super().feed_data(data)


async def _decoded_content(
    message: aiohttp.ClientResponse | web.Request, body: bytes, *, max_size: int = 0
) -> aiohttp.StreamReader:
    # aiohttp has no public method for decompressing a body after reading it.
    # HttpPayloadParser decompresses the verified bytes into a new StreamReader;
    # aiohttp has already removed HTTP chunk framing.
    limit, _ = message.content.get_read_buffer_limits()
    content = _DecodedStream(min(limit, max_size) if max_size else limit, max_size)
    # Match the active aiohttp parser: Python selects the first field, C the last.
    encodings = message.headers.getall("Content-Encoding", ("",))
    encoding = encodings[0 if HttpResponseParser is HttpResponseParserPy else -1].lower()
    decode = encoding in {"gzip", "deflate", "br", "zstd"}
    try:
        parser = HttpPayloadParser(
            content,
            compression=encoding,
            auto_decompress=decode,
            headers_parser=HeadersParser(),
        )
        if decode:
            # Bound the input suffix that decompression may copy between output chunks.
            for offset in range(0, len(body), 65536):
                parser.feed_data(body[offset : offset + 65536])
                await asyncio.sleep(0)
        else:
            parser.feed_data(body)
        parser.feed_eof()
    except ContentEncodingError as exc:
        if isinstance(message, web.Request):
            raise web.HTTPBadRequest(text=str(exc)) from exc
        raise aiohttp.ClientPayloadError(str(exc)) from exc
    return content


class _ProxyRequest(_Request):
    @property
    def request_target(self) -> str:
        return self.url


def _request_view(request: aiohttp.ClientRequest) -> _Request:
    # aiohttp writes header values as UTF-8. This adapter converts those bytes
    # to Latin-1 strings so HTTPSignatureComponentResolver can recover them
    # for ;bs coverage.
    headers = _outgoing_headers(request.headers)
    # ClientRequest.send() uses absolute form for HTTP forward proxies;
    # HTTPS tunnels and CONNECT retain the resolver's normal target forms.
    view = _ProxyRequest if request.proxy and not request.is_ssl() and request.method != "CONNECT" else _Request
    return view(method=request.method, url=str(request.url), headers=headers)


def _outgoing_headers(headers: CIMultiDict[str]) -> _HeaderFields:
    return _HeaderFields(
        lambda: ((name, value.encode("utf-8", "surrogateescape").decode("latin-1")) for name, value in headers.items()),
        writable=headers,
    )


class SignatureMiddleware(_SignatureAdapter):
    """aiohttp middleware for signing requests, verifying responses, or both.

    :param mode: Operations that the middleware performs; defaults to both.
    :param sign_options: SigningOptions dictionary for enabled request signing.
    :param verify_options: VerificationOptions dictionary for enabled response verification.
    :ivar signer: Configured HTTPMessageSigner, or None when signing is disabled.
    :ivar verifier: Configured HTTPMessageVerifier, or None when verification is disabled.
    :cvar signer_class: Subclasses may override the HTTPMessageSigner class used by the middleware.
    :cvar verifier_class: Subclasses may override the HTTPMessageVerifier class used by the middleware.

    Pass ``**middleware.session_kwargs`` to ``aiohttp.ClientSession``. Place this
    middleware last: it signs outgoing changes and verifies responses before
    other middleware reads them. Keep ``auto_decompress=False`` when verifying;
    aiohttp must leave content encoded until verification succeeds.

    The middleware buffers complete bodies without a size limit. It supports
    aiohttp's ``compress=`` request option and restores decoded response content
    for the usual aiohttp readers. Replay uses aiohttp's internal payload parser
    and discards HTTP chunk boundaries.

    Each enabled operation restricts requests and redirects to its configured
    origin. The base signer and verifier supply omitted signature defaults.
    Existing digests require ``use_existing_digest=True`` and must match the body.
    The middleware permits reuse on retries of the same request unless explicitly
    disabled. Use ``require_components`` for coverage beyond the body digest.

    Failed verification closes the response before cookie-jar updates. Authenticating
    cookies also requires ``'"set-cookie";bs'`` coverage. Successful results are
    available through ``verification_results(response)``.
    """

    def __init__(
        self,
        mode: SignatureMiddlewareMode = SignatureMiddlewareMode.SIGN_REQUEST_VERIFY_RESPONSE,
        *,
        sign_options: SigningOptions | None = None,
        verify_options: VerificationOptions | None = None,
    ) -> None:
        if not isinstance(mode, SignatureMiddlewareMode):
            raise TypeError("mode must be a SignatureMiddlewareMode")
        super().__init__(
            sign_requests=mode is not SignatureMiddlewareMode.VERIFY_RESPONSE,
            verify_responses=mode is not SignatureMiddlewareMode.SIGN_REQUEST,
            sign_options=sign_options,
            verify_options=verify_options,
        )
        self.mode = mode
        # The set tracks requests signed by this middleware for digest reuse on retries;
        # the dictionary stores results for verification_results(response). Weak
        # references prevent either collection from keeping messages alive and remove
        # entries automatically when their request or response is garbage-collected.
        self._signed_requests: WeakSet[aiohttp.ClientRequest] = WeakSet()
        self._results: WeakKeyDictionary[aiohttp.ClientResponse, list[VerifyResult]] = WeakKeyDictionary()

    @staticmethod
    def _parse_origin(origin: str) -> tuple[str, str, int | None]:
        url = URL(origin)
        host = url.host
        if (
            not url.is_absolute()
            or host is None
            or url.scheme not in {"http", "https"}
            or url.raw_path != "/"
            or url.query_string
            or url.fragment
            or url.user is not None
        ):
            raise ValueError("origin must be an HTTP origin without a path, query, fragment, or credentials")
        return url.scheme, host, url.port

    @staticmethod
    def _check_origin(request: aiohttp.ClientRequest, origin: tuple[str, str, int | None] | None) -> None:
        url = request.url
        if (url.scheme, url.host, url.port) != origin:
            raise HTTPMessageSignaturesException("Request origin is not authorized for these signature keys")

    @property
    def session_kwargs(self) -> _SessionOptions:
        """Return fresh ClientSession options that install middleware and defer decoding."""
        options: _SessionOptions = {"middlewares": (self,)}
        if self.verifier is not None:
            options["auto_decompress"] = False
        return options

    async def __call__(
        self, request: aiohttp.ClientRequest, handler: aiohttp.ClientHandlerType
    ) -> aiohttp.ClientResponse:
        response = None
        try:
            if self.verifier is not None:
                if request.session.auto_decompress:
                    raise ValueError("Response verification requires ClientSession(**middleware.session_kwargs)")
                self._check_origin(request, self._verify_origin)
            if self.signer is not None:
                self._check_origin(request, self._sign_origin)
                body = await _buffer_request(request)
                options = self._sign_kwargs
                if request in self._signed_requests:
                    options = {"use_existing_digest": True, **options}
                self.signer.sign(_request_view(request), body=body, **options)
                self._signed_requests.add(request)
            response = await handler(request)
            if self.verifier is not None:
                self._results.pop(response, None)
                message = _Response(
                    status_code=response.status,
                    headers=_HeaderFields.from_raw(lambda: response.raw_headers),
                    request=_request_view(request),
                )
                results = self.verifier.verify(message, **self._verify_kwargs)
                empty = isinstance(response.content, EmptyStreamReader)
                if not empty and response.content.total_compressed_bytes is not None:
                    raise ValueError("Do not override auto_decompress=True when using signature verification")
                body = await response.content.read()
                if not empty and len(body) != response.content.total_bytes:
                    raise InvalidSignature(
                        "Response body was consumed before verification; install signature middleware last"
                    )
                results = self.verifier.verify_body(message, results, body)
                if not empty:
                    response.content = await _decoded_content(response, body)
                self._results[response] = results
            return response
        except BaseException:
            if response is not None:
                response.close()
            try:
                await request.close()
            finally:
                # ClientRequest.close() waits for its writer, but does not close
                # a payload whose preparation failed before that writer started.
                payload = request.body
                if isinstance(payload, Payload):
                    await payload.close()
            raise

    def verification_results(self, response: aiohttp.ClientResponse) -> list[VerifyResult]:
        """Return successful response verification results from this instance."""
        try:
            return self._results[response]
        except KeyError:
            raise InvalidSignature("This response has not been verified by this middleware") from None


class ServerSigningOptions(_BaseSigningOptions):
    """Response signing configuration for ServerSignatureMiddleware.

    ``signature_algorithm``, ``key_id``, and ``key_resolver`` are required.
    Other entries are optional ``HTTPMessageSigner.sign()`` keywords. The
    middleware supplies ``body``; the signer supplies omitted defaults. Set
    ``covered_component_ids`` for responses: the base defaults cover a request.
    """


class ServerVerificationOptions(_BaseVerificationOptions):
    """Request verification configuration for ServerSignatureMiddleware.

    ``signature_algorithm`` and ``key_resolver`` are required. Other entries
    are optional ``HTTPMessageVerifier.verify()`` keywords. The middleware
    supplies ``body``; the verifier supplies omitted defaults.
    """


class ServerSignatureMiddlewareMode(Enum):
    """Operations that ServerSignatureMiddleware performs for each exchange."""

    VERIFY_REQUEST = "verify_request"
    SIGN_RESPONSE = "sign_response"
    VERIFY_REQUEST_SIGN_RESPONSE = "verify_request_sign_response"


class _ApplicationOptions(TypedDict, total=False):
    middlewares: tuple[Middleware, ...]
    handler_args: dict[str, Any]


@dataclass
class _ServerRequest(_Request):
    request_target: str


@dataclass
class _ServerState:
    message: _ServerRequest
    results: list[VerifyResult] | None = None
    signing_failed: bool = False


class ServerSignatureMiddleware(_SignatureConfiguration):
    """aiohttp server middleware for verifying requests and signing responses.

    :param mode: Operations that the middleware performs; defaults to both.
    :param sign_options: ServerSigningOptions dictionary for response signing.
    :param verify_options: ServerVerificationOptions dictionary for request verification.
    :ivar signer: Configured HTTPMessageSigner, or None when signing is disabled.
    :ivar verifier: Configured HTTPMessageVerifier, or None when verification is disabled.
    :cvar signer_class: Subclasses may override the HTTPMessageSigner class.
    :cvar verifier_class: Subclasses may override the HTTPMessageVerifier class.

    Pass ``**middleware.application_kwargs`` to ``web.Application``. For signing,
    register ``middleware.on_response_prepare`` last, after all header changes.
    Place trusted proxy middleware before this middleware and body consumers after it.

    Verification buffers encoded requests, validates their digests, and restores
    decoded content for aiohttp readers. Both buffers respect ``request.client_max_size``;
    zero disables the limit. Keep the supplied ``auto_decompress=False`` setting.
    Applications handle InvalidSignature and retrieve successful results with
    ``verification_results(request)``.

    Signing supports buffered ``web.Response`` bodies and native compression.
    Return finite Payloads without preparing them; the middleware buffers and
    closes them. Streaming, FileResponse, and chunked compression are unsupported.
    Signing failures close the connection before headers are sent.

    The base signer and verifier supply omitted defaults. Configure response
    ``covered_component_ids`` explicitly: the base defaults cover requests.
    Existing digests require ``use_existing_digest=True`` and must match the body.
    Request replay and compressed response access use aiohttp's private caches.
    """

    def __init__(
        self,
        mode: ServerSignatureMiddlewareMode = ServerSignatureMiddlewareMode.VERIFY_REQUEST_SIGN_RESPONSE,
        *,
        sign_options: ServerSigningOptions | None = None,
        verify_options: ServerVerificationOptions | None = None,
    ) -> None:
        if not isinstance(mode, ServerSignatureMiddlewareMode):
            raise TypeError("mode must be a ServerSignatureMiddlewareMode")
        if mode is not ServerSignatureMiddlewareMode.VERIFY_REQUEST and sign_options is None:
            raise ValueError("sign_options is required when signing responses")
        if mode is ServerSignatureMiddlewareMode.VERIFY_REQUEST and sign_options is not None:
            raise ValueError("Signing configuration is not allowed in VERIFY_REQUEST mode")
        if mode is not ServerSignatureMiddlewareMode.SIGN_RESPONSE and verify_options is None:
            raise ValueError("verify_options is required when verifying requests")
        if mode is ServerSignatureMiddlewareMode.SIGN_RESPONSE and verify_options is not None:
            raise ValueError("Verification configuration is not allowed in SIGN_RESPONSE mode")
        super().__init__(sign_options=sign_options, verify_options=verify_options)
        self.mode = mode
        # Request/response mapping storage keeps each instance's snapshot and
        # verification results with the exchange, without retaining messages.
        self._request_key = web.RequestKey("http_message_signatures", _ServerState)
        self._response_key = web.ResponseKey("http_message_signatures", _ServerState)
        # aiohttp gives each request its own context. A proxy middleware may
        # clone the request before this state is stored; preparation of an error
        # response can still receive the original request with its older mapping.
        self._request_state: ContextVar[_ServerState | None] = ContextVar("http_message_signatures", default=None)

    @property
    def application_kwargs(self) -> _ApplicationOptions:
        """Return fresh Application options that install middleware and defer decoding."""
        options: _ApplicationOptions = {"middlewares": (self._middleware,)}
        if self.verifier is not None:
            options["handler_args"] = {"auto_decompress": False}
        return options

    @staticmethod
    def _abort(request: web.Request, state: _ServerState) -> None:
        # aiohttp may otherwise turn a signing exception into an unsigned 500,
        # or run preparation again for an error raised during explicit prepare().
        state.signing_failed = True
        if request.transport is not None:
            request.transport.abort()

    def _check_installation(self, request: web.Request) -> None:
        callbacks = [callback for app in request.match_info.apps for callback in app.on_response_prepare]
        if callbacks.count(self.on_response_prepare) != 1 or callbacks[-1] != self.on_response_prepare:
            raise ValueError("Register on_response_prepare once, after all preparation callbacks for this route")

    @web.middleware
    async def _middleware(self, request: web.Request, handler: Handler) -> web.StreamResponse:
        raw_headers = request.raw_headers
        state = _ServerState(
            _ServerRequest(
                method=request.method,
                url=str(request.url),
                headers=_HeaderFields.from_raw(lambda: raw_headers),
                request_target=request.raw_path,
            )
        )
        request[self._request_key] = state
        self._request_state.set(state)
        if self.signer is not None:
            try:
                self._check_installation(request)
            except BaseException:
                self._abort(request, state)
                raise
        if self.verifier is not None:
            await self._verify_request(request, state)
        try:
            response = await handler(request)
        except web.HTTPException as error_response:
            if self.signer is not None:
                await self._stage_response(request, error_response, state)
            raise
        if self.signer is not None:
            await self._stage_response(request, response, state)
        return response

    async def _verify_request(self, request: web.Request, state: _ServerState) -> None:
        assert self.verifier is not None
        content = request.content
        empty = isinstance(content, EmptyStreamReader)
        if not empty and content.total_compressed_bytes is not None:
            raise ValueError("Request verification requires handler_args={'auto_decompress': False}")
        results = self.verifier.verify(state.message, **self._verify_kwargs)
        body = await request.read()
        if not empty and len(body) != content.total_bytes:
            raise ValueError("Request body was partially consumed; install signature middleware before body readers")
        if request.client_max_size and len(body) > request.client_max_size:
            raise web.HTTPRequestEntityTooLarge(max_size=request.client_max_size, actual_size=len(body))
        results = self.verifier.verify_body(state.message, results, body)
        if not empty:
            replay = await _decoded_content(request, body, max_size=request.client_max_size)
            # Request has no public body replacement API. Clear the encoded read
            # cache and cached content property so every native reader sees replay.
            request._payload = replay
            request._cache.pop("content", None)
            request._read_bytes = None
        state.results = results

    async def _stage_response(self, request: web.Request, response: web.StreamResponse, state: _ServerState) -> None:
        response[self._response_key] = state
        try:
            if isinstance(response, web.Response) and not response.prepared and isinstance(response.body, Payload):
                payload = response.body
                try:
                    with BytesIO() as content:
                        await payload.write_with_length(_BodyWriter(content), response.content_length)
                        response.body = content.getvalue()
                finally:
                    await payload.close()
        except BaseException:
            self._abort(request, state)
            raise

    async def on_response_prepare(self, request: web.Request, response: web.StreamResponse) -> None:
        """Sign finalized headers and encoded content before aiohttp sends headers.

        Register this callback last on ``app.on_response_prepare`` when signing
        is enabled. With subapplications, it must run after child callbacks too;
        install it on the relevant leaf application, without duplicate registration.
        """
        state: _ServerState | None = response.get(
            self._response_key, request.get(self._request_key, self._request_state.get())
        )
        try:
            if self.signer is None:
                raise ValueError("on_response_prepare requires response signing to be enabled")
            if state is None or state.signing_failed:
                raise ValueError("Response signing requires an active ServerSignatureMiddleware")
            if not isinstance(response, web.Response):
                raise TypeError(
                    "Response signing requires a buffered web.Response; streaming and files are unsupported"
                )
            if isinstance(response.body, Payload):
                raise TypeError("Return Payload responses without calling prepare(); middleware must buffer them first")
            if response.chunked and response.compression:
                raise ValueError("Response signing cannot combine chunking and compression; disable chunking")
            if must_be_empty_body(request.method, response.status):
                body = b""
            else:
                # aiohttp has already selected and applied buffered compression.
                body = (
                    response._compressed_body if response._compressed_body is not None else bytes(response.body or b"")
                )
                # Response.write_eof() sends the whole bytes body, unlike
                # Payload.write(), whose writes honor the writer's length limit.
                if response.content_length is not None and response.content_length != len(body):
                    raise ValueError(
                        "Content-Length does not match the encoded response body; correct it before signing"
                    )
            message = _Response(response.status, _outgoing_headers(response.headers), state.message)
            self.signer.sign(message, body=body, **self._sign_kwargs)
        except BaseException:
            if state is not None:
                self._abort(request, state)
            elif request.transport is not None:
                request.transport.abort()
            if isinstance(response, web.Response) and isinstance(response.body, Payload):
                await response.body.close()
            raise

    def verification_results(self, request: web.Request) -> list[VerifyResult]:
        """Return successful request verification results from this instance."""
        state: _ServerState | None = request.get(self._request_key)
        if state is None or state.results is None:
            raise InvalidSignature("This request has not been verified by this middleware")
        return state.results
