"""Buffered request signing and response verification for aiohttp."""

import asyncio
from enum import Enum
from functools import cached_property
from io import BytesIO
from typing import TypedDict, cast
from weakref import WeakKeyDictionary, WeakSet

import aiohttp
from aiohttp.abc import AbstractStreamWriter
from aiohttp.base_protocol import BaseProtocol
from aiohttp.compression_utils import ZLibCompressor
from aiohttp.http_exceptions import ContentEncodingError
from aiohttp.http_parser import HeadersParser, HttpPayloadParser
from aiohttp.payload import BytesPayload, Payload
from aiohttp.streams import EmptyStreamReader
from multidict import CIMultiDict
from yarl import URL

from ._integrations import _SignatureAdapter, _SigningOptions, _VerificationOptions
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
    def __init__(self, body: bytes, content_encoding: str, content_type: str | None):
        super().__init__(body, content_type=content_type)
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
        await request.update_body(_CompressedPayload(body, encoding, request.headers.get("Content-Type")))
        request.compress = None
    elif isinstance(payload, Payload):
        await request.update_body(body)
        if content_length is not None:
            request.headers["Content-Length"] = str(content_length)
    return body


class _BufferedProtocol(BaseProtocol):
    # aiohttp.StreamReader uses these methods for connection flow control.
    # This protocol serves a body buffered in memory. The methods do nothing
    # because aiohttp may have reused the original connection.
    def pause_reading(self) -> None:
        pass

    def resume_reading(self, resume_parser: bool = True) -> None:
        pass


def _decoded_content(response: aiohttp.ClientResponse, body: bytes) -> aiohttp.StreamReader:
    # aiohttp.ClientResponse has no method for decompressing a body after reading it.
    # HttpPayloadParser decompresses the verified bytes into a new StreamReader;
    # aiohttp has already removed HTTP chunk framing.
    loop = asyncio.get_running_loop()
    limit, _ = response.content.get_read_buffer_limits()
    content = aiohttp.StreamReader(_BufferedProtocol(loop), limit, loop=loop)
    encoding = response.headers.get("Content-Encoding", "").strip().lower()
    try:
        parser = HttpPayloadParser(
            content,
            compression=encoding,
            auto_decompress=encoding in {"gzip", "deflate", "br", "zstd"},
            headers_parser=HeadersParser(),
        )
        parser.feed_data(body)
        parser.feed_eof()
    except ContentEncodingError as exc:
        raise aiohttp.ClientPayloadError(str(exc)) from exc
    return content


def _request_view(request: aiohttp.ClientRequest) -> _Request:
    # aiohttp writes header values as UTF-8. This adapter converts those bytes
    # to Latin-1 strings so HTTPSignatureComponentResolver can recover them
    # for ;bs coverage.
    headers = _HeaderFields(
        lambda: (
            (name, value.encode("utf-8", "surrogateescape").decode("latin-1"))
            for name, value in request.headers.items()
        ),
        writable=request.headers,
    )
    return _Request(method=request.method, url=str(request.url), headers=headers)


class SignatureMiddleware(_SignatureAdapter):
    """aiohttp middleware for signing requests, verifying responses, or both.

    :param mode: Operations that the middleware performs; defaults to both.
    :param sign_options: SigningOptions dictionary for enabled request signing.
    :param verify_options: VerificationOptions dictionary for enabled response verification.
    :ivar signer: Configured HTTPMessageSigner, or None when signing is disabled.
    :ivar verifier: Configured HTTPMessageVerifier, or None when verification is disabled.
    :cvar signer_class: Subclasses may override the HTTPMessageSigner class used by the middleware.
    :cvar verifier_class: Subclasses may override the HTTPMessageVerifier class used by the middleware.

    Pass ``**middleware.session_kwargs`` to ``aiohttp.ClientSession``. When
    verification is enabled, these options disable aiohttp's early decompression.
    The middleware verifies encoded content first, then restores decoded content
    for normal ``read()``, ``text()``, ``json()``, and ``content`` access.
    Do not override ``auto_decompress`` or replace the configured middleware.
    A per-request override can trigger decoding before the middleware rejects it.

    Place this middleware last, after middleware that changes outgoing requests,
    so it signs those changes and verifies responses before other middleware reads
    them. The middleware buffers complete bodies, including streaming uploads and
    downloads; HTTP chunk boundaries are not retained in the verified response.
    When you pass ``compress=`` to aiohttp, the middleware compresses the upload
    while buffering it, then signs the compressed bytes that aiohttp sends. Retries
    and redirects that preserve the body reuse those bytes without recompression. You can also
    supply encoded bytes and a Content-Encoding header without ``compress=``.

    Each operation uses its own origin, algorithm, and key resolver. The middleware
    forwards signing options to ``HTTPMessageSigner.sign()`` and verification options
    to ``HTTPMessageVerifier.verify()``. These methods supply defaults for omitted
    options and reject unknown keywords. Use ``use_existing_digest=True`` to
    accept a supplied digest. The middleware also permits digest reuse when the
    same instance signs the same request again, unless you set the option to False.
    ``HTTPMessageSigner.sign()`` checks reused digests against the buffered content.

    HTTPMessageVerifier requires a signed digest for nonempty responses or responses with
    Content-Digest. Use ``require_components`` for other coverage requirements.
    Call ``verification_results(response)`` to retrieve successful verification results.
    Failed verification closes the response before aiohttp updates its cookie jar.
    To authenticate cookie fields, require ``'"set-cookie";bs'`` coverage as well.

    Restoring decoded response streams uses aiohttp's internal payload parser and stream
    construction APIs.
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

    @cached_property
    def session_kwargs(self) -> _SessionOptions:
        """Options that install this middleware and defer decoding until after verification."""
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
                results = self.verifier.verify_body(message, results, body)
                if not empty:
                    response.content = _decoded_content(response, body)
                self._results[response] = results
            return response
        except BaseException:
            if response is not None:
                response.close()
            await request.close()
            raise

    def verification_results(self, response: aiohttp.ClientResponse) -> list[VerifyResult]:
        """This method returns results for a response verified by this middleware instance."""
        try:
            return self._results[response]
        except KeyError:
            raise InvalidSignature("This response has not been verified by this middleware") from None
