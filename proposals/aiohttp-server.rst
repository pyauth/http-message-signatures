aiohttp server integration proposal
====================================

Status: proposed API, not implemented. This document builds on PR #45, including
the client compatibility fixes merged from PR #49. It is a design review document;
the README will describe server support only after implementation and validation.

Public API
----------

Add ``http_message_signatures.aiohttp.ServerSignatureMiddleware`` with a first
constructor argument of ``ServerSignatureMiddlewareMode``. Its modes are
``VERIFY_REQUEST``, ``SIGN_RESPONSE``, and ``VERIFY_REQUEST_SIGN_RESPONSE``;
the last mode is the default. Each enabled operation accepts its own TypedDict:
``ServerVerificationOptions`` or ``ServerSigningOptions``. Disabled operations
require no keys, key IDs, or option dictionaries.

The dictionaries retain the base verifier/signer's keyword names, independent
algorithms, and custom key resolvers. They have no ``origin`` entry: the client
adapter's destination restriction is not a server authentication policy.
Applications configure their accepted hosts and trusted proxies separately.

The adapter forwards only supplied signature options. The base implementation
continues to supply all signature defaults, and rejects unknown options. The
adapter supplies body bytes internally. Response examples specify
``covered_component_ids`` because the base signer's default components describe
a request; the server adapter must not substitute another default list.

Proposed usage, assuming application-provided client and server key resolvers::

    from aiohttp import web
    from http_message_signatures import InvalidSignature, algorithms
    from http_message_signatures.aiohttp import (
        ServerSignatureMiddleware,
        ServerSignatureMiddlewareMode,
    )

    signatures = ServerSignatureMiddleware(
        ServerSignatureMiddlewareMode.VERIFY_REQUEST_SIGN_RESPONSE,
        verify_options={
            "signature_algorithm": algorithms.ED25519,
            "key_resolver": client_key_resolver,
            "require_components": ("@method", "@target-uri", "content-type"),
        },
        sign_options={
            "signature_algorithm": algorithms.ED25519,
            "key_id": "server-1",
            "key_resolver": server_key_resolver,
            "covered_component_ids": (
                "@status", "content-type", '"@method";req', '"@target-uri";req',
            ),
        },
    )

    @web.middleware
    async def signature_errors(request, handler):
        try:
            return await handler(request)
        except InvalidSignature:
            raise web.HTTPForbidden(text="Invalid request signature") from None

    async def echo(request):
        data = await request.json()
        results = signatures.verification_results(request)
        # Apply application authorization using the verified identity and components.
        return web.json_response(data)

    app = web.Application(**signatures.application_kwargs)
    app.middlewares.insert(0, signature_errors)
    app.router.add_post("/echo", echo)
    app.on_response_prepare.append(signatures.on_response_prepare)
    web.run_app(app)

``application_kwargs`` supplies the verification/staging middleware and, when
verification is enabled, ``handler_args={"auto_decompress": False}``. It preserves
the usual ``web.Application``, ``web.run_app``, and ``web.AppRunner`` entry points.
Applications may merge their other handler arguments into this dictionary, but
must retain that decompression setting. Verification-only mode does not need the
response callback; signing-only mode leaves request consumption to the handler.

Applications register ``on_response_prepare`` last, after callbacks that modify
response headers. The adapter must detect missing or incorrectly ordered
registration before serving signed responses. An installation spanning subapps
must register and validate the final callback on each relevant leaf app, because
aiohttp invokes parent preparation callbacks before child callbacks. Registering
only a parent callback must not silently claim to cover later child changes.

Request verification
--------------------

1. After any trusted proxy middleware, capture the request method, effective URL,
   raw request target, and raw header lines. Preserve repeated fields and original
   bytes, including non-ASCII values covered with ``;bs``. Store this snapshot for
   response components qualified with ``;req``; later handler mutations must not
   change the request that a response signature references.
2. Verify signature headers before consuming the content. Read the encoded body
   with aiohttp's normal request reader, then call the base verifier's
   ``verify_body()``. This avoids verifying the signature twice and retains its
   requirement for signed digest coverage when content is present.
3. After successful verification, use aiohttp's decoder to construct a replay
   stream. Handlers receive normal decoded content through ``read()``, ``text()``,
   ``json()``, ``post()``, ``multipart()``, and ``content`` iteration. These remain
   aiohttp's usual consumption APIs: the adapter does not make arbitrary mixtures
   of stream reads and high-level reads repeatable.
4. Store verification results and the snapshot in the request's supported mapping
   storage, with per-instance private state. ``verification_results(request)``
   returns only successful results from this middleware. No weak collections or
   additions to the native request's attribute namespace are needed for this state.

The incoming stream must still contain encoded content. An already-decoded stream
or a partially consumed stream without a complete cached body produces an error
before the handler runs. The adapter must not trust a digest computed over only
the remaining bytes. Empty requests retain aiohttp's empty-stream handling.

Respect ``request.client_max_size`` when buffering and when producing decoded
content; do not copy aiohttp's numeric default into this library. The decoder
needs a size-limited output sink so a compressed body cannot allocate an
unbounded decoded buffer before the size check. A value of zero retains the
application's explicit unlimited setting. This bounds both encoded and decoded
buffering by the application's chosen limit, rather than just the decoded input
that aiohttp normally exposes. Cancellation and disconnects must release buffers
and propagate without invoking the handler.

Request replay requires a small, isolated use of aiohttp internals: replacing
``request._payload``, invalidating cached ``content``, and clearing the encoded
``_read_bytes`` cache. The adapter leaves request headers unchanged, as aiohttp
does when decoding normally. The public request API has no body-replacement
method; ``clone()`` alone reuses the consumed stream and does not solve this.

Response signing
----------------

The middleware stages supported response bodies before preparation. The final
signature is created by ``on_response_prepare``, when aiohttp has populated
cookies, selected content encoding, and computed default headers. The response
view maps ``response.status`` to the base message interface and uses the captured
request for ``;req`` components. Outgoing header values use aiohttp's UTF-8 wire
representation, including each individual Set-Cookie field.

For ordinary buffered ``web.Response`` objects, let aiohttp perform its native
compression. At the preparation callback, sign its cached compressed bytes when
present, otherwise its body bytes. Reading ``Response._compressed_body`` is an
additional private API dependency; this avoids implementing compression
negotiation again or recompressing the body. The callback changes only signature
and digest headers, not the already prepared body, framing, or encoding.
If an explicit Content-Length bounds what aiohttp's writer sends, the digest must
cover that bounded content. Buffering must not silently change the declared length.

Apply aiohttp's bodyless-response semantics before computing the digest. A HEAD,
204, or 304 response signs empty content even if the Response object retains
representation bytes. A partial response signs its transmitted range, not the
complete resource. ``Content-Digest`` and ``Repr-Digest`` are not interchangeable.

When a supported response already has Content-Digest, the base signer requires
explicit ``use_existing_digest=True`` and checks the supplied digest against the
encoded content. The adapter must neither replace that digest silently nor copy
request headers into the response. Application-required coverage of cookies,
Location, Content-Type, or Content-Encoding remains explicit configuration.

Initial implementation boundaries
---------------------------------

* Automatically sign returned ``web.Response`` objects containing bytes, text,
  JSON, or a finite Payload that can be buffered before preparation. Close the
  original Payload even if buffering fails. Preserve its existing response
  metadata without copying credentials from the request.
* Support ordinary ``Response.enable_compression()`` through aiohttp's buffered
  compression path. A chunked, compressed response uses a different path that
  compresses while writing; it cannot be treated as already encoded at the
  preparation callback. Initially reject that combination with an actionable
  error before headers are sent, rather than alter framing or sign decoded bytes.
* Bytes-backed Responses can be signed at explicit ``prepare()`` calls. A Payload
  prepared inside the handler before the middleware can buffer it requires a
  distinct error; the callback cannot safely replace its body after framing has
  been finalized.
* Automatic signing of incremental ``StreamResponse``, SSE, and ``FileResponse``
  needs further work. These APIs can send headers before all content exists, and
  FileResponse can choose a range or compressed file during preparation. Do not
  buffer them by replacing aiohttp's writer or assume that a file's full digest
  authenticates a selected range. WebSocket frames are outside HTTP signatures.

A later streaming path can reuse the base signer's precomputed-digest contract:
the caller supplies Content-Digest, explicitly sets ``use_existing_digest=True``,
and includes digest coverage. The caller must know the final encoded content
before headers are sent. The adapter cannot then claim to have checked the digest
against future bytes. This requires separate review, especially for FileResponse
range selection and compression; it is not an implicit fallback for unsupported
automatic signing. Signature trailers would require separate protocol support.

Failures, ordering, and authorization
--------------------------------------

Verification runs before handlers and middleware that consume or interpret the
body. Trusted proxy configuration precedes signature verification and must not
consume the body. The adapter must not infer trust from Forwarded headers.
Applications map InvalidSignature to an HTTP response using ordinary error
middleware; the example's 403 is an application choice, not a new base default.

The response hook also runs for application-generated error responses. It can
bind an error response to a captured incoming request without claiming that the
request passed verification. Failed verification must never populate successful
results. Response signing failures must abort before headers are sent; the
adapter must not silently emit an unsigned replacement response or repeatedly
attempt signing an error caused by the signer itself.

For returned Payload responses, place the staging middleware outside response
body mutators so it sees their final output. Preparation callbacks may modify
headers before the signing callback, but must not change the body or covered
headers afterward. Installation checks and tests must cover both middleware and
signal ordering, including exception responses and nested applications.

Signature validity does not choose an authorized identity, prevent replay, or
authenticate uncovered headers. Those checks remain application policy. In
particular, cookie authentication needs Cookie or Set-Cookie coverage as
appropriate, and redirect authentication needs Location coverage. Client origin
checks remain unchanged by this server proposal.

Shared implementation and acceptance tests
--------------------------------------------

Extract only the reusable pieces: base option TypedDict fields without the client
origin, signer/verifier construction and option forwarding, raw message views,
payload buffering, and the aiohttp decoder/replay helper. Keep client origin
checks and server lifecycle handling in their respective adapters. Reuse the
existing component resolver, ContentDigest implementation, and verify_body().
Do not duplicate signature defaults, add runtime keyword introspection, or expose
internal utility functions as public API.

Implementation should arrive in reviewable steps: native server message views;
request verification and bounded replay; buffered response signing at preparation;
then public examples and failure/ordering coverage. Keep these tests alongside
each corresponding change:

* Signing-only, verification-only, and combined modes; custom resolvers and
  different algorithms; omitted options and unknown keywords.
* Repeated and non-ASCII headers, ``;bs``, request targets, trusted proxy clones,
  request-bound response signatures, and immutable request snapshots.
* Encoded requests with JSON, forms, multipart, and direct stream handlers;
  rejected tampering before handler/decoder execution; preconsumption; empty
  streams; size limits; cancellation and connection reuse.
* Native response compression, explicit Content-Length, cookies added with
  ``set_cookie()``, header changes in preparation callbacks, explicit preparation,
  HEAD/204/304, existing digests,
  error responses, and failures before any response headers are sent.
* Unsupported streaming/file combinations, missing installation pieces, and
  parent/child middleware and signal ordering. Exercise both aiohttp parsers and
  the declared minimum dependency version without adding a new CI job.

A local feasibility probe passed on aiohttp 3.14.0 with its C parser and on
aiohttp 3.14.5 with both C and Python parsers:
compressed signed requests reached JSON and multipart handlers as decoded data;
non-ASCII header verification succeeded; gzip response signatures covered the
encoded bytes and two finalized cookies; HEAD response digests covered empty
content. This validates the lifecycle approach, not the full implementation or
the failure, size-limit, streaming, and subapplication cases listed above.

References
----------

* `Application and request/response APIs <https://docs.aiohttp.org/en/stable/web_reference.html>`_
* `Request body consumption <https://docs.aiohttp.org/en/stable/web_advanced.html#request-body-stream-consumption>`_
* `Preparation signals <https://docs.aiohttp.org/en/stable/web_advanced.html#signals>`_
* `Trusted proxy deployment <https://docs.aiohttp.org/en/stable/web_advanced.html#deploying-behind-a-proxy>`_
* `aiohttp 3.14.5 response preparation and compression <https://github.com/aio-libs/aiohttp/blob/v3.14.5/aiohttp/web_response.py>`_
* `aiohttp 3.14.5 request caches and cloning <https://github.com/aio-libs/aiohttp/blob/v3.14.5/aiohttp/web_request.py>`_
* `RFC 9530: empty content and ranges <https://www.rfc-editor.org/rfc/rfc9530.html#appendix-B.2>`_
