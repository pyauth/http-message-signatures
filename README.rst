http-message-signatures: An implementation of RFC 9421, the IETF HTTP Message Signatures standard
=================================================================================================

*http-message-signatures* is an implementation of the IETF
`RFC 9421 HTTP Message Signatures <https://datatracker.ietf.org/doc/rfc9421/>`_ standard in
Python.

.. admonition:: Security considerations

 It is recommended that you read and understand
 `section 7 of the RFC, Security Considerations <https://www.rfc-editor.org/rfc/rfc9421#name-security-considerations>`_
 before using this library.

Installation
------------
::

    pip install http-message-signatures

Synopsis
--------

.. code-block:: python

    import requests
    from http_message_signatures import HTTPMessageSigner, HTTPMessageVerifier, HTTPSignatureKeyResolver, algorithms

    class MyHTTPSignatureKeyResolver(HTTPSignatureKeyResolver):
        keys = {"my-key": b"top-secret-key"}

        def resolve_public_key(self, key_id: str):
            return self.keys[key_id]

        def resolve_private_key(self, key_id: str):
            return self.keys[key_id]

    request = requests.Request('POST', 'https://example.com/foo?param=Value&Pet=dog', json={"hello": "world"})
    request = request.prepare()

    signer = HTTPMessageSigner(signature_algorithm=algorithms.HMAC_SHA256, key_resolver=MyHTTPSignatureKeyResolver())
    signer.sign(request, key_id="my-key", body=request.body)

    verifier = HTTPMessageVerifier(signature_algorithm=algorithms.HMAC_SHA256, key_resolver=MyHTTPSignatureKeyResolver())
    verifier.verify(request, body=request.body)

Signing Content-Digest and checking it against the body protects the body against tampering.
Supply content bytes before decoding as ``body=``. With this argument, ``sign()`` generates Content-Digest if absent
and adds digest coverage to the signature, while ``verify()`` checks the signed digest against those bytes.
When signing, components covered by the signature can be customized using ``covered_component_ids``, for example
``covered_component_ids=("@method", "@authority", "@target-uri", "content-type", "content-digest")``.

Signing a message with an existing Content-Digest requires ``use_existing_digest=True`` on ``sign()`` or
``prepare()``. With ``body=`` supplied, these methods validate the existing digest against those bytes and add digest
coverage to the signature. Without ``body=``, they check only the digest's format and algorithms; you must ensure
the digest matches the content and include it in ``covered_component_ids`` to sign it. Both methods preserve existing
digest field lines and raise an error if the digest is malformed or does not match supplied content.
They also raise an error if you supply ``use_existing_digest=True`` with neither a digest nor body bytes.

.. admonition:: See what is signed

 It is important to understand and follow the best practice rule of "See what is signed" when verifying HTTP message
 signatures. The gist of this rule is: if your application neglects to verify that the information it trusts is
 what was actually signed, the attacker can supply a valid signature but point you to malicious data that wasn't signed
 by that signature. Failure to follow this rule can lead to vulnerability against signature wrapping and substitution
 attacks.

 In http-message-signatures, you can ensure that the information signed is what you expect to be signed by only trusting the
 data returned by the ``verify()`` method::

   verify_results = verifier.verify(request, body=request.body)

 This returns a list of ``VerifyResult`` s, which are ``namedtuple`` s with the following attributes:

 * label (str): The label for the signature
 * algorithm: (same as signature_algorithm above)
 * covered_components: A mapping of component names to their values, as covered by the signature
 * parameters: A mapping of signature parameters to their values, as covered by the signature
 * body: Content bytes that the verifier validated against a signed digest, before decoding; otherwise ``None``.

Integrations
------------

Three integrations are available: `Requests <https://github.com/pyauth/requests-http-signature>`_, HTTPX2, and aiohttp.

Requests
~~~~~~~~

See https://github.com/pyauth/requests-http-signature.

HTTPX2 integration
~~~~~~~~~~~~~~~~~~

Install the optional dependency::

    pip install 'http-message-signatures[httpx2]'

``http_message_signatures.httpx2.SignatureHooks`` signs requests and verifies responses through HTTPX2 event hooks.
Configure signing and verification with ``sign_options`` and ``verify_options``. This example loads keys from
application key stores::

    import httpx2
    from http_message_signatures import HTTPSignatureKeyResolver, algorithms
    from http_message_signatures.httpx2 import SignatureHooks, SignatureHooksMode

    class ClientKeyResolver(HTTPSignatureKeyResolver):
        def resolve_private_key(self, key_id):
            return signing_key_store.load_private_key(key_id)

    class ServerKeyResolver(HTTPSignatureKeyResolver):
        def resolve_public_key(self, key_id):
            return trusted_key_store.load_public_key(key_id)

    client_key_resolver = ClientKeyResolver()
    server_key_resolver = ServerKeyResolver()

    signatures = SignatureHooks(
        sign_options={
            "origin": "https://api.example.com",
            "signature_algorithm": algorithms.ED25519,
            "key_id": "client-1",
            "key_resolver": client_key_resolver,
            "tag": "example-api",
        },
        verify_options={
            "origin": "https://api.example.com",
            "signature_algorithm": algorithms.ED25519,
            "key_resolver": server_key_resolver,
            "expect_tag": "example-api",
            "require_components": ("@status", '"@method";req', '"@target-uri";req'),
        },
    )

    with httpx2.Client(event_hooks=signatures.event_hooks) as client:
        response = client.post("https://api.example.com/items", json={"hello": "world"})
        response.raise_for_status()
        data = response.json()
        results = response.extensions["http_message_signatures"]

If you just want to supply the keys directly, use ``http_message_signatures.MappingKeyResolver`` with ``private_keys``
and ``public_keys`` dictionaries keyed by key ID.

The hooks buffer bodies and verify responses before returning them, raising ``InvalidSignature`` on failure.
Response verification requires a signed Content-Digest for nonempty content or when the header is present.
Use ``require_components`` to require coverage of other fields your application trusts.

Use the async hook collection with ``AsyncClient``::

    async with httpx2.AsyncClient(event_hooks=signatures.async_event_hooks) as client:
        response = await client.post("https://api.example.com/items", json={"hello": "world"})
        data = response.json()

Signing only or verification only
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The first argument selects which operations to enable:

* ``SignatureHooksMode.SIGN_REQUEST_VERIFY_RESPONSE`` (the default) requires both ``sign_options`` and ``verify_options``.
* ``SignatureHooksMode.SIGN_REQUEST`` requires only ``sign_options``.
* ``SignatureHooksMode.VERIFY_RESPONSE`` requires only ``verify_options``.

.. warning::

 HTTPX2 updates its cookie jar before response verification. Failed verification does not undo those updates,
 so these hooks do not provide authenticated automatic cookie persistence.

aiohttp integration
~~~~~~~~~~~~~~~~~~~

Install the optional dependency (aiohttp 3.14 or later)::

    pip install 'http-message-signatures[aiohttp]'

``http_message_signatures.aiohttp.SignatureMiddleware`` signs requests and verifies responses through
``aiohttp.ClientSession``. Pass ``session_kwargs`` to the session constructor::

    import aiohttp
    from http_message_signatures.aiohttp import SignatureMiddleware, SignatureMiddlewareMode

    signatures = SignatureMiddleware(
        sign_options={
            "origin": "https://api.example.com",
            "signature_algorithm": algorithms.ED25519,
            "key_id": "client-1",
            "key_resolver": client_key_resolver,
            "tag": "example-api",
        },
        verify_options={
            "origin": "https://api.example.com",
            "signature_algorithm": algorithms.ED25519,
            "key_resolver": server_key_resolver,
            "expect_tag": "example-api",
            "require_components": ("@status", '"@method";req', '"@target-uri";req'),
        },
    )
    async with aiohttp.ClientSession(**signatures.session_kwargs) as client:
        async with client.post("https://api.example.com/items", json={"hello": "world"}, allow_redirects=False) as response:
            response.raise_for_status()
            data = await response.json()
            results = signatures.verification_results(response)

The first constructor argument selects the mode. ``SignatureMiddlewareMode.SIGN_REQUEST`` needs only ``sign_options``;
``SignatureMiddlewareMode.VERIFY_RESPONSE`` needs only ``verify_options``. The default,
``SignatureMiddlewareMode.SIGN_REQUEST_VERIFY_RESPONSE``, needs both dictionaries.

The middleware buffers complete bodies and verifies encoded responses before decoding them for normal aiohttp readers.
Client buffering has no size limit, even with streaming readers. aiohttp's ``compress=`` request option is supported.

Place the signature middleware last, so other middleware can change requests before signing and read responses after
verification. Keep ``auto_decompress=False`` from ``session_kwargs`` and retain the signature middleware when overriding
the per-request middleware list.

Requests and redirects must match each enabled operation's configured origin. Keep ``allow_redirects=False`` unless
your verification policy requires signed Location on redirect responses: an origin check does not authenticate paths
within that origin. Require coverage of other fields the application trusts, including Content-Type and Content-Encoding.
Failed verification prevents cookie-jar updates; authenticating cookies also requires ``'"set-cookie";bs'`` coverage.

aiohttp servers
^^^^^^^^^^^^^^^

``http_message_signatures.aiohttp.ServerSignatureMiddleware`` verifies requests and signs responses through
``aiohttp.web.Application``. This example uses the client and server key resolvers defined earlier::

    from aiohttp import web
    from http_message_signatures import InvalidSignature, algorithms
    from http_message_signatures.aiohttp import ServerSignatureMiddleware

    signatures = ServerSignatureMiddleware(
        verify_options={
            "signature_algorithm": algorithms.ED25519,
            "key_resolver": client_key_resolver,
            "expect_tag": "example-api",
            "require_components": ("@method", "@target-uri"),
        },
        sign_options={
            "signature_algorithm": algorithms.ED25519,
            "key_id": "server-1",
            "key_resolver": server_key_resolver,
            "tag": "example-api",
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
        results = signatures.verification_results(request)
        # Apply your application's authorization policy using these verified results.
        return web.json_response(await request.json())

    app = web.Application(**signatures.application_kwargs)
    app.middlewares.insert(0, signature_errors)
    app.router.add_post("/items", echo)
    app.on_response_prepare.append(signatures.on_response_prepare)
    web.run_app(app)

The first argument selects ``ServerSignatureMiddlewareMode.VERIFY_REQUEST``, ``SIGN_RESPONSE``, or
``VERIFY_REQUEST_SIGN_RESPONSE`` (the default). Supply options for the enabled operations. Configure response
``covered_component_ids`` explicitly; the defaults cover requests. Content-Digest coverage is added automatically.

Keep the ``auto_decompress=False`` setting supplied by ``application_kwargs``. Verification checks encoded content
before decoding it or invoking the handler. Encoded and decoded request buffers respect ``request.client_max_size``.

Place trusted proxy middleware before signature verification and body consumers after it. Applications control
accepted hosts, trusted proxies, authorization, and replay prevention. Require coverage of fields the application trusts.

For signing, return a buffered ``web.Response``. Streaming, FileResponse, and chunked compression are unsupported;
response buffering has no size limit. Return finite Payloads without preparing them so the middleware can buffer them.

Register ``on_response_prepare`` after all callbacks that modify headers, including subapplication callbacks.
Place the signature middleware outside middleware that changes response bodies, and do not change bodies or covered
headers after preparation. Application error responses are signed too; a response signature does not imply that its
request was verified.

Remote and asynchronous signing
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use ``prepare()`` and ``apply()`` when a KMS, HSM, SSH agent, or asynchronous client holds the signing key.
``prepare()`` builds the RFC 9421 signature base without reading a private key. When you supply ``body=``, it generates
Content-Digest if absent and adds digest coverage to the signature.
It accepts the signing options used by ``sign()``, including covered components, creation and expiration times,
nonce, tag, label, and ``include_alg``. The returned ``PreparedSignature`` contains immutable bytes and strings.
``apply()`` writes the Signature-Input and Signature headers after the external signer returns.

In this example, ``request`` is a prepared Requests request whose ``body`` contains encoded content bytes and whose
headers do not yet contain Content-Digest. Passing ``body=request.body`` makes ``prepare()`` generate the digest
and add it to the covered components before building the signing input.

The asynchronous ``sign_base`` function signs the supplied bytes with Ed25519 and returns the raw 64-byte signature.
The external signer must use the private key identified by ``key_id``::

    from collections.abc import Awaitable, Callable

    from http_message_signatures import HTTPMessageSigner, algorithms

    async def sign_request(request, key_id: str, sign_base: Callable[[bytes], Awaitable[bytes]]):
        signer = HTTPMessageSigner(signature_algorithm=algorithms.ED25519)
        prepared = signer.prepare(
            request,
            key_id=key_id,
            body=request.body,
            label="sig1",
        )
        signature = await sign_base(prepared.signature_base)
        signer.apply(request, prepared, signature)

The same two calls work with a synchronous signer or a signing job completed in another process.
No local ``key_resolver`` is needed. The existing ``sign()`` method still resolves a local key and performs all three
steps synchronously.

Pass ``prepared.signature_base`` to the signing algorithm as bytes, without base64 encoding or a trailing newline.
``prepared.signature_params`` is the serialized ``@signature-params`` value; it is useful for inspecting the covered
component list and signed metadata. Do not rebuild either value yourself. The selected algorithm applies to the remote
signer even when ``include_alg=False``; omitting the parameter does not negotiate an algorithm.

External signing services differ in their accepted input and output formats. When calling a signing service, configure
its signing operation according to
`RFC 9421 section 3.3 <https://www.rfc-editor.org/rfc/rfc9421.html#section-3.3>`_. Ed25519 signs the base without prehashing.
For RSA and ECDSA, an API that accepts raw messages must perform the specified hashing. If the API accepts a digest,
hash the signature base before calling it and select a mode that does not hash the digest again. The RSA-PSS profile
uses SHA-512, MGF1 with SHA-512, and a 64-byte salt.

``apply()`` expects raw signature bytes and performs the Structured Field base64 encoding. Decode base64 responses
from a service before calling it. ECDSA P-256 clients often return DER, while RFC 9421 requires a 64-byte concatenation
of ``r`` and ``s``, each padded to 32 bytes. Convert DER output using the algorithm's helper::

    signer = HTTPMessageSigner(signature_algorithm=algorithms.ECDSA_P256_SHA256)
    prepared = signer.prepare(request, key_id="p256-key")
    # der_signature is the client's ECDSA P-256/SHA-256 signature of prepared.signature_base.
    signature = algorithms.ECDSA_P256_SHA256.signature_from_der(der_signature)
    signer.apply(request, prepared, signature)

Retain the prepared object and associate each remote result with its input. Use a trusted signing service and protect
queued signing input against modification and disclosure: the base contains covered header and URL values.
``apply()`` compares the message's current signature base with the prepared bytes and rejects changes before writing
headers. For example, changing a covered method from ``POST`` to ``DELETE`` while awaiting the signature is rejected.
Changes to uncovered values or values with the same RFC normalization are permitted. This check does not authenticate
the prepared object, verify the returned signature, or check a body against its digest. Applications must handle those
responsibilities and keep the message stable during ``apply()`` and until it is sent.

Creation and expiration times are set during preparation and are not refreshed by ``apply()``. Allow for signing delays
when choosing expiration times; an expired result will still be rejected by a verifier. To add the result alongside
existing signatures, pass ``append_if_signature_exists=True`` to ``apply()``. Duplicate labels or malformed existing
signature headers are rejected. By default it replaces existing signature headers, just like ``sign()``.

Structured Field serialization
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use the ``sf`` component parameter to cover a whole header field using Structured Fields serialization::

    signer.sign(request, key_id="my-key", covered_component_ids=('"priority";sf',))

For example, ``Priority: u=03,   i=?1`` produces this signature-base line::

    "priority";sf: u=3, i

The field's type comes from ``http_sf``'s registry; both endpoints must use matching type definitions.
Unknown types and invalid values are rejected.

Use ``;sf`` only when all consumers interpret the field using Structured Fields semantics. For legacy fields such
as Cache-Control, differing duplicate-handling rules can change behavior without invalidating the signature.
Omit ``;sf`` when compatibility is unknown.

Binary wrapping and Set-Cookie
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use ``covered_component_ids=('"set-cookie";bs',)`` to cover each field line as a separate Structured Field
Byte Sequence, following `RFC 9421 section 2.1.3 <https://www.rfc-editor.org/rfc/rfc9421.html#section-2.1.3>`_.
When Set-Cookie is covered and multiple field lines are present, ``sign()`` and ``prepare()`` automatically
add ``bs``. Verification rejects signatures covering multiple Set-Cookie lines without it.

For binary wrapping, ``headers.items()`` must expose each original field line separately and in order.
The library cannot recover boundaries from values already combined by an HTTP client.

Message interface
~~~~~~~~~~~~~~~~~

Requests supply ``headers``, an uppercase ``method``, and an encoded absolute ``url`` with a nonempty host.
Responses supply ``headers``, ``status_code``, and the associated ``request`` for components marked ``req``.

``headers.items()`` must expose all field lines in wire order, separately or already combined.
Signing also requires mutable headers. Binary wrapping requires separate field lines.

Supply ``message.request_target`` when ``@request-target`` cannot be inferred from the URL, such as absolute-form
proxy requests or ``OPTIONS *``. The target and URL must describe the same request.
See ``HTTPSignatureComponentResolver`` in the API reference for the full interface.

Multiple signatures
~~~~~~~~~~~~~~~~~~~

By default, signing replaces existing signatures and verification requires a single signature. Before enabling
multiple signatures, read
`section 7.2.6 of the RFC, Multiple Signature Confusion <https://www.rfc-editor.org/rfc/rfc9421#name-multiple-signature-confusio>`_.

To append a signature, use::

    signer.sign(request, append_if_signature_exists=True, ...)

To select signatures by their signed application tag, use::

    verifier.verify(request, expect_tag="my_app_tag")

Every matching signature must verify. The method returns a list of ``VerifyResult`` s.

Error handling
~~~~~~~~~~~~~~

``verify()`` raises ``InvalidSignature`` for failed verification. Library exceptions derive from
``HTTPMessageSignaturesException``; key resolver and algorithm errors can also propagate.

Authors
-------
* `Andrey Kislyuk <https://kislyuk.com>`

Links
-----
* `Project home page (GitHub) <https://github.com/pyauth/http-message-signatures>`_
* `API reference and usage examples <https://github.com/pyauth/http-message-signatures/tree/main/docs>`_
* `Package distribution (PyPI) <https://pypi.python.org/pypi/http-message-signatures>`_
* `Change log <https://github.com/pyauth/http-message-signatures/blob/master/Changes.rst>`_
* `IETF HTTP Message Signatures standard tracker <https://datatracker.ietf.org/doc/rfc9421/>`_
* `OWASP Top Ten <https://owasp.org/www-project-top-ten/>`_

Bugs
~~~~
Please report bugs, issues, feature requests, etc. on `GitHub <https://github.com/pyauth/http-message-signatures/issues>`_.

License
-------
Copyright 2022-2026, Andrey Kislyuk and http-message-signatures contributors. Licensed under the terms of the
`Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0>`_. Distribution of attribution information,
LICENSE and NOTICE files with source copies of this package and derivative works is **REQUIRED** as specified by the
Apache License.

Our interoperability tests use published fixtures from
`Cloudflare's Web Bot Auth repository <https://github.com/cloudflare/web-bot-auth>`_.
