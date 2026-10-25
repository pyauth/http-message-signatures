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

    import hashlib

    import requests
    from http_sf.compat import Dictionary
    from http_message_signatures import HTTPMessageSigner, HTTPMessageVerifier, HTTPSignatureKeyResolver, algorithms

    class MyHTTPSignatureKeyResolver(HTTPSignatureKeyResolver):
        keys = {"my-key": b"top-secret-key"}

        def resolve_public_key(self, key_id: str):
            return self.keys[key_id]

        def resolve_private_key(self, key_id: str):
            return self.keys[key_id]

    request = requests.Request('POST', 'https://example.com/foo?param=Value&Pet=dog', json={"hello": "world"})
    request = request.prepare()
    request.headers["Content-Digest"] = str(Dictionary({"sha-256": hashlib.sha256(request.body).digest()}))

    signer = HTTPMessageSigner(signature_algorithm=algorithms.HMAC_SHA256, key_resolver=MyHTTPSignatureKeyResolver())
    signer.sign(request, key_id="my-key", covered_component_ids=("@method", "@authority", "@target-uri", "content-digest"))

    verifier = HTTPMessageVerifier(signature_algorithm=algorithms.HMAC_SHA256, key_resolver=MyHTTPSignatureKeyResolver())
    verifier.verify(request)

The base API reads no body implicitly. Pass ``body=`` with content bytes before decoding to ``sign()`` to generate
and cover Content-Digest, or to ``verify()`` to validate the signed digest. Digest generation refuses an existing
Content-Digest without modifying headers. The HTTPX integration below manages these bytes automatically.
The `requests-http-signature <https://github.com/pyauth/requests-http-signature>`_ library
provides a Requests integration.

.. admonition:: See what is signed

 It is important to understand and follow the best practice rule of "See what is signed" when verifying HTTP message
 signatures. The gist of this rule is: if your application neglects to verify that the information it trusts is
 what was actually signed, the attacker can supply a valid signature but point you to malicious data that wasn't signed
 by that signature. Failure to follow this rule can lead to vulnerability against signature wrapping and substitution
 attacks.

 In http-message-signatures, you can ensure that the information signed is what you expect to be signed by only trusting the
 data returned by the ``verify()`` method::

   verify_results = verifier.verify(request)

 This returns a list of ``VerifyResult`` s, which are ``namedtuple`` s with the following attributes:

 * label (str): The label for the signature
 * algorithm: (same as signature_algorithm above)
 * covered_components: A mapping of component names to their values, as covered by the signature
 * parameters: A mapping of signature parameters to their values, as covered by the signature
 * body: Content bytes before decoding after successful digest validation, or ``None`` when no digest was validated.

HTTPX integration
~~~~~~~~~~~~~~~~~

Install the optional dependency::

    pip install 'http-message-signatures[httpx]'

``SignatureHooks`` can sign prepared requests, verify responses, or do both through HTTPX event hooks. The default mode
enables both operations. Configure each operation independently in ``sign_options`` and ``verify_options``, including
its origin, algorithm, and keys. PEM bytes and cryptography key objects work for asymmetric algorithms; HMAC uses shared
secret bytes. Signing and verification can use different algorithms and keys::

    import httpx
    from http_message_signatures import algorithms
    from http_message_signatures.httpx import SignatureHooks, SignatureHooksMode

    signatures = SignatureHooks(
        sign_options={
            "origin": "https://api.example.com",
            "signature_algorithm": algorithms.ED25519,
            "key_id": "client-1",
            "signing_key": client_private_key,
            "tag": "example-api",
        },
        verify_options={
            "origin": "https://api.example.com",
            "signature_algorithm": algorithms.ED25519,
            "verification_keys": {"server-1": server_public_key},
            "expect_tag": "example-api",
            "require_components": ("@status", '"@method";req', '"@target-uri";req'),
        },
    )

    with httpx.Client(event_hooks=signatures.event_hooks) as client:
        response = client.post("https://api.example.com/items", json={"hello": "world"})
        response.raise_for_status()
        data = response.json()
        results = response.extensions["http_message_signatures"]

The server must return a signature from one of the configured verification keys, using the verification algorithm and
application tag. This example explicitly requires status and request method/URL coverage. A nonempty response, or any
response carrying Content-Digest, also requires a signed digest of the response's content. A digest of request content
selected using ``;req`` does not satisfy this requirement. Missing signatures, untrusted keys, insufficient configured
coverage, and body mismatches raise ``InvalidSignature`` before later response hooks or the caller receive the response.
Normal HTTP status handling remains with the application; signed error responses are verified too.

Use the async hook collection with ``AsyncClient``::

    async with httpx.AsyncClient(event_hooks=signatures.async_event_hooks) as client:
        response = await client.post("https://api.example.com/items", json={"hello": "world"})
        data = response.json()

Signing only or verification only
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The first argument, ``mode``, selects which hooks are installed. All other arguments are keyword-only:

* ``SignatureHooksMode.SIGN_REQUEST_VERIFY_RESPONSE`` (the default) requires both containers.
* ``SignatureHooksMode.SIGN_REQUEST`` requires only ``sign_options``. Responses use normal HTTPX handling.
* ``SignatureHooksMode.VERIFY_RESPONSE`` requires only ``verify_options``. Requests are sent without signing.

For signing only::

    signatures = SignatureHooks(
        SignatureHooksMode.SIGN_REQUEST,
        sign_options={
            "origin": "https://api.example.com",
            "signature_algorithm": algorithms.ED25519,
            "key_id": "client-1",
            "signing_key": client_private_key,
            "tag": "example-api",
        },
    )
    with httpx.Client(event_hooks=signatures.event_hooks) as client:
        response = client.post("https://api.example.com/items", json={"hello": "world"})

For verification only::

    signatures = SignatureHooks(
        SignatureHooksMode.VERIFY_RESPONSE,
        verify_options={
            "origin": "https://api.example.com",
            "signature_algorithm": algorithms.ED25519,
            "verification_keys": {"server-1": server_public_key},
            "expect_tag": "example-api",
            "require_components": ("@status",),
        },
    )
    with httpx.Client(event_hooks=signatures.event_hooks) as client:
        response = client.get("https://api.example.com/items")
        results = response.extensions["http_message_signatures"]

The same modes work with ``AsyncClient(event_hooks=signatures.async_event_hooks)``. Supply containers only for the enabled
operations. Missing containers or containers for a disabled operation raise ``ValueError``; missing required entries
raise ``TypeError`` at construction. No dummy keys or IDs are needed. Disabled handlers are not constructed, and their
hook lists are empty.

.. warning::

 When response verification is enabled, HTTPX updates its client cookie jar before running the verification hook.
 Verification failure does not undo cookie changes,
 even when Set-Cookie coverage is required. These hooks therefore do not provide authenticated automatic cookie
 persistence. Applications relying on signature-authenticated cookies need verification earlier in the HTTPX response
 lifecycle, such as an HTTPX transport wrapper. Restoring a cookie-jar snapshot is unsafe with concurrent requests.

Remote and asynchronous signing
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use ``prepare()`` and ``apply()`` when a KMS, HSM, SSH agent, or asynchronous client holds the signing key.
``prepare()`` builds the RFC 9421 signature base without reading a private key. It leaves the message unchanged unless
``body=`` is supplied to generate its digest.
It accepts the signing options used by ``sign()``, including covered components, creation and expiration times,
nonce, tag, label, and ``include_alg``. The returned ``PreparedSignature`` contains immutable bytes and strings.
``apply()`` writes the Signature-Input and Signature headers after the external signer returns.

``sign()`` now always passes the ``body`` keyword to ``prepare()``, including ``None``. Subclasses overriding
``prepare()`` must accept this keyword or forward ``**kwargs``; this is a breaking change to the recently introduced
preparation API.

This example expects an asynchronous ``sign_base`` function that signs the supplied bytes with Ed25519 and
returns the raw 64-byte signature. The client must use the private key identified by ``key_id``::

    from collections.abc import Awaitable, Callable

    from http_message_signatures import HTTPMessageSigner, algorithms

    async def sign_request(request, key_id: str, sign_base: Callable[[bytes], Awaitable[bytes]]):
        signer = HTTPMessageSigner(signature_algorithm=algorithms.ED25519)
        prepared = signer.prepare(
            request,
            key_id=key_id,
            label="sig1",
            covered_component_ids=("@method", "@authority", "@target-uri", "content-digest"),
        )
        signature = await sign_base(prepared.signature_base)
        signer.apply(request, prepared, signature)

Populate ``Content-Digest`` from the request body before this example runs, as in the synopsis above.
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

The field's Item, List, or Dictionary type is selected by its name using ``http_sf``'s registry.
Both endpoints must use matching type definitions. The registry may omit otherwise standardized fields;
an unknown type or a value invalid for its registered type raises ``HTTPMessageSignaturesException`` during
signing, or ``InvalidSignature`` during verification. The library does not infer types from field values.
Headers covered without ``sf`` use the ordinary HTTP field normalization rules and do not require a registry entry.

The registry also contains retrofit mappings for legacy headers whose parsing rules can differ from Structured
Fields. For example, this header::

    Cache-Control: max-age=3600

can be changed to::

    Cache-Control: max-age=0, max-age=3600

Both produce the same signed component because Structured Fields Dictionary parsing keeps the last duplicate::

    "cache-control";sf: max-age=3600

However, `RFC 9111 section 4.2.1 <https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2.1>`_ says duplicate
freshness directives should use the first occurrence or make the response stale. The change can therefore alter
caching behavior without invalidating a signature that covers ``"cache-control";sf``. The
`retrofit draft <https://httpwg.org/http-extensions/draft-ietf-httpbis-retrofit.html#section-2.1>`_ acknowledges
this difference in duplicate handling.

Omit ``;sf`` when the application's or other HTTP consumers' interpretation differs from Structured Fields
semantics, or compatibility is unknown. For example, use ``covered_component_ids=("cache-control",)`` to keep
both duplicate directives in the signed value; adding one then changes the signature base. Use ``;sf`` for fields
defined as Structured Fields, or legacy fields only when compatible interpretation is enforced. Applications
must still validate header values: successful signature verification does not establish their semantic validity.

Repeated field lines are combined before parsing. In a response signature, ``'"priority";req;sf'`` uses
the associated request's field. Dictionary-member selection with ``key`` continues to work without a registry
entry and may include the redundant ``sf`` flag. The ``tr`` parameter remains unsupported.

Binary wrapping and Set-Cookie
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use ``covered_component_ids=('"set-cookie";bs',)`` to cover each field line as a separate Structured Field
Byte Sequence, following `RFC 9421 section 2.1.3 <https://www.rfc-editor.org/rfc/rfc9421.html#section-2.1.3>`_.
The ``bs`` flag works with any header field, including request fields selected with ``req``. It cannot be
combined with ``sf`` or ``key``. Leading and trailing spaces and tabs are trimmed and obsolete line folding is
removed before encoding each line. Header strings represent the original field bytes decoded as Latin-1.

When Set-Cookie is covered and multiple field lines are present, ``sign()`` and ``prepare()`` automatically
add ``bs``. Verification rejects signatures that cover multiple Set-Cookie lines without ``bs``. Uncovered
Set-Cookie fields remain outside this check, and a single field line can still be covered without ``bs``.
This preserves field boundaries that comma joining would erase, as discussed in
`RFC 9421 section 7.5.6 <https://www.rfc-editor.org/rfc/rfc9421.html#section-7.5.6>`_.

For binary wrapping, ``headers.items()`` must expose each original field line separately and in order.
The library cannot recover boundaries from values already combined by an HTTP client. A comma inside one
Set-Cookie value, such as an Expires date, does not indicate multiple field lines. Cookie syntax and other
application-level content validation remain the caller's responsibility.

URL components
~~~~~~~~~~~~~~

The request's ``url`` supplies the target URL. URL components preserve percent-encoded octets and distinguish an
absent query from an empty query. ``@authority`` omits credentials and default ports; ``@target-uri`` excludes
credentials and fragments. Empty paths normally become ``/``. For ``OPTIONS``, ``@target-uri`` preserves an
empty path so server-wide ``OPTIONS *`` remains distinct from
``OPTIONS /``. The separate ``@path`` component still represents an empty path as ``/``.

Supply an encoded absolute URL with a nonempty host. Parsing preserves the supplied spelling and rejects invalid
syntax, including malformed percent escapes (``%``, ``%2``, or ``%ZZ``), spaces, control characters, and unencoded
non-ASCII characters. It never repairs input. Each signature component applies its own RFC 9421 formatting rules.
This applies during signing, verification, applying a prepared signature, and resolving request components covered
by a response signature. A response's own ``url`` is not used; components marked ``req`` use its associated request.

For ``@request-target``, clients can supply ``message.request_target`` containing the HTTP/1.1 request
target. This is necessary for absolute-form proxy requests and asterisk-form ``OPTIONS *`` requests, since those
forms cannot be inferred from an absolute URL. Without this attribute, the resolver derives origin form from the
URL, or authority form for ``CONNECT``. The supplied target and URL must describe the same request.

Multiple signatures
~~~~~~~~~~~~~~~~~~~

The message's ``headers.items()`` must expose every field line, or values already combined in wire order. Repeated
field names are compared case-insensitively, normalized individually, and joined with a comma followed by a space
before signing or parsing Structured Fields. Containers that discard repeated field lines before passing them to this library cannot be used
to verify those fields reliably. Signing also requires header assignment and deletion; existing Signature and
Signature-Input field lines are replaced together, including when appending a signature.

An HTTP request can potentially have multiple signatures. By default, http-message-signatures overwrites any existing
signature when signing, and requires exactly one signature to be present when verifying. Before enabling multi-signature
support, please read
`section 7.2.6 of the RFC, Multiple Signature Confusion <https://www.rfc-editor.org/rfc/rfc9421#name-multiple-signature-confusio>`_.

To append a signature to a message that might already carry an existing signature without overwriting it, use::

    signer.sign(request, append_if_signature_exists=True, ...)

To identify a signature using a ``tag`` parameter and verify it on a message possibly carrying multiple signatures, use::

    verifier.verify(request, expect_tag="my_app_tag")

This will filter all signatures down to only those that set the tag to the expected value, verify each of them, and
return a list of ``VerifyResult`` s. Verifying multiple signatures without prior knowledge of the application tag is not
supported.

Error handling
~~~~~~~~~~~~~~
Input request methods must be uppercase strings, including the request associated with a response.
Methods such as ``get`` or ``Fetch`` are rejected before signature construction or verification;
the library does not change their case. This applies even when ``@method`` is not covered.

Individual query parameters use the component name ``@query-param`` with a ``name`` parameter,
for example ``'"@query-param";name="Pet"'``. The previous spelling ``@query-params`` is rejected.

Signatures require a ``created`` timestamp by default. To accept signatures without one, set
``verifier.require_created = False`` and pass ``max_age=None`` to ``verify()``; an age limit cannot be enforced
without a creation timestamp. Expiration checks still apply when ``expires`` is present.

If multiple signatures are found in the request but ``expect_tag=...`` was not passed, then ``InvalidSignature`` is
raised. Also, the ``verify()`` method raises ``HTTPMessageSignaturesException`` or an exception derived from this class
in case an error occurs (unable to load PEM key, unsupported algorithm specified in signature input, signature doesn't
match digest etc.)

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
