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

Note that verifying the body content-digest is outside the scope of this package's functionality, so it remains the
caller's responsibility. The `requests-http-signature <https://github.com/pyauth/requests-http-signature>`_ library
builds upon this package to provide integrated signing and validation of the request body.

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
 * body: Always ``None`` (the `requests-http-signature <https://github.com/pyauth/requests-http-signature>`_ package
   implements returning the body upon successful digest validation).

Remote and asynchronous signing
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use ``prepare()`` and ``apply()`` when a KMS, HSM, SSH agent, or asynchronous client holds the signing key.
``prepare()`` builds the RFC 9421 signature base without reading a private key or modifying the message.
It accepts the signing options used by ``sign()``, including covered components, creation and expiration times,
nonce, tag, label, and ``include_alg``. The returned ``PreparedSignature`` contains immutable bytes and strings.
``apply()`` writes the Signature-Input and Signature headers after the external signer returns.

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

Remote clients differ in their accepted input and output formats. Configure the algorithm as specified in
`RFC 9421 section 3.3 <https://www.rfc-editor.org/rfc/rfc9421.html#section-3.3>`_. Ed25519 signs the base without prehashing.
For RSA and ECDSA, a client that accepts raw messages must perform the specified hashing; a client that accepts a digest
must receive that digest and be configured to avoid hashing it a second time. The RSA-PSS profile uses SHA-512,
MGF1 with SHA-512, and a 64-byte salt.

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
Copyright 2017-2024, Andrey Kislyuk and http-message-signatures contributors. Licensed under the terms of the
`Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0>`_. Distribution of attribution information,
LICENSE and NOTICE files with source copies of this package and derivative works is **REQUIRED** as specified by the
Apache License.
