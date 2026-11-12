Remote signing reference
========================

Use ``HTTPMessageSigner.prepare()`` to build the signing input and ``apply()`` to attach the result.
The README's remote signing example shows this workflow with an asynchronous Ed25519 signer.

Signing service configuration
-----------------------------

External signing services differ in their accepted input and output formats. Configure the service according to
`RFC 9421 section 3.3 <https://www.rfc-editor.org/rfc/rfc9421.html#section-3.3>`_:

* Ed25519 signs ``prepared.signature_base`` without prehashing.
* For RSA and ECDSA, an API accepting raw messages must perform the specified hashing. If the API accepts a digest,
  hash the signature base before calling it and select a mode that does not hash the digest again.
* The RSA-PSS profile uses SHA-512, MGF1 with SHA-512, and a 64-byte salt.

The configured algorithm applies even when ``include_alg=False``; omitting the parameter does not negotiate an algorithm.
Pass the signature base without additional encoding or an added newline.

Signature formats
-----------------

``apply()`` expects raw signature bytes and performs the Structured Field base64 encoding.
Decode base64 responses from a service before calling it. ECDSA P-256 services often return DER, while RFC 9421
requires a 64-byte concatenation of ``r`` and ``s``, each padded to 32 bytes. Convert DER output with the algorithm's helper::

    from http_message_signatures import HTTPMessageSigner, algorithms

    signer = HTTPMessageSigner(signature_algorithm=algorithms.ECDSA_P256_SHA256)
    prepared = signer.prepare(request, key_id="p256-key")
    # der_signature is the service's ECDSA P-256/SHA-256 signature of prepared.signature_base.
    signature = algorithms.ECDSA_P256_SHA256.signature_from_der(der_signature)
    signer.apply(request, prepared, signature)

Prepared input
--------------

Associate each result with its prepared input. Protect queued input against modification and disclosure:
the signature base contains covered header and URL values. ``apply()`` checks covered values, but does not
authenticate the prepared object, verify the returned signature, or check the body against its digest.
Keep the message stable during ``apply()`` and until it is sent.

Creation and expiration times are set during preparation. Allow for signing delays when choosing expiration times;
``apply()`` does not refresh them.
