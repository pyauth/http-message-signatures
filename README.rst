http-message-signatures: An implementation of RFC 9421, the IETF HTTP Message Signatures standard
=================================================================================================

*http-message-signatures* is an implementation of the IETF
`RFC 9421 HTTP Message Signatures <https://datatracker.ietf.org/doc/rfc9421/>`_ standard in
Python.

Installation
------------
::

    pip3 install http-message-signatures

Synopsis
--------

.. code-block:: python

    from http_message_signatures import HTTPMessageSigner, HTTPMessageVerifier, HTTPSignatureKeyResolver, algorithms, http_sfv
    import requests, base64, hashlib

    class MyHTTPSignatureKeyResolver(HTTPSignatureKeyResolver):
        keys = {"my-key": b"top-secret-key"}

        def resolve_public_key(self, key_id: str):
            return self.keys[key_id]

        def resolve_private_key(self, key_id: str):
            return self.keys[key_id]

    request = requests.Request('POST', 'https://example.com/foo?param=Value&Pet=dog', json={"hello": "world"})
    request = request.prepare()
    request.headers["Content-Digest"] = str(http_sfv.Dictionary({"sha-256": hashlib.sha256(request.body).digest()}))

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

Multiple signatures
~~~~~~~~~~~~~~~~~~~

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
* `Documentation <https://FIXME>`_
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
