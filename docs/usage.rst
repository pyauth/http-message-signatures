Message interface and examples
==============================

Message objects
---------------

The signer and verifier accept objects with the attributes below. No inheritance
from a package class is required. ``requests.PreparedRequest`` and
``requests.Response`` are examples of compatible objects; the examples here use
``types.SimpleNamespace`` to show the interface independently of a client library.

* Requests provide ``method`` (an uppercase string), ``url`` (the absolute target
  URI), and ``headers``. Method validation also applies when ``@method`` is not
  covered by the signature.
* Responses provide ``status_code`` (an integer), ``url``, and ``headers``. The
  resolver uses the presence of ``status_code`` to identify a response. The
  ``url`` attribute is read during initialization even for a status-only signature.
* A response's ``request`` is needed for request components qualified with ``req``.
  When present, the associated request's method must also be uppercase.
* ``headers.items()`` returns string names and string values, exposing all field
  lines in order or values already combined in that order. Signing additionally
  needs iteration over names, assignment, membership testing, and deletion.
* A request may provide ``request_target`` when its HTTP/1.1 request target cannot
  be recovered from ``url``, such as an absolute-form proxy target or ``*``.
  This value and ``url`` must describe the same request.

Signing and verifying a request
----------------------------------

Supply a sequence for ``covered_component_ids``. For one component, use
``("date",)`` or ``["date"]``; ``("date")`` is a scalar string and is rejected.
Parameterized identifiers use Structured Field syntax, for example
``'"@query-param";name="Pet"'``.

.. testcode::

    from types import SimpleNamespace

    from http_message_signatures import (
        HTTPMessageSigner, HTTPMessageVerifier, HTTPSignatureKeyResolver, InvalidSignature,
    )
    from http_message_signatures.algorithms import HMAC_SHA256

    class Keys(HTTPSignatureKeyResolver):
        def resolve_private_key(self, key_id):
            return {"example-key": b"example-only-secret"}[key_id]

        def resolve_public_key(self, key_id):
            return self.resolve_private_key(key_id)

    request = SimpleNamespace(
        method="GET", url="https://example.com/pets?Pet=dog", headers={},
    )
    signer = HTTPMessageSigner(signature_algorithm=HMAC_SHA256, key_resolver=Keys())
    verifier = HTTPMessageVerifier(signature_algorithm=HMAC_SHA256, key_resolver=Keys())
    signer.sign(request, key_id="example-key")
    result = verifier.verify(request)[0]
    required = {'"@method"', '"@authority"', '"@target-uri"'}
    if not required.issubset(result.covered_components):
        raise InvalidSignature("Required request components were not signed")
    assert result.covered_components['"@method"'] == "GET"
    assert result.covered_components['"@target-uri"'] == request.url

Verification results contain serialized component identifiers, including quotes
and any parameters. Verification does not establish application authorization,
validate body digests, or detect nonce reuse; implement those checks as needed.

Signing and verifying a response
----------------------------------

The default covered components belong to a request. When signing a response,
choose its components explicitly. Request components in a response signature
must carry ``req``; the example binds the response status and content type to
the original request's target URI.

.. testcode::

    response = SimpleNamespace(
        status_code=200,
        url=request.url,
        request=request,
        headers={"Content-Type": "application/json"},
    )
    signer.sign(
        response,
        key_id="example-key",
        covered_component_ids=("@status", "content-type", '"@target-uri";req'),
    )
    result = verifier.verify(response)[0]
    assert result.covered_components['"@status"'] == "200"
    assert result.covered_components['"content-type"'] == "application/json"
    assert result.covered_components['"@target-uri";req'] == request.url

    response.status_code = 201
    try:
        verifier.verify(response)
    except InvalidSignature:
        pass
    else:
        raise AssertionError("Changing a signed response status must invalidate the signature")

This example has no response body. If a response carries a body, the application
must calculate, sign, and validate its digest separately.

Building the documentation
--------------------------

From a source checkout, install ``pip install '.[docs]'`` and run ``make docs``.
The generated reference is in ``docs/html/index.html``. Run ``make test-docs`` to
execute these examples. CI builds the reference with warnings treated as errors
and executes the examples.
