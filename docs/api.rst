API reference
=============

Signing and verification
------------------------

.. autoclass:: http_message_signatures.HTTPMessageSigner
   :class-doc-from: both
   :members: sign

.. autoclass:: http_message_signatures.HTTPMessageVerifier
   :class-doc-from: both
   :members: verify, max_clock_skew, require_created, allow_label_only_selection

.. autoclass:: http_message_signatures.VerifyResult
   :members:

Resolvers
---------

.. autoclass:: http_message_signatures.HTTPSignatureKeyResolver
   :members:

.. autoclass:: http_message_signatures.HTTPSignatureComponentResolver
   :members: resolve

Algorithms
----------

These classes can be passed as ``signature_algorithm`` to the signer or verifier.
Calling an algorithm directly operates on bytes, without constructing an HTTP
signature base. Direct cryptographic failures may raise cryptography exceptions;
``HTTPMessageVerifier`` converts these failures to ``InvalidSignature``.

.. autoclass:: http_message_signatures.algorithms.HTTPSignatureAlgorithm
   :members: sign, verify

.. autoclass:: http_message_signatures.algorithms.HMAC_SHA256

.. autoclass:: http_message_signatures.algorithms.RSA_PSS_SHA512

.. autoclass:: http_message_signatures.algorithms.RSA_V1_5_SHA256

.. autoclass:: http_message_signatures.algorithms.ECDSA_P256_SHA256

.. autoclass:: http_message_signatures.algorithms.ED25519

Exceptions
----------

.. autoexception:: http_message_signatures.HTTPMessageSignaturesException

.. autoexception:: http_message_signatures.InvalidSignature
