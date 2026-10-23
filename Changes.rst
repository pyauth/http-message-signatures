Changes for v2.2.0 (2026-10-22)
===============================

-  Support bs field wrapping and reduce pre-verification parsing work
   (#40)

-  Support whole-field Structured Fields serialization (#38)

-  Documentation improvements

Changes for v2.1.0 (2026-10-18)
===============================

-  Add prepare/apply API for remote HTTP message signing

-  Honor and validate HMAC shared secret arguments

-  Reject scalar strings as covered component sequences

-  Reject prohibited control characters in covered header values

-  Preserve empty OPTIONS paths in the target URI

-  Use the RFC query-param component name

-  Allow strict serialization with dictionary member selection

-  Reject non-uppercase request methods before signature construction

-  Report verification input and key failures as InvalidSignature

-  Enforce Structured Field types and derived component characters

-  Reject duplicate signature labels through the Structured Fields
   parser

-  Normalize the full obsolete header folding sequence

-  Compare signature timestamps in UTC across DST transitions

-  Require request context parameters on response signatures

-  Normalize signature component values per RFC 9421

-  Test and documentation improvements

Changes for v2.0.1 (2026-01-18)
===============================

Remove Python 3.8 and 3.9 from PyPI metadata

Changes for v2.0.0 (2026-01-02)
===============================

- Multiple signature support (#22)

- Drop Python 3.9 support

Changes for v1.0.1 (2026-01-01)
===============================

- Remove extra ? in get_request_target (#19)

Changes for v1.0.0 (2025-07-26)
===============================

- Vendor http_sfv

- Package is stable

Changes for v0.7.0 (2025-06-29)
===============================

-  fix: convert url to string in HTTPSignatureComponentResolver
   constructor (#18)

Changes for v0.6.1 (2025-05-29)
===============================

- Switch to trusted publishing

Changes for v0.6.0 (2025-05-29)
===============================

- [http-message-signatures-add] Add support for ‘tag’ signature
  parameter (#17)

Changes for v0.5.0 (2024-02-21)
===============================

-  Add max_clock_skew to HTTPMessageVerifier (#11)

-  Documentation and test infrastructure improvements

Changes for v0.4.4 (2022-08-31)
===============================

-  Fix call signature in RSA_V1_5_SHA256 algorithm

-  Test improvements

Changes for v0.4.3 (2022-04-19)
===============================

-  Relocate VerifyResult

Changes for v0.4.2 (2022-04-19)
===============================

-  Fix casting bug

Changes for v0.4.1 (2022-04-19)
===============================

-  Add type information

-  Clean up algorithms namespace

-  Use max-age=24h by default

Changes for v0.4.0 (2022-04-14)
===============================

-  Validate created and expires params

Changes for v0.3.0 (2022-04-12)
===============================

-  Support query parameter addressing

Changes for v0.2.3 (2022-04-12)
===============================

-  Raise InvalidSignature in more code paths

-  Return related request method

-  Clarify that sign and verify work on both requests and responses

Changes for v0.2.2 (2022-04-10)
===============================

-  Add body placeholder

Changes for v0.2.1 (2022-04-10)
===============================

-  Return VerifyResult in verifier

Changes for v0.2.0 (2022-04-10)
===============================

-  Organize exceptions

Changes for v0.1.0 (2022-04-09)
===============================

-  Initial release.

Changes for v0.0.3 (2022-04-04)
===============================

-  Begin http-message-signatures
