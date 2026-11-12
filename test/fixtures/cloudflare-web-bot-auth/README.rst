Cloudflare Web Bot Auth interoperability fixtures
================================================

These files are unmodified copies from
`cloudflare/web-bot-auth <https://github.com/cloudflare/web-bot-auth>`_,
pinned to commit ``01c0d10a5f00d4e77cc5677576a7a2b6e4954d50`` (2026-11-10).

The JSON files come from
`packages/web-bot-auth/test/test_data
<https://github.com/cloudflare/web-bot-auth/tree/01c0d10a5f00d4e77cc5677576a7a2b6e4954d50/packages/web-bot-auth/test/test_data>`_:

* ``web_bot_auth_architecture_v1.json``: four request signatures using
  RSA-PSS/SHA-512 or Ed25519, with and without a whole-field Signature-Agent.
* ``web_bot_auth_architecture_v2.json``: four request signatures using the same
  algorithms, including Signature-Agent dictionary member coverage (``;key``).
* ``web_bot_auth_directory_response_v1.json``: an Ed25519 response signature
  covering Content-Digest and the associated request's authority (``;req``),
  with a published signature base and response body.

The adjacent LICENSE is copied from the upstream repository root. The fixtures
are Copyright 2025 Cloudflare, Inc., licensed under Apache License 2.0.
Their published private keys are test material. They use the RFC 9421 RSA-PSS
and Ed25519 keys already stored as PEM files in our test directory; the tests
reuse those files and resolve them under the fixtures' signature key IDs.

``test/test_cloudflare_interop.py`` loads these files with Python's JSON parser
and uses the existing Structured Fields parser for Signature-Input. Verification
runs at each fixture's creation time. Tests verify the published signatures,
reproduce signing inputs and deterministic Ed25519 signatures, and check the
directory response's signature base and body digest. RSA-PSS signing output is
verified because its signatures are randomized. Tampering checks change covered
authorities or the response body without changing the published signatures.

These are HTTP Message Signatures interoperability tests. The older architecture
fixtures remain useful for RFC 9421 even where the Web Bot Auth profile has since
changed. The tests do not implement key discovery or enforce Web Bot Auth policy.

To update, select and record a new upstream commit, copy the three JSON files
and root LICENSE without reformatting, review changes to their coverage and
profile versions, then run::

    python -m unittest discover -s test -p 'test_cloudflare_interop.py' -v

The fixtures are vendored so normal test runs require no network access.
