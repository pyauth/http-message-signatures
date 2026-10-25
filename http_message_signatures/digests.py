"""Client-independent Content-Digest generation and validation (RFC 9530)."""

import hashlib
import hmac
from collections.abc import Mapping
from typing import ClassVar

import http_sf
from http_sf.compat import Dictionary, Item

from .components import parse_component_ids
from .exceptions import HTTPMessageSignaturesException, InvalidSignature
from .messages import Headers
from .structures import get_header_fields


def is_content_digest(component: Item) -> bool:
    """Whether a component covers this message's digest field or a member."""
    return component.value == "content-digest" and not set(component.params) - {"sf", "key"}


class ContentDigest:
    """Generate and verify SHA-256/SHA-512 digests of content before decoding.

    Subclass and set ``algorithm`` to select the outgoing digest algorithm.
    Verification accepts either supported algorithm and checks every supplied
    member. Dictionary-member coverage can be verified with ``key=``.
    """

    algorithm = "sha-256"
    _hashers: ClassVar = {"sha-256": hashlib.sha256, "sha-512": hashlib.sha512}

    @staticmethod
    def _check_body(body: bytes) -> None:
        if not isinstance(body, bytes):
            raise HTTPMessageSignaturesException("body must contain bytes before content decoding")

    @classmethod
    def create(cls, body: bytes) -> str:
        """Serialize a digest for the supplied content, including empty content."""
        cls._check_body(body)
        if cls.algorithm not in cls._hashers:
            raise HTTPMessageSignaturesException(f"Unsupported content digest algorithm {cls.algorithm!r}")
        return str(Dictionary({cls.algorithm: cls._hashers[cls.algorithm](body).digest()}))

    @classmethod
    def add(cls, headers: Headers, body: bytes) -> None:
        """Add a digest, refusing any existing Content-Digest field without mutation."""
        if any(name.lower() == "content-digest" for name, _ in headers.items()):
            raise HTTPMessageSignaturesException("Cannot add Content-Digest: the field is already present")
        headers["Content-Digest"] = cls.create(body)

    @classmethod
    def prepare(cls, headers: Headers, body: bytes | None, *, allow_existing_digest: bool) -> None:
        """Prepare or explicitly reuse a digest, leaving existing field lines intact."""
        if not isinstance(allow_existing_digest, bool):
            raise TypeError("allow_existing_digest must be True or False")
        if body is not None:
            cls._check_body(body)
        fields = get_header_fields(headers)
        if "content-digest" in fields:
            if not allow_existing_digest:
                raise HTTPMessageSignaturesException(
                    "Content-Digest is already present; pass allow_existing_digest=True to reuse it"
                )
            if body is None:
                cls._parse(fields["content-digest"])
            else:
                cls.verify(fields["content-digest"], body)
        elif body is not None:
            cls.add(headers, body)
        elif allow_existing_digest:
            raise HTTPMessageSignaturesException(
                "allow_existing_digest=True requires an existing Content-Digest or body bytes to generate one"
            )

    @classmethod
    def _parse(cls, value: str | bytes, *, key: str | None = None) -> dict[str, bytes]:

        def reject_duplicate(name: str, context: str) -> None:
            if context == "dictionary":
                raise InvalidSignature(f"Duplicate content digest algorithm {name!r}")

        try:
            parsed = http_sf.parse(
                value.encode("ascii") if isinstance(value, str) else value,
                tltype="dictionary" if key is None else "item",
                on_duplicate_key=reject_duplicate,
            )
        except (ValueError, TypeError) as exc:
            raise InvalidSignature("Malformed Content-Digest field") from exc
        members = parsed if key is None else {key: parsed}
        if not isinstance(members, dict) or not members:
            raise InvalidSignature("Content-Digest must contain at least one digest")
        digests = {}
        for algorithm, member in members.items():
            if not isinstance(member, tuple) or not isinstance(member[0], bytes):
                raise InvalidSignature("Content digest values must be Structured Field byte sequences")
            if algorithm not in cls._hashers:
                raise InvalidSignature(f"Unsupported content digest algorithm {algorithm!r}")
            if len(member[0]) != cls._hashers[algorithm]().digest_size:
                raise InvalidSignature(f"Invalid {algorithm} digest length")
            digests[algorithm] = member[0]
        return digests

    @classmethod
    def verify(cls, value: str | bytes, body: bytes, *, key: str | None = None) -> None:
        """Validate a field or selected member; raise InvalidSignature on failure."""
        cls._check_body(body)
        for algorithm, digest in cls._parse(value, key=key).items():
            if not hmac.compare_digest(digest, cls._hashers[algorithm](body).digest()):
                raise InvalidSignature("Content-Digest does not match the message body")

    @classmethod
    def verify_components(cls, covered_components: Mapping[str, str], body: bytes) -> bool:
        """Validate this message's digest components in an authenticated mapping.

        Pass all of VerifyResult.covered_components, or a subset selected by the
        caller's coverage policy. Return whether a digest was validated. Request
        components qualified with ``req`` do not cover a response's body.
        """
        cls._check_body(body)
        verified = False
        for identifier, value in covered_components.items():
            node = parse_component_ids((identifier,))[0]
            if is_content_digest(node):
                cls.verify(value, body, key=node.params.get("key"))
                verified = True
        return verified
