"""Client-independent Content-Digest generation and validation (RFC 9530)."""

import hashlib
import hmac
from typing import ClassVar

import http_sf
from http_sf.compat import Dictionary, Item

from .exceptions import HTTPMessageSignaturesException, InvalidSignature


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
    def verify(cls, value: str, body: bytes, *, key: str | None = None) -> None:
        """Validate a field or selected member; raise InvalidSignature on failure."""
        cls._check_body(body)

        def reject_duplicate(name: str, context: str) -> None:
            if context == "dictionary":
                raise InvalidSignature(f"Duplicate content digest algorithm {name!r}")

        try:
            parsed = http_sf.parse(
                value.encode("ascii"),
                tltype="dictionary" if key is None else "item",
                on_duplicate_key=reject_duplicate,
            )
        except (ValueError, TypeError) as exc:
            raise InvalidSignature("Malformed Content-Digest field") from exc
        members = parsed if key is None else {key: parsed}
        if not isinstance(members, dict) or not members:
            raise InvalidSignature("Content-Digest must contain at least one digest")
        for algorithm, member in members.items():
            if not isinstance(member, tuple) or not isinstance(member[0], bytes):
                raise InvalidSignature("Content digest values must be Structured Field byte sequences")
            if algorithm not in cls._hashers:
                raise InvalidSignature(f"Unsupported content digest algorithm {algorithm!r}")
            if not hmac.compare_digest(member[0], cls._hashers[algorithm](body).digest()):
                raise InvalidSignature("Content-Digest does not match the message body")
