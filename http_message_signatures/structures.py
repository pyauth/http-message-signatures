import re
from collections import OrderedDict
from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass
from typing import NamedTuple

from .algorithms import HTTPSignatureAlgorithm


@dataclass(frozen=True)
class PreparedSignature:
    """Immutable signing input returned by ``HTTPMessageSigner.prepare()``.

    :ivar signature_base: ASCII bytes to pass to the signing algorithm, without
        additional encoding or an added newline.
    :ivar signature_params: Serialized ``@signature-params`` value, including the
        covered component list and signed metadata.
    :ivar label: Signature dictionary label (not covered by the signature).
    :ivar algorithm_id: Configured algorithm ID, retained even when ``alg`` is omitted.

    Retain this object until applying the corresponding signature. It contains
    covered message values, which may be sensitive. Immutability prevents
    accidental edits; it does not authenticate data sent through a queue or service.
    """

    signature_base: bytes
    signature_params: str
    label: str
    algorithm_id: str


class VerifyResult(NamedTuple):
    """A verified signature and the values it covers.

    :ivar label: Signature dictionary label (not covered by the signature).
    :ivar algorithm: Algorithm class used for verification.
    :ivar covered_components: Serialized component identifiers mapped to signed
        values, including the generated ``\"@signature-params\"`` entry.
    :ivar parameters: Signed signature metadata, such as ``keyid`` and ``created``.
    :ivar body: Content bytes that the verifier validated against a signed digest,
        before decoding; otherwise ``None``.
    :ivar nonce: Signed nonce, or ``None`` when omitted.
    """

    label: str
    algorithm: type[HTTPSignatureAlgorithm]
    covered_components: dict[str, str]
    parameters: dict[str, int | str]
    body: bytes | None
    nonce: str | None


def normalize_header_value(value: str) -> str:
    # RFC 9421 section 2.1: unfold obsolete HTTP/1.1 line folding and trim OWS.
    # Bare CR/LF are not folds and must remain visible to validation.
    if "\r\n" not in value:
        return value.strip(" \t")
    # Only try preceding OWS at the start of a whitespace run, avoiding
    # quadratic retries. CRLF can still match after a previous fold's RWS.
    return re.sub(r"(?:(?<![ \t])[ \t]+)?\r\n[ \t]+", " ", value).strip(" \t")


class CaseInsensitiveDict(MutableMapping):
    """
    A copy of requests.structures.CaseInsensitiveDict.
    """

    def __init__(self, data=None, **kwargs):
        self._store = OrderedDict()
        if data is None:
            data = {}
        self.update(data, **kwargs)

    def __setitem__(self, key, value):
        # Use the lowercased key for lookups, but store the actual
        # key alongside the value.
        self._store[key.lower()] = (key, value)

    def __getitem__(self, key):
        return self._store[key.lower()][1]

    def __delitem__(self, key):
        del self._store[key.lower()]

    def __iter__(self):
        return (casedkey for casedkey, mappedvalue in self._store.values())

    def __len__(self):
        return len(self._store)

    def lower_items(self):
        """Like iteritems(), but with all lowercase keys."""
        return ((lowerkey, keyval[1]) for (lowerkey, keyval) in self._store.items())

    def __eq__(self, other):
        if isinstance(other, Mapping):
            other = CaseInsensitiveDict(other)
        else:
            return NotImplemented
        # Compare insensitively
        return dict(self.lower_items()) == dict(other.lower_items())

    # Copy is required
    def copy(self):
        return CaseInsensitiveDict(self._store.values())

    def __repr__(self):
        return str(dict(self.items()))


def get_header_field_lines(headers):
    """Group normalized field lines without losing their boundaries or wire order."""
    fields = CaseInsensitiveDict()
    for name, value in headers.items():
        value = normalize_header_value(value)
        if name in fields:
            fields[name].append(value)
        else:
            fields[name] = [value]
    return fields


def get_header_fields(headers):
    """Combine all field lines exposed by items(), preserving their wire order."""
    return CaseInsensitiveDict((name, ", ".join(values)) for name, values in get_header_field_lines(headers).items())
