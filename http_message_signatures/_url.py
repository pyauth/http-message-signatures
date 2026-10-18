"""Strict URL parsing for HTTP signature components.

Accept an ASCII, absolute URL with a scheme and nonempty host, using the
RFC 3986 component grammar. Return the scheme, host (including IP brackets),
port, path, and query with their supplied spelling. An absent path is "";
an absent port or query is None, distinct from an explicitly empty value.
Credentials and fragments are validated but omitted from the result because
they do not belong to the HTTP request target.

Reject invalid syntax with HTTPMessageSignaturesException. Never repair,
decode, quote, lowercase, remove dot segments, or supply a default path/port.
Signature component resolvers perform their own RFC 9421 formatting.

This is not a general URL library: relative and opaque references, Unicode
input, name resolution, and scheme-specific port limits are outside its
scope. IPv6 validation uses ipaddress; encoded zone IDs use RFC 6874 syntax.
Query parameter decoding remains the responsibility of urllib.parse.
"""

import re
from dataclasses import dataclass
from ipaddress import IPv6Address

from .exceptions import HTTPMessageSignaturesException

# RFC 3986 sections 2 and 3. Each repeated alternative consumes either one
# allowed character or one percent escape; their leading characters differ.
_UNRESERVED = r"A-Za-z0-9._~\-"
_SUB_DELIMS = r"!$&'()*+,;="
_CHARS = _UNRESERVED + _SUB_DELIMS
_PCT_ENCODED = r"%[0-9A-Fa-f]{2}"
_ZONE_ID = rf"(?:[{_UNRESERVED}]|{_PCT_ENCODED})+"
_IPV6 = rf"[0-9A-Fa-f:.]+(?:%25{_ZONE_ID})?"
_IPVFUTURE = rf"[vV][0-9A-Fa-f]+\.[{_CHARS}:]+"
_URL = re.compile(
    r"(?P<scheme>[A-Za-z][A-Za-z0-9+.\-]*)://"
    rf"(?:(?:[{_CHARS}:]|{_PCT_ENCODED})*@)?"
    rf"(?P<host>\[(?:{_IPV6}|{_IPVFUTURE})\]|(?:[{_CHARS}]|{_PCT_ENCODED})+)"
    r"(?::(?P<port>[0-9]*))?"
    rf"(?P<path>/(?:[{_CHARS}:@/]|{_PCT_ENCODED})*)?"
    rf"(?:\?(?P<query>(?:[{_CHARS}:@/?]|{_PCT_ENCODED})*))?"
    rf"(?:\#(?:[{_CHARS}:@/?]|{_PCT_ENCODED})*)?"
)


@dataclass(frozen=True)
class URLParts:
    scheme: str
    host: str
    port: str | None
    path: str
    query: str | None

    @property
    def authority(self) -> str:
        return self.host if self.port is None else f"{self.host}:{self.port}"

    @property
    def query_suffix(self) -> str:
        return "" if self.query is None else "?" + self.query


def parse_url(url: str) -> URLParts:
    match = _URL.fullmatch(url)
    if match is None:
        raise HTTPMessageSignaturesException("Invalid URL: expected an encoded absolute URL with a host")
    host = match["host"]
    if host.startswith("[") and host[1] not in "vV":
        # Validate the address without adopting ipaddress's canonical spelling.
        address = host[1:-1].partition("%25")[0]
        try:
            IPv6Address(address)
        except ValueError as e:
            raise HTTPMessageSignaturesException("Invalid URL: invalid IPv6 address") from e
    return URLParts(match["scheme"], host, match["port"], match["path"] or "", match["query"])
