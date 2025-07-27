from string import ascii_lowercase, ascii_uppercase, digits
from typing import Tuple

SPACE = ord(b" ")
HTTP_OWS = set(b" \t")


def discard_ows(data: bytes) -> int:
    "Return the number of space characters at the beginning of data."
    i = 0
    ln = len(data)
    while True:
        if i == ln or data[i] != SPACE:
            return i
        i += 1


def discard_http_ows(data: bytes) -> int:
    "Return the number of space or HTAB characters at the beginning of data."
    i = 0
    ln = len(data)
    while True:
        if i == ln or data[i] not in HTTP_OWS:
            return i
        i += 1


KEY_START_CHARS = set((ascii_lowercase + "*").encode("ascii"))
KEY_CHARS = set((ascii_lowercase + digits + "_-*.").encode("ascii"))
UPPER_CHARS = set((ascii_uppercase).encode("ascii"))
COMPAT = False


def parse_key(data: bytes) -> Tuple[int, str]:
    if data == b"" or data[0] not in KEY_START_CHARS:
        if data == b"" or not (COMPAT and data[0] in UPPER_CHARS):
            raise ValueError("Key does not begin with lcalpha or *")
    bytes_consumed = 1
    while bytes_consumed < len(data):
        if data[bytes_consumed] not in KEY_CHARS:
            if not (COMPAT and data[bytes_consumed] in UPPER_CHARS):
                return bytes_consumed, data[:bytes_consumed].decode("ascii").lower()
        bytes_consumed += 1
    return bytes_consumed, data.decode("ascii").lower()


def ser_key(key: str) -> str:
    if not all(ord(char) in KEY_CHARS for char in key):
        raise ValueError("Key contains disallowed characters")
    if ord(key[0]) not in KEY_START_CHARS:
        raise ValueError("Key does not start with allowed character")
    return key


class StructuredFieldValue:
    def parse(self, data: bytes) -> None:
        bytes_consumed = discard_ows(data)
        bytes_consumed += self.parse_content(data[bytes_consumed:])
        bytes_consumed += discard_ows(data[bytes_consumed:])
        if data[bytes_consumed:]:
            raise ValueError("Trailing text after parsed value")

    def parse_content(self, data: bytes) -> int:
        raise NotImplementedError

    def __str__(self) -> str:
        raise NotImplementedError
