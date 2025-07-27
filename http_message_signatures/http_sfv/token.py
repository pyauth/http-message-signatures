from string import ascii_letters, digits
from typing import Tuple

from .types import Token

TOKEN_START_CHARS = set((ascii_letters + "*").encode("ascii"))
TOKEN_CHARS = set((ascii_letters + digits + ":/!#$%&'*+-.^_`|~").encode("ascii"))


def parse_token(data: bytes) -> Tuple[int, Token]:
    bytes_consumed = 1  # consume start char
    size = len(data)
    while bytes_consumed < size:
        if data[bytes_consumed] not in TOKEN_CHARS:
            return bytes_consumed, Token(data[:bytes_consumed].decode("ascii"))
        bytes_consumed += 1
    return bytes_consumed, Token(data[:bytes_consumed].decode("ascii"))


def ser_token(token: Token) -> str:
    if token and ord(str(token)[0]) not in TOKEN_START_CHARS:
        raise ValueError("Token didn't start with legal character")
    if not all(ord(char) in TOKEN_CHARS for char in str(token)):
        raise ValueError("Token contains disallowed characters")
    return str(token)
