from typing import Tuple

from .types import DisplayString

PERCENT = ord("%")
DQUOTE = ord('"')


def parse_display_string(data: bytes) -> Tuple[int, DisplayString]:
    output_array = bytearray([])
    if data[:2] != b'%"':
        raise ValueError('Display string does not start with %"')
    bytes_consumed = 2  # consume PERCENT DQUOTE
    while True:
        try:
            char = data[bytes_consumed]
        except IndexError as why:
            raise ValueError("Reached end of input without finding a closing DQUOTE") from why
        bytes_consumed += 1
        if char == PERCENT:
            try:
                next_chars = data[bytes_consumed : bytes_consumed + 2]
            except IndexError as why:
                raise ValueError("Incomplete percent encoding") from why
            bytes_consumed += 2
            if next_chars.lower() != next_chars:
                raise ValueError("Uppercase percent encoding")
            try:
                octet = int(next_chars, base=16)
            except ValueError as why:
                raise ValueError("Invalid percent encoding") from why
            output_array.append(octet)
        elif char == DQUOTE:
            try:
                output_string = output_array.decode("utf-8")
            except UnicodeDecodeError as why:
                raise ValueError("Invalid UTF-8") from why
            return bytes_consumed, DisplayString(output_string)
        elif 31 < char < 127:
            output_array.append(char)
        else:
            raise ValueError("String contains disallowed character")


def ser_display_string(inval: DisplayString) -> str:
    byte_array = inval.encode("utf-8")
    escaped = []
    for byte in byte_array:
        if byte in [PERCENT, DQUOTE] or not 31 <= byte <= 127:
            escaped.append(f"%{byte:x}")
        else:
            escaped.append(chr(byte))
    return DisplayString(f'%"{"".join(escaped)}"')
