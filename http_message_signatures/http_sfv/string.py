from typing import Tuple

DQUOTE = ord('"')
BACKSLASH = ord("\\")
DQUOTEBACKSLASH = set([DQUOTE, BACKSLASH])


def parse_string(data: bytes) -> Tuple[int, str]:
    output_string = bytearray()
    bytes_consumed = 1  # consume DQUOTE
    while True:
        try:
            char = data[bytes_consumed]
        except IndexError as why:
            raise ValueError("Reached end of input without finding a closing DQUOTE") from why
        bytes_consumed += 1
        if char == BACKSLASH:
            try:
                next_char = data[bytes_consumed]
            except IndexError as why:
                raise ValueError("Last character of input was a backslash") from why
            bytes_consumed += 1
            if next_char not in DQUOTEBACKSLASH:
                raise ValueError(f"Backslash before disallowed character '{chr(next_char)}'")
            output_string.append(next_char)
        elif char == DQUOTE:
            return bytes_consumed, output_string.decode("ascii")
        elif not 31 < char < 127:
            raise ValueError("String contains disallowed character")
        else:
            output_string.append(char)


def ser_string(inval: str) -> str:
    if not all(31 < ord(char) < 127 for char in inval):
        raise ValueError("String contains disallowed characters")
    escaped = inval.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'
