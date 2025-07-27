from decimal import Decimal
from string import digits
from typing import Tuple, Union

MAX_INT = 999999999999999
MIN_INT = -999999999999999

DIGITS = set(digits.encode("ascii"))
NUMBER_START_CHARS = set((digits + "-").encode("ascii"))
PERIOD = ord(b".")
MINUS = ord(b"-")


def parse_integer(data: bytes) -> Tuple[int, int]:
    return parse_number(data)  # type: ignore


def ser_integer(inval: int) -> str:
    if not MIN_INT <= inval <= MAX_INT:
        raise ValueError("Input is out of Integer range.")
    output = ""
    if inval < 0:
        output += "-"
    output += str(abs(inval))
    return output


INTEGER = "integer"
DECIMAL = "decimal"


def parse_number(data: bytes) -> Tuple[int, Union[int, Decimal]]:
    _type = INTEGER
    _sign = 1
    bytes_consumed = 0
    num_start = 0
    decimal_index = 0
    num_length = 0
    if data[0] == MINUS:
        bytes_consumed += 1
        num_start += 1
        _sign = -1
    if not data[bytes_consumed:]:
        raise ValueError("Number input lacked a number")
    if data[num_start] not in DIGITS:
        raise ValueError("Number doesn't start with a DIGIT")
    while True:
        try:
            char = data[bytes_consumed]
        except IndexError:
            break
        bytes_consumed += 1
        num_length = bytes_consumed - num_start - 1
        if char in DIGITS:
            pass
        elif _type is INTEGER and char == PERIOD:
            if num_length > 12:
                raise ValueError("Decimal too long.")
            _type = DECIMAL
            decimal_index = bytes_consumed
        else:
            bytes_consumed -= 1
            break
    if _type == INTEGER:
        if num_length > 15:
            raise ValueError("Integer too long.")
        output_int = int(data[num_start:bytes_consumed]) * _sign
        if not MIN_INT <= output_int <= MAX_INT:
            raise ValueError("Integer outside allowed range")
        return bytes_consumed, output_int
    # Decimal
    if num_length > 16:
        raise ValueError("Decimal too long.")
    if data[bytes_consumed - 1] == MINUS:
        raise ValueError("Decimal ends in '.'")
    if bytes_consumed - decimal_index > 3:
        raise ValueError("Decimal fractional component too long")
    output_float = Decimal(data[num_start:bytes_consumed].decode("ascii")) * _sign
    return bytes_consumed, output_float
