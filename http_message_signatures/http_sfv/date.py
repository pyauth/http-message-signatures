from datetime import datetime
from typing import Tuple

from .integer import parse_integer


def parse_date(data: bytes) -> Tuple[int, datetime]:
    bytes_consumed, value = parse_integer(data[1:])
    if not isinstance(value, int):
        raise ValueError("Non-integer Date")
    return bytes_consumed + 1, datetime.fromtimestamp(value)


def ser_date(inval: datetime) -> str:
    return f"@{int(inval.timestamp())}"
