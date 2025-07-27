from decimal import Decimal
from typing import Tuple, Union

from .integer import parse_number

INT_DIGITS = 12
FRAC_DIGITS = 3
PRECISION = Decimal(10) ** -FRAC_DIGITS


def parse_decimal(data: bytes) -> Tuple[int, Decimal]:
    return parse_number(data)  # type: ignore


def ser_decimal(input_decimal: Union[Decimal, float]) -> str:
    if isinstance(input_decimal, float):
        input_decimal = Decimal(input_decimal)
    if not isinstance(input_decimal, Decimal):
        raise ValueError("decimal input is not decimal")
    input_decimal = round(input_decimal, FRAC_DIGITS)
    abs_decimal = input_decimal.copy_abs()
    integer_component_s = str(int(abs_decimal))
    if len(integer_component_s) > INT_DIGITS:
        raise ValueError(f"decimal with oversize integer component {integer_component_s}")
    fractional_component = abs_decimal.quantize(PRECISION).normalize() % 1
    return (
        f"{'-' if input_decimal < 0 else ''}{integer_component_s}."
        f"{str(fractional_component)[2:] if fractional_component else '0'}"
    )
