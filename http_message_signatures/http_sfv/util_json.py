import base64
from datetime import datetime
from decimal import Decimal

from .types import BareItemType, JsonBareType, Token, DisplayString


def value_to_json(value: BareItemType) -> JsonBareType:
    if isinstance(value, bytes):
        return {
            "__type": "binary",
            "value": base64.b32encode(value).decode("ascii"),
        }
    if isinstance(value, Token):
        return {"__type": "token", "value": str(value)}
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, datetime):
        return {"__type": "date", "value": value.timestamp()}
    if isinstance(value, DisplayString):
        return {"__type": "displaystring", "value": str(value)}
    return value


def value_from_json(value: JsonBareType) -> BareItemType:
    if isinstance(value, dict):
        if "__type" in value:
            if value["__type"] == "token":
                return Token(value["value"])
            if value["__type"] == "binary":
                return base64.b32decode(value["value"])
            if value["__type"] == "date":
                return datetime.fromtimestamp(value["value"])
            if value["__type"] == "displaystring":
                return DisplayString(value["value"])
            raise RuntimeError(f"Unrecognised data type {value['__type']}")
        raise RuntimeError("Dictionary as Item")
    return value
