from collections import UserList
from datetime import datetime
from decimal import Decimal
from typing import List as _List, Tuple, Union, Any, Iterable, cast
from typing_extensions import SupportsIndex

from .boolean import parse_boolean, ser_boolean
from .byteseq import parse_byteseq, ser_byteseq, BYTE_DELIMIT
from .decimal import ser_decimal
from .integer import parse_number, ser_integer, NUMBER_START_CHARS
from .string import parse_string, ser_string, DQUOTE
from .token import parse_token, ser_token, Token, TOKEN_START_CHARS
from .date import parse_date, ser_date
from .display_string import parse_display_string, ser_display_string, DisplayString
from .types import BareItemType, JsonItemType, JsonParamType, JsonInnerListType
from .util import (
    StructuredFieldValue,
    discard_ows,
    parse_key,
    ser_key,
)
from .util_json import value_to_json, value_from_json


SEMICOLON = ord(b";")
EQUALS = ord(b"=")
PAREN_OPEN = ord(b"(")
PAREN_CLOSE = ord(b")")
INNERLIST_DELIMS = set(b" )")


class Item(StructuredFieldValue):
    def __init__(self, value: BareItemType = None) -> None:
        StructuredFieldValue.__init__(self)
        self.value = value
        self.params = Parameters()

    def parse_content(self, data: bytes) -> int:
        try:
            bytes_consumed, self.value = parse_bare_item(data)
            bytes_consumed += self.params.parse(data[bytes_consumed:])
        except Exception as why:
            self.value = None
            raise ValueError from why
        return bytes_consumed

    def __str__(self) -> str:
        return f"{ser_bare_item(self.value)}{str(self.params)}"

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, Item):
            return self.value == other.value
        return bool(self.value == other)

    def to_json(self) -> JsonItemType:
        value = value_to_json(self.value)
        return (value, self.params.to_json())

    def from_json(self, json_data: JsonItemType) -> None:
        try:
            [value, params] = json_data
        except ValueError as why:
            raise ValueError(json_data) from why
        self.value = value_from_json(value)
        self.params.from_json(params)


class Parameters(dict):
    def parse(self, data: bytes) -> int:
        bytes_consumed = 0
        while True:
            try:
                if data[bytes_consumed] != SEMICOLON:
                    break
            except IndexError:
                break
            bytes_consumed += 1  # consume the ";"
            bytes_consumed += discard_ows(data[bytes_consumed:])
            offset, param_name = parse_key(data[bytes_consumed:])
            bytes_consumed += offset
            param_value: BareItemType = True
            try:
                if data[bytes_consumed] == EQUALS:
                    bytes_consumed += 1  # consume the "="
                    offset, param_value = parse_bare_item(data[bytes_consumed:])
                    bytes_consumed += offset
            except IndexError:
                pass
            self[param_name] = param_value
        return bytes_consumed

    def __str__(self) -> str:
        return "".join([f";{ser_key(k)}{f'={ser_bare_item(v)}' if v is not True else ''}" for k, v in self.items()])

    def to_json(self) -> JsonParamType:
        return [(k, value_to_json(v)) for (k, v) in self.items()]

    def from_json(self, json_data: JsonParamType) -> None:
        for name, value in json_data:
            self[name] = value_from_json(value)


SingleItemType = Union[BareItemType, Item]


class InnerList(UserList):
    def __init__(self, values: _List[Union[Item, SingleItemType]] = None) -> None:
        UserList.__init__(self, [itemise(v) for v in values or []])
        self.params = Parameters()

    def parse(self, data: bytes) -> int:
        bytes_consumed = 1  # consume the "("
        while True:
            bytes_consumed += discard_ows(data[bytes_consumed:])
            if data[bytes_consumed] == PAREN_CLOSE:
                bytes_consumed += 1
                bytes_consumed += self.params.parse(data[bytes_consumed:])
                return bytes_consumed
            item = Item()
            bytes_consumed += item.parse_content(data[bytes_consumed:])
            self.data.append(item)
            try:
                if data[bytes_consumed] not in INNERLIST_DELIMS:
                    raise ValueError("Inner list bad delimitation")
            except IndexError as why:
                raise ValueError("End of inner list not found") from why

    def __str__(self) -> str:
        return f"({' '.join([str(i) for i in self.data])}){self.params}"

    def __setitem__(
        self,
        index: Union[SupportsIndex, slice],
        value: Union[SingleItemType, Iterable[SingleItemType]],
    ) -> None:
        if isinstance(index, slice):
            self.data[index] = [itemise(v) for v in value]  # type: ignore
        else:
            self.data[index] = itemise(cast(SingleItemType, value))

    def append(self, item: SingleItemType) -> None:
        self.data.append(itemise(item))

    def insert(self, i: int, item: SingleItemType) -> None:
        self.data.insert(i, itemise(item))

    def to_json(self) -> JsonInnerListType:
        return ([i.to_json() for i in self.data], self.params.to_json())

    def from_json(self, json_data: JsonInnerListType) -> None:
        try:
            values, params = json_data
        except ValueError as why:
            raise ValueError(json_data) from why
        for i in values:
            self.data.append(Item())
            self[-1].from_json(i)
        self.params.from_json(params)


_parse_map = {
    DQUOTE: parse_string,
    BYTE_DELIMIT: parse_byteseq,
    ord(b"?"): parse_boolean,
    ord(b"@"): parse_date,
    ord(b"%"): parse_display_string,
}
for c in TOKEN_START_CHARS:
    _parse_map[c] = parse_token
for c in NUMBER_START_CHARS:
    _parse_map[c] = parse_number


def parse_bare_item(data: bytes) -> Tuple[int, BareItemType]:
    if not data:
        raise ValueError("Empty item")
    try:
        return _parse_map[data[0]](data)  # type: ignore
    except KeyError as why:
        raise ValueError(f"Item starting with '{data[0:1].decode('ascii')}' can't be identified") from why


_ser_map = {
    int: ser_integer,
    float: ser_decimal,
    str: ser_string,
    bool: ser_boolean,
    bytes: ser_byteseq,
}


def ser_bare_item(item: BareItemType) -> str:
    try:
        return _ser_map[type(item)](item)  # type: ignore
    except KeyError:
        pass
    if isinstance(item, Token):
        return ser_token(item)
    if isinstance(item, Decimal):
        return ser_decimal(item)
    if isinstance(item, datetime):
        return ser_date(item)
    if isinstance(item, DisplayString):
        return ser_display_string(item)
    raise ValueError(f"Can't serialise; unrecognised item with type {type(item)}")


def itemise(thing: Union[BareItemType, InnerList, Item, _List]) -> Union[InnerList, Item]:
    if isinstance(thing, (Item, InnerList)):
        return thing
    if isinstance(thing, list):
        return InnerList(thing)
    return Item(thing)


AllItemType = Union[BareItemType, Item, InnerList]
