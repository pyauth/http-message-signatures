from collections import UserDict

from .item import Item, InnerList, itemise, AllItemType
from .list import parse_item_or_inner_list
from .types import JsonDictType
from .util import (
    StructuredFieldValue,
    discard_http_ows,
    ser_key,
    parse_key,
)

EQUALS = ord(b"=")
COMMA = ord(b",")


class Dictionary(UserDict, StructuredFieldValue):
    def parse_content(self, data: bytes) -> int:
        bytes_consumed = 0
        data_len = len(data)
        try:
            while True:
                offset, this_key = parse_key(data[bytes_consumed:])
                bytes_consumed += offset
                try:
                    is_equals = data[bytes_consumed] == EQUALS
                except IndexError:
                    is_equals = False
                if is_equals:
                    bytes_consumed += 1  # consume the "="
                    offset, member = parse_item_or_inner_list(data[bytes_consumed:])
                    bytes_consumed += offset
                else:
                    member = Item()
                    member.value = True
                    bytes_consumed += member.params.parse(data[bytes_consumed:])
                self[this_key] = member
                bytes_consumed += discard_http_ows(data[bytes_consumed:])
                if bytes_consumed == data_len:
                    return bytes_consumed
                if data[bytes_consumed] != COMMA:
                    raise ValueError(f"Dictionary member '{this_key}' has trailing characters")
                bytes_consumed += 1
                bytes_consumed += discard_http_ows(data[bytes_consumed:])
                if bytes_consumed == data_len:
                    raise ValueError("Dictionary has trailing comma")
        except Exception as why:
            self.clear()
            raise ValueError from why

    def __setitem__(self, key: str, value: AllItemType) -> None:
        self.data[key] = itemise(value)

    def __str__(self) -> str:
        if len(self) == 0:
            raise ValueError("No contents; field should not be emitted")
        return ", ".join(
            [
                f"{ser_key(m)}"
                f"""{n.params if (isinstance(n, Item) and n.value is True) else f"={n}"}"""
                for m, n in self.items()
            ]
        )

    def to_json(self) -> JsonDictType:
        return [(key, val.to_json()) for (key, val) in self.items()]

    def from_json(self, json_data: JsonDictType) -> None:
        for key, val in json_data:
            if isinstance(val[0], list):
                self[key] = InnerList()
            else:
                self[key] = Item()
            self[key].from_json(val)
