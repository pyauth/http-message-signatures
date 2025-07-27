from collections import UserList
from typing import Tuple, Union, Iterable, cast
from typing_extensions import SupportsIndex

from .item import Item, InnerList, itemise, AllItemType, PAREN_OPEN
from .types import JsonListType
from .util import StructuredFieldValue, discard_http_ows


COMMA = ord(b",")


class List(UserList, StructuredFieldValue):
    def parse_content(self, data: bytes) -> int:
        bytes_consumed = 0
        data_len = len(data)
        try:
            while True:
                offset, member = parse_item_or_inner_list(data[bytes_consumed:])
                bytes_consumed += offset
                self.append(member)
                bytes_consumed += discard_http_ows(data[bytes_consumed:])
                if bytes_consumed == data_len:
                    return bytes_consumed
                if data[bytes_consumed] != COMMA:
                    raise ValueError("Trailing text after item in list")
                bytes_consumed += 1
                bytes_consumed += discard_http_ows(data[bytes_consumed:])
                if bytes_consumed == data_len:
                    raise ValueError("Trailing comma at end of list")
        except Exception:
            self.clear()
            raise

    def __str__(self) -> str:
        if len(self) == 0:
            raise ValueError("No contents; field should not be emitted")
        return ", ".join([str(m) for m in self])

    def __setitem__(
        self,
        index: Union[SupportsIndex, slice],
        value: Union[AllItemType, Iterable[AllItemType]],
    ) -> None:
        if isinstance(index, slice):
            self.data[index] = [itemise(v) for v in value]  # type: ignore
        else:
            self.data[index] = itemise(cast(AllItemType, value))

    def append(self, item: AllItemType) -> None:
        self.data.append(itemise(item))

    def insert(self, i: int, item: AllItemType) -> None:
        self.data.insert(i, itemise(item))

    def to_json(self) -> JsonListType:
        return [i.to_json() for i in self]

    def from_json(self, json_data: JsonListType) -> None:
        for i in json_data:
            if isinstance(i[0], list):
                self.append(InnerList())
            else:
                self.append(Item())
            self[-1].from_json(i)


def parse_item_or_inner_list(data: bytes) -> Tuple[int, Union[Item, InnerList]]:
    try:
        if data[0] == PAREN_OPEN:
            inner_list = InnerList()
            bytes_consumed = inner_list.parse(data)
            return bytes_consumed, inner_list
    except IndexError:
        pass
    item = Item()
    bytes_consumed = item.parse_content(data)
    return bytes_consumed, item
