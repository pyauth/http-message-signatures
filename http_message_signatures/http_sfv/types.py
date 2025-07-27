from datetime import datetime
from decimal import Decimal
from typing import Union, Dict, List, Tuple


class Token(str):
    pass


class DisplayString(str):
    pass


BareItemType = Union[int, float, str, bool, Decimal, bytes, Token, datetime, DisplayString]
JsonBareType = Union[int, float, str, bool, Decimal, Dict]

JsonParamType = List[Tuple[str, JsonBareType]]
JsonItemType = Tuple[JsonBareType, JsonParamType]
JsonInnerListType = Tuple[List[JsonItemType], JsonParamType]
JsonListType = List[Union[JsonItemType, JsonInnerListType]]
JsonDictType = List[Tuple[str, Union[JsonItemType, JsonInnerListType]]]
