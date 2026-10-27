"""Structured Field component identifiers shared by signers and integrations."""

from collections.abc import Sequence
from typing import Any

import http_sf
from http_sf.compat import Item

from .exceptions import HTTPMessageSignaturesException


def _parse_component_ids(component_ids: Sequence[str]) -> list[Item]:
    """This function parses names or serialized String items, preserving parameter order."""
    if isinstance(component_ids, (str, bytes, bytearray)):
        raise HTTPMessageSignaturesException(
            'covered_component_ids must be a sequence of component strings, such as ("date",)'
        )
    nodes = []
    for component_id in component_ids:
        if not isinstance(component_id, str):
            raise HTTPMessageSignaturesException("Component identifiers must be strings")
        node = Item()
        node.parse((component_id if component_id.startswith('"') else http_sf.ser(component_id)).encode())
        if not isinstance(node.value, str) or node.value != node.value.lower():
            raise HTTPMessageSignaturesException("Component names must be lowercase Structured Field strings")
        nodes.append(node)
    return nodes


def _component_identity(node: Item) -> tuple[Any, frozenset[tuple[str, Any]]]:
    """The returned identity ignores parameter order without changing the signed item."""
    return node.value, frozenset(node.params.items())
