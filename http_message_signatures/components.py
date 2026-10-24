"""Structured Field component identifiers shared by signers and integrations."""

from collections.abc import Sequence

import http_sf
from http_sf.compat import Item

from .exceptions import HTTPMessageSignaturesException


def parse_component_ids(component_ids: Sequence[str]) -> list[Item]:
    """Parse lowercase names or serialized String items, preserving parameter order."""
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


def normalized_component_key(node: Item) -> str:
    """Compare component identities without changing their signed parameter order."""
    canonical = Item(node.value)
    canonical.params.update(sorted(node.params.items()))
    return str(canonical)


def component_map(component_ids: Sequence[str]) -> dict[str, str]:
    """Map normalized identities to supplied identifiers; reject duplicates.

    Use the keys to compare required and covered components. Values retain the
    caller's spelling so they can index a VerifyResult's covered_components.
    """
    components = {}
    for identifier, node in zip(component_ids, parse_component_ids(component_ids)):
        key = normalized_component_key(node)
        if key in components:
            raise HTTPMessageSignaturesException(f"Duplicate component identifier: {identifier}")
        components[key] = identifier
    return components
