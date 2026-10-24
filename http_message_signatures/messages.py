"""Small message views for client integrations, without reading message bodies."""

from collections.abc import Callable, Iterable, Iterator, MutableMapping
from dataclasses import dataclass
from typing import Protocol


class Headers(Protocol):
    """Header operations used by the core; items must retain repeated field lines."""

    def items(self) -> Iterable[tuple[str, str]]: ...
    def __iter__(self) -> Iterator[str]: ...
    def __contains__(self, name: str) -> bool: ...
    def __setitem__(self, name: str, value: str) -> None: ...
    def __delitem__(self, name: str) -> None: ...


class HeaderFields:
    """Read live field lines, with optional writes to their underlying container.

    ``fields`` returns all string field lines in order. For incoming byte pairs,
    use ``from_raw()``. Supply ``writable`` only when its mutations are reflected
    by ``fields``; omitting it creates a view for verification only.
    """

    def __init__(
        self,
        fields: Callable[[], Iterable[tuple[str, str]]],
        *,
        writable: MutableMapping[str, str] | None = None,
    ) -> None:
        self._fields = fields
        self._writable = writable

    @classmethod
    def from_raw(
        cls,
        fields: Callable[[], Iterable[tuple[bytes, bytes]]],
        *,
        writable: MutableMapping[str, str] | None = None,
    ) -> "HeaderFields":
        """Preserve header bytes using ASCII names and Latin-1 field values."""
        return cls(
            lambda: ((name.decode("ascii"), value.decode("latin-1")) for name, value in fields()),
            writable=writable,
        )

    def items(self) -> Iterable[tuple[str, str]]:
        return self._fields()

    def __iter__(self) -> Iterator[str]:
        return iter(dict.fromkeys(name for name, _ in self.items()))

    def __contains__(self, name: str) -> bool:
        return any(field.lower() == name.lower() for field, _ in self.items())

    def __setitem__(self, name: str, value: str) -> None:
        if self._writable is None:
            raise TypeError("This header view is read-only")
        self._writable[name] = value

    def __delitem__(self, name: str) -> None:
        if self._writable is None:
            raise TypeError("This header view is read-only")
        del self._writable[name]


@dataclass
class Request:
    """View of a prepared request's encoded URL, method, and header fields."""

    method: str
    url: str
    headers: Headers


@dataclass
class Response:
    """View of a response and the prepared request it answers."""

    status_code: int
    headers: Headers
    request: Request
