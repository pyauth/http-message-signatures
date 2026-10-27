import urllib.parse
from collections.abc import Callable, Mapping
from functools import cached_property
from typing import ClassVar, TypeAlias

import http_sf
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from http_sf.compat import Dictionary, Item, List

from ._url import parse_url
from .exceptions import HTTPMessageSignaturesException
from .structures import CaseInsensitiveDict, get_header_field_lines

SigningKey: TypeAlias = bytes | rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey
VerificationKey: TypeAlias = bytes | rsa.RSAPublicKey | ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey


class HTTPSignatureComponentResolver:
    """Resolve covered components from a request or response object.

    The constructor reads ``headers``. Requests also supply an uppercase
    ``method`` and an encoded absolute ``url`` with a nonempty host. Invalid
    URL syntax is rejected, including malformed percent escapes and unencoded
    spaces, controls, or non-ASCII characters.
    The presence of ``status_code`` identifies a response; its ``request``
    supplies components qualified with ``req``. An associated request must
    also have an uppercase method. The response's own ``url`` is not used.
    Parsed fields and queries are cached for the lifetime of the resolver;
    keep the message and its associated request stable while resolving components.
    Create a new resolver after changing either message.

    ``headers.items()`` must expose string names and values for all field lines
    in order, or values already combined in that order. Signing additionally
    requires iteration over names, membership testing, assignment, and deletion.
    Binary wrapping (``bs``) requires separate field lines; strings represent
    their original bytes decoded as Latin-1.

    A request may provide ``request_target`` for an HTTP/1.1 target that cannot
    be inferred from ``url``, such as an absolute-form proxy target or ``*``.
    The supplied target and URL must describe the same request.

    Whole-field ``sf`` serialization treats Content-Digest as a Dictionary and
    uses the field type registered in ``http_sf`` for other fields. Unknown
    types and malformed values raise
    :class:`~http_message_signatures.HTTPMessageSignaturesException`.
    """

    # RFC 9421 section 2.1 parameters a covered HTTP field may carry.
    # "sf" supports whole fields and dictionary member selection with "key".
    # "bs" wraps each field line separately. Trailers ("tr") are unsupported.
    field_component_parameters = frozenset({"key", "sf", "bs", "tr"})
    #: Callables receive the resolver instance followed by component parameters.
    #: Subclasses can copy and extend this mapping to support additional components.
    derived_component_resolvers: ClassVar[dict[str, Callable[..., str]]] = {
        "@method": lambda resolver: resolver.get_method(),
        "@target-uri": lambda resolver: resolver.get_target_uri(),
        "@authority": lambda resolver: resolver.get_authority(),
        "@scheme": lambda resolver: resolver.get_scheme(),
        "@request-target": lambda resolver: resolver.get_request_target(),
        "@path": lambda resolver: resolver.get_path(),
        "@query": lambda resolver: resolver.get_query(),
        "@query-param": lambda resolver, **params: resolver.get_query_params(**params),
        "@status": lambda resolver: resolver.get_status(),
    }

    def __init__(self, message):
        self.message = message
        self.message_type = "request"
        if hasattr(message, "status_code"):
            self.message_type = "response"
        if self.message_type == "request":
            self._validate_method(message.method)
            self.url_parts = parse_url(str(message.url))
        elif hasattr(message, "request") and message.request is not None:
            self._validate_method(message.request.method)
        self.header_field_lines = get_header_field_lines(message.headers)
        self.headers = CaseInsensitiveDict(
            (name, ", ".join(values)) for name, values in self.header_field_lines.items()
        )
        self._parsed_dictionaries: dict[str, Dictionary] = {}
        self._serialized_structured_fields: dict[tuple[str, str], str] = {}

    @cached_property
    def _request_resolver(self):
        return self.__class__(self.message.request)

    @cached_property
    def _query_params(self):
        return urllib.parse.parse_qs(self.url_parts.query or "", keep_blank_values=True)

    @staticmethod
    def _validate_method(method):
        if not isinstance(method, str) or method != method.upper():
            raise HTTPMessageSignaturesException("HTTP request method must be an uppercase string")

    def resolve(self, component_node: Item):
        """Return the string value of a parsed Structured Field component item."""
        component_id = str(component_node.value)
        params = dict(component_node.params)
        if "req" in params:
            # RFC 9421 section 2.4: a component of the request a response answers.
            if params.pop("req") is not True:
                raise HTTPMessageSignaturesException('The "req" parameter must be a Boolean flag')
            if self.message_type != "response":
                raise HTTPMessageSignaturesException('The "req" parameter is only valid in a response signature')
            request_node = Item(component_node.value)
            request_node.params.update(params)
            return self._request_resolver.resolve(request_node)
        if component_id.startswith("@"):  # derived component
            if component_id not in self.derived_component_resolvers:
                raise HTTPMessageSignaturesException(f"Unknown covered derived component name {component_id}")
            if self.message_type == "response" and component_id != "@status":
                raise HTTPMessageSignaturesException(
                    f'Component "{component_id}" requires "req" in a response signature'
                )
            return self.derived_component_resolvers[component_id](self, **params)
        if component_id not in self.headers:
            raise HTTPMessageSignaturesException(f'Covered header field "{component_id}" not found in the message')
        field_value = self.headers[component_id]
        unknown = set(params) - self.field_component_parameters
        if unknown:
            raise HTTPMessageSignaturesException(
                f'Unknown parameter(s) {sorted(unknown)} on covered field "{component_id}"'
            )
        if component_id == "set-cookie" and len(self.header_field_lines[component_id]) > 1 and "bs" not in params:
            raise HTTPMessageSignaturesException('Multiple Set-Cookie field values require the "bs" parameter')
        if "key" in params:
            return self.get_dictionary_member(component_id, field_value, params)
        if set(params) == {"sf"}:
            if params["sf"] is not True:
                raise HTTPMessageSignaturesException('The "sf" parameter must be a Boolean flag')
            cache_key = (component_id, field_value)
            if cache_key in self._serialized_structured_fields:
                return self._serialized_structured_fields[cache_key]
            try:
                parsed = http_sf.parse(
                    field_value.encode(),
                    name=component_id,
                    tltype="dictionary" if component_id == "content-digest" else None,
                )
                serialized = http_sf.ser(parsed)
            except KeyError as e:
                raise HTTPMessageSignaturesException(
                    f'Unknown Structured Field type for covered field "{component_id}"'
                ) from e
            except (ValueError, TypeError) as e:
                raise HTTPMessageSignaturesException(
                    f'Covered field "{component_id}" is not valid for its registered Structured Field type'
                ) from e
            self._serialized_structured_fields[cache_key] = serialized
            return serialized
        if set(params) == {"bs"}:
            if params["bs"] is not True:
                raise HTTPMessageSignaturesException('The "bs" parameter must be a Boolean flag')
            values = self.header_field_lines[component_id]
            try:
                return str(List(value.encode("latin-1") for value in values))
            except UnicodeEncodeError as e:
                raise HTTPMessageSignaturesException(
                    f'Binary-wrapped field "{component_id}" must contain Latin-1 encoded bytes'
                ) from e
        if params:
            raise HTTPMessageSignaturesException(
                f'Parameter(s) {sorted(params)} on covered field "{component_id}" are not supported'
            )
        return field_value

    def get_dictionary_member(self, component_id: str, field_value: str, params: dict):
        # RFC 9421 section 2.1.2: the value is the serialization of the named
        # member of the Dictionary Structured Field, parameters included.
        key = params["key"]
        if set(params) - {"key", "sf"}:
            raise HTTPMessageSignaturesException(
                f'The "key" parameter on covered field "{component_id}" cannot be combined with parameters other than "sf"'
            )
        if "sf" in params and params["sf"] is not True:
            raise HTTPMessageSignaturesException('The "sf" parameter must be a Boolean flag')
        if not isinstance(key, str):
            raise HTTPMessageSignaturesException(
                f'The "key" parameter on covered field "{component_id}" must be a string'
            )
        if field_value not in self._parsed_dictionaries:
            dictionary = Dictionary()
            try:
                dictionary.parse(field_value.encode())
            except Exception as e:
                raise HTTPMessageSignaturesException(
                    f'Covered field "{component_id}" is not a Dictionary Structured Field'
                ) from e
            self._parsed_dictionaries[field_value] = dictionary
        dictionary = self._parsed_dictionaries[field_value]
        if key not in dictionary:
            raise HTTPMessageSignaturesException(f'Covered field "{component_id}" has no member "{key}"')
        return str(dictionary[key])

    def get_method(self):
        if self.message_type == "response":
            return self.message.request.method
        return self.message.method

    def get_target_uri(self):
        # An empty OPTIONS target URL path identifies the server as a whole;
        # RFC 9110 section 4.2.3 excludes it from normalization to '/'.
        parts = self.url_parts
        path = parts.path if self.message.method == "OPTIONS" else self.get_path()
        return f"{parts.scheme}://{parts.authority}{path}{parts.query_suffix}"

    def get_authority(self):
        host, port = self.url_parts.host.lower(), self.url_parts.port
        if port and port.lstrip("0") == {"http": "80", "https": "443"}.get(self.get_scheme()):
            port = None
        return f"{host}:{port}" if port else host

    def get_scheme(self):
        return self.url_parts.scheme.lower()

    def get_request_target(self):
        # Clients can expose the HTTP/1.1 request target, including proxy and
        # asterisk forms, which cannot be inferred from an absolute URL alone.
        if hasattr(self.message, "request_target"):
            return self.message.request_target
        if self.message.method == "CONNECT":
            return self.url_parts.authority
        return self.get_path() + self.url_parts.query_suffix

    def get_path(self):
        return self.url_parts.path or "/"

    def get_query(self):
        return "?" + (self.url_parts.query or "")

    def get_query_params(self, *, name: str):
        if not isinstance(name, str):
            raise HTTPMessageSignaturesException('The query parameter "name" must be a string')
        query = self._query_params
        name = urllib.parse.unquote(name)
        if name not in query:
            raise HTTPMessageSignaturesException(f'Query parameter "{name}" not found in the message URL')
        if len(query[name]) != 1:
            raise HTTPMessageSignaturesException("Query parameters with multiple values are not supported.")
        # RFC 9421 section 2.2.8: re-encode the decoded value using the HTML form
        # percent-encode set, with spaces encoded as %20 rather than '+'.
        return urllib.parse.quote(query[name][0], safe="*").replace("~", "%7E")

    def get_status(self):
        if self.message_type != "response":
            raise HTTPMessageSignaturesException('Unexpected "@status" component in a request signature')
        return str(self.message.status_code)


class HTTPSignatureKeyResolver:
    """Subclass this interface to look up keys by their signed key IDs.

    Return PEM bytes or the appropriate cryptography key object for asymmetric
    algorithms. For HMAC, return the same secret bytes from both methods.
    The public type aliases ``http_message_signatures.SigningKey`` and
    ``http_message_signatures.VerificationKey`` describe the accepted signing
    and verification key types, respectively.
    """

    def resolve_public_key(self, key_id: str):
        """Return the verification key for ``key_id``; ``None`` means unavailable."""
        raise NotImplementedError("This method must be implemented by a subclass.")

    def resolve_private_key(self, key_id: str):
        """Return the signing key for ``key_id`` or raise if it is unavailable."""
        raise NotImplementedError("This method must be implemented by a subclass.")


class MappingKeyResolver(HTTPSignatureKeyResolver):
    """Resolve locally configured keys without a custom resolver subclass.

    Public and private mappings are separate, including for HMAC. For unknown key IDs,
    ``resolve_public_key()`` returns ``None`` and ``resolve_private_key()`` raises
    ``KeyError``. Keys may be PEM
    bytes, cryptography key objects, or shared secret bytes, as for the base resolver.
    The constructor copies the mappings, so changes to the supplied mappings do not
    affect which keys this resolver trusts.
    """

    def __init__(self, *, public_keys: Mapping[str, VerificationKey], private_keys: Mapping[str, SigningKey]) -> None:
        self.public_keys = dict(public_keys)
        self.private_keys = dict(private_keys)

    def resolve_public_key(self, key_id: str) -> VerificationKey | None:
        return self.public_keys.get(key_id)

    def resolve_private_key(self, key_id: str) -> SigningKey:
        return self.private_keys[key_id]
