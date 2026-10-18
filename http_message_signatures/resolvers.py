import urllib.parse

from http_sf.compat import Dictionary, Item

from .exceptions import HTTPMessageSignaturesException
from .structures import CaseInsensitiveDict, normalize_header_value


class HTTPSignatureComponentResolver:
    # RFC 9421 section 2.1 parameters a covered HTTP field may carry. "key" is
    # implemented (section 2.1.2); "sf", "bs" and "tr" are recognized so that a
    # signature naming them is refused instead of silently resolving to the
    # wrong value.
    field_component_parameters = frozenset({"key", "sf", "bs", "tr"})
    derived_component_names = {
        "@method",
        "@target-uri",
        "@authority",
        "@scheme",
        "@request-target",
        "@path",
        "@query",
        "@query-params",
        "@status",
        "@request-response",
    }

    # TODO: describe interface
    def __init__(self, message):
        self.message = message
        self.message_type = "request"
        if hasattr(message, "status_code"):
            self.message_type = "response"
        self.url = str(message.url)
        self.headers = CaseInsensitiveDict(message.headers)

    def resolve(self, component_node: Item):
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
            return self.__class__(self.message.request).resolve(request_node)
        if component_id.startswith("@"):  # derived component
            if component_id not in self.derived_component_names:
                raise HTTPMessageSignaturesException(f"Unknown covered derived component name {component_id}")
            resolver = getattr(self, "get_" + component_id[1:].replace("-", "_"))
            return resolver(**params)
        if component_id not in self.headers:
            raise HTTPMessageSignaturesException(f'Covered header field "{component_id}" not found in the message')
        field_value = normalize_header_value(self.headers[component_id])
        unknown = set(params) - self.field_component_parameters
        if unknown:
            raise HTTPMessageSignaturesException(
                f'Unknown parameter(s) {sorted(unknown)} on covered field "{component_id}"'
            )
        if "key" in params:
            return self.get_dictionary_member(component_id, field_value, params)
        if params:
            raise HTTPMessageSignaturesException(
                f'Parameter(s) {sorted(params)} on covered field "{component_id}" are not supported'
            )
        return field_value

    def get_dictionary_member(self, component_id: str, field_value: str, params: dict):
        # RFC 9421 section 2.1.2: the value is the serialization of the named
        # member of the Dictionary Structured Field, parameters included.
        key = params["key"]
        if set(params) != {"key"}:
            raise HTTPMessageSignaturesException(
                f'The "key" parameter on covered field "{component_id}" cannot be combined with other parameters'
            )
        if not isinstance(key, str):
            raise HTTPMessageSignaturesException(
                f'The "key" parameter on covered field "{component_id}" must be a string'
            )
        dictionary = Dictionary()
        try:
            dictionary.parse(field_value.encode())
        except Exception as e:
            raise HTTPMessageSignaturesException(
                f'Covered field "{component_id}" is not a Dictionary Structured Field'
            ) from e
        if key not in dictionary:
            raise HTTPMessageSignaturesException(f'Covered field "{component_id}" has no member "{key}"')
        return str(dictionary[key])

    def get_method(self):
        if self.message_type == "response":
            return self.message.request.method.upper()
        return self.message.method.upper()

    def get_target_uri(self):
        return self.url

    def get_authority(self):
        return urllib.parse.urlsplit(self.url).netloc.lower()

    def get_scheme(self):
        return urllib.parse.urlsplit(self.url).scheme.lower()

    def get_request_target(self):
        query = self.get_query()
        if not query.startswith("?"):
            query = "?" + query
        return self.get_path() + query

    def get_path(self):
        return urllib.parse.urlsplit(self.url).path

    def get_query(self):
        return "?" + urllib.parse.urlsplit(self.url).query

    def get_query_params(self, *, name: str):
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.url).query, keep_blank_values=True)
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

    def get_request_response(self, *, key: str):
        # See 2.2.11 Request-Response Signature Binding
        # self.message.request.headers["Signature"][key]
        raise NotImplementedError()


class HTTPSignatureKeyResolver:
    def resolve_public_key(self, key_id: str):
        raise NotImplementedError("This method must be implemented by a subclass.")

    def resolve_private_key(self, key_id: str):
        raise NotImplementedError("This method must be implemented by a subclass.")
