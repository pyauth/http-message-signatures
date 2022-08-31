import urllib.parse

import http_sfv

from .exceptions import HTTPMessageSignaturesException
from .structures import CaseInsensitiveDict


class HTTPSignatureComponentResolver:
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
        self.url = message.url
        self.headers = CaseInsensitiveDict(message.headers)

    def resolve(self, component_node: http_sfv.Item):
        component_id = str(component_node.value)
        if component_id.startswith("@"):  # derived component
            if component_id not in self.derived_component_names:
                raise HTTPMessageSignaturesException(f"Unknown covered derived component name {component_id}")
            resolver = getattr(self, "get_" + component_id[1:].replace("-", "_"))
            return resolver(**component_node.params)
        if component_id not in self.headers:
            raise HTTPMessageSignaturesException(f'Covered header field "{component_id}" not found in the message')
        return self.headers[component_id]

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
        return self.get_path() + "?" + self.get_query()

    def get_path(self):
        return urllib.parse.urlsplit(self.url).path

    def get_query(self):
        return "?" + urllib.parse.urlsplit(self.url).query

    def get_query_params(self, *, name: str):
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.url).query, keep_blank_values=True)
        if name not in query:
            raise HTTPMessageSignaturesException(f'Query parameter "{name}" not found in the message URL')
        if len(query[name]) != 1:
            raise HTTPMessageSignaturesException("Query parameters with multiple values are not supported.")
        return query[name][0]

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
