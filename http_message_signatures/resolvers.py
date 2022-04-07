import urllib

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
        "@request-response"
    }

    # TODO: describe interface
    def __init__(self, message):
        self.message_type = "request"
        if hasattr(message, "status_code"):
            self.message_type = "response"
        self.method = getattr(message, "method", None)
        self.url = message.url
        self.status_code = getattr(message, "status_code", None)

        # TODO: check header key and value transforms are applied per 2.1
        self.headers = CaseInsensitiveDict(message.headers)

    def resolve(self, component_id):
        if component_id.startswith("@"):  # derived component
            if component_id not in self.derived_component_names:
                raise Exception(f'Unknown derived component name "{component_id}"')
            resolver = getattr(self, "get_" + component_id[1:].replace("-", "_"))
            return resolver()
        return self.headers[component_id]

    def get_method(self):
        return self.method.upper()

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

    def get_query_params(self):
        # need to parse component id as a structured field
        # urllib.parse.parse_qs(urllib.parse.urlsplit(request.url).query, keep_blank_values=True)
        raise NotImplementedError()

    def get_status(self):
        if self.message_type != "response":
            raise Exception('Unexpected "@status" component in a request signature')
        return str(self.status_code)

    def get_request_response(self):
        raise NotImplementedError()


class HTTPSignatureKeyResolver:
    def resolve_public_key(self, key_id: str):
        raise NotImplementedError("This method must be implemented by a subclass.")

    def resolve_private_key(self, key_id: str):
        raise NotImplementedError("This method must be implemented by a subclass.")
