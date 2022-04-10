import collections
import datetime
from typing import List, Dict

import http_sfv

from .resolvers import HTTPSignatureComponentResolver, HTTPSignatureKeyResolver
from .algorithms import HTTPSignatureAlgorithm, signature_algorithms
from .exceptions import HTTPMessageSignaturesException, InvalidSignature


class HTTPSignatureHandler:
    signature_metadata_parameters = {
        "alg",
        "created",
        "expires",
        "keyid",
        "nonce"
    }

    def __init__(self, *,
                 signature_algorithm: HTTPSignatureAlgorithm,
                 key_resolver: HTTPSignatureKeyResolver,
                 component_resolver_class: type = HTTPSignatureComponentResolver):
        if signature_algorithm not in signature_algorithms.values():
            raise HTTPMessageSignaturesException(f"Unknown signature algorithm {signature_algorithm}")
        self.signature_algorithm = signature_algorithm
        self.key_resolver = key_resolver
        self.component_resolver_class = component_resolver_class

    def build_signature_base(self, message, *,
                             covered_component_ids: List[str],
                             signature_params: Dict[str, str]):
        assert "@signature-params" not in covered_component_ids
        sig_elements = collections.OrderedDict()
        component_resolver = self.component_resolver_class(message)
        for component_id in covered_component_ids:
            component_name_node = http_sfv.Item(component_id)
            component_key = str(http_sfv.List([component_name_node]))
            # TODO: model situations when header occurs multiple times
            # TODO: 2.1.2 parameterized keys
            component_value = component_resolver.resolve(component_id)
            if component_key.lower() != component_key:
                raise HTTPMessageSignaturesException(f'Component ID "{component_key}" is not all lowercase')
            if "\n" in component_key:
                raise HTTPMessageSignaturesException(f'Component ID "{component_key}" contains newline character')
            if component_key in sig_elements:
                raise HTTPMessageSignaturesException(f'Component ID "{component_key}" appeared multiple times in '
                                                     'signature input')
            sig_elements[component_key] = component_value
        sig_params_node = http_sfv.InnerList(covered_component_ids)
        sig_params_node.params.update(signature_params)
        sig_elements['"@signature-params"'] = str(sig_params_node)
        sig_base = "\n".join(f"{k}: {v}" for k, v in sig_elements.items())
        return sig_base, sig_params_node


class HTTPMessageSigner(HTTPSignatureHandler):
    DEFAULT_SIGNATURE_LABEL = "pyhms"

    def sign(self, request, *,
             key_id: str,
             created: datetime.datetime = None,
             expires: datetime.datetime = None,
             nonce: str = None,
             label: str = None,
             include_alg: bool = True,
             covered_component_ids: List[str] = ("@method", "@authority", "@target-uri")):
        # TODO: Accept-Signature autonegotiation
        # TODO: if sign_body=True and body exists: inject content-digest if not set, add to covered components
        key = self.key_resolver.resolve_private_key(key_id)
        if created is None:
            created = datetime.datetime.utcnow()
        created = int(created.timestamp())
        signature_params = collections.OrderedDict()
        signature_params["created"] = created
        signature_params["keyid"] = key_id
        if expires:
            signature_params["expires"] = int(expires.timestamp())
        if nonce:
            signature_params["nonce"] = nonce
        if include_alg:
            signature_params["alg"] = self.signature_algorithm.algorithm_id
        # TODO: content-digest autoconfiguration
        # - if request has a body and no content-digest header, compute content-digest as a structured header and set it
        sig_base, sig_params_node = self.build_signature_base(request,
                                                              covered_component_ids=covered_component_ids,
                                                              signature_params=signature_params)
        signer = self.signature_algorithm(private_key=key)
        signature = signer.sign(sig_base.encode())
        sig_label = self.DEFAULT_SIGNATURE_LABEL
        if label is not None:
            sig_label = label
        sig_input_node = http_sfv.Dictionary({sig_label: sig_params_node})
        request.headers["Signature-Input"] = str(sig_input_node)
        sig_node = http_sfv.Dictionary({sig_label: signature})
        request.headers["Signature"] = str(sig_node)


class HTTPMessageVerifier(HTTPSignatureHandler):
    def verify(self, response):
        # TODO: verify content-digest automatically
        if "Signature-Input" not in response.headers:
            raise InvalidSignature("Expected Signature-Input header to be present")
        sig_inputs = http_sfv.Dictionary()
        sig_inputs.parse(response.headers["Signature-Input"].encode())
        if len(sig_inputs) != 1:
            # FIXME
            raise InvalidSignature("Multiple signatures are not supported")
        signature = http_sfv.Dictionary()
        signature.parse(response.headers["Signature"].encode())
        for label, sig_input in sig_inputs.items():
            # see 3.2.1, app requirements
            # (minimal required fields, max age, detect expired, prohibit alg param, expect alg, nonce)
            # resolve key by key_id; if alg is present, assert match
            if label not in signature:
                raise InvalidSignature("Signature-Input contains a label not listed in Signature")
            if "alg" in sig_input.params:
                if sig_input.params["alg"] != self.signature_algorithm.algorithm_id:
                    raise InvalidSignature("Unexpected algorithm specified in the signature")
            key = self.key_resolver.resolve_public_key(sig_input.params["keyid"])
            covered_component_ids = [i.value for i in sig_input]
            for param in sig_input.params:
                if param not in self.signature_metadata_parameters:
                    raise InvalidSignature(f'Unexpected signature metadata parameter "{param}"')
            sig_base, sig_params_node = self.build_signature_base(response,
                                                                  covered_component_ids=covered_component_ids,
                                                                  signature_params=sig_input.params)
            verifier = self.signature_algorithm(public_key=key)
            raw_signature = signature[label].value
            try:
                verifier.verify(signature=raw_signature, message=sig_base.encode())
            except Exception as e:
                raise InvalidSignature(e) from e
            # FIXME: recover trusted subset using sig_params_node and return it,
            # prominently noting created/expired and nonce
