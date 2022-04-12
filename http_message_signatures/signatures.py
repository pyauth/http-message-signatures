import collections
import datetime
import logging
from typing import List, Dict

import http_sfv

from .resolvers import HTTPSignatureComponentResolver, HTTPSignatureKeyResolver
from .algorithms import HTTPSignatureAlgorithm, signature_algorithms
from .exceptions import HTTPMessageSignaturesException, InvalidSignature

logger = logging.getLogger(__name__)


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
                             covered_component_ids: List[http_sfv.Item],
                             signature_params: Dict[str, str]):
        assert "@signature-params" not in covered_component_ids
        sig_elements = collections.OrderedDict()
        component_resolver = self.component_resolver_class(message)
        for component_id in covered_component_ids:
            component_key = str(http_sfv.List([component_id]))
            # TODO: model situations when header occurs multiple times
            component_value = component_resolver.resolve(component_id)
            if component_id.value.lower() != component_id.value:
                raise HTTPMessageSignaturesException(f'Component ID "{component_id.value}" is not all lowercase')
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
        return sig_base, sig_params_node, sig_elements


class HTTPMessageSigner(HTTPSignatureHandler):
    DEFAULT_SIGNATURE_LABEL = "pyhms"

    def parse_covered_component_ids(self, covered_component_ids):
        covered_component_nodes = []
        for component_id in covered_component_ids:
            component_name_node = http_sfv.Item()
            if component_id.startswith('"'):
                component_name_node.parse(component_id.encode())
            else:
                component_name_node.value = component_id
            covered_component_nodes.append(component_name_node)
        return covered_component_nodes

    def sign(self, message, *,
             key_id: str,
             created: datetime.datetime = None,
             expires: datetime.datetime = None,
             nonce: str = None,
             label: str = None,
             include_alg: bool = True,
             covered_component_ids: List[str] = ("@method", "@authority", "@target-uri")):
        # TODO: Accept-Signature autonegotiation
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
        covered_component_nodes = self.parse_covered_component_ids(covered_component_ids)
        sig_base, sig_params_node, _ = self.build_signature_base(
            message,
            covered_component_ids=covered_component_nodes,
            signature_params=signature_params
        )
        signer = self.signature_algorithm(private_key=key)
        signature = signer.sign(sig_base.encode())
        sig_label = self.DEFAULT_SIGNATURE_LABEL
        if label is not None:
            sig_label = label
        sig_input_node = http_sfv.Dictionary({sig_label: sig_params_node})
        message.headers["Signature-Input"] = str(sig_input_node)
        sig_node = http_sfv.Dictionary({sig_label: signature})
        message.headers["Signature"] = str(sig_node)


VerifyResult = collections.namedtuple("VerifyResult", "label algorithm covered_components parameters body")


class HTTPMessageVerifier(HTTPSignatureHandler):
    def parse_dict_header(self, header_name, headers):
        if header_name not in headers:
            raise InvalidSignature(f'Expected "{header_name}" header field to be present')
        try:
            dict_header_node = http_sfv.Dictionary()
            dict_header_node.parse(headers[header_name].encode())
        except Exception as e:
            raise InvalidSignature(f'Malformed structured header field "{header_name}"') from e
        return dict_header_node

    def verify(self, message):
        sig_inputs = self.parse_dict_header("Signature-Input", message.headers)
        if len(sig_inputs) != 1:
            # TODO: validate all behaviors with multiple signatures
            raise InvalidSignature("Multiple signatures are not supported")
        signature = self.parse_dict_header("Signature", message.headers)
        verify_results = []
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
            for param in sig_input.params:
                if param not in self.signature_metadata_parameters:
                    raise InvalidSignature(f'Unexpected signature metadata parameter "{param}"')
            try:
                sig_base, sig_params_node, sig_elements = self.build_signature_base(
                    message,
                    covered_component_ids=list(sig_input),
                    signature_params=sig_input.params
                )
            except Exception as e:
                raise InvalidSignature(e) from e
            verifier = self.signature_algorithm(public_key=key)
            raw_signature = signature[label].value
            try:
                verifier.verify(signature=raw_signature, message=sig_base.encode())
            except Exception as e:
                raise InvalidSignature(e) from e
            verify_result = VerifyResult(label=label,
                                         algorithm=self.signature_algorithm,
                                         covered_components=sig_elements,
                                         parameters=dict(sig_params_node.params),
                                         body=None)
            verify_results.append(verify_result)
            return verify_results
