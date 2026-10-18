import collections
import datetime
import logging
from collections.abc import Sequence
from typing import Any, ClassVar, cast
from warnings import warn

from http_sf import parse
from http_sf.compat import Dictionary, InnerList, Item

from .algorithms import HTTPSignatureAlgorithm, signature_algorithms
from .exceptions import HTTPMessageSignaturesException, InvalidSignature
from .resolvers import HTTPSignatureComponentResolver, HTTPSignatureKeyResolver
from .structures import VerifyResult, get_header_fields

logger = logging.getLogger(__name__)


class SignatureVerifyWarning(UserWarning):
    pass


class HTTPSignatureHandler:
    signature_metadata_parameters: ClassVar[set[str]] = {"alg", "created", "expires", "keyid", "nonce", "tag"}

    def __init__(
        self,
        *,
        signature_algorithm: type[HTTPSignatureAlgorithm],
        key_resolver: HTTPSignatureKeyResolver,
        component_resolver_class: type = HTTPSignatureComponentResolver,
    ):
        if signature_algorithm not in signature_algorithms.values():
            raise HTTPMessageSignaturesException(f"Unknown signature algorithm {signature_algorithm}")
        self.signature_algorithm = signature_algorithm
        self.key_resolver = key_resolver
        self.component_resolver_class = component_resolver_class

    @staticmethod
    def _parse_signature_dictionary(value: str) -> Dictionary:
        def reject_duplicate(key: str, context: str):
            if context == "dictionary":
                raise HTTPMessageSignaturesException(f'Duplicate signature label "{key}"')

        parsed = cast(dict[str, Any], parse(value.encode(), tltype="dictionary", on_duplicate_key=reject_duplicate))
        # Adapt the already parsed values to the compatibility objects used by
        # signature construction, without parsing or tokenizing the field again.
        result = Dictionary()
        for label, (member, params) in parsed.items():
            node: Item | InnerList
            if isinstance(member, list):
                node = InnerList()
                for bare_value, item_params in member:
                    item = Item(bare_value)
                    item.params.update(item_params)
                    node.append(item)
            else:
                node = Item(member)
            node.params.update(params)
            result[label] = node
        return result

    def _build_signature_base(
        self, message, *, covered_component_ids: list[Any], signature_params: dict[str, Any]
    ) -> tuple:
        self._validate_signature_param_types(signature_params)
        assert "@signature-params" not in covered_component_ids
        sig_elements = collections.OrderedDict()
        seen_components = set()
        component_resolver = self.component_resolver_class(message)
        for component_id in covered_component_ids:
            if not isinstance(component_id, Item) or not isinstance(component_id.value, str):
                raise HTTPMessageSignaturesException("Component names must be Structured Field Strings")
            component_key = str(component_id)
            component_value = component_resolver.resolve(component_id)
            if not isinstance(component_value, str):
                raise HTTPMessageSignaturesException(f'Component value for "{component_key}" must be a string')
            if str(component_id.value).lower() != str(component_id.value):
                msg = f'Component ID "{component_id.value}" is not all lowercase'  # type: ignore
                raise HTTPMessageSignaturesException(msg)
            if "\n" in component_key:
                raise HTTPMessageSignaturesException(f'Component ID "{component_key}" contains newline character')
            if "\r" in component_value or "\n" in component_value:
                raise HTTPMessageSignaturesException(
                    f'Component value for "{component_key}" contains newline character'
                )
            if (
                component_id.value.startswith("@")
                and component_value
                and (
                    not component_value.isprintable()
                    or component_value.startswith(" ")
                    or component_value.endswith(" ")
                )
            ):
                raise HTTPMessageSignaturesException(
                    f'Derived component "{component_key}" must be printable with no surrounding whitespace'
                )
            # Component identity ignores parameter order (RFC 9421 section 2).
            component_identity = (component_id.value, frozenset(component_id.params.items()))
            if component_identity in seen_components:
                raise HTTPMessageSignaturesException(
                    f'Component ID "{component_key}" appeared multiple times in signature input'
                )
            seen_components.add(component_identity)
            sig_elements[component_key] = component_value
        sig_params_node = InnerList(covered_component_ids)
        sig_params_node.params.update(signature_params)
        sig_elements['"@signature-params"'] = str(sig_params_node)
        sig_base = "\n".join(f"{k}: {v}" for k, v in sig_elements.items())
        if not sig_base.isascii():
            raise HTTPMessageSignaturesException("Signature base contains non-ASCII characters")
        return sig_base, sig_params_node, sig_elements

    @staticmethod
    def _validate_signature_param_types(params):
        for name, value in params.items():
            if name in {"created", "expires"} and type(value) is not int:
                raise HTTPMessageSignaturesException(f'Parameter "{name}" must be a Structured Field Integer')
            if name in {"alg", "keyid", "nonce", "tag"} and not isinstance(value, str):
                raise HTTPMessageSignaturesException(f'Parameter "{name}" must be a Structured Field String')


class HTTPMessageSigner(HTTPSignatureHandler):
    DEFAULT_SIGNATURE_LABEL = "pyhms"

    def _parse_covered_component_ids(self, covered_component_ids):
        covered_component_nodes = []
        for component_id in covered_component_ids:
            component_name_node = Item()
            if component_id.startswith('"'):
                component_name_node.parse(component_id.encode())
            else:
                component_name_node.value = component_id
            covered_component_nodes.append(component_name_node)
        return covered_component_nodes

    def sign(
        self,
        message,
        *,
        key_id: str,
        created: datetime.datetime | None = None,
        expires: datetime.datetime | None = None,
        nonce: str | None = None,
        label: str | None = None,
        tag: str | None = None,
        include_alg: bool = True,
        covered_component_ids: Sequence[str] = ("@method", "@authority", "@target-uri"),
        append_if_signature_exists: bool = False,
    ):
        # TODO: Accept-Signature autonegotiation
        if created is None:
            created = datetime.datetime.now()
        signature_params: dict[str, Any] = collections.OrderedDict()
        signature_params["created"] = int(created.timestamp())
        signature_params["keyid"] = key_id
        if include_alg:
            signature_params["alg"] = self.signature_algorithm.algorithm_id
        if expires:
            signature_params["expires"] = int(expires.timestamp())
        if nonce is not None:
            signature_params["nonce"] = nonce
        if tag is not None:
            signature_params["tag"] = tag
        covered_component_nodes = self._parse_covered_component_ids(covered_component_ids)
        sig_base, sig_params_node, _ = self._build_signature_base(
            message, covered_component_ids=covered_component_nodes, signature_params=signature_params
        )
        key = self.key_resolver.resolve_private_key(key_id)
        signer = self.signature_algorithm(private_key=key)
        signature = signer.sign(sig_base.encode())
        sig_label = self.DEFAULT_SIGNATURE_LABEL
        if label is not None:
            sig_label = label

        headers = get_header_fields(message.headers)
        sig_input_node = Dictionary()
        sig_node = Dictionary()
        if append_if_signature_exists and ("Signature-Input" in headers or "Signature" in headers):
            if "Signature-Input" not in headers or "Signature" not in headers:
                raise HTTPMessageSignaturesException(
                    'Cannot append unless both "Signature-Input" and "Signature" are present'
                )
            try:
                sig_input_node = self._parse_signature_dictionary(headers["Signature-Input"])
                sig_node = self._parse_signature_dictionary(headers["Signature"])
            except HTTPMessageSignaturesException:
                raise
            except Exception as e:
                raise HTTPMessageSignaturesException("Malformed existing signature headers") from e
            if sig_input_node.keys() != sig_node.keys():
                raise HTTPMessageSignaturesException("Signature-Input and Signature headers have different labels")
            if sig_label in sig_input_node:
                raise HTTPMessageSignaturesException(f'Signature label "{sig_label}" already present in the message')
        sig_input_node[sig_label] = sig_params_node
        sig_node[sig_label] = signature
        signature_headers = {"Signature-Input": str(sig_input_node), "Signature": str(sig_node)}
        # Some containers append on assignment. Remove all old field lines first,
        # including differently cased names in an ordinary dict.
        for name in list(message.headers):
            if name.lower() in {"signature-input", "signature"} and name in message.headers:
                del message.headers[name]
        for name, value in signature_headers.items():
            message.headers[name] = value


class HTTPMessageVerifier(HTTPSignatureHandler):
    max_clock_skew: datetime.timedelta = datetime.timedelta(seconds=5)
    require_created: bool = True
    allow_label_only_selection: bool = False

    def _parse_dict_header(self, header_name, headers):
        if header_name not in headers:
            raise InvalidSignature(f'Expected "{header_name}" header field to be present')
        try:
            dict_header_node = self._parse_signature_dictionary(headers[header_name])
        except Exception as e:
            raise InvalidSignature(f'Malformed structured header field "{header_name}"') from e
        return dict_header_node

    def _parse_integer_timestamp(self, ts, field_name):
        if type(ts) is not int:
            raise InvalidSignature(f'Parameter "{field_name}" must be a Structured Field Integer')
        try:
            dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
        except Exception as e:
            raise InvalidSignature(f'Malformed "{field_name}" parameter: {e}') from e
        return dt

    def validate_created_and_expires(self, sig_input, max_age=None):
        now = datetime.datetime.now(datetime.timezone.utc)
        min_time = now - self.max_clock_skew
        max_time = now + self.max_clock_skew
        if "created" in sig_input.params:
            if self._parse_integer_timestamp(sig_input.params["created"], field_name="created") > max_time:
                raise InvalidSignature('Signature "created" parameter is set to a time in the future')
        elif self.require_created or max_age is not None:
            raise InvalidSignature('Signature is missing a required "created" parameter')
        if (
            "expires" in sig_input.params
            and self._parse_integer_timestamp(sig_input.params["expires"], field_name="expires") < min_time
        ):
            raise InvalidSignature('Signature "expires" parameter is set to a time in the past')
        if (
            max_age is not None
            and self._parse_integer_timestamp(sig_input.params["created"], field_name="created") + max_age < min_time
        ):
            raise InvalidSignature(f"Signature age exceeds maximum allowable age {max_age}")

    def _get_sig_inputs_and_signatures(self, message, *, expect_tag=None, expect_label=None):
        headers = get_header_fields(message.headers)
        sig_inputs = self._parse_dict_header("Signature-Input", headers)
        signatures = self._parse_dict_header("Signature", headers)
        if len(sig_inputs) == 0 or len(signatures) == 0:
            raise InvalidSignature("No signatures found in the message")
        if (len(sig_inputs) > 1 or len(signatures) > 1) and expect_tag is None and expect_label is None:
            raise InvalidSignature("Multiple signatures found and no tag or label specified")
        if sig_inputs.keys() != signatures.keys():
            raise InvalidSignature("Signature-Input and Signature headers have different labels")
        n_sigs = 0
        for label, sig_input in sig_inputs.items():
            if label not in signatures:
                raise InvalidSignature(f'Signature missing expected label "{label}"')
            if not isinstance(sig_input, InnerList):
                raise InvalidSignature(f'Signature-Input member "{label}" must be an Inner List')
            signature = signatures[label]
            if not isinstance(signature, Item) or not isinstance(signature.value, bytes):
                raise InvalidSignature(f'Signature member "{label}" must be a Byte Sequence')
            try:
                self._validate_signature_param_types(sig_input.params)
            except HTTPMessageSignaturesException as e:
                raise InvalidSignature(str(e)) from e
            if expect_tag is not None and sig_input.params.get("tag") != expect_tag:
                continue
            if expect_label is not None and label != expect_label:
                continue
            yield label, sig_input, signatures[label]
            n_sigs += 1
        if n_sigs == 0:
            raise InvalidSignature("No signatures found matching the expected tag or label")

    def _verify_one(self, *, label, sig_input, signature, message, max_age):
        self.validate_created_and_expires(sig_input, max_age=max_age)
        if "alg" in sig_input.params and sig_input.params["alg"] != self.signature_algorithm.algorithm_id:
            raise InvalidSignature("Unexpected algorithm specified in the signature")
        if "keyid" not in sig_input.params:
            raise InvalidSignature('Signature is missing a required "keyid" parameter')
        for param in sig_input.params:
            if param not in self.signature_metadata_parameters:
                raise InvalidSignature(f'Unexpected signature metadata parameter "{param}"')
        try:
            key = self.key_resolver.resolve_public_key(sig_input.params["keyid"])
            if key is None:
                raise InvalidSignature("Unable to resolve verification key")
            verifier = self.signature_algorithm(public_key=key)
            sig_base, sig_params_node, sig_elements = self._build_signature_base(
                message, covered_component_ids=list(sig_input), signature_params=sig_input.params
            )
            verifier.verify(signature=signature.value, message=sig_base.encode())
        except InvalidSignature:
            raise
        except Exception as e:
            raise InvalidSignature(e) from e
        return VerifyResult(
            label=label,
            algorithm=self.signature_algorithm,
            covered_components=sig_elements,
            parameters=dict(sig_params_node.params),
            body=None,
            nonce=sig_input.params.get("nonce"),
        )

    def verify(
        self,
        message,
        *,
        max_age: datetime.timedelta | None = datetime.timedelta(days=1),
        expect_tag: str | None = None,
        expect_label: str | None = None,
    ) -> list[VerifyResult]:
        if expect_tag is None and expect_label is not None:
            if self.allow_label_only_selection:
                warn(
                    "Using only a label to identify a signature is not recommended, as the label is not covered by the "
                    "signature. Consider setting expect_tag.",
                    SignatureVerifyWarning,
                )
            else:
                raise HTTPMessageSignaturesException("expect_tag must be set if expect_label is set")
        verify_results = []
        for label, sig_input, signature in self._get_sig_inputs_and_signatures(
            message, expect_tag=expect_tag, expect_label=expect_label
        ):
            verify_result = self._verify_one(
                label=label, sig_input=sig_input, signature=signature, message=message, max_age=max_age
            )
            verify_results.append(verify_result)
        return verify_results
