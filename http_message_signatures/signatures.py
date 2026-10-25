import collections
import datetime
import logging
from collections.abc import Sequence
from functools import cache
from typing import Any, ClassVar, cast
from warnings import warn

import http_sf
from http_sf.compat import Dictionary, InnerList, Item

from ._components import _component_identity, _parse_component_ids
from .algorithms import HTTPSignatureAlgorithm
from .digests import ContentDigest, _is_content_digest
from .exceptions import HTTPMessageSignaturesException, InvalidSignature
from .resolvers import HTTPSignatureComponentResolver, HTTPSignatureKeyResolver
from .structures import (
    PreparedSignature,
    VerifyResult,
    get_header_field_lines,
    get_header_fields,
)

logger = logging.getLogger(__name__)


class SignatureVerifyWarning(UserWarning):
    pass


class HTTPSignatureHandler:
    signature_metadata_parameters: ClassVar[set[str]] = {"alg", "created", "expires", "keyid", "nonce", "tag"}
    #: Shared digest implementation for opt-in body signing and verification.
    content_digest_class: type[ContentDigest] = ContentDigest

    def __init__(
        self,
        *,
        signature_algorithm: type[HTTPSignatureAlgorithm],
        key_resolver: HTTPSignatureKeyResolver | None,
        component_resolver_class: type = HTTPSignatureComponentResolver,
    ):
        """Configure signing or verification.

        :param signature_algorithm: Built-in or custom subclass of
            :class:`~http_message_signatures.HTTPSignatureAlgorithm`.
        :param key_resolver: Resolves key IDs to key bytes or cryptography key objects.
        :param component_resolver_class: Resolver class instantiated for each message.
        """
        if (
            not isinstance(signature_algorithm, type)
            or not issubclass(signature_algorithm, HTTPSignatureAlgorithm)
            or signature_algorithm is HTTPSignatureAlgorithm
        ):
            raise HTTPMessageSignaturesException("signature_algorithm must be an HTTPSignatureAlgorithm subclass")
        self.signature_algorithm = signature_algorithm
        self.key_resolver = key_resolver
        self.component_resolver_class = component_resolver_class

    @staticmethod
    def _parse_signature_dictionary(value: str) -> Dictionary:
        def reject_duplicate(key: str, context: str):
            if context == "dictionary":
                raise HTTPMessageSignaturesException(f'Duplicate signature label "{key}"')

        parsed = cast(
            dict[str, Any], http_sf.parse(value.encode(), tltype="dictionary", on_duplicate_key=reject_duplicate)
        )
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
        self, message, *, covered_component_ids: list[Any], signature_params: dict[str, Any], component_resolver=None
    ) -> tuple:
        self._validate_signature_param_types(signature_params)
        assert "@signature-params" not in covered_component_ids
        sig_elements = collections.OrderedDict()
        seen_components = set()
        if component_resolver is None:
            component_resolver = self.component_resolver_class(message)
        for component_id in covered_component_ids:
            if not isinstance(component_id, Item) or not isinstance(component_id.value, str):
                raise HTTPMessageSignaturesException("Component names must be Structured Field Strings")
            component_key = str(component_id)
            # Reject repeated identities before resolving potentially large values.
            # Component identity ignores parameter order (RFC 9421 section 2).
            identity = _component_identity(component_id)
            if identity in seen_components:
                raise HTTPMessageSignaturesException(
                    f'Component ID "{component_key}" appeared multiple times in signature input'
                )
            seen_components.add(identity)
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
            # RFC 9421 section 2.5 permits internal HTAB in field values,
            # but no other control characters in the signature base.
            if (
                not component_id.value.startswith("@")
                and component_value
                and not component_value.replace("\t", " ").isprintable()
            ):
                raise HTTPMessageSignaturesException(
                    f'Field component "{component_key}" contains invalid control characters'
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
    """Construct HTTP message signatures and write their headers to a message."""

    DEFAULT_SIGNATURE_LABEL = "pyhms"

    def __init__(
        self,
        *,
        signature_algorithm: type[HTTPSignatureAlgorithm],
        key_resolver: HTTPSignatureKeyResolver | None = None,
        component_resolver_class: type = HTTPSignatureComponentResolver,
    ):
        """Configure the algorithm and component resolver used for signing.

        :param signature_algorithm: Built-in or custom subclass of
            :class:`~http_message_signatures.HTTPSignatureAlgorithm`.
        :param key_resolver: Required by ``sign()`` for local signing. May be
            omitted when using ``prepare()`` and ``apply()`` with an external signer.
        :param component_resolver_class: Resolver class instantiated for each message.
        """
        super().__init__(
            signature_algorithm=signature_algorithm,
            key_resolver=key_resolver,
            component_resolver_class=component_resolver_class,
        )

    def _parse_covered_component_ids(self, covered_component_ids):
        return _parse_component_ids(covered_component_ids)

    def _armor_set_cookie(self, message, covered_component_nodes):
        field_lines = {}
        for component in covered_component_nodes:
            if component.value != "set-cookie" or "bs" in component.params:
                continue
            use_request = component.params.get("req") is True
            if use_request not in field_lines:
                source = message.request if use_request and hasattr(message, "status_code") else message
                field_lines[use_request] = get_header_field_lines(source.headers)
            if len(field_lines[use_request].get("set-cookie", [])) > 1:
                component.params["bs"] = True

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
        body: bytes | None = None,
        use_existing_digest: bool = False,
    ):
        """Sign a message in place; return ``None``.

        :param message: Request or response implementing the message interface
            documented in :class:`~http_message_signatures.HTTPSignatureComponentResolver`.
        :param key_id: ID passed to ``key_resolver.resolve_private_key`` and
            included in the signed metadata.
        :param created: Creation time; defaults to the current time. A naive
            datetime is interpreted in the local timezone.
        :param expires: Optional expiration time, with the same timezone rules.
        :param nonce: Optional signed nonce. Replay detection is the caller's responsibility.
        :param label: Signature dictionary key; defaults to ``pyhms``.
        :param tag: Optional signed application identifier.
        :param include_alg: Include the configured algorithm ID in signed metadata.
        :param covered_component_ids: Sequence of component names or serialized
            Structured Field String items, for example ``("date",)`` or
            ``('\"@query-param\";name="Pet"',)``. A scalar string is rejected.
            Defaults cover request method, authority, and target URL. Responses
            require an explicit list such as ``("@status", "content-type")``.
            Use ``('\"set-cookie\";bs',)`` to wrap individual field values as
            Byte Sequences. Covered Set-Cookie fields with multiple values
            automatically receive ``bs``; explicit invalid flags are rejected.
        :param append_if_signature_exists: Preserve existing signatures and add a
            new label. Otherwise replace existing signature headers.
        :param body: Optional content bytes before decoding. When supplied,
            ``sign()`` generates Content-Digest if absent and adds digest coverage
            to the signature, including when ``body=b""``.
        :param use_existing_digest: Whether ``sign()`` may reuse an existing
            Content-Digest. When true, ``sign()`` preserves the field and validates
            it against ``body`` if supplied. Without ``body``, ``sign()`` checks
            only the digest's format and algorithms; you must ensure it matches
            the content and include it in ``covered_component_ids`` to sign it.
            If this option is true but neither a digest nor ``body`` is available,
            ``sign()`` raises an error.
        :raises HTTPMessageSignaturesException: A component or signature parameter
            is invalid or an existing signature cannot be appended to.

        Key resolver and algorithm errors can also propagate. Signing does not
        calculate a body digest unless ``body`` is supplied.
        """
        if self.key_resolver is None:
            raise HTTPMessageSignaturesException("A key_resolver is required for local signing")
        prepared = self.prepare(
            message,
            key_id=key_id,
            created=created,
            expires=expires,
            nonce=nonce,
            label=label,
            tag=tag,
            include_alg=include_alg,
            covered_component_ids=covered_component_ids,
            body=body,
            use_existing_digest=use_existing_digest,
        )
        key = self.key_resolver.resolve_private_key(key_id)
        signer = self.signature_algorithm(private_key=key)
        signature = signer.sign(prepared.signature_base)
        self.apply(message, prepared, signature, append_if_signature_exists=append_if_signature_exists)

    def prepare(
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
        body: bytes | None = None,
        use_existing_digest: bool = False,
    ) -> PreparedSignature:
        """Build the signing input without resolving a key.

        Arguments have the same meaning and defaults as in ``sign()``. Creation
        time is captured here, before any remote signing delay. Header append or
        replacement policy is selected later in ``apply()``.
        ``prepare()`` handles ``body`` and ``use_existing_digest`` as documented
        for ``sign()``. It changes the message only when it generates a digest.
        Supply bytes that match the message's content; ``prepare()`` does not read
        the message's body to check that you supplied the correct bytes.

        :returns: Immutable signing input for a synchronous or asynchronous signer.
            Sign ``signature_base`` with the configured algorithm and the key
            identified by ``key_id``, then pass the resulting bytes to ``apply()``.
        :raises HTTPMessageSignaturesException: A component, parameter, or label is invalid.

        The component resolver must return stable values for unchanged messages;
        ``apply()`` resolves them again to check for changes while signing.
        """
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
        self.content_digest_class.prepare(message.headers, body, use_existing_digest=use_existing_digest)
        if body is not None and not any(_is_content_digest(node) for node in covered_component_nodes):
            covered_component_nodes.append(Item("content-digest"))
        self._armor_set_cookie(message, covered_component_nodes)
        sig_base, sig_params_node, _ = self._build_signature_base(
            message, covered_component_ids=covered_component_nodes, signature_params=signature_params
        )
        sig_label = self.DEFAULT_SIGNATURE_LABEL if label is None else label
        try:
            # Let the Structured Fields serializer validate the dictionary key.
            str(Dictionary({sig_label: sig_params_node}))
        except (ValueError, TypeError) as e:
            raise HTTPMessageSignaturesException("Invalid signature label") from e
        return PreparedSignature(
            sig_base.encode(), str(sig_params_node), sig_label, self.signature_algorithm.algorithm_id
        )

    def apply(
        self,
        message,
        prepared: PreparedSignature,
        signature: bytes,
        *,
        append_if_signature_exists: bool = False,
    ) -> None:
        """Attach an externally generated signature to a message in place.

        :param message: Message whose covered values still match ``prepared``.
        :param prepared: Input returned by ``prepare()`` with the same algorithm
            and component resolver configuration.
        :param signature: Raw algorithm output, before base64 encoding. ECDSA
            P-256 requires 64 bytes containing ``r || s``; convert DER output with
            ``ECDSA_P256_SHA256.signature_from_der()`` first.
        :param append_if_signature_exists: Preserve existing signatures and add
            the prepared label. Otherwise replace existing signature headers.
        :raises HTTPMessageSignaturesException: Covered values changed, prepared
            input is inconsistent, signature bytes are empty, or headers cannot
            be appended to. Validation completes before changing headers.

        This method neither resolves keys nor verifies the signature. The caller
        must associate the result with the prepared input and use a trusted signer
        with the intended key and algorithm. The comparison covers signature-base
        values only; it does not validate the body against a digest header, check
        expiration, or prevent concurrent message mutation. Keep the message
        stable during this call and until it is sent.
        """
        if not isinstance(prepared, PreparedSignature):
            raise HTTPMessageSignaturesException("Expected a PreparedSignature from prepare()")
        if prepared.algorithm_id != self.signature_algorithm.algorithm_id:
            raise HTTPMessageSignaturesException("Prepared signature uses a different algorithm")
        if not isinstance(signature, bytes) or not signature:
            raise HTTPMessageSignaturesException("Signature must be non-empty raw bytes")
        try:
            # A fixed dictionary key lets the existing parser read the complete
            # inner list, including its parameters, without parsing base lines.
            parsed = self._parse_signature_dictionary("prepared=" + prepared.signature_params)
            if list(parsed) != ["prepared"] or not isinstance(parsed["prepared"], InnerList):
                raise HTTPMessageSignaturesException("Invalid prepared signature parameters")
            sig_params_node = parsed["prepared"]
            if "alg" in sig_params_node.params and sig_params_node.params["alg"] != prepared.algorithm_id:
                raise HTTPMessageSignaturesException("Prepared signature has a conflicting algorithm parameter")
            sig_base, _, _ = self._build_signature_base(
                message, covered_component_ids=list(sig_params_node), signature_params=sig_params_node.params
            )
            # The message may have changed while the external signer was working.
            if sig_base.encode() != prepared.signature_base:
                raise HTTPMessageSignaturesException("Message or signature parameters changed after prepare()")
            # Validate the label before looking at or changing existing headers.
            str(Dictionary({prepared.label: sig_params_node}))
        except HTTPMessageSignaturesException:
            raise
        except (ValueError, TypeError) as e:
            raise HTTPMessageSignaturesException("Invalid prepared signature input") from e
        sig_label = prepared.label

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
    """Verify signatures using a configured algorithm and key resolver."""

    #: Tolerance for creation, expiration, and maximum-age checks.
    max_clock_skew: datetime.timedelta = datetime.timedelta(seconds=5)
    #: Require a creation timestamp. Set False and use max_age=None to allow its omission.
    require_created: bool = True
    #: Permit label selection without a signed tag, with a warning.
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

    def _verify_one(self, *, label, sig_input, signature, message, max_age, component_resolver_factory=None):
        self.validate_created_and_expires(sig_input, max_age=max_age)
        if "alg" in sig_input.params and sig_input.params["alg"] != self.signature_algorithm.algorithm_id:
            raise InvalidSignature("Unexpected algorithm specified in the signature")
        if "keyid" not in sig_input.params:
            raise InvalidSignature('Signature is missing a required "keyid" parameter')
        for param in sig_input.params:
            if param not in self.signature_metadata_parameters:
                raise InvalidSignature(f'Unexpected signature metadata parameter "{param}"')
        try:
            if self.key_resolver is None:
                raise InvalidSignature("A key_resolver is required for verification")
            key = self.key_resolver.resolve_public_key(sig_input.params["keyid"])
            if key is None:
                raise InvalidSignature("Unable to resolve verification key")
            verifier = self.signature_algorithm(public_key=key)
            sig_base, sig_params_node, sig_elements = self._build_signature_base(
                message,
                covered_component_ids=list(sig_input),
                signature_params=sig_input.params,
                component_resolver=component_resolver_factory() if component_resolver_factory is not None else None,
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
        require_components: Sequence[str] = (),
        body: bytes | None = None,
    ) -> list[VerifyResult]:
        """Return verified signatures matching the requested selection.

        :param message: Request or response implementing the interface documented
            in :class:`~http_message_signatures.HTTPSignatureComponentResolver`.
        :param max_age: Maximum age since creation, with clock-skew tolerance.
            ``None`` disables the age limit; expiration checks still apply.
        :param expect_tag: Require this signed application tag. Required when
            selecting among multiple signatures unless label-only selection is enabled.
        :param expect_label: Also select this signature dictionary label. Labels
            are not signed; normally ``expect_tag`` must be supplied with this option.
        :param require_components: Components that ``verify()`` requires every
            selected signature to cover. Use the same component syntax as for
            signing. ``verify()`` ignores parameter order when comparing components
            and adds no coverage requirements for this option when it is omitted.
        :param body: Optional content bytes before decoding. When supplied,
            ``verify()`` validates the signed Content-Digest against these bytes
            and returns them in each result's ``body`` field. It requires every
            selected signature to cover the digest unless the content is empty
            and Content-Digest is absent; in that case, each result's ``body`` is ``None``.
        :returns: A list of :class:`~http_message_signatures.VerifyResult` objects.
            Every selected signature must verify; no partial result is returned.
        :raises InvalidSignature: A signature is missing, malformed, expired,
            uses an unexpected algorithm, or fails cryptographic verification.
        :raises HTTPMessageSignaturesException: The selection policy is invalid.

        Check returned coverage, or specify ``require_components``, before trusting
        message data. Without ``body``, digest validation remains the caller's
        responsibility. Authorization and replay detection are always caller policy.
        """
        if expect_tag is None and expect_label is not None:
            if self.allow_label_only_selection:
                warn(
                    "Using only a label to identify a signature is not recommended, as the label is not covered by the "
                    "signature. Consider setting expect_tag.",
                    SignatureVerifyWarning,
                )
            else:
                raise HTTPMessageSignaturesException("expect_tag must be set if expect_label is set")

        required = _parse_component_ids(require_components)
        if len({_component_identity(node) for node in required}) != len(required):
            raise HTTPMessageSignaturesException("Duplicate required component identifier")

        # Share parsed message data across selected signatures, but never across
        # verify() calls: callers may mutate or reuse a message between calls.
        @cache
        def component_resolver_factory():
            return self.component_resolver_class(message)

        verify_results = []
        for label, sig_input, signature in self._get_sig_inputs_and_signatures(
            message, expect_tag=expect_tag, expect_label=expect_label
        ):
            verify_result = self._verify_one(
                label=label,
                sig_input=sig_input,
                signature=signature,
                message=message,
                max_age=max_age,
                component_resolver_factory=component_resolver_factory,
            )
            if required:
                covered = {
                    _component_identity(node) for node in _parse_component_ids(tuple(verify_result.covered_components))
                }
                for component in required:
                    if _component_identity(component) not in covered:
                        raise InvalidSignature(f"Required component {component} was not covered by the signature")
            verify_results.append(verify_result)
        if body is not None:
            return self.verify_body(message, verify_results, body)
        return verify_results

    def verify_body(self, message, results: Sequence[VerifyResult], body: bytes) -> list[VerifyResult]:
        """This method validates body digests after ``verify()`` has authenticated headers."""
        self.content_digest_class._check_body(body)
        needs_digest = bool(body) or "content-digest" in get_header_fields(message.headers)
        verified = []
        for result in results:
            digest_verified = self.content_digest_class.verify_components(result.covered_components, body)
            if needs_digest and not digest_verified:
                raise InvalidSignature("The message body requires a signed Content-Digest")
            verified.append(result._replace(body=body) if digest_verified else result)
        return verified
