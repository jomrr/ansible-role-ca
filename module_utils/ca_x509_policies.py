"""Typed certificate policies and local issuer policy authorization."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from cryptography import x509

ANY_POLICY = "2.5.29.32.0"
POLICY_EXTENSION_OIDS = {"2.5.29.32", "2.5.29.33", "2.5.29.36", "2.5.29.54"}
CONSTRAINT_FIELDS = {"require_explicit_policy", "inhibit_policy_mapping"}


def policy_argument_spec() -> dict[str, dict[str, Any]]:
    """Return the optional authority policy module arguments."""
    return {
        "certificate_policies": {
            "type": "list",
            "elements": "dict",
            "default": [],
        },
        "policy_constraints": {"type": "dict", "default": {}},
        "inhibit_any_policy": {"type": "raw"},
    }


def _policy_oid(value: str) -> str:
    """Require canonical dotted OIDs, including when inspecting raw extensions."""
    oid = x509.ObjectIdentifier(value).dotted_string
    if oid != ".".join(str(int(arc)) for arc in oid.split(".")):
        raise ValueError(f"Noncanonical policy extension OID {value}")
    return oid


def _policies(value: Any) -> list[dict[str, str]]:
    """Validate and sort policy identifiers and optional CPS URIs."""
    if not isinstance(value, list):
        raise ValueError("certificate_policies must be a list")
    result = []
    seen = set()
    for item in value:
        if not isinstance(item, dict) or set(item).difference({"oid", "cps_uri"}):
            raise ValueError("Each certificate policy needs oid and optional cps_uri")
        oid = item.get("oid")
        if not isinstance(oid, str):
            raise ValueError("Certificate policy oid must be a dotted string")
        identifier = _policy_oid(oid)
        if identifier in seen:
            raise ValueError(f"Duplicate certificate policy OID {identifier}")
        seen.add(identifier)
        policy = {"oid": identifier}
        if "cps_uri" in item:
            uri = item["cps_uri"]
            if not isinstance(uri, str) or not uri.isascii():
                raise ValueError("cps_uri must be an ASCII HTTP or HTTPS URL")
            parsed = urlsplit(uri)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or any(character.isspace() or ord(character) < 32 for character in uri)
            ):
                raise ValueError("cps_uri must be an absolute HTTP or HTTPS URL")
            policy["cps_uri"] = uri
        result.append(policy)
    return sorted(result, key=lambda policy: policy["oid"])


def _skip_certs(value: Any, name: str) -> int | None:
    """Validate a constraint counter while retaining zero as an active value."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a nonnegative integer")
    return value


def normalize_policy_params(params: dict[str, Any], *, signed: bool) -> None:
    """Normalize policy configuration before any certificate material is written."""
    policies = _policies(params.get("certificate_policies", []))
    constraints = params.get("policy_constraints", {})
    if not isinstance(constraints, dict) or set(constraints) - CONSTRAINT_FIELDS:
        raise ValueError(
            "policy_constraints accepts only require_explicit_policy and inhibit_policy_mapping"
        )
    constraints = {
        field: _skip_certs(value, field)
        for field, value in constraints.items()
        if value is not None
    }
    inhibit_any = _skip_certs(params.get("inhibit_any_policy"), "inhibit_any_policy")
    is_root = params["authority"] and not signed
    if any(policy["oid"] == ANY_POLICY for policy in policies) and not is_root:
        raise ValueError("anyPolicy is only supported on self-signed root authorities")
    if constraints or inhibit_any is not None:
        if not params["authority"] or not signed:
            raise ValueError("Policy constraints are only supported on sub-CAs")
        if not policies:
            raise ValueError("Sub-CA policy constraints require certificate_policies")
    for extension in params.get("raw_extensions") or []:
        oid = _policy_oid(str(extension["oid"]))
        if oid in POLICY_EXTENSION_OIDS:
            raise ValueError(
                f"Policy extension {oid} is not supported in raw_extensions; "
                "use typed policy fields"
            )
    params["certificate_policies"] = policies
    params["policy_constraints"] = constraints
    params["inhibit_any_policy"] = inhibit_any


def validate_issuer_policies(params: dict[str, Any], issuer: x509.Certificate) -> None:
    """Require EE policies to be a nonempty subset of a policy-bearing issuer."""
    if params["authority"]:
        return
    try:
        issued_under = issuer.extensions.get_extension_for_class(
            x509.CertificatePolicies
        ).value
        allowed = {policy.policy_identifier.dotted_string for policy in issued_under}
    except x509.ExtensionNotFound:
        allowed = set()
    requested = {policy["oid"] for policy in params["certificate_policies"]}
    if allowed and not requested:
        raise ValueError(
            f"Certificate {params['name']} requires certificate_policies matching its issuer"
        )
    if requested - allowed:
        raise ValueError(
            f"Certificate {params['name']} policies are not allowed by its issuer: "
            + ", ".join(sorted(requested - allowed))
        )


def policy_extensions(
    params: dict[str, Any],
) -> list[tuple[x509.ObjectIdentifier, bool, x509.ExtensionType]]:
    """Build policy extensions from previously normalized configuration."""
    result: list[tuple[x509.ObjectIdentifier, bool, x509.ExtensionType]] = []
    policies = params["certificate_policies"]
    if policies:
        value = x509.CertificatePolicies(
            [
                x509.PolicyInformation(
                    x509.ObjectIdentifier(policy["oid"]),
                    [policy["cps_uri"]] if "cps_uri" in policy else None,
                )
                for policy in policies
            ]
        )
        result.append((value.oid, False, value))
    constraints = params["policy_constraints"]
    if constraints:
        constraint_value = x509.PolicyConstraints(
            require_explicit_policy=constraints.get("require_explicit_policy"),
            inhibit_policy_mapping=constraints.get("inhibit_policy_mapping"),
        )
        result.append((constraint_value.oid, True, constraint_value))
    if params["inhibit_any_policy"] is not None:
        inhibit_value = x509.InhibitAnyPolicy(params["inhibit_any_policy"])
        result.append((inhibit_value.oid, True, inhibit_value))
    return result


def policy_extension_token(value: x509.ExtensionType) -> tuple | None:
    """Return order-independent tokens for supported policy extensions."""
    if isinstance(value, x509.CertificatePolicies):
        return (
            "certificate_policies",
            tuple(
                sorted(
                    (
                        policy.policy_identifier.dotted_string,
                        tuple(
                            sorted(
                                repr(qualifier)
                                for qualifier in policy.policy_qualifiers or []
                            )
                        ),
                    )
                    for policy in value
                )
            ),
        )
    if isinstance(value, x509.PolicyConstraints):
        return (
            "policy_constraints",
            value.require_explicit_policy,
            value.inhibit_policy_mapping,
        )
    if isinstance(value, x509.InhibitAnyPolicy):
        return ("inhibit_any_policy", value.skip_certs)
    return None


def policy_extension_text(value: x509.ExtensionType) -> list[str]:
    """Return readable policy extension values for certificate text exports."""
    if isinstance(value, x509.CertificatePolicies):
        return [
            f"Policy: {policy.policy_identifier.dotted_string}"
            + "".join(
                f"; CPS: {qualifier}" for qualifier in policy.policy_qualifiers or []
            )
            for policy in value
        ]
    if isinstance(value, x509.PolicyConstraints):
        return [
            f"{field}: {getattr(value, field)}"
            for field in ("require_explicit_policy", "inhibit_policy_mapping")
            if getattr(value, field) is not None
        ]
    if isinstance(value, x509.InhibitAnyPolicy):
        return [f"Skip certificates: {value.skip_certs}"]
    return []
