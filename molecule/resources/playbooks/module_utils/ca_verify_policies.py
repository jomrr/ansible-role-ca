"""Verify role-issued policy extensions and native path validation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ca_verify_common import _load_pem_cert
from cryptography import x509


def _check_extensions(path: Path, config: dict[str, Any], errors: list[str]) -> None:
    """Compare the encoded policy configuration, including absent extensions."""
    cert = _load_pem_cert(path)
    expected = {
        policy["oid"]: [policy["cps_uri"]] if "cps_uri" in policy else []
        for policy in config.get("certificate_policies", [])
    }
    try:
        extension = cert.extensions.get_extension_for_class(x509.CertificatePolicies)
        actual = {
            policy.policy_identifier.dotted_string: list(policy.policy_qualifiers or [])
            for policy in extension.value
        }
        if actual != expected or extension.critical:
            errors.append(f"{path}: incorrect policies, qualifiers, or critical flag")
    except x509.ExtensionNotFound:
        if expected:
            errors.append(f"{path}: certificatePolicies missing")
    constraints = config.get("policy_constraints", {})
    try:
        constraint_extension = cert.extensions.get_extension_for_class(
            x509.PolicyConstraints
        )
        if (
            not constraints
            or not constraint_extension.critical
            or constraint_extension.value.require_explicit_policy
            != constraints.get("require_explicit_policy")
            or constraint_extension.value.inhibit_policy_mapping
            != constraints.get("inhibit_policy_mapping")
        ):
            errors.append(f"{path}: incorrect policyConstraints")
    except x509.ExtensionNotFound:
        if constraints:
            errors.append(f"{path}: policyConstraints missing")
    try:
        inhibit_extension = cert.extensions.get_extension_for_class(
            x509.InhibitAnyPolicy
        )
        if (
            not inhibit_extension.critical
            or inhibit_extension.value.skip_certs != config.get("inhibit_any_policy")
        ):
            errors.append(f"{path}: incorrect inhibitAnyPolicy")
    except x509.ExtensionNotFound:
        if config.get("inhibit_any_policy") is not None:
            errors.append(f"{path}: inhibitAnyPolicy missing")


def _check_path_validation(module: AnsibleModule, base_dir: Path) -> None:
    """Verify acceptance and policy-specific rejection of the role-issued chain."""
    openssl = module.get_bin_path("openssl", required=True)
    command = [
        openssl,
        "verify",
        "-CAfile",
        str(base_dir / "ca/root-ca.pem"),
        "-untrusted",
        str(base_dir / "ca/component-ca.pem"),
        "-policy",
    ]
    certificate = str(base_dir / "certs/external-csr/external-csr.pem")
    status, stdout, stderr = module.run_command(
        command + ["1.3.6.1.4.1.32473.1.1.1", certificate]
    )
    if status != 0:
        raise ValueError(f"Matching policy chain rejected: {stdout} {stderr}")
    status, stdout, stderr = module.run_command(
        command + ["1.3.6.1.4.1.32473.1.1.99", certificate]
    )
    if status == 0 or "no explicit policy" not in (stdout + stderr).lower():
        raise ValueError(
            f"Expected explicit-policy failure, got: {status}: {stdout} {stderr}"
        )


def check_policies(module: AnsibleModule, base_dir: Path, errors: list[str]) -> None:
    """Check policy extensions and paths of the role-issued certificates."""
    for authority in module.params["authorities"]:
        _check_extensions(
            base_dir / "ca" / f"{authority['name']}-ca.pem", authority, errors
        )
    for certificate in module.params["certificates"]:
        name = certificate["name"]
        _check_extensions(
            base_dir / "certs" / name / f"{name}.pem", certificate, errors
        )
    _check_path_validation(module, base_dir)
