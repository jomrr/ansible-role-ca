"""Verify policy extensions, issuance rules, and native path validation."""

from __future__ import annotations

import os
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ca_certificate_engine import (
    ensure_certificate_artifacts,
    ensure_certificate_batch,
)
from ansible.module_utils.ca_verify_common import _load_pem_cert, _public_key_bytes
from ansible.module_utils.ca_verify_algorithms import check_algorithm_changes
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


def _expect_rejection(
    params: dict[str, Any], certificates: list[dict[str, Any]], *, batch: bool
) -> None:
    """Require policy rejection before any member's key, CSR, or certificate exists."""
    try:
        if batch:
            ensure_certificate_batch(dict(params, certificates=certificates))
        else:
            ensure_certificate_artifacts(params, certificates[0])
    except ValueError as exc:
        if "polic" not in str(exc).lower():
            raise ValueError(f"Unexpected issuance rejection: {exc}") from exc
    else:
        raise ValueError("Invalid policy declaration was accepted")
    base_dir = Path(params["base_dir"])
    for certificate in certificates:
        name = certificate["name"]
        if (base_dir / "certs" / name).exists() or (
            base_dir / "csr" / f"{name}.csr"
        ).exists():
            raise ValueError(f"Rejected policy request created material for {name}")


def _check_issuance(params: dict[str, Any]) -> None:
    """Exercise single issuance, grouped rejection, reordering, and policy updates."""
    server = {
        "oid": "1.3.6.1.4.1.32473.1.1.1",
        "cps_uri": "https://pki.example.org/cps",
    }
    device = {"oid": "1.3.6.1.4.1.32473.1.1.2"}
    certificate: dict[str, Any] = {
        "name": "policy-check",
        "type": "tls_server",
        "common_name": "policy-check.example.org",
        "key_type": "ECDSA",
        "key_size": 256,
        "certificate_policies": [server, device],
    }
    first = ensure_certificate_artifacts(params, certificate)
    original = _load_pem_cert(Path(first["cert_path"]))
    if not first["cert_changed"]:
        raise ValueError("Initial policy certificate was not issued")
    certificate["certificate_policies"] = [device, server]
    if ensure_certificate_artifacts(params, certificate)["changed"]:
        raise ValueError("Reordered policies were not idempotent")
    for policies in (
        [server],
        [dict(server, cps_uri="https://pki.example.org/cps/v2")],
    ):
        certificate["certificate_policies"] = policies
        changed = ensure_certificate_artifacts(params, certificate)
        renewed = _load_pem_cert(Path(changed["cert_path"]))
        if (
            not changed["cert_changed"]
            or original.serial_number == renewed.serial_number
        ):
            raise ValueError("Policy change did not reissue the certificate")
        if _public_key_bytes(original.public_key()) != _public_key_bytes(
            renewed.public_key()
        ):
            raise ValueError("Policy change unexpectedly replaced the private key")
        if ensure_certificate_artifacts(params, certificate)["changed"]:
            raise ValueError("Changed policy certificate is not idempotent")
        original = renewed
    check_algorithm_changes(params, certificate)
    valid = dict(certificate, name="batch-valid")
    for index, policies in enumerate(([], [{"oid": "1.3.6.1.4.1.32473.1.1.3"}])):
        invalid = dict(
            certificate, name=f"rejected-{index}", certificate_policies=policies
        )
        _expect_rejection(params, [invalid], batch=False)
        _expect_rejection(params, [valid, invalid], batch=True)
    _expect_rejection(
        params, [dict(certificate, name="unscoped", type="eap_tls_client")], batch=False
    )
    rejected_options: tuple[dict[str, Any], ...] = (
        {"policy_constraints": {"require_explicit_policy": 0}},
        {"inhibit_any_policy": 0},
        {"certificate_policies": [{"oid": "2.5.29.32.0"}]},
        {"raw_extensions": [{"oid": "2.5.29.32", "value": "DER:3000"}]},
    )
    for index, overrides in enumerate(rejected_options):
        invalid = dict(certificate, name=f"unsupported-{index}", **overrides)
        _expect_rejection(params, [invalid], batch=False)


def check_policies(module: AnsibleModule, base_dir: Path, errors: list[str]) -> None:
    """Check scenario artifacts and run isolated policy issuance against its CAs."""
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
    if module.check_mode:
        return
    with TemporaryDirectory(prefix="ca-policy-verify-") as directory:
        scratch = Path(directory)
        for name in ("ca", "private", "chains"):
            (scratch / name).symlink_to(base_dir / name, target_is_directory=True)
        params = {
            "base_dir": directory,
            "base_url": "http://pki.example.org",
            "ca_name": "Policy verification",
            "authorities": module.params["authorities"],
            "certificate_types": module.params["certificate_types"],
            "owner": str(os.geteuid()),
            "group": str(os.getegid()),
            "force": False,
        }
        _check_issuance(params)
