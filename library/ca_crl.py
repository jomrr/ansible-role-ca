#!/usr/bin/python
"""Manage CA role certificate revocation lists."""

from __future__ import annotations

import datetime as _dt
import grp
import os
import pwd
import re
from pathlib import Path

from ansible.module_utils.basic import AnsibleModule

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID
except Exception as exc:  # pragma: no cover
    CRYPTOGRAPHY_IMPORT_ERROR = exc
else:
    CRYPTOGRAPHY_IMPORT_ERROR = None


NAME_OIDS = {
    "C": NameOID.COUNTRY_NAME,
    "countryName": NameOID.COUNTRY_NAME,
    "ST": NameOID.STATE_OR_PROVINCE_NAME,
    "stateOrProvinceName": NameOID.STATE_OR_PROVINCE_NAME,
    "L": NameOID.LOCALITY_NAME,
    "localityName": NameOID.LOCALITY_NAME,
    "O": NameOID.ORGANIZATION_NAME,
    "organizationName": NameOID.ORGANIZATION_NAME,
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "organizationalUnitName": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "CN": NameOID.COMMON_NAME,
    "commonName": NameOID.COMMON_NAME,
    "emailAddress": NameOID.EMAIL_ADDRESS,
}

REASON_FLAGS = {
    "key_compromise": x509.ReasonFlags.key_compromise,
    "ca_compromise": x509.ReasonFlags.ca_compromise,
    "affiliation_changed": x509.ReasonFlags.affiliation_changed,
    "superseded": x509.ReasonFlags.superseded,
    "cessation_of_operation": x509.ReasonFlags.cessation_of_operation,
    "certificate_hold": x509.ReasonFlags.certificate_hold,
    "privilege_withdrawn": x509.ReasonFlags.privilege_withdrawn,
    "aa_compromise": x509.ReasonFlags.aa_compromise,
}


def _digest(name: str):
    normalized = name.replace("-", "").lower()
    digests = {
        "sha1": hashes.SHA1,
        "sha224": hashes.SHA224,
        "sha256": hashes.SHA256,
        "sha384": hashes.SHA384,
        "sha512": hashes.SHA512,
    }
    if normalized not in digests:
        raise ValueError(f"Unsupported digest {name}")
    return digests[normalized]()


def _uid(owner):
    if owner is None:
        return -1
    value = str(owner)
    if value.isdigit():
        return int(value)
    return pwd.getpwnam(value).pw_uid


def _gid(group):
    if group is None:
        return -1
    value = str(group)
    if value.isdigit():
        return int(value)
    return grp.getgrnam(value).gr_gid


def _set_attrs(path: str, owner, group, mode) -> bool:
    changed = False
    stat = os.stat(path)
    uid = _uid(owner)
    gid = _gid(group)
    if (uid != -1 and stat.st_uid != uid) or (gid != -1 and stat.st_gid != gid):
        os.chown(path, uid, gid)
        changed = True
    if mode is not None:
        desired = int(str(mode), 8)
        if (stat.st_mode & 0o7777) != desired:
            os.chmod(path, desired)
            changed = True
    return changed


def _write_file(path: str, content: bytes, owner, group, mode) -> bool:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    changed = True
    if os.path.exists(path):
        changed = Path(path).read_bytes() != content
    if changed:
        tmp_path = f"{path}.ansible_tmp"
        Path(tmp_path).write_bytes(content)
        os.replace(tmp_path, path)
    return changed | _set_attrs(path, owner, group, mode)


def _subject(subject_ordered) -> x509.Name:
    attributes = []
    for item in subject_ordered or []:
        if len(item) != 1:
            raise ValueError("issuer_ordered entries must contain exactly one item")
        key, value = next(iter(item.items()))
        if value is None or str(value) == "":
            continue
        oid = NAME_OIDS.get(str(key))
        if oid is None:
            raise ValueError(f"Unsupported issuer attribute {key}")
        attributes.append(x509.NameAttribute(oid, str(value)))
    return x509.Name(attributes)


def _load_key(path: str, passphrase: str | None):
    return serialization.load_pem_private_key(
        Path(path).read_bytes(),
        password=passphrase.encode() if passphrase else None,
    )


def _load_crl(path: str):
    data = Path(path).read_bytes()
    try:
        return x509.load_pem_x509_crl(data)
    except ValueError:
        return x509.load_der_x509_crl(data)


def _parse_serial(value) -> int:
    if isinstance(value, int):
        return value
    text = str(value)
    if ":" in text:
        return int(re.sub(r"[^0-9A-Fa-f]", "", text), 16)
    if text.lower().startswith("0x"):
        return int(text, 16)
    return int(text)


def _parse_revocation_date(value):
    if not value:
        return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)
    text = str(value)
    if re.match(r"^\d{14}Z$", text):
        return _dt.datetime.strptime(text, "%Y%m%d%H%M%SZ").replace(tzinfo=_dt.timezone.utc)
    return _dt.datetime.fromisoformat(text.replace("Z", "+00:00"))


def _revoked_signature(crl):
    result = []
    for revoked in crl:
        reason = None
        try:
            reason_ext = revoked.extensions.get_extension_for_class(x509.CRLReason)
            reason = reason_ext.value.reason.name
        except x509.ExtensionNotFound:
            pass
        result.append((revoked.serial_number, reason))
    return sorted(result)


def _desired_revoked(entries):
    result = []
    for entry in entries or []:
        serial = _parse_serial(entry.get("serial_number", entry.get("serial")))
        reason = entry.get("reason")
        result.append((serial, reason))
    return sorted(result)


def _build_crl(params):
    now = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(_subject(params["issuer_ordered"]))
        .last_update(now)
        .next_update(now + _dt.timedelta(days=int(params["next_update_days"])))
    )
    for entry in params["revoked_certificates"] or []:
        revoked = (
            x509.RevokedCertificateBuilder()
            .serial_number(_parse_serial(entry.get("serial_number", entry.get("serial"))))
            .revocation_date(_parse_revocation_date(entry.get("revocation_date")))
        )
        if entry.get("reason"):
            reason = REASON_FLAGS[str(entry["reason"])]
            revoked = revoked.add_extension(x509.CRLReason(reason), critical=False)
        builder = builder.add_revoked_certificate(revoked.build())
    return builder.sign(private_key=_load_key(params["privatekey_path"], params["privatekey_passphrase"]), algorithm=_digest(params["digest"]))


def _ca_passphrase(params: dict, name: str) -> str:
    passphrases = params.get("ca_passphrases") or {}
    value = passphrases.get(name)
    if value is None or str(value) == "":
        raise ValueError(f"Missing CA passphrase for {name}")
    return str(value)


def _with_derived_paths(params: dict) -> dict:
    result = dict(params)
    base_dir = str(result["base_dir"]).rstrip("/")
    name = str(result["name"])
    result["path"] = (
        f"{base_dir}/crl/{name}-ca.crl"
        if result["format"] == "der"
        else f"{base_dir}/crl/{name}-ca.crl.pem"
    )
    result["privatekey_path"] = f"{base_dir}/private/{name}-ca.key"
    result["privatekey_passphrase"] = _ca_passphrase(result, name)
    return result


def run_module():
    module = AnsibleModule(
        argument_spec={
            "base_dir": {"type": "path", "required": True},
            "name": {"type": "str", "required": True},
            "format": {"type": "str", "choices": ["pem", "der"], "default": "pem"},
            "ca_passphrases": {"type": "dict", "default": {}, "no_log": True},
            "issuer_ordered": {"type": "list", "elements": "dict", "required": True},
            "next_update_days": {"type": "int", "required": True},
            "revoked_certificates": {"type": "list", "elements": "dict", "default": []},
            "digest": {"type": "str", "default": "sha256"},
            "owner": {"type": "str"},
            "group": {"type": "str"},
            "mode": {"type": "str", "default": "0644"},
            "force": {"type": "bool", "default": False},
        },
        supports_check_mode=False,
    )

    if CRYPTOGRAPHY_IMPORT_ERROR is not None:
        module.fail_json(msg=f"Failed to import cryptography: {CRYPTOGRAPHY_IMPORT_ERROR}")

    params = _with_derived_paths(module.params)
    try:
        crl = _build_crl(params)
        changed = params["force"] or not os.path.exists(params["path"])
        if not changed:
            try:
                existing = _load_crl(params["path"])
                changed = existing.issuer != _subject(params["issuer_ordered"]) or _revoked_signature(existing) != _desired_revoked(params["revoked_certificates"])
            except Exception:
                changed = True
        encoding = serialization.Encoding.DER if params["format"] == "der" else serialization.Encoding.PEM
        content = crl.public_bytes(encoding) if changed else Path(params["path"]).read_bytes()
        changed = _write_file(params["path"], content, params["owner"], params["group"], params["mode"]) or changed
    except Exception as exc:
        module.fail_json(msg=str(exc))
    module.exit_json(changed=changed)


def main():
    run_module()


if __name__ == "__main__":
    main()
