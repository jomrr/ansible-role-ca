#!/usr/bin/python
"""Manage CA role PKCS#12 bundles."""

from __future__ import annotations

import grp
import os
import pwd
from pathlib import Path

from ansible.module_utils.basic import AnsibleModule

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.serialization import pkcs12
except Exception as exc:  # pragma: no cover
    CRYPTOGRAPHY_IMPORT_ERROR = exc
else:
    CRYPTOGRAPHY_IMPORT_ERROR = None


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
    tmp_path = f"{path}.ansible_tmp"
    Path(tmp_path).write_bytes(content)
    os.replace(tmp_path, path)
    return True | _set_attrs(path, owner, group, mode)


def _load_key(path: str, passphrase: str | None):
    return serialization.load_pem_private_key(
        Path(path).read_bytes(),
        password=passphrase.encode() if passphrase else None,
    )


def _load_certificates(path: str):
    data = Path(path).read_bytes()
    certs = []
    marker = b"-----END CERTIFICATE-----"
    if marker in data:
        chunks = data.split(marker)
        for chunk in chunks:
            if b"-----BEGIN CERTIFICATE-----" in chunk:
                certs.append(x509.load_pem_x509_certificate(chunk + marker + b"\n"))
    else:
        certs.append(x509.load_der_x509_certificate(data))
    return certs


def _public_key_bytes(key_or_cert) -> bytes:
    key = key_or_cert.public_key() if hasattr(key_or_cert, "public_key") else key_or_cert
    return key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _cert_fingerprint(cert):
    return cert.fingerprint(hashes.SHA256())


def _existing_matches(path, passphrase, key, cert, extra_certs):
    try:
        existing_key, existing_cert, existing_extra = pkcs12.load_key_and_certificates(
            Path(path).read_bytes(),
            passphrase.encode() if passphrase else None,
        )
    except Exception:
        return False
    if existing_key is None or existing_cert is None:
        return False
    if _public_key_bytes(existing_key) != _public_key_bytes(key.public_key()):
        return False
    if _cert_fingerprint(existing_cert) != _cert_fingerprint(cert):
        return False
    existing_fingerprints = sorted(_cert_fingerprint(item) for item in (existing_extra or []))
    desired_fingerprints = sorted(_cert_fingerprint(item) for item in extra_certs)
    return existing_fingerprints == desired_fingerprints


def run_module():
    module = AnsibleModule(
        argument_spec={
            "path": {"type": "path", "required": True},
            "friendly_name": {"type": "str", "required": True},
            "privatekey_path": {"type": "path", "required": True},
            "privatekey_passphrase": {"type": "str", "no_log": True},
            "certificate_path": {"type": "path", "required": True},
            "other_certificates": {"type": "list", "elements": "path", "default": []},
            "passphrase": {"type": "str", "required": True, "no_log": True},
            "owner": {"type": "str"},
            "group": {"type": "str"},
            "mode": {"type": "str", "default": "0600"},
            "force": {"type": "bool", "default": False},
        },
        supports_check_mode=False,
    )

    if CRYPTOGRAPHY_IMPORT_ERROR is not None:
        module.fail_json(msg=f"Failed to import cryptography: {CRYPTOGRAPHY_IMPORT_ERROR}")

    params = module.params
    try:
        key = _load_key(params["privatekey_path"], params["privatekey_passphrase"])
        cert = _load_certificates(params["certificate_path"])[0]
        extra_certs = []
        for path in params["other_certificates"]:
            extra_certs.extend(_load_certificates(path))
        changed = params["force"] or not os.path.exists(params["path"])
        if not changed:
            changed = not _existing_matches(params["path"], params["passphrase"], key, cert, extra_certs)
        if changed:
            content = pkcs12.serialize_key_and_certificates(
                name=params["friendly_name"].encode(),
                key=key,
                cert=cert,
                cas=extra_certs,
                encryption_algorithm=serialization.BestAvailableEncryption(params["passphrase"].encode()),
            )
            changed = _write_file(params["path"], content, params["owner"], params["group"], params["mode"])
        else:
            changed = _set_attrs(params["path"], params["owner"], params["group"], params["mode"])
    except Exception as exc:
        module.fail_json(msg=str(exc))
    module.exit_json(changed=changed)


def main():
    run_module()


if __name__ == "__main__":
    main()
