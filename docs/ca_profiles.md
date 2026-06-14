# ca_profiles

Internal certificate profile defaults and validators.

`module_utils/ca_profiles.py` is not an Ansible module. It contains the built-in
certificate profile defaults used by [`ca_certificate`](ca_certificate.md).

## Public Helpers

| Helper | Purpose |
| --- | --- |
| `apply_profile_defaults(params, defaults)` | Applies default key usage, EKU, digest, raw extensions, and DNS SAN behavior without overriding explicit values. |
| `apply_certificate_profile(params, profile)` | Applies one built-in profile and profile-specific validation. |

## Profile Defaults

| Profile | Formats | Digest | Key Usage | Extended Key Usage | Extra behavior |
| --- | --- | --- | --- | --- | --- |
| `tls_server` | `pem`, `der`, `txt` | `sha384` | `digitalSignature`, `keyEncipherment` | `serverAuth` | Adds `DNS:<common_name>` if no DNS SAN exists. |
| `tls_client` | `pem`, `der`, `txt` | `sha384` | `digitalSignature`, `keyEncipherment` | `clientAuth` | none |
| `eap_tls_client` | `pem`, `der`, `txt` | `sha384` | `digitalSignature`, `keyEncipherment` | `clientAuth` | none |
| `identity` | `pem`, `der`, `txt`, `pfx` | `sha384` | `digitalSignature`, `keyEncipherment`, `nonRepudiation` | `clientAuth`, `emailProtection`, `1.3.6.1.4.1.311.20.2.2` | Smartcard logon and S/MIME. |
| `identity_full` | `pem`, `der`, `txt`, `pfx` | `sha384` | `digitalSignature`, `keyEncipherment`, `nonRepudiation` | `clientAuth`, `emailProtection`, `codeSigning`, `1.3.6.1.4.1.311.20.2.2` | Smartcard logon, S/MIME, and code signing. |
| `mskdc` | `pem`, `der`, `txt` | `sha384` | `digitalSignature`, `keyEncipherment` | `serverAuth`, `clientAuth`, `1.3.6.1.5.2.3.5` | Adds DNS SAN, KRB5PrincipalName SAN, NTDS objectGUID, and DomainController template extension. |
| `fritzbox` | `pem`, `der`, `txt`, `fritzbox` | `sha384` | `digitalSignature`, `keyEncipherment` | `serverAuth`, `clientAuth` | Adds DNS SAN and rejects digests stronger than `sha384`. |

## MSKDC Extensions

The `mskdc` profile adds:

- SAN `otherName:1.3.6.1.5.2.2;SEQUENCE:<internal-name>` for
  KRB5PrincipalName.
- Raw extension `1.3.6.1.4.1.311.25.1` containing the AD objectGUID as an
  OCTET STRING in directory byte order.
- Raw extension `1.3.6.1.4.1.311.20.2` containing BMPString
  `DomainController`.
- EKU OID `1.3.6.1.5.2.3.5` for KDC Authentication.

`ad_object_guid` may be canonical GUID syntax or raw 16-byte hexadecimal text.
`krb5_realm` must match `^[A-Z0-9][A-Z0-9._-]*$`.

## Defaults And Constants

| Name | Value |
| --- | --- |
| `CERTIFICATE_DEFAULT_FORMATS` | per-profile format map above |
| `CERTIFICATE_PROFILE_DEFAULTS` | per-profile extension defaults above |
| `FRITZBOX_DIGESTS` | `sha1`, `sha224`, `sha256`, `sha384` |

## Internal Example

```python
params = apply_certificate_profile(params, model["type"])
```

## Used By

- `ca_certificate`

