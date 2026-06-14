# ca_authority

Manage one CA authority certificate.

`ca_authority` creates the private key, CSR, PEM certificate, optional DER and
text exports, and CA inventory state for a root or issuing CA.

## Behavior

- `parent` defaults to `name`.
- `parent == name` creates a self-signed root CA.
- `parent != name` creates an issuing CA signed by the parent CA.
- Root CA defaults: `basic_constraints: ["CA:TRUE", "pathlen:1"]`.
- Issuing CA defaults: `basic_constraints: ["CA:TRUE", "pathlen:0"]`.
- Both authority types default `key_usage` to `["keyCertSign", "cRLSign"]`.
- The default signature digest is `sha384`.
- `key_passphrase` is required and is only used in memory by the module.
- `parent_key_passphrase` is required for issuing CAs.
- AIA and CDP URLs are added when `base_url`, `aia_base_url`, or
  `cdp_base_url` are set.
- PEM is always the canonical certificate format. `der` and `txt` add exports.

## Parameters

| Parameter | Type | Required | Default | Allowed values | Secret | Description |
| --- | --- | --- | --- | --- | --- | --- |
| `base_dir` | path | yes | none | any absolute or relative path | no | Base directory for CA artifacts. |
| `base_url` | str | no | `""` | any URL prefix | no | Base publication URL. If set, AIA defaults to `<base_url>/aia/<name>-ca.der` and CDP to `<base_url>/crl/<name>-ca.crl`. |
| `ca_name` | str | no | `""` | any string | no | Enables composed inventory output when non-empty. |
| `name` | str | yes | none | safe filename stem | no | Authority short name. |
| `parent` | str | no | `""`, treated as `name` | existing authority name | no | Parent CA name. Same as `name` means self-signed root. |
| `formats` | list[str] | no | `["pem", "der", "txt"]` | `pem`, `der`, `txt` | no | Output formats for the CA certificate. |
| `key_type` | str | no | `RSA` | see [index](index.md#common-value-sets) | no | Private key algorithm. |
| `key_size` | int | no | `4096` | RSA bit size, or `256`/`384` for generic ECDSA | no | Key size or ECDSA curve selector. Ignored for Ed25519 and Ed448. |
| `key_passphrase` | str | yes | none | any string | yes | Passphrase for the generated authority private key. |
| `parent_key_passphrase` | str | conditional | none | any string | yes | Parent CA private key passphrase for issuing CAs. |
| `subject_ordered` | list[dict] | no | `[]` | supported subject keys | no | Full ordered subject override. Takes precedence over `subject`, `common_name`, and `email`. |
| `common_name` | str | conditional | none | any string | no | Common Name. Required unless `subject_ordered` is set. |
| `email` | str | no | none | email address | no | Optional subject `emailAddress`. |
| `subject` | dict | no | `{}` | supported subject keys | no | Subject defaults used with `common_name`. |
| `basic_constraints` | list[str] | no | root or issuing default | `CA:TRUE`, `CA:FALSE`, `pathlen:<n>` | no | Basic Constraints tokens. |
| `key_usage` | list[str] | no | `["keyCertSign", "cRLSign"]` | see below | no | Key Usage tokens. |
| `key_usage_critical` | bool | no | `true` | `true`, `false` | no | Marks Key Usage critical. |
| `extended_key_usage` | list[str] | no | `[]` | EKU names or dotted OIDs | no | Extended Key Usage values. Usually empty for CAs. |
| `extended_key_usage_critical` | bool | no | `false` | `true`, `false` | no | Marks Extended Key Usage critical. |
| `san` | list[str] | no | `[]` | supported SAN syntax | no | Subject Alternative Name entries. |
| `san_critical` | bool | no | `false` | `true`, `false` | no | Marks SAN critical. |
| `aia_base_url` | str | no | `""` | any URL prefix | no | Explicit AIA URL prefix. The module appends `<name>-ca.der`. |
| `cdp_base_url` | str | no | `""` | any URL prefix | no | Explicit CDP URL prefix. The module appends `<name>-ca.crl`. |
| `raw_extensions` | list[dict] | no | `[]` | supported raw extension syntax | no | Additional unrecognized extensions. |
| `pkinit` | dict | no | `{}` | internal PKINIT shape | no | Internal PKINIT context for SAN otherName encoding. |
| `days` | int | yes | none | positive integer | no | Certificate validity in days. |
| `digest` | str | no | `sha384` | `sha1`, `sha224`, `sha256`, `sha384`, `sha512` | no | Signature digest for RSA and ECDSA keys. |
| `include_identifiers` | bool | no | `true` | `true`, `false` | no | Adds SKI and AKI extensions. |
| `owner` | str | no | none | user name or UID | no | Owner for generated files. |
| `group` | str | no | none | group name or GID | no | Group for generated files. |
| `key_mode` | str | no | `0600` | octal mode string | no | Private key file mode. |
| `public_mode` | str | no | `0644` | octal mode string | no | CSR, certificate, DER, text, and inventory file mode. |
| `force` | bool | no | `false` | `true`, `false` | no | Regenerates managed material even if current files match. |

Supported Key Usage values are `digitalSignature`, `nonRepudiation`,
`contentCommitment`, `keyEncipherment`, `dataEncipherment`, `keyAgreement`,
`keyCertSign`, `cRLSign`, `encipherOnly`, and `decipherOnly`.

## Generated Files

For `name: root` and `base_dir: /etc/pki/example`:

- `/etc/pki/example/private/root-ca.key`
- `/etc/pki/example/csr/root-ca.csr`
- `/etc/pki/example/ca/root-ca.pem`
- `/etc/pki/example/ca/root-ca.der` when `der` is requested
- `/etc/pki/example/ca/root-ca.txt` when `txt` is requested
- `/etc/pki/example/inventory/state/authorities/root.json`
- `/etc/pki/example/inventory/ca-inventory.json` when `ca_name` is set

`ca_authority` does not create chain files. Chain generation is handled by
[`ca_chain`](ca_chain.md).

## Return Values

| Name | Type | Description |
| --- | --- | --- |
| `changed` | bool | Whether any generated artifact or inventory state changed. |
| `directory_changed` | bool | Always `false` for authorities. |
| `key_changed` | bool | Whether the private key changed. |
| `csr_changed` | bool | Whether the CSR changed. |
| `cert_changed` | bool | Whether the PEM certificate changed. |
| `der_changed` | bool | Whether the DER export changed. |
| `txt_changed` | bool | Whether the text export changed. |
| `chain_changed` | bool | Always `false` for authorities. |
| `inventory_changed` | bool | Whether CA inventory state changed. |
| `formats` | list[str] | Normalized certificate formats. |
| `csr_path` | str | CSR path. |
| `cert_path` | str | PEM certificate path. |
| `txt_path` | str | Text export path, or empty string. |

## Examples

Create a self-signed root CA:

```yaml
- name: Create root CA
  ca_authority:
    base_dir: /etc/pki/example
    ca_name: example
    base_url: http://pki.example.test
    name: root
    parent: root
    common_name: Example Root CA
    subject:
      country: DE
      organization: Example
      organizational_unit: Example PKI
    days: 3650
    key_passphrase: "{{ ca_root_passphrase }}"
```

Create an issuing CA signed by the root CA:

```yaml
- name: Create component CA
  ca_authority:
    base_dir: /etc/pki/example
    ca_name: example
    base_url: http://pki.example.test
    name: component
    parent: root
    common_name: Example Component CA
    subject:
      country: DE
      organization: Example
      organizational_unit: Example PKI
    days: 1825
    key_passphrase: "{{ ca_component_passphrase }}"
    parent_key_passphrase: "{{ ca_root_passphrase }}"
```

