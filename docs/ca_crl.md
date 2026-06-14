# ca_crl

Manage one CA certificate revocation list.

`ca_crl` creates PEM or DER CRLs for a CA authority and records CRL and
revocation state in the internal CA inventory.

## Behavior

- Reads the CA private key from `<base_dir>/private/<name>-ca.key`.
- Builds the CRL issuer subject from `subject` and `common_name`.
- Writes PEM CRLs to `<base_dir>/crl/<name>-ca.crl.pem`.
- Writes DER CRLs to `<base_dir>/crl/<name>-ca.crl`.
- Rewrites the CRL when the issuer, digest, next update, or revoked serial list
  differs, when the existing CRL is expired, or when `force: true` is set.
- The default signature digest is `sha384`.
- Revocation events are recorded as inventory fragments.

## Parameters

| Parameter | Type | Required | Default | Allowed values | Secret | Description |
| --- | --- | --- | --- | --- | --- | --- |
| `base_dir` | path | yes | none | any absolute or relative path | no | Base CA directory. |
| `base_url` | str | no | `""` | any URL prefix | no | Stored in composed inventory when `ca_name` is set. |
| `ca_name` | str | no | `""` | any string | no | Enables composed inventory output when non-empty. |
| `name` | str | yes | none | authority name | no | CA authority short name. |
| `format` | str | no | `pem` | `pem`, `der` | no | CRL output format. |
| `key_passphrase` | str | yes | none | any string | yes | Passphrase for the CA private key. |
| `common_name` | str | yes | none | any string | no | CA subject Common Name. |
| `subject` | dict | no | `{}` | supported subject keys | no | Subject defaults for the CRL issuer name. |
| `next_update_days` | int | yes | none | positive integer | no | Number of days until CRL `nextUpdate`. |
| `revoked_certificates` | list[dict] | no | `[]` | see below | no | Declarative revoked certificate entries. |
| `digest` | str | no | `sha384` | `sha1`, `sha224`, `sha256`, `sha384`, `sha512` | no | Signature digest for RSA and ECDSA CA keys. |
| `owner` | str | no | none | user name or UID | no | Owner for the CRL and inventory files. |
| `group` | str | no | none | group name or GID | no | Group for the CRL and inventory files. |
| `mode` | str | no | `0644` | octal mode string | no | CRL file mode. |
| `force` | bool | no | `false` | `true`, `false` | no | Rewrites the CRL even if current content matches. |

Each `revoked_certificates` item accepts:

| Key | Type | Required | Default | Allowed values | Description |
| --- | --- | --- | --- | --- | --- |
| `serial` | int/str | conditional | none | decimal, `0x` hex, or colon-separated hex | Certificate serial number. Either `serial` or `serial_number` is required. |
| `serial_number` | int/str | conditional | none | decimal, `0x` hex, or colon-separated hex | Certificate serial number. Either `serial` or `serial_number` is required. |
| `revocation_date` | str | no | current UTC time | ISO-8601 or `YYYYMMDDHHMMSSZ` | Revocation timestamp. |
| `reason` | str | no | none | see reason list | CRL reason extension. |

Supported revocation reasons:

- `key_compromise`
- `ca_compromise`
- `affiliation_changed`
- `superseded`
- `cessation_of_operation`
- `certificate_hold`
- `privilege_withdrawn`
- `aa_compromise`

## Generated Files

For `name: component` and `base_dir: /etc/pki/example`:

- `/etc/pki/example/crl/component-ca.crl.pem` for `format: pem`
- `/etc/pki/example/crl/component-ca.crl` for `format: der`
- `/etc/pki/example/inventory/state/crls/component/<format>.json`
- `/etc/pki/example/inventory/state/revocations/component/<serial>.json`
- `/etc/pki/example/inventory/ca-inventory.json` when `ca_name` is set

## Return Values

| Name | Type | Description |
| --- | --- | --- |
| `changed` | bool | Whether the CRL or inventory state changed. |
| `inventory_changed` | bool | Whether inventory state changed. |

## Examples

Create a PEM CRL:

```yaml
- name: Create component CA CRL
  ca_crl:
    base_dir: /etc/pki/example
    ca_name: example
    name: component
    common_name: Example Component CA
    subject:
      country: DE
      organization: Example
      organizational_unit: Example PKI
    next_update_days: 7
    key_passphrase: "{{ ca_component_passphrase }}"
```

Create a DER CRL with one revoked certificate:

```yaml
- name: Create component CA DER CRL
  ca_crl:
    base_dir: /etc/pki/example
    ca_name: example
    name: component
    format: der
    common_name: Example Component CA
    next_update_days: 7
    key_passphrase: "{{ ca_component_passphrase }}"
    revoked_certificates:
      - serial_number: "5C:9A:02"
        reason: key_compromise
        revocation_date: "20260614120000Z"
```

