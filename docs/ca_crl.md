# ca_crl

Manage one CA certificate revocation list.

`ca_crl` creates PEM and DER CRL exports from one shared CRL object for a CA
authority and records CRL and revocation state in the internal CA inventory.

Serial parsing and timestamp normalization are delegated to the internal
`ca_serial` and `ca_time` helpers.

## Behavior

- Reads the CA private key from `<base_dir>/private/<name>-ca.key`.
- Builds the CRL issuer subject from `subject` and `common_name`.
- Writes PEM CRLs to `<base_dir>/crl/<name>-ca.crl.pem`.
- Writes DER CRLs to `<base_dir>/crl/<name>-ca.crl`.
- PEM and DER are exports of the same generated CRL object, so they share CRL
  Number, AKI, `lastUpdate`, `nextUpdate`, and revoked entries.
- Rewrites the CRL when the issuer, digest, next update, or revoked serial list
  differs, when CRL Number or AKI is missing or inconsistent, when the existing
  CRL is expired, or when `force: true` is set.
- The default signature digest is `sha384`.
- Adds CRL Number and Authority Key Identifier extensions.
- Supports CRL Reason and Invalidity Date revoked-certificate extensions.
- Resolves revocations by certificate name or fingerprint through CA inventory
  state.
- Revocation events are recorded as inventory fragments.

## Parameters

At role level, users normally declare revocations with `ca_revocations`, keyed
by issuing authority name. The role passes `ca_revocations[<authority>]` to this
module as `revoked_certificates`.

| Parameter | Type | Required | Default | Allowed values | Secret | Description |
| --- | --- | --- | --- | --- | --- | --- |
| `base_dir` | path | yes | none | any absolute or relative path | no | Base CA directory. |
| `base_url` | str | no | `""` | any URL prefix | no | Stored in composed inventory when `ca_name` is set. |
| `ca_name` | str | no | `""` | any string | no | Enables composed inventory output when non-empty. |
| `name` | str | yes | none | authority name | no | CA authority short name. |
| `formats` | list[str] | no | `["pem", "der"]` | `pem`, `der` | no | CRL output formats written from one generated CRL object. |
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

Each `revoked_certificates` item accepts one certificate selector:

| Key | Type | Required | Default | Allowed values | Description |
| --- | --- | --- | --- | --- | --- |
| `name` | str | conditional | none | managed certificate name | Current certificate name resolved through CA inventory. |
| `certificate_name` | str | conditional | none | managed certificate name | Alias for `name`. |
| `certificate` | str | conditional | none | managed certificate name | Alias for `name`. |
| `fingerprint` | str | conditional | none | SHA-1 or SHA-256 hex, optionally prefixed with `sha1:` or `sha256:` | Certificate fingerprint resolved through CA inventory. |
| `sha1` | str | conditional | none | SHA-1 hex | SHA-1 certificate fingerprint. |
| `sha256` | str | conditional | none | SHA-256 hex | SHA-256 certificate fingerprint. |
| `serial` | int/str | conditional | none | decimal, `0x` hex, or colon-separated hex | Certificate serial number. |
| `serial_number` | int/str | conditional | none | decimal, `0x` hex, or colon-separated hex | Certificate serial number. |

Each item also accepts:

| Key | Type | Required | Default | Allowed values | Description |
| --- | --- | --- | --- | --- | --- |
| `revocation_date` | str | no | current UTC time | ISO-8601 or `YYYYMMDDHHMMSSZ` | Revocation timestamp. |
| `reason` | str | no | none | see reason list | CRL reason extension. |
| `invalidity_date` | str | no | none | ISO-8601 or `YYYYMMDDHHMMSSZ` | Invalidity Date extension. |

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

- `/etc/pki/example/crl/component-ca.crl.pem` when `pem` is requested
- `/etc/pki/example/crl/component-ca.crl` when `der` is requested
- `/etc/pki/example/inventory/state/crls/component/<format>.json`
- `/etc/pki/example/inventory/state/revocations/component/<serial>.json`
- `/etc/pki/example/inventory/ca-inventory.json` when `ca_name` is set

## Return Values

| Name | Type | Description |
| --- | --- | --- |
| `changed` | bool | Whether the CRL or inventory state changed. |
| `inventory_changed` | bool | Whether inventory state changed. |
| `formats` | list[str] | Written formats. |
| `paths` | dict | Output paths keyed by format. |
| `crl_number` | int | CRL Number extension value. |

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

Create PEM and DER CRLs with one revoked certificate by name:

```yaml
- name: Create component CA CRLs
  ca_crl:
    base_dir: /etc/pki/example
    ca_name: example
    name: component
    formats:
      - pem
      - der
    common_name: Example Component CA
    next_update_days: 7
    key_passphrase: "{{ ca_component_passphrase }}"
    revoked_certificates:
      - name: web01
        reason: key_compromise
        invalidity_date: "2026-06-14T00:00:00Z"
```

Revoke by SHA-256 fingerprint:

```yaml
- name: Create component CA CRLs with fingerprint revocation
  ca_crl:
    base_dir: /etc/pki/example
    ca_name: example
    name: component
    common_name: Example Component CA
    next_update_days: 7
    key_passphrase: "{{ ca_component_passphrase }}"
    revoked_certificates:
      - sha256: "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
        reason: superseded
```
