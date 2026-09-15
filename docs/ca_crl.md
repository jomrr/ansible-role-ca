# ca_crl

Manage one CA certificate revocation list.

`ca_crl` creates PEM and DER CRL exports from one shared CRL object for a CA
authority and records CRL and revocation state in the internal CA inventory.

Serial parsing and timestamp normalization are delegated to the internal
`ca_serial` and `ca_time` helpers.

## Behavior

- Reads the CA private key from `<base_dir>/private/<name>-ca.key`.
- Builds the CRL issuer subject from `subject` and `common_name`.
- Defaults to writing both `pem` and `der` CRL formats when `formats` is not
  supplied.
- Writes PEM CRLs to `<base_dir>/crl/<name>-ca.crl.pem`.
- Writes DER CRLs to `<base_dir>/crl/<name>-ca.crl`.
- PEM and DER are exports of the same generated CRL object, so they share CRL
  Number, AKI, `lastUpdate`, `nextUpdate`, and revoked entries.
- Rewrites the CRL when the issuer, digest, next update, or revoked serial list
  differs, when CRL Number or AKI is missing or inconsistent, when the existing
  CRL enters its renewal window, or when `force: true` is set.
- CRLs renew seven days before nextUpdate by default. `renew_before_days` may be
  fractional, must be nonnegative, and must be less than `next_update_days`.
- CRL sequence numbers are persisted before export in
  `inventory/state/crl_numbers/<name>.json`, independently of PEM and DER
  exports. Corrupt counter state fails instead of resetting the sequence.
- The default signature digest is `sha384`; SHA-1 signatures are forbidden.
- Adds CRL Number and Authority Key Identifier extensions.
- Supports CRL Reason and Invalidity Date revoked-certificate extensions.
- Resolves revocations by certificate name or fingerprint through CA inventory
  state.
- Revocation events are recorded by issuer and serial before exporting the CRL.
  They remain in later CRLs even when their declarations are removed.
- A name selector binds to its first revoked generation. A reissued certificate
  is not automatically revoked; select its serial or fingerprint to revoke it.
- An omitted revocation date retains the first recorded revocation time.

## Parameters

At role level, users normally declare revocations with `ca_revocations`, keyed
by issuing authority name. The role passes `ca_revocations[<authority>]` to this
module as `revoked_certificates`.

- **`base_dir`**: Base CA directory.
  Type: path; Required: yes; Default: none; Allowed values: any absolute or
  relative path; Secret: no

- **`base_url`**: Stored in composed inventory when `ca_name` is set.
  Type: str; Required: no; Default: `""`; Allowed values: any URL prefix;
  Secret: no

- **`ca_name`**: Enables composed inventory output when non-empty.
  Type: str; Required: no; Default: `""`; Allowed values: any string; Secret: no

- **`name`**: CA authority short name.
  Type: str; Required: yes; Default: none; Allowed values: authority name;
  Secret: no

- **`formats`**: CRL output formats written from one generated CRL object.
  Type: list[str]; Required: no; Default: `["pem", "der"]`; Allowed values:
  `pem`, `der`; Secret: no

- **`key_passphrase`**: Passphrase for the CA private key.
  Type: str; Required: yes; Default: none; Allowed values: any string; Secret:
  yes

- **`common_name`**: CA subject Common Name.
  Type: str; Required: yes; Default: none; Allowed values: any string; Secret:
  no

- **`subject`**: Subject defaults for the CRL issuer name.
  Type: dict; Required: no; Default: `{}`; Allowed values: supported subject
  keys; Secret: no

- **`next_update_days`**: Number of days until CRL `nextUpdate`.
  Type: int; Required: yes; Default: none; Allowed values: positive integer;
  Secret: no

- **`renew_before_days`**: Renew before expiry; role default is
  `ca_crl_renew_before_days`, with per-authority `crl_renew_before_days`
  overrides.
  Type: float; Required: no; Default: `7`; Allowed values: nonnegative, less
  than `next_update_days`; Secret: no

- **`revoked_certificates`**: Declarative revoked certificate entries.
  Type: list[dict]; Required: no; Default: `[]`; Allowed values: see below;
  Secret: no

- **`digest`**: Signature digest for RSA and ECDSA CA keys.
  Type: str; Required: no; Default: `sha384`; Allowed values: `sha224`, `sha256`,
  `sha384`, `sha512`; Secret: no

- **`owner`**: Owner for the CRL and inventory files.
  Type: str; Required: no; Default: none; Allowed values: user name or UID;
  Secret: no

- **`group`**: Group for the CRL and inventory files.
  Type: str; Required: no; Default: none; Allowed values: group name or GID;
  Secret: no

- **`mode`**: CRL file mode.
  Type: str; Required: no; Default: `0644`; Allowed values: octal mode string;
  Secret: no

- **`force`**: Rewrites the CRL even if current content matches.
  Type: bool; Required: no; Default: `false`; Allowed values: `true`, `false`;
  Secret: no

Each `revoked_certificates` item accepts one certificate selector:

- **`name`**: Current certificate name resolved through CA inventory.
  Type: str; Required: conditional; Default: none; Allowed values: managed
  certificate name

- **`certificate_name`**: Alias for `name`.
  Type: str; Required: conditional; Default: none; Allowed values: managed
  certificate name

- **`certificate`**: Alias for `name`.
  Type: str; Required: conditional; Default: none; Allowed values: managed
  certificate name

- **`fingerprint`**: Certificate fingerprint resolved through CA inventory.
  Type: str; Required: conditional; Default: none; Allowed values: SHA-1 or
  SHA-256 hex, optionally prefixed with `sha1:` or `sha256:`

- **`sha1`**: SHA-1 certificate fingerprint.
  Type: str; Required: conditional; Default: none; Allowed values: SHA-1 hex

- **`sha256`**: SHA-256 certificate fingerprint.
  Type: str; Required: conditional; Default: none; Allowed values: SHA-256 hex

- **`serial`**: Certificate serial number.
  Type: int/str; Required: conditional; Default: none; Allowed values: decimal,
  `0x` hex, or colon-separated hex

- **`serial_number`**: Certificate serial number.
  Type: int/str; Required: conditional; Default: none; Allowed values: decimal,
  `0x` hex, or colon-separated hex

Each item also accepts:

- **`revocation_date`**: Revocation timestamp.
  Type: str; Required: no; Default: current UTC time; Allowed values: ISO-8601
  or `YYYYMMDDHHMMSSZ`

- **`reason`**: CRL reason extension.
  Type: str; Required: no; Default: none; Allowed values: see reason list

- **`invalidity_date`**: Invalidity Date extension.
  Type: str; Required: no; Default: none; Allowed values: ISO-8601 or
  `YYYYMMDDHHMMSSZ`

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
- `/etc/pki/example/inventory/state/crl_numbers/component.json`
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
    renew_before_days: 1
    key_passphrase: "{{ ca_component_passphrase }}"
```

Create default PEM and DER CRLs with one revoked certificate by name:

```yaml
- name: Create component CA CRLs
  ca_crl:
    base_dir: /etc/pki/example
    ca_name: example
    name: component
    common_name: Example Component CA
    next_update_days: 7
    renew_before_days: 1
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
    renew_before_days: 1
    key_passphrase: "{{ ca_component_passphrase }}"
    revoked_certificates:
      - sha256: "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
        reason: superseded
```
