# CA Role Module Documentation

This directory documents the role-local Ansible modules and internal helpers
shipped with the CA role.

The role implements a managed two-tier CA with declarative authorities,
certificates, chains, CRLs, bundles, FritzBox deployment, and a non-secret CA
inventory state. The public modules live in `library/`; shared implementation
code lives in `module_utils/` and `filter_plugins/`.

## Public Module Flow

The role tasks use the public modules in this order:

1. `ca_authority` creates root and issuing CA certificates.
2. `ca_chain` derives issuing CA chain files from the generated CA certificates.
3. `ca_certificate_batch` dispatches the declarative `ca_certificates` list to
   the built-in certificate profiles and writes all requested certificate export
   formats. Certificate entries can also sign external CSRs with `csr_path` or
   `csr_content`. `ca_certificate` uses the same engine for one certificate.
4. `ca_fritzbox_deploy` can deploy a generated FritzBox bundle to FRITZ!OS.
5. `ca_crl` resolves declared revocations and creates PEM/DER CRL exports for
   every CA.
6. Optional publish tasks use `ca_publish_archive` to build deterministic
   archives and unpack CA certificates, issuing chains, and CRLs to configured
   AIA/CDP target webroots.

`ca_authority`, `ca_certificate_batch`, `ca_certificate`, and `ca_crl` update
internal CA inventory fragments. When `ca_name` is set, the fragments are
composed into `<base_dir>/inventory/ca-inventory.json`.

## Public Modules

- [ca_authority](ca_authority.md)
- [ca_chain](ca_chain.md)
- [ca_certificate](ca_certificate.md)
- [ca_certificate_batch](ca_certificate_batch.md)
- [ca_crl](ca_crl.md)
- [ca_fritzbox_deploy](ca_fritzbox_deploy.md)
- [ca_publish_archive](ca_publish_archive.md)
- [AIA/CDP publishing](publishing.md)

## Internal Helpers

These files are not user-facing Ansible modules. They are documented because
their behavior affects the public module interface, generated files, locking,
inventory state, and validation.

- [ca_file](ca_file.md)
- [ca_certificate_engine](ca_certificate_engine.md)
- [ca_inventory](ca_inventory.md)
- [ca_profiles](ca_profiles.md)
- [ca_renewal](ca_renewal.md)
- [ca_serial](ca_serial.md)
- [ca_text](ca_text.md)
- [ca_time](ca_time.md)
- [ca_validation](ca_validation.md)
- [ca_x509](ca_x509.md)
- [filter_plugins/ca.py](filter_plugins_ca.md)

## Common Behavior

All certificate-generating modules use Python `cryptography` instead of the
OpenSSL command line. Ed25519 and Ed448 signatures use the EdDSA-required
digest-free signing mode; RSA and ECDSA default to `sha384`.

File-producing modules are idempotent. They compare existing files with the
desired content and only rewrite when the content or file attributes differ, or
when `force: true` is set. Certificate renewal should normally use the
`renewal` policy instead of `force`.

Authorities and certificates renew seven days before expiry by default, when
the role runs. Setting `renew_before_days: 0` disables advance renewal. The
policy
also supports warning windows, scheduled renewal, and renewal with a new key:

```yaml
ca_renewal:
  warn_before_days: 30
  renew_before_days: 14
  renew_at: ""
  rekey: false
```

Per-authority and per-certificate `renewal` dictionaries override the global
role defaults. `warn_before_days` only affects inventory state.
`renew_before_days`
and `renew_at` trigger renewal. `rekey: true` replaces the private key when
renewal is due; otherwise the existing key is reused.

Managed writes use atomic temporary files and advisory locks below
`<base_dir>/.locks`. Lock names are scoped by object type and name, so unrelated
certificates can still be processed in parallel. Operations that read signer CA
material also lock the signer authority, so issued certificates and CRLs cannot
mix certificate and key material across concurrent authority renewal. Authority
writes and CA chain generation also use an authority graph lock, so chain files
are built from a consistent CA graph. FritzBox deployments use a per-target URL
lock, so async deploy jobs cannot upload different certificates to the same
device concurrently. Inventory state updates use a shared inventory lock, so
fragment writes and composed inventory writes are committed in one critical
section.

Secret-looking values are masked from module error messages. Parameters marked
as secret in the argument spec also use `no_log: true`.

All public modules currently use `supports_check_mode: false`.

## Derived Path Layout

- **Private key**
  Authority path: `<base_dir>/private/<name>-ca.key`; Certificate path:
  `<output_dir>/<name>.key`

- **CSR**
  Authority path: `<base_dir>/csr/<name>-ca.csr`; Certificate path:
  `<base_dir>/csr/<name>.csr`

- **PEM certificate**
  Authority path: `<base_dir>/ca/<name>-ca.pem`; Certificate path:
  `<output_dir>/<name>.pem`

- **DER certificate**
  Authority path: `<base_dir>/ca/<name>-ca.der`; Certificate path:
  `<output_dir>/<name>.der`

- **Text certificate**
  Authority path: `<base_dir>/ca/<name>-ca.txt`; Certificate path:
  `<output_dir>/<name>.txt`

- **CA chain**
  Authority path: `<base_dir>/chains/<name>-ca-chain.{pem,der,txt}` for issuing
  CAs; Certificate path: copied to `<output_dir>/<name>-chain.pem`

- **Versioned CA chain**
  Authority path: `<base_dir>/chains/<name>-ca-chain-<serial>.{pem,der,txt}` for
  issuing CAs; Certificate path: none

- **Fullchain bundle**
  Authority path: none; Certificate path: `<output_dir>/<name>-fullchain.pem`

- **FritzBox bundle**
  Authority path: none; Certificate path: `<output_dir>/<name>-fritzbox.pem`

- **CRL PEM**
  Authority path: `<base_dir>/crl/<name>-ca.crl.pem`; Certificate path: none

- **CRL DER**
  Authority path: `<base_dir>/crl/<name>-ca.crl`; Certificate path: none

- **Inventory**
  Authority path: `<base_dir>/inventory/ca-inventory.json`; Certificate path:
  `<base_dir>/inventory/ca-inventory.json`

- **Archive**
  Authority path: `<base_dir>/archive/authorities/<name>/<serial>/...`;
  Certificate path: `<base_dir>/archive/certificates/<name>/<serial>/...`

For certificates, `output_dir` defaults to `<base_dir>/certs/<name>`.
CSR-signed certificates do not create `<output_dir>/<name>.key`; the CSR subject
and public key are used instead.

## Common Value Sets

Supported certificate formats:

- `pem`
- `der`
- `txt`
- `pfx`
- `p12`
- `fullchain`
- `fritzbox`

Supported key type aliases:

- `RSA`
- `ECDSA`
- `P-256`
- `P-384`
- `EC`
- `P256`
- `P384`
- `ECDSA_P256`
- `ECDSA_P384`
- `prime256v1`
- `secp256r1`
- `secp384r1`
- `Ed25519`
- `Ed448`

Supported RSA and ECDSA digests:

- `sha224`
- `sha256`
- `sha384`
- `sha512`

SHA-1 is explicitly rejected for all signature requests, including EdDSA.
Allowed `digest` values do not change EdDSA signatures. Signature hashes are
independent of inventory fingerprints and revocation selectors.

Supported subject keys:

- `C`, `countryName`, `country`
- `ST`, `stateOrProvinceName`, `state`
- `L`, `localityName`, `locality`
- `O`, `organizationName`, `organization`
- `OU`, `organizationalUnitName`, `organizational_unit`
- `CN`, `commonName`, `common_name`
- `emailAddress`, `email`

Supported SAN syntaxes:

- `DNS:<name>`
- `IP:<address>`
- `email:<address>`
- `URI:<uri>`
- `RID:<oid>`
- `otherName:<oid>;UTF8:<value>`
- `otherName:<oid>;SEQUENCE:<name>` for the internal MSKDC PKINIT encoder

Supported raw extension syntaxes:

- `ASN1:BMPSTRING:<value>`
- `ASN1:UTF8String:<value>`
- `ASN1:FORMAT:HEX,OCTETSTRING:<hex>`
- `DER:<hex>`

## Revocation Workflow

Revocations are declared with the role variable `ca_revocations`, keyed by
issuing authority name:

```yaml
ca_revocations:
  component:
    - name: web01
      reason: key_compromise
      invalidity_date: "2026-06-14T00:00:00Z"
  network: []
```

Missing authority keys mean that no certificate is revoked for that authority.
Keys must match names from `ca_authorities`.

The role passes the selected authority list to `ca_crl` as
`revoked_certificates`. Revocations are resolved by `ca_crl` when CRLs are
generated. A revocation entry can identify a certificate by:

- `name`, `certificate`, or `certificate_name`
- `fingerprint`, optionally prefixed with `sha1:` or `sha256:`
- `sha1`
- `sha256`
- `serial` or `serial_number`

Name and fingerprint selectors are resolved through the internal CA inventory.
The resolved serial number is written into CRLs and revocation inventory state.
Name selectors bind to that first generation; revoke a replacement by its serial
or fingerprint. Recorded revocations remain in later CRLs even if an input entry
is removed, and an omitted revocation date preserves the original recorded time.

Each revocation can also set:

- `reason`
- `revocation_date`
- `invalidity_date`

PEM and DER CRL files are exported from one generated CRL object, so they have
the same CRL Number, Authority Key Identifier, timestamps, signature, and
revoked certificate entries.
