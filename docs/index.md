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
3. `ca_crl` creates CRLs for every CA.
4. `ca_certificate` dispatches declarative certificate entries to the built-in
   certificate profiles.
5. `ca_pkcs12_bundle`, `ca_fullchain_bundle`, and `ca_fritzbox_bundle` create
   optional certificate export bundles.
6. `ca_fritzbox_deploy` can deploy a generated FritzBox bundle to FRITZ!OS.
7. `ca_dhparam` optionally creates a DH parameter file.

`ca_authority`, `ca_certificate`, and `ca_crl` update internal CA inventory
fragments. When `ca_name` is set, the fragments are composed into
`<base_dir>/inventory/ca-inventory.json`.

## Public Modules

- [ca_authority](ca_authority.md)
- [ca_chain](ca_chain.md)
- [ca_certificate](ca_certificate.md)
- [ca_crl](ca_crl.md)
- [ca_pkcs12_bundle](ca_pkcs12_bundle.md)
- [ca_fullchain_bundle](ca_fullchain_bundle.md)
- [ca_fritzbox_bundle](ca_fritzbox_bundle.md)
- [ca_fritzbox_deploy](ca_fritzbox_deploy.md)
- [ca_dhparam](ca_dhparam.md)

## Internal Helpers

These files are not user-facing Ansible modules. They are documented because
their behavior affects the public module interface, generated files, locking,
inventory state, and validation.

- [ca_file](ca_file.md)
- [ca_inventory](ca_inventory.md)
- [ca_profiles](ca_profiles.md)
- [ca_text](ca_text.md)
- [ca_x509](ca_x509.md)
- [filter_plugins/ca.py](filter_plugins_ca.md)

## Common Behavior

All certificate-generating modules use Python `cryptography` instead of the
OpenSSL command line. Ed25519 and Ed448 signatures use the EdDSA-required
digest-free signing mode; RSA and ECDSA default to `sha384`.

File-producing modules are idempotent. They compare existing files with the
desired content and only rewrite when the content or file attributes differ, or
when `force: true` is set.

Managed writes use atomic temporary files and advisory locks below
`<base_dir>/.locks`. Lock names are scoped by object type and name, so unrelated
certificates can still be processed in parallel.

Secret-looking values are masked from module error messages. Parameters marked
as secret in the argument spec also use `no_log: true`.

All public modules currently use `supports_check_mode: false`.

## Derived Path Layout

| Artifact | Authority path | Certificate path |
| --- | --- | --- |
| Private key | `<base_dir>/private/<name>-ca.key` | `<output_dir>/<name>.key` |
| CSR | `<base_dir>/csr/<name>-ca.csr` | `<base_dir>/csr/<name>.csr` |
| PEM certificate | `<base_dir>/ca/<name>-ca.pem` | `<output_dir>/<name>.pem` |
| DER certificate | `<base_dir>/ca/<name>-ca.der` | `<output_dir>/<name>.der` |
| Text certificate | `<base_dir>/ca/<name>-ca.txt` | `<output_dir>/<name>.txt` |
| CA chain | `<base_dir>/chains/<name>-ca-chain.pem` for issuing CAs | copied to `<output_dir>/<name>-chain.pem` |
| Fullchain bundle | none | `<output_dir>/<name>-fullchain.pem` |
| FritzBox bundle | none | `<output_dir>/<name>-fritzbox.pem` |
| CRL PEM | `<base_dir>/crl/<name>-ca.crl.pem` | none |
| CRL DER | `<base_dir>/crl/<name>-ca.crl` | none |
| Inventory | `<base_dir>/inventory/ca-inventory.json` | `<base_dir>/inventory/ca-inventory.json` |

For certificates, `output_dir` defaults to `<base_dir>/certs/<name>`.

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

- `sha1`
- `sha224`
- `sha256`
- `sha384`
- `sha512`

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

