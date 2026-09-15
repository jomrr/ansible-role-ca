# ca_certificate

Dispatch one declarative role certificate to a built-in certificate profile.

`ca_certificate` is the single-certificate public module. The role tasks use
`ca_certificate_batch` for `ca_certificates`; both modules use the same
certificate engine. This module is useful when a playbook wants to issue one
certificate without invoking the role task loop. It is not a low-level generic
X.509 module.

## Behavior

- Requires `certificate.name`, `certificate.type`, and `certificate.common_name`
  for CA-generated certificates.
- Allows `certificate.csr_path` or `certificate.csr_content` instead of
  `certificate.common_name` when signing an external CSR.
- Validates `certificate.type` against the built-in profiles and the provided
  `certificate_types` map.
- Resolves the issuer and issuer passphrase from `authorities`.
- Uses `certificate.days` when set; otherwise uses issuer `default_days`.
- Merges module-level `subject` defaults with `certificate.subject`.
- Applies profile defaults for formats, key usage, EKU, SAN defaults, digest,
  and raw extensions.
- Creates the output directory.
- Generates or reuses the private key and CSR.
- For external CSR signing, verifies the CSR signature, uses the CSR subject
  and public key, and does not create a private key on the CA host.
- Issues a PEM certificate and optional DER and text exports.
- Copies the issuer chain into the certificate output directory.
- Writes requested PKCS#12, fullchain, and FritzBox bundles directly.
- Renewal policy can mark warning state, renew inside a configured window, or
  renew at a planned timestamp.
- Renewal keeps the existing key by default. Set `renewal.rekey: true` to
  generate a new private key when renewal is due.
- Replaced generations are archived below `<base_dir>/archive/certificates`.
- Records certificate inventory state.

## Certificate Profiles

- **`tls_server`**
  Default formats: `pem`, `der`, `txt`; Key Usage: `digitalSignature`,
  `keyEncipherment`; Extended Key Usage: `serverAuth`; Extra behavior: Adds
  `DNS:<common_name>` when no DNS SAN is set.

- **`tls_client`**
  Default formats: `pem`, `der`, `txt`; Key Usage: `digitalSignature`,
  `keyEncipherment`; Extended Key Usage: `clientAuth`; Extra behavior: Standard
  TLS client certificate.

- **`eap_tls_client`**
  Default formats: `pem`, `der`, `txt`; Key Usage: `digitalSignature`,
  `keyEncipherment`; Extended Key Usage: `clientAuth`; Extra behavior: Network
  EAP-TLS client certificate.

- **`identity`**
  Default formats: `pem`, `der`, `txt`, `pfx`; Key Usage: `digitalSignature`,
  `keyEncipherment`, `nonRepudiation`; Extended Key Usage: `clientAuth`,
  `emailProtection`, `1.3.6.1.4.1.311.20.2.2`; Extra behavior: Smartcard logon
  and S/MIME. Requires `pfx_passphrase` unless formats are overridden without
  `pfx`/`p12`.

- **`identity_full`**
  Default formats: `pem`, `der`, `txt`, `pfx`; Key Usage: `digitalSignature`,
  `keyEncipherment`, `nonRepudiation`; Extended Key Usage: `clientAuth`,
  `emailProtection`, `codeSigning`, `1.3.6.1.4.1.311.20.2.2`; Extra behavior:
  Smartcard logon, S/MIME, and code signing. Requires `pfx_passphrase` unless
  formats are overridden without `pfx`/`p12`.

- **`mskdc`**
  Default formats: `pem`, `der`, `txt`; Key Usage: `digitalSignature`,
  `keyEncipherment`; Extended Key Usage: `serverAuth`, `clientAuth`,
  `1.3.6.1.5.2.3.5`; Extra behavior: Adds DNS SAN, KRB5PrincipalName PKINIT SAN,
  NTDS objectGUID extension, and `DomainController` template extension. Requires
  `ad_object_guid` and `krb5_realm` or module `kerberos_realm`.

- **`fritzbox`**
  Default formats: `pem`, `der`, `txt`, `fritzbox`; Key Usage:
  `digitalSignature`, `keyEncipherment`; Extended Key Usage: `serverAuth`,
  `clientAuth`; Extra behavior: Adds DNS SAN and limits the digest to `sha384`
  or weaker because FRITZ!OS rejects stronger hashes.

All profiles default to `digest: sha384`.

## Module Parameters

- **`base_dir`**: Base CA directory used to locate issuer material and derive
  CSR paths.
  Type: path; Required: yes; Default: none; Allowed values: any absolute or
  relative path; Secret: no

- **`base_url`**: Base publication URL. If set, AIA defaults to
  `<base_url>/aia/<issuer>-ca.der` and CDP to `<base_url>/crl/<issuer>-ca.crl`.
  Type: str; Required: no; Default: `""`; Allowed values: any URL prefix;
  Secret: no

- **`ca_name`**: Enables composed inventory output when non-empty.
  Type: str; Required: no; Default: `""`; Allowed values: any string; Secret: no

- **`certificate`**: Declarative certificate item.
  Type: dict; Required: yes; Default: none; Allowed values: see certificate
  model below; Secret: yes

- **`certificate_types`**: Role type map. The selected type must define `issuer`
  and may define `required_fields`.
  Type: dict; Required: yes; Default: none; Allowed values: map keyed by profile
  type; Secret: no

- **`authorities`**: Authority list used to resolve issuer passphrase and
  `default_days`.
  Type: list[dict]; Required: yes; Default: none; Allowed values: authority
  dictionaries; Secret: yes

- **`kerberos_realm`**: Default realm for MSKDC certificates.
  Type: str; Required: no; Default: `""`; Allowed values: Kerberos realm;
  Secret: no

- **`subject`**: Role-level subject defaults.
  Type: dict; Required: no; Default: `{}`; Allowed values: supported subject
  keys; Secret: no

- **`renewal`**: Module-level renewal policy defaults. Certificate-local
  `renewal` overrides these values.
  Type: dict; Required: no; Default: `{}`; Allowed values: see below; Secret: no

- **`owner`**: Owner for generated files.
  Type: str; Required: no; Default: none; Allowed values: user name or UID;
  Secret: no

- **`group`**: Group for generated files.
  Type: str; Required: no; Default: none; Allowed values: group name or GID;
  Secret: no

- **`force`**: Regenerates managed material even if current files match.
  Type: bool; Required: no; Default: `false`; Allowed values: `true`, `false`;
  Secret: no

## Certificate Model

These keys are accepted inside `certificate`.

- **`name`**: Certificate short name and file stem.
  Type: str; Required: yes; Default: none; Allowed values: letters, digits,
  dots, underscores, hyphens; Secret: no

- **`type`**: Certificate profile.
  Type: str; Required: yes; Default: none; Allowed values: built-in profile
  name; Secret: no

- **`common_name`**: Common Name. Required for CA-generated certificates.
  Optional for CSR-signed certificates; when set, it must match the CSR common
  name.
  Type: str; Required: conditional; Default: none; Allowed values: any string;
  Secret: no

- **`csr_path`**: External CSR to sign. Mutually exclusive with `csr_content`.
  Type: path; Required: no; Default: none; Allowed values: readable PEM CSR path
  on the managed CA host; Secret: no

- **`csr_content`**: Inline external CSR to sign. Mutually exclusive with
  `csr_path`.
  Type: str; Required: no; Default: none; Allowed values: PEM CSR content;
  Secret: no

- **`days`**: Certificate validity.
  Type: int; Required: no; Default: issuer `default_days`; Allowed values:
  positive integer; Secret: no

- **`formats`**: Output and export formats. CSR-signed certificates reject
  `pfx`, `p12`, and `fritzbox`.
  Type: list[str]; Required: no; Default: profile default; Allowed values:
  `pem`, `der`, `txt`, `pfx`, `p12`, `fullchain`, `fritzbox`; Secret: no

- **`output_dir`**: Directory for key, certificate, chain copy, and bundles.
  Type: path; Required: no; Default: `<base_dir>/certs/<name>`; Allowed values:
  any path; Secret: no

- **`key_type`**: Private key algorithm.
  Type: str; Required: no; Default: `RSA`; Allowed values: see
  [index](index.md#common-value-sets); Secret: no

- **`key_size`**: Key size or curve selector.
  Type: int; Required: no; Default: `4096`; Allowed values: RSA bit size, or
  `256`/`384` for generic ECDSA; Secret: no

- **`key_passphrase`**: Optional certificate private key passphrase. Ignored for
  CSR-signed certificates.
  Type: str; Required: no; Default: none; Allowed values: any string; Secret:
  yes

- **`pfx_passphrase`**: Required when `formats` contains `pfx` or `p12`, unless
  `passphrase` is set.
  Type: str; Required: conditional; Default: none; Allowed values: any string;
  Secret: yes

- **`friendly_name`**: Friendly name for PKCS#12 exports.
  Type: str; Required: no; Default: `common_name` or `name`; Allowed values: any
  string; Secret: no

- **`renewal`**: Certificate-local renewal and rekey policy.
  Type: dict; Required: no; Default: module `renewal`; Allowed values: see
  below; Secret: no

- **`subject_ordered`**: Full ordered subject override.
  Type: list[dict]; Required: no; Default: `[]`; Allowed values: supported
  subject keys; Secret: no

- **`email`**: Subject `emailAddress`.
  Type: str; Required: no; Default: none; Allowed values: email address; Secret:
  no

- **`subject`**: Certificate-local subject values merged over module `subject`.
  Type: dict; Required: no; Default: `{}`; Allowed values: supported subject
  keys; Secret: no

- **`key_usage`**: Overrides profile Key Usage when non-empty.
  Type: list[str]; Required: no; Default: profile default; Allowed values:
  supported Key Usage names; Secret: no

- **`key_usage_critical`**: Marks Key Usage critical.
  Type: bool; Required: no; Default: `true`; Allowed values: `true`, `false`;
  Secret: no

- **`extended_key_usage`**: Overrides profile EKU when non-empty.
  Type: list[str]; Required: no; Default: profile default; Allowed values: EKU
  names or dotted OIDs; Secret: no

- **`extended_key_usage_critical`**: Marks EKU critical.
  Type: bool; Required: no; Default: `false`; Allowed values: `true`, `false`;
  Secret: no

- **`san`**: Subject Alternative Names.
  Type: list[str]; Required: no; Default: `[]` plus profile defaults; Allowed
  values: supported SAN syntax; Secret: no

- **`san_critical`**: Marks SAN critical.
  Type: bool; Required: no; Default: `false`; Allowed values: `true`, `false`;
  Secret: no

- **`aia_base_url`**: Explicit AIA URL prefix.
  Type: str; Required: no; Default: `""`; Allowed values: URL prefix; Secret: no

- **`cdp_base_url`**: Explicit CDP URL prefix.
  Type: str; Required: no; Default: `""`; Allowed values: URL prefix; Secret: no

- **`raw_extensions`**: Additional unrecognized extensions.
  Type: list[dict]; Required: no; Default: `[]` plus profile defaults; Allowed
  values: supported raw extension syntax; Secret: no

- **`digest`**: Signature digest for RSA and ECDSA. FritzBox profiles reject
  values stronger than `sha384`.
  Type: str; Required: no; Default: `sha384`; Allowed values: `sha1`, `sha224`,
  `sha256`, `sha384`, `sha512`; Secret: no

- **`include_identifiers`**: Adds SKI and AKI.
  Type: bool; Required: no; Default: `true`; Allowed values: `true`, `false`;
  Secret: no

- **`key_mode`**: Private key file mode.
  Type: str; Required: no; Default: `0600`; Allowed values: octal mode string;
  Secret: no

- **`public_mode`**: CSR, certificate, DER, text, and chain mode.
  Type: str; Required: no; Default: `0644`; Allowed values: octal mode string;
  Secret: no

- **`directory_mode`**: Output directory mode.
  Type: str; Required: no; Default: `0755`; Allowed values: octal mode string;
  Secret: no

- **`ad_object_guid`**: Required for `mskdc`. Encoded as NTDS objectGUID
  extension OID `1.3.6.1.4.1.311.25.1`.
  Type: str; Required: conditional; Default: none; Allowed values: canonical
  GUID or raw 16-byte hex; Secret: no

- **`krb5_realm`**: MSKDC PKINIT realm.
  Type: str; Required: conditional; Default: module `kerberos_realm`; Allowed
  values: uppercase realm; Secret: no

Supported Key Usage values are `digitalSignature`, `nonRepudiation`,
`contentCommitment`, `keyEncipherment`, `dataEncipherment`, `keyAgreement`,
`keyCertSign`, `cRLSign`, `encipherOnly`, and `decipherOnly`.

Supported EKU aliases are `serverAuth`, `clientAuth`, `codeSigning`,
`emailProtection`, `timeStamping`, `OCSPSigning`, and `smartcardLogon`.
Dotted OIDs are accepted for additional EKUs.

### Renewal Policy

- **`warn_before_days`**: Adds warning state to inventory when remaining
  validity is inside this window.
  Type: int; Default: `0`

- **`renew_before_days`**: Renews when remaining validity is inside this window.
  Type: int; Default: `7`

- **`renew_at`**: Planned renewal timestamp as ISO-8601 or `YYYYMMDDHHMMSSZ`. It
  only affects certificates issued before that timestamp.
  Type: str; Default: `""`

- **`rekey`**: Generates a new private key when renewal is due.
  Type: bool; Default: `false`

## Generated Files

For `name: web01`, `issuer: component`, and `base_dir: /etc/pki/example`:

- `/etc/pki/example/certs/web01/web01.key`
- `/etc/pki/example/csr/web01.csr`
- `/etc/pki/example/certs/web01/web01.pem`
- `/etc/pki/example/certs/web01/web01.der` when `der` is requested
- `/etc/pki/example/certs/web01/web01.txt` when `txt` is requested
- `/etc/pki/example/certs/web01/web01-chain.pem`
- `/etc/pki/example/certs/web01/web01.pfx` when `pfx` is requested
- `/etc/pki/example/certs/web01/web01.p12` when `p12` is requested
- `/etc/pki/example/certs/web01/web01-fullchain.pem` when `fullchain` is
  requested
- `/etc/pki/example/certs/web01/web01-fritzbox.pem` when `fritzbox` is requested
- Inventory fragments below `/etc/pki/example/inventory/state`
- `/etc/pki/example/inventory/ca-inventory.json` when `ca_name` is set
- `/etc/pki/example/archive/certificates/web01/<serial>/*` for replaced
  generations

CSR-signed certificates also store a normalized copy of the CSR at
`<base_dir>/csr/<name>.csr`, but do not create `<output_dir>/<name>.key`.

## Return Values

- **`changed`**: Whether any generated artifact or inventory state changed.
  Type: bool

- **`name`**: Certificate name.
  Type: str

- **`profile`**: Resolved certificate profile.
  Type: str

- **`directory_changed`**: Whether the output directory changed.
  Type: bool

- **`archive_changed`**: Whether replaced generation material was archived.
  Type: bool

- **`key_changed`**: Whether the private key changed.
  Type: bool

- **`csr_changed`**: Whether the CSR changed.
  Type: bool

- **`cert_changed`**: Whether the PEM certificate changed.
  Type: bool

- **`der_changed`**: Whether the DER export changed.
  Type: bool

- **`txt_changed`**: Whether the text export changed.
  Type: bool

- **`chain_changed`**: Whether the issuer chain copy changed.
  Type: bool

- **`pkcs12_changed`**: Whether any PKCS#12 export changed.
  Type: bool

- **`fullchain_changed`**: Whether the fullchain bundle changed.
  Type: bool

- **`fritzbox_bundle_changed`**: Whether the FritzBox import bundle changed.
  Type: bool

- **`inventory_changed`**: Whether CA inventory state changed.
  Type: bool

- **`formats`**: Normalized formats.
  Type: list[str]

- **`renewal`**: Renewal decision for this run.
  Type: dict

- **`csr_path`**: CSR path.
  Type: str

- **`cert_path`**: PEM certificate path.
  Type: str

- **`txt_path`**: Text export path, or empty string.
  Type: str

- **`pkcs12_paths`**: Written PKCS#12 paths keyed by format.
  Type: dict

- **`fullchain_path`**: Fullchain bundle path, or empty string.
  Type: str

- **`fritzbox_bundle_path`**: FritzBox import bundle path, or empty string.
  Type: str

## Examples

Issue a TLS server certificate:

```yaml
- name: Issue web certificate
  ca_certificate:
    base_dir: /etc/pki/example
    ca_name: example
    base_url: http://pki.example.test
    certificate:
      name: web01
      type: tls_server
      common_name: web01.example.test
      san:
        - DNS:web01.example.test
        - DNS:web01
    certificate_types:
      tls_server:
        issuer: component
    authorities:
      - name: root
        parent: root
        key_passphrase: "{{ ca_root_passphrase }}"
        default_days: 3650
      - name: component
        parent: root
        key_passphrase: "{{ ca_component_passphrase }}"
        default_days: 397
```

Issue an identity certificate with PKCS#12 export:

```yaml
- name: Issue identity certificate
  ca_certificate:
    base_dir: /etc/pki/example
    ca_name: example
    certificate:
      name: alice
      type: identity
      common_name: Alice Example
      email: alice@example.test
      pfx_passphrase: "{{ alice_pfx_passphrase }}"
    certificate_types:
      identity:
        issuer: identity
    authorities: "{{ ca_authorities }}"
```

Sign an external CSR with the Component CA:

```yaml
- name: Sign external web CSR
  ca_certificate:
    base_dir: /etc/pki/example
    ca_name: example
    base_url: http://pki.example.test
    certificate:
      name: external-web01
      type: tls_server
      csr_path: /srv/pki/requests/external-web01.csr
      formats:
        - pem
        - der
        - txt
        - fullchain
    certificate_types:
      tls_server:
        issuer: component
    authorities: "{{ ca_authorities }}"
```

Issue a Samba AD domain controller certificate:

```yaml
- name: Issue MSKDC certificate
  ca_certificate:
    base_dir: /etc/pki/example
    ca_name: example
    kerberos_realm: EXAMPLE.TEST
    certificate:
      name: dc01
      type: mskdc
      common_name: dc01.example.test
      ad_object_guid: 8f2a02d1-862a-47cf-9a9b-6bda9c3bd2c5
    certificate_types:
      mskdc:
        issuer: component
        required_fields:
          - ad_object_guid
    authorities: "{{ ca_authorities }}"
```

## Certificate policies

- `certificate_policies`: list of `{oid, cps_uri?}` entries, default `[]`.

Policy-bearing issuers require every end certificate to declare a nonempty
subset
of the OIDs in the actual issuer certificate. CPS URLs need not match. Policies
are explicit: they are neither inherited nor inferred from profiles or external
CSRs. An empty issuer list accepts only certificates without policies.

Constraints require a nonempty sub-CA policy list. Roots and end certificates
cannot carry constraints through this module. `anyPolicy` is supported only on
self-signed roots; root policy lists do not restrict sub-CA issuance. The policy
extension OIDs, including unsupported policyMappings, cannot be passed through
`raw_extensions`. User Notices are not supported.

Policy reordering is idempotent. Changed policy OIDs, CPS URLs, or constraints
reissue the certificate using the existing key unless renewal requests rekeying.
See the role README for the abstract PKI example and client validation limits.
