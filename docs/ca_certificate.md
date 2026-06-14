# ca_certificate

Dispatch one declarative role certificate to a built-in certificate profile.

`ca_certificate` is the public module used for entries in `ca_certificates`.
It is not a low-level generic X.509 module. It validates the declarative model,
resolves the issuer through `certificate_types`, applies profile defaults, then
uses the shared X.509 helper to create certificate artifacts.

## Behavior

- Requires `certificate.name`, `certificate.type`, and
  `certificate.common_name`.
- Validates `certificate.type` against the built-in profiles and the provided
  `certificate_types` map.
- Resolves the issuer and issuer passphrase from `authorities`.
- Uses `certificate.days` when set; otherwise uses issuer `default_days`.
- Merges module-level `subject` defaults with `certificate.subject`.
- Applies profile defaults for formats, key usage, EKU, SAN defaults, digest,
  and raw extensions.
- Creates the output directory.
- Generates or reuses the private key and CSR.
- Issues a PEM certificate and optional DER and text exports.
- Copies the issuer chain into the certificate output directory.
- Returns export hints used by the bundle modules.
- Records certificate inventory state.

## Certificate Profiles

| Type | Default formats | Key Usage | Extended Key Usage | Extra behavior |
| --- | --- | --- | --- | --- |
| `tls_server` | `pem`, `der`, `txt` | `digitalSignature`, `keyEncipherment` | `serverAuth` | Adds `DNS:<common_name>` when no DNS SAN is set. |
| `tls_client` | `pem`, `der`, `txt` | `digitalSignature`, `keyEncipherment` | `clientAuth` | Standard TLS client certificate. |
| `eap_tls_client` | `pem`, `der`, `txt` | `digitalSignature`, `keyEncipherment` | `clientAuth` | Network EAP-TLS client certificate. |
| `identity` | `pem`, `der`, `txt`, `pfx` | `digitalSignature`, `keyEncipherment`, `nonRepudiation` | `clientAuth`, `emailProtection`, `1.3.6.1.4.1.311.20.2.2` | Smartcard logon and S/MIME. Requires `pfx_passphrase` unless formats are overridden without `pfx`/`p12`. |
| `identity_full` | `pem`, `der`, `txt`, `pfx` | `digitalSignature`, `keyEncipherment`, `nonRepudiation` | `clientAuth`, `emailProtection`, `codeSigning`, `1.3.6.1.4.1.311.20.2.2` | Smartcard logon, S/MIME, and code signing. Requires `pfx_passphrase` unless formats are overridden without `pfx`/`p12`. |
| `mskdc` | `pem`, `der`, `txt` | `digitalSignature`, `keyEncipherment` | `serverAuth`, `clientAuth`, `1.3.6.1.5.2.3.5` | Adds DNS SAN, KRB5PrincipalName PKINIT SAN, NTDS objectGUID extension, and `DomainController` template extension. Requires `ad_object_guid` and `krb5_realm` or module `kerberos_realm`. |
| `fritzbox` | `pem`, `der`, `txt`, `fritzbox` | `digitalSignature`, `keyEncipherment` | `serverAuth`, `clientAuth` | Adds DNS SAN and limits the digest to `sha384` or weaker because FRITZ!OS rejects stronger hashes. |

All profiles default to `digest: sha384`.

## Module Parameters

| Parameter | Type | Required | Default | Allowed values | Secret | Description |
| --- | --- | --- | --- | --- | --- | --- |
| `base_dir` | path | yes | none | any absolute or relative path | no | Base CA directory used to locate issuer material and derive CSR paths. |
| `base_url` | str | no | `""` | any URL prefix | no | Base publication URL. If set, AIA defaults to `<base_url>/aia/<issuer>-ca.der` and CDP to `<base_url>/crl/<issuer>-ca.crl`. |
| `ca_name` | str | no | `""` | any string | no | Enables composed inventory output when non-empty. |
| `certificate` | dict | yes | none | see certificate model below | yes | Declarative certificate item. |
| `certificate_types` | dict | yes | none | map keyed by profile type | no | Role type map. The selected type must define `issuer` and may define `required_fields`. |
| `authorities` | list[dict] | yes | none | authority dictionaries | yes | Authority list used to resolve issuer passphrase and `default_days`. |
| `kerberos_realm` | str | no | `""` | Kerberos realm | no | Default realm for MSKDC certificates. |
| `subject` | dict | no | `{}` | supported subject keys | no | Role-level subject defaults. |
| `owner` | str | no | none | user name or UID | no | Owner for generated files. |
| `group` | str | no | none | group name or GID | no | Group for generated files. |
| `force` | bool | no | `false` | `true`, `false` | no | Regenerates managed material even if current files match. |

## Certificate Model

These keys are accepted inside `certificate`.

| Key | Type | Required | Default | Allowed values | Secret | Description |
| --- | --- | --- | --- | --- | --- | --- |
| `name` | str | yes | none | letters, digits, dots, underscores, hyphens | no | Certificate short name and file stem. |
| `type` | str | yes | none | built-in profile name | no | Certificate profile. |
| `common_name` | str | yes | none | any string | no | Common Name. |
| `days` | int | no | issuer `default_days` | positive integer | no | Certificate validity. |
| `formats` | list[str] | no | profile default | `pem`, `der`, `txt`, `pfx`, `p12`, `fullchain`, `fritzbox` | no | Output and export formats. |
| `output_dir` | path | no | `<base_dir>/certs/<name>` | any path | no | Directory for key, certificate, chain copy, and bundles. |
| `key_type` | str | no | `RSA` | see [index](index.md#common-value-sets) | no | Private key algorithm. |
| `key_size` | int | no | `4096` | RSA bit size, or `256`/`384` for generic ECDSA | no | Key size or curve selector. |
| `key_passphrase` | str | no | none | any string | yes | Optional certificate private key passphrase. |
| `pfx_passphrase` | str | conditional | none | any string | yes | Required when `formats` contains `pfx` or `p12`, unless `passphrase` is used by the bundle task. |
| `friendly_name` | str | no | `common_name` or `name` | any string | no | Friendly name for PKCS#12 exports. |
| `subject_ordered` | list[dict] | no | `[]` | supported subject keys | no | Full ordered subject override. |
| `email` | str | no | none | email address | no | Subject `emailAddress`. |
| `subject` | dict | no | `{}` | supported subject keys | no | Certificate-local subject values merged over module `subject`. |
| `key_usage` | list[str] | no | profile default | supported Key Usage names | no | Overrides profile Key Usage when non-empty. |
| `key_usage_critical` | bool | no | `true` | `true`, `false` | no | Marks Key Usage critical. |
| `extended_key_usage` | list[str] | no | profile default | EKU names or dotted OIDs | no | Overrides profile EKU when non-empty. |
| `extended_key_usage_critical` | bool | no | `false` | `true`, `false` | no | Marks EKU critical. |
| `san` | list[str] | no | `[]` plus profile defaults | supported SAN syntax | no | Subject Alternative Names. |
| `san_critical` | bool | no | `false` | `true`, `false` | no | Marks SAN critical. |
| `aia_base_url` | str | no | `""` | URL prefix | no | Explicit AIA URL prefix. |
| `cdp_base_url` | str | no | `""` | URL prefix | no | Explicit CDP URL prefix. |
| `raw_extensions` | list[dict] | no | `[]` plus profile defaults | supported raw extension syntax | no | Additional unrecognized extensions. |
| `digest` | str | no | `sha384` | `sha1`, `sha224`, `sha256`, `sha384`, `sha512` | no | Signature digest for RSA and ECDSA. FritzBox profiles reject values stronger than `sha384`. |
| `include_identifiers` | bool | no | `true` | `true`, `false` | no | Adds SKI and AKI. |
| `key_mode` | str | no | `0600` | octal mode string | no | Private key file mode. |
| `public_mode` | str | no | `0644` | octal mode string | no | CSR, certificate, DER, text, and chain mode. |
| `directory_mode` | str | no | `0755` | octal mode string | no | Output directory mode. |
| `ad_object_guid` | str | conditional | none | canonical GUID or raw 16-byte hex | no | Required for `mskdc`. Encoded as NTDS objectGUID extension OID `1.3.6.1.4.1.311.25.1`. |
| `krb5_realm` | str | conditional | module `kerberos_realm` | uppercase realm | no | MSKDC PKINIT realm. |

Supported Key Usage values are `digitalSignature`, `nonRepudiation`,
`contentCommitment`, `keyEncipherment`, `dataEncipherment`, `keyAgreement`,
`keyCertSign`, `cRLSign`, `encipherOnly`, and `decipherOnly`.

Supported EKU aliases are `serverAuth`, `clientAuth`, `codeSigning`,
`emailProtection`, `timeStamping`, `OCSPSigning`, and `smartcardLogon`.
Dotted OIDs are accepted for additional EKUs.

## Generated Files

For `name: web01`, `issuer: component`, and `base_dir: /etc/pki/example`:

- `/etc/pki/example/certs/web01/web01.key`
- `/etc/pki/example/csr/web01.csr`
- `/etc/pki/example/certs/web01/web01.pem`
- `/etc/pki/example/certs/web01/web01.der` when `der` is requested
- `/etc/pki/example/certs/web01/web01.txt` when `txt` is requested
- `/etc/pki/example/certs/web01/web01-chain.pem`
- Inventory fragments below `/etc/pki/example/inventory/state`
- `/etc/pki/example/inventory/ca-inventory.json` when `ca_name` is set

Bundle formats are produced by the dedicated bundle modules after
`ca_certificate` returns its export hints.

## Return Values

| Name | Type | Description |
| --- | --- | --- |
| `changed` | bool | Whether any generated artifact or inventory state changed. |
| `name` | str | Certificate name. |
| `profile` | str | Resolved certificate profile. |
| `directory_changed` | bool | Whether the output directory changed. |
| `key_changed` | bool | Whether the private key changed. |
| `csr_changed` | bool | Whether the CSR changed. |
| `cert_changed` | bool | Whether the PEM certificate changed. |
| `der_changed` | bool | Whether the DER export changed. |
| `txt_changed` | bool | Whether the text export changed. |
| `chain_changed` | bool | Whether the issuer chain copy changed. |
| `inventory_changed` | bool | Whether CA inventory state changed. |
| `formats` | list[str] | Normalized formats. |
| `pkcs12_formats` | list[str] | `pfx` and `p12` formats requested for follow-up bundle tasks. |
| `fullchain_bundle` | bool | Whether a fullchain bundle should be generated. |
| `fritzbox_bundle` | bool | Whether a FritzBox bundle should be generated. |
| `csr_path` | str | CSR path. |
| `cert_path` | str | PEM certificate path. |
| `txt_path` | str | Text export path, or empty string. |

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

