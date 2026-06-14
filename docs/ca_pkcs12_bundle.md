# ca_pkcs12_bundle

Manage a PKCS#12 certificate bundle.

`ca_pkcs12_bundle` assembles an existing certificate private key, leaf
certificate, and chain into a `.pfx` or `.p12` file.

## Behavior

- Reads `<output_dir>/<name>.key`, `<output_dir>/<name>.pem`, and
  `<output_dir>/<name>-chain.pem`.
- Writes `<output_dir>/<name>.<format>`.
- `output_dir` defaults to `<base_dir>/certs/<name>`.
- The export passphrase is required.
- Existing PKCS#12 files are parsed and compared by key, leaf certificate, and
  extra certificate fingerprints.
- The private key passphrase is optional and only needed when the input key is
  encrypted.

## Parameters

| Parameter | Type | Required | Default | Allowed values | Secret | Description |
| --- | --- | --- | --- | --- | --- | --- |
| `base_dir` | path | yes | none | any absolute or relative path | no | Base CA directory. |
| `certificate` | dict | no | `{}` | certificate model | yes | Optional source for `output_dir`, `key_passphrase`, `passphrase`, and `friendly_name`. |
| `name` | str | yes | none | certificate name | no | Certificate short name and file stem. |
| `output_dir` | path | no | `<base_dir>/certs/<name>` | any path | no | Directory containing the certificate artifacts and receiving the bundle. |
| `format` | str | yes | none | `pfx`, `p12` | no | PKCS#12 filename extension. |
| `friendly_name` | str | no | certificate `common_name` or `name` | any string | no | PKCS#12 friendly name. |
| `key_passphrase` | str | no | certificate `key_passphrase` | any string | yes | Input private key passphrase. |
| `passphrase` | str | conditional | certificate `pfx_passphrase` | any string | yes | PKCS#12 export passphrase. Required. |
| `owner` | str | no | none | user name or UID | no | Owner for the bundle file. |
| `group` | str | no | none | group name or GID | no | Group for the bundle file. |
| `mode` | str | no | `0600` | octal mode string | no | Bundle file mode. |
| `force` | bool | no | `false` | `true`, `false` | no | Rewrites the bundle even if current content matches. |

## Generated Files

For `name: alice`, `format: pfx`, and `base_dir: /etc/pki/example`:

- `/etc/pki/example/certs/alice/alice.pfx`

## Return Values

| Name | Type | Description |
| --- | --- | --- |
| `changed` | bool | Whether the PKCS#12 bundle or file attributes changed. |
| `path` | str | Bundle path. |

## Examples

Create a PFX bundle:

```yaml
- name: Create identity PFX bundle
  ca_pkcs12_bundle:
    base_dir: /etc/pki/example
    name: alice
    format: pfx
    key_passphrase: "{{ alice_key_passphrase | default(omit) }}"
    passphrase: "{{ alice_pfx_passphrase }}"
```

Use values from the declarative certificate model:

```yaml
- name: Create configured PKCS#12 bundle
  ca_pkcs12_bundle:
    base_dir: /etc/pki/example
    name: "{{ certificate.name }}"
    format: pfx
    certificate: "{{ certificate }}"
```

