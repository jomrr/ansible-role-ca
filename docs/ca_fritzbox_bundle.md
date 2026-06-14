# ca_fritzbox_bundle

Manage a FritzBox PEM import bundle.

`ca_fritzbox_bundle` concatenates an existing leaf certificate, copied issuer
chain, and private key into the PEM order expected by FRITZ!OS certificate
import.

The module uses the internal `ca_pem_bundle` helper for path derivation,
locking, source concatenation, and atomic writes.

## Behavior

- Reads `<output_dir>/<name>.pem`.
- Reads `<output_dir>/<name>-chain.pem`.
- Reads `<output_dir>/<name>.key`.
- Writes `<output_dir>/<name>-fritzbox.pem`.
- `output_dir` defaults to `<base_dir>/certs/<name>`.
- The order is fixed in module code: certificate, chain, private key.
- The default file mode is `0600`.
- The module only assembles files; FRITZ!OS upload is handled by
  [`ca_fritzbox_deploy`](ca_fritzbox_deploy.md).

## Parameters

| Parameter | Type | Required | Default | Allowed values | Secret | Description |
| --- | --- | --- | --- | --- | --- | --- |
| `base_dir` | path | yes | none | any absolute or relative path | no | Base CA directory. |
| `certificate` | dict | no | `{}` | certificate model | yes | Optional source for `output_dir`. |
| `name` | str | yes | none | certificate name | no | Certificate short name and file stem. |
| `output_dir` | path | no | `<base_dir>/certs/<name>` | any path | no | Directory containing inputs and receiving the bundle. |
| `owner` | str | no | none | user name or UID | no | Owner for the bundle file. |
| `group` | str | no | none | group name or GID | no | Group for the bundle file. |
| `mode` | str | no | `0600` | octal mode string | no | Bundle file mode. |
| `force` | bool | no | `false` | `true`, `false` | no | Rewrites the bundle even if current content matches. |

## Generated Files

For `name: fritzbox` and `base_dir: /etc/pki/example`:

- `/etc/pki/example/certs/fritzbox/fritzbox-fritzbox.pem`

## Return Values

| Name | Type | Description |
| --- | --- | --- |
| `changed` | bool | Whether the bundle or file attributes changed. |
| `path` | str | Bundle path. |

## Example

```yaml
- name: Create FritzBox import bundle
  ca_fritzbox_bundle:
    base_dir: /etc/pki/example
    name: fritzbox
```
