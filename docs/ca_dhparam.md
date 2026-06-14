# ca_dhparam

Manage a Diffie-Hellman parameter file.

`ca_dhparam` creates or refreshes a PEM encoded PKCS#3 DH parameter file.

## Behavior

- Writes `<base_dir>/dhparams.pem` unless `path` is set.
- Defaults to 4096-bit DH parameters.
- Reuses an existing file when the parameter size matches.
- Regenerates when the existing size differs or when `force: true` is set.

## Parameters

| Parameter | Type | Required | Default | Allowed values | Secret | Description |
| --- | --- | --- | --- | --- | --- | --- |
| `base_dir` | path | yes | none | any absolute or relative path | no | Base CA directory. |
| `path` | path | no | `<base_dir>/dhparams.pem` | any path | no | Output path. |
| `size` | int | no | `4096` | DH key size supported by cryptography | no | DH parameter size in bits. |
| `owner` | str | no | none | user name or UID | no | Owner for the file. |
| `group` | str | no | none | group name or GID | no | Group for the file. |
| `mode` | str | no | `0644` | octal mode string | no | File mode. |
| `force` | bool | no | `false` | `true`, `false` | no | Regenerates even when current size matches. |

## Generated Files

For `base_dir: /etc/pki/example`:

- `/etc/pki/example/dhparams.pem`

## Return Values

| Name | Type | Description |
| --- | --- | --- |
| `changed` | bool | Whether the parameter file or attributes changed. |
| `path` | str | Output path. |

## Example

```yaml
- name: Create DH parameters
  ca_dhparam:
    base_dir: /etc/pki/example
    size: 4096
```

