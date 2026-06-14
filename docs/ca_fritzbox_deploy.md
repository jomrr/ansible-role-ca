# ca_fritzbox_deploy

Deploy a FritzBox PEM bundle to FRITZ!OS.

`ca_fritzbox_deploy` uploads an already generated FritzBox PEM bundle through
the FRITZ!OS certificate import endpoint.

## Behavior

- Reads `<output_dir>/<name>-fritzbox.pem` unless `bundle_path` is set.
- Validates that the bundle contains at least one certificate and one
  unencrypted RSA private key.
- Defaults `url` to `https://fritz.box`.
- Defaults `validate_certs` to `false`.
- Always compares the desired leaf certificate with the current HTTPS
  certificate before deploying.
- Deploys only when the certificates differ, unless `force: true` is set.
- The idempotence comparison requires an HTTPS `url`.
- Supports both legacy MD5 challenge-response and FRITZ!OS PBKDF2 login
  challenge-response.
- Logs out after the upload attempt when a session was opened.

## Parameters

| Parameter | Type | Required | Default | Allowed values | Secret | Description |
| --- | --- | --- | --- | --- | --- | --- |
| `base_dir` | path | yes | none | any absolute or relative path | no | Base CA directory. |
| `certificate` | dict | no | `{}` | certificate model | yes | Optional source for `output_dir` and nested `fritzbox_deploy`. |
| `deploy` | dict | no | `{}` | deploy model | yes | Explicit deployment settings. Values override nested `certificate.fritzbox_deploy`. |
| `name` | str | yes | none | certificate name | no | Certificate short name and file stem. |
| `output_dir` | path | no | `<base_dir>/certs/<name>` | any path | no | Directory containing the generated FritzBox bundle. |
| `bundle_path` | path | no | `<output_dir>/<name>-fritzbox.pem` | any path | no | Explicit FritzBox bundle path. |
| `url` | str | no | `https://fritz.box` | absolute `http` or `https` URL | no | FRITZ!Box URL. HTTPS is required for idempotence comparison. |
| `username` | str | yes | none | FRITZ!OS user name | no | Login user. |
| `password` | str | yes | none | FRITZ!OS password | yes | Login password. |
| `timeout` | int | no | `30` | positive integer | no | Network timeout in seconds. |
| `validate_certs` | bool | no | `false` | `true`, `false` | no | Validate the current FRITZ!Box HTTPS certificate while connecting. |
| `force` | bool | no | `false` | `true`, `false` | no | Deploy even when the current HTTPS certificate already matches. |

The `deploy` dictionary accepts the same deployment keys:

- `url`
- `username`
- `password`
- `bundle_path`
- `timeout`
- `validate_certs`
- `force`

## Return Values

| Name | Type | Description |
| --- | --- | --- |
| `changed` | bool | `true` when an upload was performed. |
| `path` | str | Bundle path used for deployment. |

## Examples

Deploy a generated bundle:

```yaml
- name: Deploy FritzBox certificate
  ca_fritzbox_deploy:
    base_dir: /etc/pki/example
    name: fritzbox
    username: "{{ fritzbox_username }}"
    password: "{{ fritzbox_password }}"
```

Use certificate-local deployment settings:

```yaml
- name: Deploy configured FritzBox certificate
  ca_fritzbox_deploy:
    base_dir: /etc/pki/example
    name: "{{ certificate.name }}"
    certificate: "{{ certificate }}"
```

Certificate model:

```yaml
certificate:
  name: fritzbox
  type: fritzbox
  common_name: fritz.box
  fritzbox_deploy:
    url: https://fritz.box
    username: "{{ fritzbox_username }}"
    password: "{{ fritzbox_password }}"
```

