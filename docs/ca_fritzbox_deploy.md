# ca_fritzbox_deploy

Deploy a FritzBox PEM bundle to FRITZ!OS.

`ca_fritzbox_deploy` uploads an already generated FritzBox PEM bundle through
the FRITZ!OS certificate import endpoint.

## Behavior

- Reads `<output_dir>/<name>-fritzbox.pem` unless `bundle_path` is set.
- Validates that the bundle contains at least one certificate and one
  unencrypted RSA private key.
- Defaults `url` to `https://fritz.box`.
- Normalizes `url` to `scheme://host[:port]` and rejects embedded credentials.
- Defaults `validate_certs` to `false`.
- Always compares the desired leaf certificate with the current HTTPS
  certificate before deploying.
- Deploys only when the certificates differ, unless `force: true` is set.
- Deployment is serialized per normalized `url` with a local lock, so async jobs
  cannot concurrently upload different certificates to the same FRITZ!Box.
- The idempotence comparison requires an HTTPS `url`.
- Supports both legacy MD5 challenge-response and FRITZ!OS PBKDF2 login
  challenge-response.
- Logs out after the upload attempt when a session was opened.

## Parameters

- **`base_dir`**: Base CA directory.
  Type: path; Required: yes; Default: none; Allowed values: any absolute or
  relative path; Secret: no

- **`certificate`**: Optional source for `output_dir` and nested
  `fritzbox_deploy`.
  Type: dict; Required: no; Default: `{}`; Allowed values: certificate model;
  Secret: yes

- **`deploy`**: Explicit deployment settings. Values override nested
  `certificate.fritzbox_deploy`.
  Type: dict; Required: no; Default: `{}`; Allowed values: deploy model; Secret:
  yes

- **`name`**: Certificate short name and file stem.
  Type: str; Required: yes; Default: none; Allowed values: certificate name;
  Secret: no

- **`output_dir`**: Directory containing the generated FritzBox bundle.
  Type: path; Required: no; Default: `<base_dir>/certs/<name>`; Allowed values:
  any path; Secret: no

- **`bundle_path`**: Explicit FritzBox bundle path.
  Type: path; Required: no; Default: `<output_dir>/<name>-fritzbox.pem`; Allowed
  values: any path; Secret: no

- **`url`**: FRITZ!Box URL. HTTPS is required for idempotence comparison.
  Type: str; Required: no; Default: `https://fritz.box`; Allowed values:
  absolute `http` or `https` URL; Secret: no

- **`username`**: Login user.
  Type: str; Required: yes; Default: none; Allowed values: FRITZ!OS user name;
  Secret: no

- **`password`**: Login password.
  Type: str; Required: yes; Default: none; Allowed values: FRITZ!OS password;
  Secret: yes

- **`timeout`**: Network timeout in seconds.
  Type: int; Required: no; Default: `30`; Allowed values: positive integer;
  Secret: no

- **`validate_certs`**: Validate the current FRITZ!Box HTTPS certificate while
  connecting.
  Type: bool; Required: no; Default: `false`; Allowed values: `true`, `false`;
  Secret: no

- **`force`**: Deploy even when the current HTTPS certificate already matches.
  Type: bool; Required: no; Default: `false`; Allowed values: `true`, `false`;
  Secret: no

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
