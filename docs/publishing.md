# AIA/CDP Publishing

The role can publish public CA artifacts to SSH/Ansible targets with
`ca_publish_targets`. Each target is one destination host with one webroot.
The role creates fixed `aia` and `crl` subdirectories below that webroot.

## Published Artifacts

AIA directories receive:

- every CA certificate as `<name>-ca.pem`, `<name>-ca.der`, and `<name>-ca.txt`
- every issuing CA chain as `<name>-ca-chain.pem`, `<name>-ca-chain.der`, and
  `<name>-ca-chain.txt`

CDP directories receive:

- every CRL as `<name>-ca.crl.pem`
- every CRL as `<name>-ca.crl`

Self-signed root CAs do not have chain files because the root chain would be
identical to the root CA certificate.

## Target Model

```yaml
ca_publish_targets:
  - name: pki-web-01
    ansible_host: 192.0.2.10
    ansible_user: root
    path: /var/www/pki
    owner: root
    group: root
    become: true
    directory_mode: "0755"
    mode: "0644"
  - name: pki-web-02
    ansible_host: 198.51.100.10
    ansible_user: root
    path: /var/www/pki
    owner: root
    group: root
    become: true
```

Use multiple target entries when several hosts serve the same AIA/CDP URLs, for
example in Split-DNS setups.

## Parameters

| Name | Required | Default | Description |
| ---- | -------- | ------- | ----------- |
| `name` | yes | | Ansible host receiving the files. |
| `ansible_host` | no | | SSH address registered with `add_host`. |
| `ansible_user` | no | | SSH user registered with `add_host`. |
| `ansible_port` | no | | SSH port registered with `add_host`. |
| `ansible_ssh_private_key_file` | no | | SSH private key path registered with `add_host`. |
| `path` | yes | | Remote webroot. CA certificates and chains are unpacked below `path/aia`; CRLs are unpacked below `path/crl`. |
| `owner` | no | `ca_owner` | Owner for published files and directories. |
| `group` | no | `ca_group` | Group for published files and directories. |
| `mode` | no | `ca_publish_mode` | Published file mode. |
| `directory_mode` | no | `ca_publish_directory_mode` | Published directory mode. |
| `become` | no | `false` | Whether to use privilege escalation on the target. |
| `become_user` | no | `root` | Privilege escalation user. |

## Behavior

- The normal role run builds one deterministic publish archive on the CA host,
  fetches it once to the controller, and unpacks it on each target.
- The archive contains fixed top-level `aia/` and `crl/` directories plus a
  `.ca-publish-manifest.json` in each directory.
- Target webroot, `aia`, and `crl` directories are created before unpacking.
- Targets are unpacked only when their manifest checksums differ from the
  generated archive manifests.
- The CRL renewal systemd playbook builds and unpacks a CRL-only archive with
  the same `ca_publish_targets`.

## Not Managed

The role does not install HTTP server packages, render virtual-host
configuration, or validate URLs. Configure the HTTP server separately so
`path/aia` and `path/crl` are served by the URLs embedded in certificates.
