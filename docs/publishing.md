# AIA/CDP Publishing

The role can publish public CA artifacts to SSH/Ansible targets with
`ca_publish_targets`. Each target references an existing inventory host with
one webroot. The CA host itself is a valid destination.
The role creates fixed `aia` and `crl` subdirectories below that webroot.

## Published Artifacts

For the initial issuer generation, AIA directories receive:

- every CA certificate as `<name>-ca.pem`, `<name>-ca.der`, and `<name>-ca.txt`
- every issuing CA chain as `<name>-ca-chain.pem`, `<name>-ca-chain.der`, and
  `<name>-ca-chain.txt`

CDP directories receive:

- every CRL as `<name>-ca.crl.pem`
- every CRL as `<name>-ca.crl`

Self-signed root CAs do not have chain files because the root chain would be
identical to the root CA certificate.

The collection retains these URLs for their original issuer generation. A CA
key or subject change gives subsequent generations distinct filenames. Current
signing certificates stay below `ca/`; they must not overwrite older issuer URLs.
`jomrr.ca.publish` and `jomrr.ca.publish_archive` select the retained public
certificates and their matching active or final CRLs after the role has run
`jomrr.ca.crl_batch`.

## Target Model

### Publish on the CA Host

Use the CA host's inventory name, expressed by `inventory_hostname`:

```yaml
ca_publish_targets:
  - name: "{{ inventory_hostname }}"
    become: true
    path: /var/www/pki
```

The role calls `jomrr.ca.publish` once per local target to write files directly
on the CA host. It uses the target's `become` and `become_user` settings; with
`become: true`, the default escalation user is `root`. That user needs access to
the CA data and locks and permission to write the webroot. No archive is created
or transferred through the controller for local targets.

### Publish on Other Inventory Hosts

```yaml
ca_publish_targets:
  - name: pki-web-01
    path: /var/www/pki
    owner: root
    group: root
    become: true
    directory_mode: "0755"
    mode: "0644"
  - name: pki-web-02
    path: /var/www/pki
    owner: root
    group: root
    become: true
```

Use multiple target entries when several hosts serve the same AIA/CDP URLs, for
example in Split-DNS setups.

Configure remote host addresses, users, and interpreters in inventory:

```yaml
all:
  hosts:
    pki-web-01:
      ansible_host: 192.0.2.10
      ansible_user: pkiadmin
    pki-web-02:
      ansible_host: 198.51.100.10
      ansible_user: pkiadmin
```

The role delegates to these inventory names without adding hosts or overriding
their connection variables. An unknown inventory name is rejected before
publication starts.

## Parameters

- **`name`**: Existing inventory hostname receiving the files.
  Required: yes Default:

- **`path`**: Destination webroot. CA certificates and chains are published below
  `path/aia`; CRLs are published below `path/crl`.
  Required: yes Default:

- **`owner`**: Owner for published files and directories.
  Required: no; Default: `ca_owner`

- **`group`**: Group for published files and directories.
  Required: no; Default: `ca_group`

- **`mode`**: Published file mode.
  Required: no; Default: `ca_publish_mode`

- **`directory_mode`**: Published directory mode.
  Required: no; Default: `ca_publish_directory_mode`

- **`become`**: Whether to use privilege escalation on the target.
  Required: no; Default: `false`

- **`become_user`**: Privilege escalation user.
  Required: no; Default: `root`

## Behavior

- A target whose inventory name equals `inventory_hostname` receives public files
  directly through `jomrr.ca.publish`. Other aliases are treated as remote targets.
- For remote targets, the role builds one deterministic publish archive per
  distinct remote file mode on the CA host, fetches each once to the controller,
  and unpacks the matching archive on each target. Remote targets with the same
  file mode share an archive. Directory modes are managed separately.
- A run with only local targets creates no archive or staging directories.
- The archive contains public CA and CRL files below fixed `aia/` and `crl/`
  paths.
- Target webroot, `aia`, and `crl` directories are created before publication.
- Both paths compare the actual files and repair missing or altered content and
  attributes. Unrelated files are preserved. Local writes are atomic per file;
  remote publication uses `ansible.builtin.unarchive`.

## Check Mode

With `jomrr.ca` 1.2.0 or later, the authority, certificate, and CRL batch modules
predict changes without writing CA state.

For remote publishing, check mode creates temporary staging directories and
archives from the existing public CA artifacts, then transfers the archives to
the controller. Both staging directories are removed in the `always` cleanup,
including when publication fails. Target directory management remains in check
mode and reports predicted changes without applying them. Archive extraction
also remains in check mode, but Ansible 2.22 skips tar archives because its GNU
tar handler does not support check mode. It therefore does not predict changes
to individual published files. The source artifacts and destination webroot
must already exist; a check run does not generate missing certificates or CRLs.

Direct local publication through `jomrr.ca.publish` does not support check mode
and is skipped. Its target directories are still checked.

## Not Managed

The role does not install HTTP server packages, render virtual-host
configuration, or validate URLs. Configure the HTTP server separately so
`path/aia` and `path/crl` are served by the URLs embedded in certificates.
