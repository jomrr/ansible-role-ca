# ca_publish_archive

`ca_publish_archive` is a role-local module used by the CA role's publish tasks.
It creates one deterministic tar archive on the CA host from managed authority
definitions or from an explicit list of public AIA/CDP artifacts. The role
builds one archive per distinct target file mode, fetches each once, and unpacks
the matching archive on each configured publish target.

The module is mostly role-internal. Users normally configure
`ca_publish_targets` instead of calling this module directly.

## Parameters

| Name | Required | Default | Allowed values | Description |
| ---- | -------- | ------- | -------------- | ----------- |
| `base_dir` | yes | | existing CA base directory | CA base directory used for the module lock. |
| `dest` | yes | | path | Archive path on the managed host. |
| `authorities` | no | `[]` | list of authority dictionaries | Managed authorities used to derive default AIA/CDP artifacts. |
| `artifacts` | no | `[]` | list of artifact dictionaries | Explicit public artifacts to include. Each item needs `src`, `file`, and `area`; when set, this overrides authority-derived artifacts. |
| `artifact_mode` | no | `0644` | octal mode string | Mode stored for files inside the archive. |
| `owner` | no | | user name | Owner for the generated archive file. |
| `group` | no | | group name | Group for the generated archive file. |
| `mode` | no | `0600` | octal mode string | Filesystem mode for the generated archive file. |
| `force` | no | `false` | `true`, `false` | Rewrite the archive even when content is identical. |

Artifact `area` values:

- `aia` writes the file below `aia/` in the archive.
- `cdp` and `crl` write the file below `crl/` in the archive.

Only plain filenames are accepted for artifact `file`; path separators are
rejected. This keeps archive extraction paths fixed below `aia/` and `crl/`.

When `authorities` is used, the module derives the role defaults:

- AIA gets every CA certificate as `pem`, `der`, and `txt`.
- AIA gets every issuing CA chain as `pem`, `der`, and `txt`.
- CDP gets every CRL as `pem` and `der`.
- Self-signed root CAs do not get chain files because they would be identical
  to the root certificate.

## Behavior

- The archive is deterministic: file mtimes are `0`, uid/gid are `0`, owner and
  group names are empty, and files are sorted.
- Publish tasks let
  `ansible.builtin.unarchive` compare the actual target files with the archive
  and restore missing or changed files.
- The module compares the generated archive with the existing `dest` content
  and only rewrites on content or metadata changes, unless `force=true`.
- Writes are protected by the role's publish archive lock below
  `<base_dir>/.locks`.
- The module only reads public CA, chain, and CRL artifacts; it should not be
  used for private keys or private bundles.

## Example

```yaml
- name: Build CA publish archive
  ca_publish_archive:
    base_dir: /etc/pki/example
    dest: /tmp/example-public.tar
    authorities: "{{ ca_authorities }}"
    artifact_mode: "0644"
    owner: root
    group: root
    mode: "0600"
```

## Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| `changed` | `bool` | Whether the archive file was written or its metadata changed. |
| `path` | `str` | Archive path on the managed host. |
| `archive_paths` | `list` | Relative paths stored in the archive. |
