# ca_file

Internal file and locking helpers for CA role modules.

`module_utils/ca_file.py` is not an Ansible module. It centralizes safe file
I/O, advisory locks, ownership handling, mode handling, and error sanitization.

## Public Helpers

| Helper | Purpose |
| --- | --- |
| `safe_path_component(value)` | Converts arbitrary text into a safe filename component. |
| `ca_lock_path(base_dir, namespace, name)` | Returns `<base_dir>/.locks/<namespace>-<name>.lock` with sanitized components. |
| `file_lock(path)` | Context manager that takes an exclusive advisory lock. |
| `file_locks(paths)` | Context manager that takes multiple exclusive advisory locks in sorted order. |
| `read_file(path)` | Reads a file without following a final symlink. |
| `set_attrs(path, owner, group, mode)` | Applies owner, group, and mode and returns whether anything changed. |
| `write_file(path, content, owner, group, mode, force=False)` | Atomically writes bytes and enforces file attributes. |
| `sanitize_error(exc, params=None)` | Returns an exception message with secret-looking values masked. |

## Defaults And Constants

| Name | Value | Description |
| --- | --- | --- |
| `MASK` | `********` | Replacement text for masked secrets. |
| `SAFE_PATH_COMPONENT_RE` | `[^A-Za-z0-9_.-]+` | Characters outside this set are replaced with `_`. |
| Secret key pattern | `passphrase`, `password`, `secret`, `token` | Keys matching these words are treated as secret values. |
| Temporary file mode | `0600` before final chmod | Temporary files are private while being written. |
| Lock directory mode | `0700` | `<base_dir>/.locks` is private to the owner. |

## Behavior

- Final symlinks are refused for reads, attribute updates, and replacements.
- Parent directory components are created and opened without following symlinks
  before writes, temporary files, replacements, and lock files are created.
- Lock directories that are symlinks are refused.
- Multiple locks are deduplicated and acquired in deterministic path order to
  avoid deadlocks between dependent CA operations.
- Writes use a temporary file created through the opened parent directory,
  `fsync`, and directory-fd based `os.replace`.
- Parent directories are created when writing.
- Directory metadata is fsynced when the platform supports it.
- Ownership accepts names, numeric strings, or `None`.
- Modes use Ansible-style octal strings such as `0644`.
- `sanitize_error` recursively scans nested module parameters for secret-like
  keys and masks their values from failure messages.

## Internal Example

```python
from ansible.module_utils.ca_file import ca_lock_path, file_locks, write_file

lock_paths = [
    ca_lock_path(base_dir, "authority", issuer),
    ca_lock_path(base_dir, "certificate", name),
]
with file_locks(lock_paths):
    changed = write_file(path, content, owner, group, "0644")
```

## Used By

- `ca_authority`
- `ca_certificate`
- `ca_chain`
- `ca_crl`
- `ca_fritzbox_deploy`
- `ca_inventory`
- `ca_text`
- `ca_x509`
