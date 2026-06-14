# filter_plugins/ca.py

Internal Ansible filter plugin for CA role variable normalization.

`filter_plugins/ca.py` exposes `ca_authority_map`. It is used by role tasks to
validate and address `ca_authorities` by name.

## Exported Filters

| Filter | Purpose |
| --- | --- |
| `ca_authority_map` | Returns authorities keyed by `name` after validating list shape, safe names, uniqueness, and parent references. |

## Behavior

- `None` is treated as an empty list.
- Non-list inputs fail.
- Each item must be a dictionary.
- Each authority requires `name`.
- Each authority requires `parent`.
- Names must match `^[A-Za-z0-9_.-]+$`.
- Duplicate names fail.
- Every `parent` must reference an authority in the same list.

## Defaults

The filter has no default authorities. Defaults are supplied by role variables,
not by the filter.

## Example

```yaml
- name: Build authority lookup
  ansible.builtin.set_fact:
    ca_authorities_by_name: "{{ ca_authorities | ca_authority_map }}"
```

## Used By

- Role tasks that need deterministic authority lookup before invoking modules.

