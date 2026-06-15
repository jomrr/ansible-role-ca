# filter_plugins/ca.py

Internal Ansible filter plugin for CA role variable normalization.

`filter_plugins/ca.py` exposes authority validation and publish artifact list
filters. It is used by role tasks to validate and address `ca_authorities` by
name and to derive deterministic AIA/CDP publish sources.

## Exported Filters

| Filter | Purpose |
| --- | --- |
| `ca_authority_map` | Returns authorities keyed by `name` after validating list shape, safe names, uniqueness, and parent references. |
| `ca_publish_aia_artifacts` | Returns CA certificate and issuing-chain artifacts for AIA publication. |
| `ca_publish_cdp_artifacts` | Returns CRL artifacts for CDP publication. |

## Behavior

- `None` is treated as an empty list.
- Non-list inputs fail.
- Each item must be a dictionary.
- Each authority requires `name`.
- Each authority requires `parent`.
- Names must match `^[A-Za-z0-9_.-]+$`.
- Duplicate names fail.
- Every `parent` must reference an authority in the same list.
- AIA publish artifacts include every CA certificate as `pem`, `der`, and `txt`.
- AIA publish artifacts include issuing CA chains as `pem`, `der`, and `txt`.
- CDP publish artifacts include every CRL as `pem` and `der`.

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
- `tasks/publish.yml`
