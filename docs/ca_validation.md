# ca_validation

Shared validation helpers for CA role modules and filter plugins.

`module_utils/ca_validation.py` is not a user-facing Ansible module. It keeps
role object validation in one place so modules and filters do not implement
separate versions of the same authority graph checks.

## Public Helpers

| Helper | Purpose |
| --- | --- |
| `string_value(value)` | Converts optional values to strings for validation. |
| `require_value(value, key, context)` | Returns a required dictionary value or raises `ValueError`. |
| `safe_name(value, context)` | Validates role object names against the safe filename/name pattern. |
| `authority_map(authorities)` | Returns authorities keyed by `name` after validating list shape, safe names, uniqueness, and parent references. |

## Validation Rules

| Rule | Behavior |
| --- | --- |
| Safe names | Names must contain only letters, digits, dots, underscores, and hyphens. |
| Authority shape | `ca_authorities` must be a list of dictionaries. |
| Authority name | Each authority requires `name`. |
| Authority parent | Each authority requires `parent`. |
| Uniqueness | Duplicate authority names are rejected. |
| Parent graph | Every `parent` must reference an authority in the same list. |

## Used By

- `ca_certificate`
- `filter_plugins/ca.py`
