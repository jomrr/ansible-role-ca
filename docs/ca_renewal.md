# ca_renewal

Shared certificate renewal policy helpers.

`module_utils/ca_renewal.py` is not a user-facing Ansible module. It keeps the
renewal policy parser, renewal decision logic, and inventory renewal status in
one place.

## Public Helpers

| Helper | Purpose |
| --- | --- |
| `renewal_policy(value)` | Normalizes a renewal dictionary and fills defaults. |
| `renewal_datetime(value)` | Parses an optional planned renewal timestamp. |
| `renewal_decision(force, not_before, not_after, policy_value, now=None)` | Returns whether a certificate should be renewed and whether renewal should re-key. |
| `renewal_status(certificate, policy_value, now=None)` | Returns inventory-facing renewal status for a certificate summary. |

## Renewal Policy

| Key | Default | Behavior |
| --- | --- | --- |
| `warn_before_days` | `0` | Marks inventory warning state only. |
| `renew_before_days` | `0` | Renews when remaining validity reaches this window. |
| `renew_at` | empty | Renews once at or after the timestamp for certificates issued before it. |
| `rekey` | `false` | Generates a new private key when renewal is due. |

`force: true` is handled as an immediate renewal and re-key decision by
`renewal_decision`.

## Decision Reasons

| Reason | Meaning |
| --- | --- |
| `missing` | No existing certificate was available. |
| `force` | The caller requested forced replacement. |
| `expired` | The existing certificate is no longer valid. |
| `scheduled` | `renew_at` is due and the existing certificate predates it. |
| `renewal_window` | Remaining validity is within `renew_before_days`. |

## Inventory States

- `valid`
- `scheduled`
- `warning`
- `renewal_due`
- `scheduled_due`
- `expired`

## Used By

- `ca_inventory`
- `ca_x509`
