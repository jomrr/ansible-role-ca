# ca_inventory

Internal CA inventory state hooks.

`module_utils/ca_inventory.py` is not a user-facing Ansible module. It records
non-secret state fragments whenever authorities, certificates, or CRLs are
managed, and composes those fragments into a central inventory JSON file.

## Purpose

The CA inventory is the role's internal state ledger. It records what was
issued, what is current, what was revoked, and where generated artifacts live.
It is intentionally managed through hooks in public modules instead of requiring
users to call a separate inventory module.

## Transactional Hooks

| Helper | Purpose |
| --- | --- |
| `update_authority_inventory(params, result)` | Records one authority certificate and derived artifact paths, then composes the inventory under one state lock. |
| `update_certificate_inventory(params, model, result)` | Records one issued certificate and its current pointer, then composes the inventory under one state lock. |
| `update_crl_inventory(params, crl)` | Records all exported CRL formats and declarative revocation events, then composes the inventory under one state lock. |
| `resolve_revocation_entries(base_dir, authority, entries)` | Resolves revocation entries by serial, certificate name, or fingerprint. |
| `compose_inventory(base_dir, ca_name, base_url)` | Builds the complete inventory dictionary from fragments. |
| `write_composed_inventory(base_dir, ca_name, base_url, owner, group, mode="0644", force=False)` | Writes `<base_dir>/inventory/ca-inventory.json`. |
| `compose_inventory_if_configured(params)` | Writes composed inventory when `params.ca_name` is non-empty. |

The `record_*_inventory` helpers are intentionally low-level fragment writers.
Public modules use the `update_*_inventory` hooks so related fragments and the
composed inventory are updated in one inventory transaction.

## Stored Files

| State | Path |
| --- | --- |
| Authority record | `<base_dir>/inventory/state/authorities/<name>.json` |
| Authority generation record | `<base_dir>/inventory/state/authority_certificates/<name>/<serial>.json` |
| Issued certificate record | `<base_dir>/inventory/state/issued_certificates/<issuer>/<serial>.json` |
| Current certificate pointer | `<base_dir>/inventory/state/current_certificates/<name>.json` |
| CRL record | `<base_dir>/inventory/state/crls/<authority>/<format>.json` |
| Revocation record | `<base_dir>/inventory/state/revocations/<authority>/<serial>.json` |
| Composed inventory | `<base_dir>/inventory/ca-inventory.json` |

## Composed Inventory Shape

The composed inventory contains:

- `schema_version`
- `ca_name`
- `base_dir`
- `base_url`
- `authorities`
- `authority_certificates`, containing recorded CA certificate generations
- `certificates`, containing only current issued certificates
- `issued_certificates`, containing all recorded issued certificates
- `revocations`
- `crls`

Issued certificate records include a computed `status`:

- `valid`
- `not_yet_valid`
- `expired`
- `revoked`

Authority and issued certificate records also include `renewal_status`:

- `valid`
- `scheduled`
- `warning`
- `renewal_due`
- `scheduled_due`
- `expired`

`renewal_status` is computed from the public validity window and the stored
renewal policy. It is separate from revocation status, so a revoked certificate
can still carry renewal metadata without changing its revoked state.

Revocation state is represented by declarative revocation event fragments keyed
by issuer and serial number. When the same issuer and serial appear in CRL
input, the composed issued certificate status becomes `revoked`.

Revocation entries can be resolved from:

- direct serials through `serial` or `serial_number`
- current managed certificate names through `name`, `certificate`, or
  `certificate_name`
- fingerprints through `fingerprint`, `sha1`, or `sha256`

Resolved revocation events can include `reason`, `revocation_date`,
`invalidity_date`, certificate name, and public fingerprints.

## Defaults And Safety

| Setting | Value |
| --- | --- |
| Schema version | `1` |
| State file mode | `0644` |
| Composed inventory mode | `0644` |
| Secret storage | none |
| Fingerprints | `sha1`, `sha256` |
| Revocation selectors | serial, current certificate name, SHA-1 fingerprint, SHA-256 fingerprint |

The inventory does not store private keys, passphrases, PKCS#12 passphrases, or
FRITZ!OS credentials. It stores certificate metadata, public fingerprints,
serial numbers, validity timestamps, selected extensions, renewal policy and
status, and generated paths.

All inventory reads and writes that compose or mutate state use a shared
inventory state lock. Certificate issuance therefore updates the issued record,
current pointer, and composed `ca-inventory.json` in one critical section.

## Internal Example

```python
inventory_changed = update_certificate_inventory(params, model, result)
```

## Used By

- `ca_authority`
- `ca_certificate`
- `ca_crl`
