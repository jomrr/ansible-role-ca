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

## Public Helpers

| Helper | Purpose |
| --- | --- |
| `record_authority_inventory(params, result)` | Records one authority certificate and derived artifact paths. |
| `record_certificate_inventory(params, model, result)` | Records one issued certificate and updates its current pointer. |
| `record_crl_inventory(params, crl)` | Records one CRL format and declarative revocation events. |
| `resolve_revocation_entries(base_dir, authority, entries)` | Resolves revocation entries by serial, certificate name, or fingerprint. |
| `compose_inventory(base_dir, ca_name, base_url)` | Builds the complete inventory dictionary from fragments. |
| `write_composed_inventory(base_dir, ca_name, base_url, owner, group, mode="0644", force=False)` | Writes `<base_dir>/inventory/ca-inventory.json`. |
| `compose_inventory_if_configured(params)` | Writes composed inventory when `params.ca_name` is non-empty. |

## Stored Files

| State | Path |
| --- | --- |
| Authority record | `<base_dir>/inventory/state/authorities/<name>.json` |
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
- `certificates`, containing only current issued certificates
- `issued_certificates`, containing all recorded issued certificates
- `revocations`
- `crls`

Issued certificate records include a computed `status`:

- `valid`
- `not_yet_valid`
- `expired`
- `revoked`

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
serial numbers, validity timestamps, selected extensions, and generated paths.

## Internal Example

```python
inventory_changed = record_certificate_inventory(params, model, result)
inventory_changed = compose_inventory_if_configured(params) or inventory_changed
```

## Used By

- `ca_authority`
- `ca_certificate`
- `ca_crl`
