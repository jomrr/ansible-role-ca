# ca_time

Shared UTC timestamp helpers.

`module_utils/ca_time.py` is not a user-facing Ansible module. It centralizes
time parsing and normalization for certificate generation, CRL generation,
inventory state, and deterministic text exports.

## Public Helpers

| Helper | Purpose |
| --- | --- |
| `utc(value)` | Converts a datetime to timezone-aware UTC. Naive datetimes are treated as UTC. |
| `now_utc(strip_microseconds=False)` | Returns the current UTC time, optionally without microseconds. |
| `parse_datetime(value)` | Parses ISO-8601 timestamps and ASN.1-style `YYYYMMDDHHMMSSZ` timestamps. Empty values return `None`. |
| `timestamp_z(value)` | Formats a UTC timestamp as ISO-8601 with a `Z` suffix. |
| `timestamp_iso(value)` | Formats a UTC timestamp as ISO-8601 with an explicit `+00:00` offset. |
| `datetime_text(value)` | Formats a timestamp as `YYYY-MM-DD HH:MM:SS UTC`. |
| `certificate_not_valid_before(cert)` | Returns a certificate not-before timestamp across cryptography versions. |
| `certificate_not_valid_after(cert)` | Returns a certificate not-after timestamp across cryptography versions. |
| `object_datetime(obj, name)` | Reads `name_utc` when available, otherwise reads `name` and normalizes it to UTC. |

## Accepted Timestamp Input

- `datetime.datetime`
- ISO-8601 strings such as `2026-06-14T10:00:00Z`
- ISO-8601 strings with offsets such as `2026-06-14T12:00:00+02:00`
- ASN.1-style UTC strings such as `20260614100000Z`
- empty values, returning `None`

## Defaults

| Setting | Value |
| --- | --- |
| Naive datetime timezone | UTC |
| Inventory timestamp format | `timestamp_z` |
| CRL comparison timestamp format | `timestamp_iso` |
| Text export timestamp format | `datetime_text` |

## Used By

- `ca_crl`
- `ca_inventory`
- `ca_text`
- `ca_x509`
