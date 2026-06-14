# ca_serial

Shared serial number and hexadecimal helpers.

`module_utils/ca_serial.py` is not a user-facing Ansible module. It centralizes
certificate serial parsing, serial formatting, and normalized hexadecimal
handling for certificates, CRLs, chains, and inventory state.

## Public Helpers

| Helper | Purpose |
| --- | --- |
| `colon_hex(data)` | Formats bytes as colon-separated uppercase hex. `None` becomes an empty string. |
| `serial_hex(value)` | Formats an integer certificate serial as even-length uppercase hex. |
| `parse_serial(value)` | Parses decimal, `0x` hexadecimal, and colon-separated hexadecimal serials. |
| `normalize_hex(value)` | Removes non-hex separators and returns uppercase hex text. |

## Accepted Serial Input

- decimal integers, for example `123456`
- decimal strings, for example `"123456"`
- hexadecimal strings, for example `"0x01AB"`
- colon-separated hexadecimal strings, for example `"01:AB"`

## Defaults

| Setting | Value |
| --- | --- |
| Hex case | uppercase |
| Serial hex length | even number of characters |
| Separator cleanup | all non-hex characters are removed by `normalize_hex` |

## Used By

- `ca_chain`
- `ca_crl`
- `ca_inventory`
- `ca_text`
- `ca_x509`
