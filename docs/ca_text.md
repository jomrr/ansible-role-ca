# ca_text

Internal deterministic certificate text exports.

`module_utils/ca_text.py` is not an Ansible module. It creates stable text
representations of X.509 certificates when the `txt` format is requested.

It uses `ca_time` for validity timestamps and `ca_serial` for hexadecimal
extension output.

## Public Helper

| Helper | Purpose |
| --- | --- |
| `certificate_text(cert)` | Returns deterministic certificate text bytes. |
| `ensure_txt(params, cert)` | Writes `params["txt_path"]` when set and returns whether the file changed. |

## Behavior

- Writes nothing when `txt_path` is empty.
- Uses the same owner, group, and public mode from the X.509 parameter model.
- Produces deterministic text instead of shelling out to `openssl x509 -text`.
- Includes certificate version, serial number, signature algorithm, issuer,
  validity, subject, public key summary, recognized extensions, and signature
  algorithm.
- Unknown extensions are represented as DER hex.

## Supported Extension Text

- Basic Constraints
- Key Usage
- Extended Key Usage
- Subject Alternative Name
- Authority Information Access
- CRL Distribution Points
- Subject Key Identifier
- Authority Key Identifier
- Unrecognized extensions as `DER:<hex>`

## Defaults

| Setting | Value |
| --- | --- |
| Timestamp format | `YYYY-MM-DD HH:MM:SS UTC` |
| Hex format | colon-separated uppercase hex |
| File mode | `params.public_mode`, usually `0644` |

## Internal Example

```python
txt_changed = ensure_txt(params, cert)
```

## Used By

- `ca_x509`
- `ca_chain`
