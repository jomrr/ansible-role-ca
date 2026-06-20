# ca_certificate_engine

Internal shared implementation for certificate dispatcher modules.

This helper is not a user-facing Ansible module. It exists so
`ca_certificate` and `ca_certificate_batch` resolve certificate models, apply
profile defaults, create artifacts, and update inventory through one code path.

## Public Helper Functions

| Function | Behavior |
| --- | --- |
| `single_certificate_argument_spec()` | Returns the Ansible argument spec for `ca_certificate`. |
| `batch_certificate_argument_spec()` | Returns the Ansible argument spec for `ca_certificate_batch`. |
| `prepare_certificate_artifacts(params, certificate=None)` | Resolves one declarative certificate model into X.509 helper parameters. |
| `ensure_certificate_artifacts(params, certificate=None)` | Ensures one certificate and updates inventory state. |
| `ensure_certificate_batch(params)` | Ensures all certificates in `params["certificates"]`, writes certificate inventory fragments, and composes inventory once. |

## Defaults And Validation

Profile defaults come from `ca_profiles`:

- standard certificates and MSKDC: `pem`, `der`, `txt`
- identity certificates: `pem`, `der`, `txt`, `pfx`
- FritzBox certificates: `pem`, `der`, `txt`, `fritzbox`

Supported export formats are `pem`, `der`, `txt`, `pfx`, `p12`, `fullchain`,
and `fritzbox`.

Certificate models that set `csr_path` or `csr_content` are treated as
CSR-signed certificates. The helper allows `common_name` to be omitted in that
mode, rejects `pfx`, `p12`, and `fritzbox`, and lets the X.509 helper copy the
CSR into the managed CSR path before signing it.

The helper validates certificate type, issuer existence, required profile
fields, PFX passphrase requirements, merged subject defaults, renewal policy
overrides, and MSKDC Kerberos realm propagation before calling the X.509 helper.
