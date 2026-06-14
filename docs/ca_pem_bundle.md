# ca_pem_bundle

Shared PEM bundle helpers.

`module_utils/ca_pem_bundle.py` is not a user-facing Ansible module. It
contains the shared implementation for public modules that concatenate existing
certificate artifacts into deterministic PEM bundles.

## Public Helpers

| Helper | Purpose |
| --- | --- |
| `pem_bundle_argument_spec(default_mode)` | Returns the common Ansible argument spec for PEM bundle modules. |
| `certificate_output_dir(base_dir, name, output_dir)` | Derives `<base_dir>/certs/<name>` unless `output_dir` is set. |
| `pem_bundle_params(params)` | Merges optional `certificate.output_dir` into module params. |
| `pem_bundle_paths(base_dir, name, output_dir, suffix, order)` | Returns output path and ordered input paths. |
| `pem_bundle_content(sources)` | Reads input files and joins them with exactly one trailing newline each. |
| `ensure_pem_bundle(params, suffix, order)` | Locks the certificate, assembles the bundle, writes it atomically, and returns module result data. |

## Supported Source Names

| Source | Path |
| --- | --- |
| `certificate` | `<output_dir>/<name>.pem` |
| `chain` | `<output_dir>/<name>-chain.pem` |
| `private_key` | `<output_dir>/<name>.key` |

## Defaults

| Setting | Value |
| --- | --- |
| Output directory | `<base_dir>/certs/<name>` |
| Lock namespace | `certificate` |
| Input newline handling | strip each source and append one newline |
| File write behavior | delegated to `ca_file.write_file` |

## Used By

- `ca_fullchain_bundle`
- `ca_fritzbox_bundle`
