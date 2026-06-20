# ca_certificate_batch

Dispatch a list of declarative role certificates to the built-in certificate
profiles.

`ca_certificate_batch` is the public module used by the role task for
`ca_certificates`. It uses the same internal engine as `ca_certificate`, so PEM,
DER, text, PKCS#12, fullchain, and FritzBox bundle generation live in one place.
Certificate models can also reference `csr_path` or `csr_content` to sign an
external CSR through the same issuer grouping and inventory flow.

## Behavior

- Accepts the same CA context parameters as `ca_certificate`.
- Accepts `certificates`, a list of certificate model dictionaries.
- Resolves and validates every certificate before issuing.
- Signs external CSRs for certificate models that set `csr_path` or
  `csr_content`.
- Groups work by issuer to keep the run deterministic and ready for issuer-level
  caching.
- Creates all certificate artifacts through the shared certificate engine.
- Writes all certificate inventory fragments and composes the CA inventory once
  after the batch completes.

## Module Parameters

| Parameter | Type | Required | Default | Secret | Description |
| --- | --- | --- | --- | --- | --- |
| `base_dir` | path | yes | none | no | Base CA directory used to locate issuer material and derive CSR paths. |
| `base_url` | str | no | `""` | no | Base publication URL for derived AIA/CDP URLs. |
| `ca_name` | str | no | `""` | no | Enables composed inventory output when non-empty. |
| `certificates` | list[dict] | yes | none | yes | Certificate models. See [ca_certificate](ca_certificate.md#certificate-model). |
| `certificate_types` | dict | yes | none | no | Role type map. The selected type must define `issuer` and may define `required_fields`. |
| `authorities` | list[dict] | yes | none | yes | Authority list used to resolve issuer passphrase and `default_days`. |
| `kerberos_realm` | str | no | `""` | no | Default realm for MSKDC certificates. |
| `subject` | dict | no | `{}` | no | Role-level subject defaults. |
| `renewal` | dict | no | `{}` | no | Module-level renewal policy defaults. Certificate-local `renewal` overrides these values. |
| `owner` | str | no | none | no | Owner for generated files. |
| `group` | str | no | none | no | Group for generated files. |
| `force` | bool | no | `false` | no | Regenerates managed material even if current files match. |

## Return Values

| Name | Type | Description |
| --- | --- | --- |
| `changed` | bool | Whether any generated artifact or inventory state changed. |
| `inventory_changed` | bool | Whether the composed inventory or any certificate inventory fragment changed. |
| `count` | int | Number of certificate models processed. |
| `issuer_groups` | dict | Number of processed certificates by issuer. |
| `results` | list[dict] | Per-certificate result dictionaries in the same order as `certificates`. |

Each item in `results` has the same artifact fields as `ca_certificate`.

## Example

```yaml
- name: Issue managed certificates
  ca_certificate_batch:
    base_dir: /etc/pki/example
    ca_name: example
    base_url: http://pki.example.test
    certificates: "{{ ca_certificates }}"
    certificate_types: "{{ ca_certificate_types }}"
    authorities: "{{ ca_authorities }}"
    subject: "{{ ca_subject }}"
    renewal: "{{ ca_renewal }}"
    owner: root
    group: root
```
