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

- **`base_dir`**: Base CA directory used to locate issuer material and derive
  CSR paths.
  Type: path; Required: yes; Default: none; Secret: no

- **`base_url`**: Base publication URL for derived AIA/CDP URLs.
  Type: str; Required: no; Default: `""`; Secret: no

- **`ca_name`**: Enables composed inventory output when non-empty.
  Type: str; Required: no; Default: `""`; Secret: no

- **`certificates`**: Certificate models. See
  [ca_certificate](ca_certificate.md#certificate-model).
  Type: list[dict]; Required: yes; Default: none; Secret: yes

- **`certificate_types`**: Role type map. The selected type must define `issuer`
  and may define `required_fields`.
  Type: dict; Required: yes; Default: none; Secret: no

- **`authorities`**: Authority list used to resolve issuer passphrase and
  `default_days`.
  Type: list[dict]; Required: yes; Default: none; Secret: yes

- **`kerberos_realm`**: Default realm for MSKDC certificates.
  Type: str; Required: no; Default: `""`; Secret: no

- **`subject`**: Role-level subject defaults.
  Type: dict; Required: no; Default: `{}`; Secret: no

- **`renewal`**: Module-level renewal policy defaults. Certificate-local
  `renewal` overrides these values.
  Type: dict; Required: no; Default: `{}`; Secret: no

- **`owner`**: Owner for generated files.
  Type: str; Required: no; Default: none; Secret: no

- **`group`**: Group for generated files.
  Type: str; Required: no; Default: none; Secret: no

- **`force`**: Regenerates managed material even if current files match.
  Type: bool; Required: no; Default: `false`; Secret: no

## Return Values

- **`changed`**: Whether any generated artifact or inventory state changed.
  Type: bool

- **`inventory_changed`**: Whether the composed inventory or any certificate
  inventory fragment changed.
  Type: bool

- **`count`**: Number of certificate models processed.
  Type: int

- **`issuer_groups`**: Number of processed certificates by issuer.
  Type: dict

- **`results`**: Per-certificate result dictionaries in the same order as
  `certificates`.
  Type: list[dict]

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
