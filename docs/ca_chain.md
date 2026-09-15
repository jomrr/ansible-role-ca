# ca_chain

Derive and manage ordered CA chain files for one authority.

`ca_chain` reads generated CA certificates below `<base_dir>/ca`, discovers the
issuer chain by subject, issuer, SKI, and AKI, and writes PEM, DER, and text
chain exports for issuing CAs. Root CA chains are intentionally absent because a
root chain would be identical to the root CA certificate.

## Behavior

- No parent parameter is required.
- The target authority is identified by `name`.
- The module loads all `<base_dir>/ca/*-ca.pem` certificates.
- The module holds the authority graph lock and the readable authority locks
  while loading the CA graph, so chains are not mixed across concurrent CA
  renewal.
- The default output paths are `<base_dir>/chains/<name>-ca-chain.pem`,
  `<base_dir>/chains/<name>-ca-chain.der`, and
  `<base_dir>/chains/<name>-ca-chain.txt`.
- The module also writes generation-specific chain files
  `<base_dir>/chains/<name>-ca-chain-<serial>.<format>` for issuing CAs.
- Before replacing the stable chain path, the previous chain is preserved under
  its own serial-specific file. This keeps old and new issuing CA chains
  available in parallel during CA rollover.
- For an issuing CA, the chain contains the issuing CA certificate followed by
  its issuer certificates up to the self-signed root.
- DER chain files contain the same ordered certificates as concatenated DER
  certificate objects.
- Text chain files contain the deterministic text representation for every
  certificate in order.
- For a self-signed root CA, an existing chain file is removed and the module
  returns `state: absent`.
- Ambiguous or missing issuer certificates fail the module.

## Parameters

- **`base_dir`**: Base directory containing CA certificates and the chain output
  directory.
  Type: path; Required: yes; Default: none; Allowed values: any absolute or
  relative path; Secret: no

- **`name`**: Authority short name. The module expects
  `<base_dir>/ca/<name>-ca.pem`.
  Type: str; Required: yes; Default: none; Allowed values: authority name;
  Secret: no

- **`formats`**: Chain output formats.
  Type: list[str]; Required: no; Default: `["pem", "der", "txt"]`; Allowed
  values: `pem`, `der`, `txt`; Secret: no

- **`owner`**: Owner for chain files.
  Type: str; Required: no; Default: none; Allowed values: user name or UID;
  Secret: no

- **`group`**: Group for chain files.
  Type: str; Required: no; Default: none; Allowed values: group name or GID;
  Secret: no

- **`mode`**: Chain file mode.
  Type: str; Required: no; Default: `0644`; Allowed values: octal mode string;
  Secret: no

- **`force`**: Rewrites chain files even if current content matches.
  Type: bool; Required: no; Default: `false`; Allowed values: `true`, `false`;
  Secret: no

## Generated Files

For `name: component` and `base_dir: /etc/pki/example`:

- `/etc/pki/example/chains/component-ca-chain.pem`
- `/etc/pki/example/chains/component-ca-chain.der`
- `/etc/pki/example/chains/component-ca-chain.txt`
- `/etc/pki/example/chains/component-ca-chain-<serial>.pem`
- `/etc/pki/example/chains/component-ca-chain-<serial>.der`
- `/etc/pki/example/chains/component-ca-chain-<serial>.txt`

For `name: root`, no chain file is kept:

- `/etc/pki/example/chains/root-ca-chain.pem` is removed when present.

## Return Values

- **`changed`**: Whether the chain file was written or removed.
  Type: bool

- **`path`**: Derived stable PEM chain path.
  Type: str

- **`paths`**: Derived stable chain paths keyed by format.
  Type: dict

- **`state`**: `present` for issuing CA chains, `absent` for root CA chains.
  Type: str

## Examples

Create or refresh an issuing CA chain:

```yaml
- name: Create component CA chain
  ca_chain:
    base_dir: /etc/pki/example
    name: component
    owner: root
    group: root
```

Ensure a root CA has no redundant chain file:

```yaml
- name: Normalize root CA chain state
  ca_chain:
    base_dir: /etc/pki/example
    name: root
```
