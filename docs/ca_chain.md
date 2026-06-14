# ca_chain

Derive and manage an ordered CA chain PEM file for one authority.

`ca_chain` reads generated CA certificates below `<base_dir>/ca`, discovers the
issuer chain by subject, issuer, SKI, and AKI, and writes the chain for issuing
CAs. Root CA chains are intentionally absent because a root chain would be
identical to the root CA certificate.

## Behavior

- No parent parameter is required.
- The target authority is identified by `name`.
- The module loads all `<base_dir>/ca/*-ca.pem` certificates.
- The module holds the authority graph lock and the readable authority locks
  while loading the CA graph, so chains are not mixed across concurrent CA
  renewal.
- The output path is `<base_dir>/chains/<name>-ca-chain.pem`.
- The module also writes a generation-specific chain file
  `<base_dir>/chains/<name>-ca-chain-<serial>.pem` for issuing CAs.
- Before replacing the stable chain path, the previous chain is preserved under
  its own serial-specific file. This keeps old and new issuing CA chains
  available in parallel during CA rollover.
- For an issuing CA, the chain contains the issuing CA certificate followed by
  its issuer certificates up to the self-signed root.
- For a self-signed root CA, an existing chain file is removed and the module
  returns `state: absent`.
- Ambiguous or missing issuer certificates fail the module.

## Parameters

| Parameter | Type | Required | Default | Allowed values | Secret | Description |
| --- | --- | --- | --- | --- | --- | --- |
| `base_dir` | path | yes | none | any absolute or relative path | no | Base directory containing CA certificates and the chain output directory. |
| `name` | str | yes | none | authority name | no | Authority short name. The module expects `<base_dir>/ca/<name>-ca.pem`. |
| `owner` | str | no | none | user name or UID | no | Owner for the chain file. |
| `group` | str | no | none | group name or GID | no | Group for the chain file. |
| `mode` | str | no | `0644` | octal mode string | no | Chain file mode. |
| `force` | bool | no | `false` | `true`, `false` | no | Rewrites the chain file even if current content matches. |

## Generated Files

For `name: component` and `base_dir: /etc/pki/example`:

- `/etc/pki/example/chains/component-ca-chain.pem`
- `/etc/pki/example/chains/component-ca-chain-<serial>.pem`

For `name: root`, no chain file is kept:

- `/etc/pki/example/chains/root-ca-chain.pem` is removed when present.

## Return Values

| Name | Type | Description |
| --- | --- | --- |
| `changed` | bool | Whether the chain file was written or removed. |
| `path` | str | Derived chain path. |
| `state` | str | `present` for issuing CA chains, `absent` for root CA chains. |

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
