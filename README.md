# Ansible Role: ca

![GitHub](https://img.shields.io/github/license/jomrr/ansible-role-ca) ![GitHub last commit](https://img.shields.io/github/last-commit/jomrr/ansible-role-ca) ![GitHub issues](https://img.shields.io/github/issues-raw/jomrr/ansible-role-ca) [![dev](https://img.shields.io/github/actions/workflow/status/jomrr/ansible-role-ca/dev-push-smoke.yml?branch=dev&event=push&label=dev)](https://github.com/jomrr/ansible-role-ca/actions/workflows/dev-push-smoke.yml?query=branch%3Adev) [![main](https://img.shields.io/github/actions/workflow/status/jomrr/ansible-role-ca/main-full-gate.yml?branch=main&event=push&label=main)](https://github.com/jomrr/ansible-role-ca/actions/workflows/main-full-gate.yml?query=branch%3Amain)

Ansible role for managing a two-tier private CA with certificate issuance, CRLs, AIA, and CDP URLs.

## Purpose

This role manages a private two-tier PKI with a Root CA and Component, Network, and Identity issuing CAs.
It creates CA keys, CSRs, certificates, chains, DER exports, CRLs, and managed end-entity certificates from inventory variables.

## Scope

### Managed

- Root CA and Component, Network, and Identity issuing CAs
- PEM and DER exports for all CA certificates
- CA chain files
- Declarative end-entity certificates in `ca_certificates`
- TLS server and TLS client certificates from the Component CA
- Samba AD Domain Controller/MSKDC certificates from the Component CA
- FritzBox import bundles from the Component CA
- Identity certificates for smartcard logon, S/MIME, and optional code signing
- EAP-TLS client certificates from the Network CA
- PEM and DER CRLs
- Embedded AIA and CDP URLs
- Optional systemd service and timer for CRL renewal

### Not Managed

- Publishing or serving AIA and CDP files
- Online certificate enrollment protocols
- OCSP responder services
- Importing certificates into applications or hardware tokens

## Requirements

- Target hosts need OpenSSL and Python cryptography bindings.
- CA private key passphrases are required in `ca_privatekey_passphrases`; store real values in Ansible Vault.
- PFX/PKCS#12 output requires a per-certificate `pfx_passphrase`.
- MSKDC certificates require `krb5_realm` or global `ca_kerberos_realm`, plus `ad_object_guid`.

## Role Variables

The following variables are part of the public role interface.

| Name | Type | Required | Default | Description |
| ---- | ---- | -------- | ------- | ----------- |
| `ca_name` | `str` | `false` | `Yourdomain` | CA name used in CA certificate common names and, lowercased, in the default CA working directory. |
| `ca_base_dir` | `str` | `false` |  | CA working directory.<br>Defaults to `/etc/pki/<ca_name \| lower>` on RedHat-family systems and `/etc/ssl/<ca_name \| lower>` on Debian and Suse-family systems. |
| `ca_base_url` | `str` | `false` | `https://pki.yourdomain.tld` | Base URL used when deriving default AIA and CDP URLs. |
| `ca_kerberos_realm` | `str` | `false` | `` | Optional default Kerberos realm for MSKDC PKINIT SAN encoding. |
| `ca_owner` | `str` | `false` | `root` | Owner for managed CA files. |
| `ca_group` | `str` | `false` | `root` | Group for managed CA files. |
| `ca_no_log` | `bool` | `false` | `True` | Suppress task output that can contain private key passphrases or PFX passphrases. |
| `ca_country` | `str` | `false` | `DE` | Default X.509 subject country. |
| `ca_state` | `str` | `false` | `Bayern` | Default X.509 subject state or province. |
| `ca_locality` | `str` | `false` | `Erlangen` | Default X.509 subject locality. |
| `ca_organization` | `str` | `false` | `Yourdomain SE` | Default X.509 subject organization. |
| `ca_organizational_unit` | `str` | `false` | `Yourdomain Certificate Authority` | Default X.509 subject organizational unit. |
| `ca_key_type` | `str` | `false` | `RSA` | Private key type for CA and end-entity keys. |
| `ca_default_bits` | `int` | `false` | `4096` | Default key size and optional DH parameter size. |
| `ca_default_md` | `str` | `false` | `sha512` | Default message digest for certificates and CRLs. |
| `ca_force_reissue` | `bool` | `false` | `False` | Force regeneration of keys, certificates, CRLs, and exports where supported. |
| `ca_certificate_async_timeout` | `int` | `false` | `600` | Async timeout in seconds for end-entity certificate and bundle jobs. |
| `ca_certificate_async_retries` | `int` | `false` | `600` | Number of async status retries for end-entity certificate and bundle jobs. |
| `ca_certificate_async_delay` | `int` | `false` | `1` | Delay in seconds between async status checks for end-entity certificate and bundle jobs. |
| `ca_privatekey_passphrases` | `dict` | `false` | {} | Passphrases for Root, Component, Network, and Identity CA private keys.<br>Store real values in Ansible Vault. |
| `ca_authority_days` | `dict` | `false` | root: 3652<br />component: 1826<br />network: 1826<br />identity: 1826 | Validity periods for the built-in CA certificates. |
| `ca_default_certificate_days` | `int` | `false` | `397` | Default validity period for end-entity certificate profiles. |
| `ca_certificate_type_days` | `dict` | `false` | tls_server: 397<br />tls_client: 397<br />mskdc: 397<br />fritzbox: 397<br />identity_full: 730<br />identity: 730<br />eap_tls_client: 397 | Validity periods for built-in certificate profiles. |
| `ca_aia` | `dict` | `false` |  | AIA URL settings. |
| `ca_cdp` | `dict` | `false` |  | CDP URL settings. |
| `ca_certificates` | `list` | `false` | [] | End-entity certificates to manage. |
| `ca_revocations` | `dict` | `false` | root: []<br />component: []<br />network: []<br />identity: [] | Revoked certificate entries grouped by issuing CA. |
| `ca_crl` | `dict` | `false` |  | CRL generation settings. |
| `ca_crl_automation` | `dict` | `false` |  | Optional systemd CRL renewal automation. |
| `ca_create_dhparams` | `bool` | `false` | `False` | Generate Diffie-Hellman parameters under the platform PKI base directory. |

## Managed Files

- `/etc/pki/<ca_name | lower> on RedHat-family systems`
- `/etc/ssl/<ca_name | lower> on Debian and Suse-family systems`
- `<ca_base_dir>/ca/*-ca.pem`
- `<ca_base_dir>/ca/*-ca.der`
- `<ca_base_dir>/chains/*-ca-chain.pem`
- `<ca_base_dir>/crl/*-ca.crl`
- `<ca_base_dir>/crl/*-ca.crl.pem`
- `<ca_base_dir>/csr/*.csr`
- `<ca_base_dir>/ext/*.ext`
- `<ca_base_dir>/private/*-ca.key`
- `<ca_base_dir>/private/*-ca.pass`
- `<ca_base_dir>/certs/*`
- `/etc/systemd/system/<ca_name | lower>-ca-crl-renew.service` when `ca_crl_automation.enabled=true`
- `/etc/systemd/system/<ca_name | lower>-ca-crl-renew.timer` when `ca_crl_automation.enabled=true`

## Security Notes

- CA private keys are passphrase-protected and their passphrases are supplied by inventory variables.
- Generated CA passphrase files and private keys are mode `0600`.
- End-entity private key passphrases are optional except for formats that require export passwords, such as PFX/PKCS#12.
- FritzBox bundles are mode `0600` because they include the private key, certificate, and issuing chain.
- MSKDC certificates include `digitalSignature`, `serverAuth`, `clientAuth`, and KDC Authentication EKU `1.3.6.1.5.2.3.5` (OpenSSL renders it as `Signing KDC Response`); the Microsoft template-name extension is emitted as `1.3.6.1.4.1.311.20.2 = ASN1:BMPSTRING:DomainController`.
- MSKDC certificates include a PKINIT SAN `otherName:1.3.6.1.5.2.2` containing the DER-encoded `KRB5PrincipalName` for `krbtgt/<REALM>@<REALM>`.
- MSKDC certificates require the domain controller AD objectGUID through `ad_object_guid`; the role emits it as `1.3.6.1.4.1.311.25.1 = ASN1:FORMAT:HEX,OCTETSTRING:<guid-bytes>`.

## Operational Notes

- Certificate SANs use module/OpenSSL syntax such as `DNS:host.example.org`, `IP:192.0.2.10`, `email:user@example.org`, and `otherName:1.3.6.1.4.1.311.20.2.3;UTF8:user@example.org`.
- MSKDC `krb5_realm` is uppercased before encoding and becomes `krbtgt/<REALM>@<REALM>` with Kerberos name type `KRB_NT_SRV_INST` (`2`).
- MSKDC `ad_object_guid` accepts the canonical AD GUID form, for example `d900ea2b-1253-4754-a22b-cf28508dfed3`, or raw 16-byte hex; canonical GUIDs are converted to AD byte order for the NTDS replication extension.
- AIA URLs point to `<ca>-ca.der`; CDP URLs point to `<ca>-ca.crl`.
- AIA/CDP publication is outside this role because URLs do not describe an Ansible transport target.
- The default CA working directory is derived from `ca_name | lower` below the platform PKI base path.
- The built-in CA topology, certificate profiles, and FritzBox bundle order are role vars; override validity periods through `ca_authority_days`, `ca_certificate_type_days`, or a per-certificate `days` value.
- FritzBox bundles are assembled in the default order `private_key`, `certificate`, `chain`.
- Existing certificates are reissued when their key, CSR, or extension file changes, or when `ca_force_reissue=true`.

## Supported Platforms

| OS Family | Distribution | Version | Container Image |
| --------- | ------------ | ------- | --------------- |
| RedHat | AlmaLinux | latest | [jomrr/molecule-almalinux:latest](https://hub.docker.com/r/jomrr/molecule-almalinux) |
| Debian | Debian | latest | [jomrr/molecule-debian:latest](https://hub.docker.com/r/jomrr/molecule-debian) |
| RedHat | Fedora | latest | [jomrr/molecule-fedora:latest](https://hub.docker.com/r/jomrr/molecule-fedora) |
| Suse | OpenSuse Leap | latest | [jomrr/molecule-opensuse-leap:latest](https://hub.docker.com/r/jomrr/molecule-opensuse-leap) |
| Suse | OpenSuse Tumbleweed | latest | [jomrr/molecule-opensuse-tumbleweed:latest](https://hub.docker.com/r/jomrr/molecule-opensuse-tumbleweed) |
| Debian | Ubuntu | latest | [jomrr/molecule-ubuntu:latest](https://hub.docker.com/r/jomrr/molecule-ubuntu) |

## Example Playbook

### Minimal two-tier PKI

Creates the Root CA and the three issuing CAs without end-entity certificates.

```yaml
---
- name: Manage private PKI
  hosts: ca_hosts
  gather_facts: true
  roles:
    - role: jomrr.ca
      vars:
        ca_name: Example
        ca_base_url: https://pki.example.org
        ca_privatekey_passphrases:
          root: vaulted-root-passphrase
          component: vaulted-component-passphrase
          network: vaulted-network-passphrase
          identity: vaulted-identity-passphrase
```
### Managed certificate examples

Issues Component, Identity, and Network certificates with embedded AIA/CDP URLs.

```yaml
---
- name: Manage private PKI with issued certificates
  hosts: ca_hosts
  gather_facts: true
  roles:
    - role: jomrr.ca
      vars:
        ca_name: Example
        ca_base_url: https://pki.example.org
        ca_privatekey_passphrases:
          root: vaulted-root-passphrase
          component: vaulted-component-passphrase
          network: vaulted-network-passphrase
          identity: vaulted-identity-passphrase
        ca_aia:
          enabled: true
          url: https://pki.example.org/aia
        ca_cdp:
          enabled: true
          url: https://pki.example.org/crl
        ca_certificates:
          - name: web01
            type: tls_server
            common_name: web01.example.org
            san:
              - DNS:web01.example.org
              - DNS:web01
          - name: dc01
            type: mskdc
            common_name: dc01.example.org
            krb5_realm: EXAMPLE.ORG
            ad_object_guid: d900ea2b-1253-4754-a22b-cf28508dfed3
            san:
              - DNS:dc01.example.org
              - DNS:dc01
          - name: user-full
            type: identity_full
            common_name: Example User
            email: user@example.org
            san:
              - email:user@example.org
              - otherName:1.3.6.1.4.1.311.20.2.3;UTF8:user@example.org
            pfx_passphrase: vaulted-user-full-pfx-passphrase
          - name: wifi-user
            type: eap_tls_client
            common_name: wifi-user@example.org
            san:
              - email:wifi-user@example.org
```

## Author

[Jonas Mauer](https://github.com/jomrr)

## License

This project is licensed under the MIT License.
See [LICENSE](LICENSE) for the full license text.

Copyright (c) 2019 Jonas Mauer.
