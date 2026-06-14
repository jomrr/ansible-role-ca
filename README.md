# Ansible Role: ca

![GitHub](https://img.shields.io/github/license/jomrr/ansible-role-ca) ![GitHub last commit](https://img.shields.io/github/last-commit/jomrr/ansible-role-ca) ![GitHub issues](https://img.shields.io/github/issues-raw/jomrr/ansible-role-ca) [![dev](https://img.shields.io/github/actions/workflow/status/jomrr/ansible-role-ca/dev-push-smoke.yml?branch=dev&event=push&label=dev)](https://github.com/jomrr/ansible-role-ca/actions/workflows/dev-push-smoke.yml?query=branch%3Adev) [![main](https://img.shields.io/github/actions/workflow/status/jomrr/ansible-role-ca/main-full-gate.yml?branch=main&event=push&label=main)](https://github.com/jomrr/ansible-role-ca/actions/workflows/main-full-gate.yml?query=branch%3Amain)

Ansible role for managing a two-tier private CA with certificate issuance, CRLs, AIA, and CDP URLs.

## Purpose

This role manages a private two-tier PKI with a Root CA and Component, Network, and Identity issuing CAs.
It creates CA keys, CSRs, certificates, issuing CA chains, DER and text exports, CRLs, and managed certificates from inventory variables.

## Scope

### Managed

- Root CA and Component, Network, and Identity issuing CAs
- PEM, DER, and text exports for all CA certificates
- Issuing CA chain files
- Declarative certificates in `ca_certificates`
- Persistent non-secret CA inventory and state fragments below `<ca_base_dir>/inventory`
- Optional certificate fullchain PEM bundles
- TLS server and TLS client certificates from the Component CA
- Samba AD Domain Controller/MSKDC certificates from the Component CA
- FritzBox import bundles from the Component CA
- Optional FritzBox certificate deployment to FRITZ!OS
- Identity certificates for smartcard logon, S/MIME, and optional code signing
- EAP-TLS client certificates from the Network CA
- PEM and DER CRLs
- Embedded AIA and CDP URLs
- Optional systemd service and timer for CRL renewal

### Not Managed

- Publishing or serving AIA and CDP files
- Online certificate enrollment protocols
- OCSP responder services
- Importing certificates into applications or hardware tokens other than optional FritzBox deployment

## Requirements

- Target hosts need OpenSSL and Python cryptography bindings.
- CA private key passphrases are required as `key_passphrase` values in `ca_authorities`; store real values in Ansible Vault.
- PFX/PKCS#12 output requires a per-certificate `pfx_passphrase`.
- MSKDC certificates require `krb5_realm` or global `ca_kerberos_realm`, plus `ad_object_guid`.
- FritzBox deployment requires network access to FRITZ!OS and a user with certificate import permissions.
- CRL renewal systemd services read CA key passphrases from `/root/.profile` environment variables named `CA_<CA_NAME>_<AUTHORITY>_KEY_PASSPHRASE`, uppercased with non-alphanumeric characters replaced by underscores.

## Dependencies

```yaml
collections:
  - name: community.general
    version: '>=12.0.0'
```

## Role Variables

The following variables are part of the public role interface.

| Name | Type | Required | Default | Description |
| ---- | ---- | -------- | ------- | ----------- |
| `ca_name` | `str` | `false` | `Yourdomain` | CA name used in CA certificate common names and, lowercased, in the default CA working directory. |
| `ca_base_dir` | `str` | `false` |  | CA working directory.<br>Defaults to `/etc/pki/<ca_name \| lower>` on RedHat-family systems and `/etc/ssl/<ca_name \| lower>` on Debian and Suse-family systems. |
| `ca_base_url` | `str` | `false` | `http://pki.yourdomain.tld` | Base URL used when deriving default AIA and CDP URLs.<br>The default uses plain HTTP because AIA and CDP endpoints should be reachable without TLS bootstrapping. |
| `ca_kerberos_realm` | `str` | `false` | `` | Optional default Kerberos realm for MSKDC PKINIT SAN encoding. |
| `ca_owner` | `str` | `false` | `root` | Owner for managed CA files. |
| `ca_group` | `str` | `false` | `root` | Group for managed CA files. |
| `ca_no_log` | `bool` | `false` | `True` | Suppress task output that can contain private key passphrases or PFX passphrases. |
| `ca_subject` | `dict` | `false` | country: DE<br />state: Bayern<br />locality: Erlangen<br />organization: Yourdomain SE<br />organizational_unit: Yourdomain Certificate Authority | Default X.509 subject attributes added before the certificate common name. |
| `ca_default_bits` | `int` | `false` | `4096` | DH parameter size when `ca_create_dhparams=true`. |
| `ca_force_reissue` | `bool` | `false` | `False` | Force regeneration of keys, certificates, CRLs, and exports where supported. |
| `ca_certificate_async_timeout` | `int` | `false` | `600` | Async timeout in seconds for certificate and bundle jobs. |
| `ca_certificate_async_retries` | `int` | `false` | `600` | Number of async status retries for certificate and bundle jobs. |
| `ca_certificate_async_delay` | `int` | `false` | `1` | Delay in seconds between async status checks for certificate and bundle jobs. |
| `ca_authorities` | `list` | `false` |  | Managed CA topology. Store real `key_passphrase` values in Ansible Vault. |
| `ca_certificates` | `list` | `false` | [] | Certificates to manage. |
| `ca_crl_automation_enabled` | `bool` | `false` | `False` | Manage and enable CRL renewal timer instances.<br>The role enables `<ca_name \| lower>-crl-renew@<authority>.timer` for every authority.<br>The service sources `/root/.profile` and expects `CA_<CA_NAME>_<AUTHORITY>_KEY_PASSPHRASE` environment variables, uppercased with non-alphanumeric characters replaced by underscores. |
| `ca_crl_automation_ansible_playbook` | `str` | `false` | `ansible-playbook` | Command used by the CRL renewal service template. |
| `ca_crl_automation_on_calendar` | `str` | `false` | `daily` | systemd timer OnCalendar value. |
| `ca_crl_automation_randomized_delay_sec` | `str` | `false` | `15m` | systemd timer randomized delay. |
| `ca_crl_automation_persistent` | `bool` | `false` | `True` | systemd timer Persistent value. |
| `ca_create_dhparams` | `bool` | `false` | `False` | Generate Diffie-Hellman parameters under the platform PKI base directory. |

## Managed Files

- `/etc/pki/<ca_name | lower> on RedHat-family systems`
- `/etc/ssl/<ca_name | lower> on Debian and Suse-family systems`
- `<ca_base_dir>/ca/*-ca.pem`
- `<ca_base_dir>/ca/*-ca.der`
- `<ca_base_dir>/ca/*-ca.txt`
- `<ca_base_dir>/chains/*-ca-chain.pem for issuing CAs`
- `<ca_base_dir>/crl/*-ca.crl`
- `<ca_base_dir>/crl/*-ca.crl.pem`
- `<ca_base_dir>/csr/*.csr`
- `<ca_base_dir>/private/*-ca.key`
- `<ca_base_dir>/certs/*`
- `<ca_base_dir>/.locks/*`
- `<ca_base_dir>/inventory/ca-inventory.json`
- `<ca_base_dir>/inventory/state/*`
- `/etc/systemd/system/<ca_name | lower>-crl-renew@.service` when `ca_crl_automation_enabled=true`
- `/etc/systemd/system/<ca_name | lower>-crl-renew@.timer` when `ca_crl_automation_enabled=true`

## Security Notes

- CA private keys are passphrase-protected and their passphrases are supplied by inventory variables.
- CRL renewal timers source `/root/.profile`; define variables such as `CA_EXAMPLE_ROOT_KEY_PASSPHRASE` there for systemd-triggered renewal.
- Certificate private key passphrases are optional except for formats that require export passwords, such as PFX/PKCS#12.
- Fullchain bundles contain the certificate followed by its issuing chain and do not include the private key.
- FritzBox bundles are mode `0600` because they include the private key, certificate, and issuing chain.
- FritzBox deployment uploads the bundle, including the private key, to the configured FRITZ!OS endpoint and requires FRITZ!OS credentials from inventory variables.
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
- `ca_subject` supplies the default X.509 subject attributes; per-authority or per-certificate `subject` values override individual fields.
- The managed CA topology is declared in `ca_authorities`; `parent == name` creates a self-signed authority.
- Self-signed root CAs do not get a separate chain file because it would be identical to the root certificate.
- CRL renewal uses instantiated systemd timers named `<ca_name | lower>-crl-renew@<authority>.timer`, for example `example-crl-renew@root.timer`.
- Private keys default to RSA 4096. `key_type` and optional `key_size` can be set per authority or certificate; supported key types are RSA, ECDSA P-256/P-384, Ed25519, and Ed448.
- Certificate output formats default in the modules: standard certificates and MSKDC use `pem,der,txt`; Identity uses `pem,der,txt,pfx`; FritzBox uses `pem,der,txt,fritzbox`.
- Add `fullchain` to a certificate `formats` list to write `<name>-fullchain.pem`.
- Default certificate validity comes from the issuing authority `default_days`; per-certificate `days` overrides it.
- The CA inventory is maintained by internal state hooks in the authority, certificate, and CRL modules; it contains non-secret metadata such as serial numbers, fingerprints, subjects, issuers, validity windows, current certificate pointers, issued certificate history, revocation events, CRL metadata, status, and managed artifact paths.
- X.509 material, authority chains, certificate bundles, CRLs, and inventory composition use internal advisory locks below `<ca_base_dir>/.locks` so concurrent jobs for the same CA object cannot interleave their file writes.
- FritzBox bundles are assembled in the fixed order `certificate`, `chain`, `private_key`.
- FritzBox deployment runs only for certificate entries with `fritzbox_deploy.enabled=true`; it compares the desired leaf certificate with the current FRITZ!Box HTTPS certificate and uploads only when they differ, unless `ca_force_reissue=true`.
- FritzBox deployment uses `fritzbox_deploy.url`, defaults to `https://fritz.box`, and disables certificate verification by default because FRITZ!OS usually starts with a self-signed HTTPS certificate.
- Existing certificates are reissued when their key, CSR, certificate profile, or declared extensions change, or when `ca_force_reissue=true`.

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

Creates the Root CA and the three issuing CAs without certificates.

```yaml
---
- name: Manage private PKI
  hosts: ca_hosts
  gather_facts: true
  roles:
    - role: jomrr.ca
      vars:
        ca_name: Example
        ca_base_url: http://pki.example.org
        ca_authorities:
          - name: root
            common_name: Example Root CA
            parent: root
            days: 3652
            default_days: 397
            crl_days: 30
            key_passphrase: vaulted-root-passphrase
          - name: component
            common_name: Example Component CA
            parent: root
            days: 1826
            default_days: 397
            crl_days: 30
            key_passphrase: vaulted-component-passphrase
          - name: network
            common_name: Example Network CA
            parent: root
            days: 1826
            default_days: 397
            crl_days: 30
            key_passphrase: vaulted-network-passphrase
          - name: identity
            common_name: Example Identity CA
            parent: root
            days: 1826
            default_days: 730
            crl_days: 30
            key_passphrase: vaulted-identity-passphrase
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
        ca_base_url: http://pki.example.org
        ca_authorities:
          - name: root
            common_name: Example Root CA
            parent: root
            days: 3652
            default_days: 397
            crl_days: 30
            key_passphrase: vaulted-root-passphrase
          - name: component
            common_name: Example Component CA
            parent: root
            days: 1826
            default_days: 397
            crl_days: 30
            key_passphrase: vaulted-component-passphrase
          - name: network
            common_name: Example Network CA
            parent: root
            days: 1826
            default_days: 397
            crl_days: 30
            key_passphrase: vaulted-network-passphrase
          - name: identity
            common_name: Example Identity CA
            parent: root
            days: 1826
            default_days: 730
            crl_days: 30
            key_passphrase: vaulted-identity-passphrase
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

Copyright (c) 2019-2026 Jonas Mauer.
