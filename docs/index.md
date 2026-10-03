# CA Role Overview

The role manages a private PKI from inventory variables. It installs the host
packages, prepares the working directory, invokes the
[jomrr.ca collection](https://github.com/jomrr/ansible-collection-ca), and
optionally distributes public CA artifacts to AIA/CDP webroots.

## Requirements

Install the role's collection dependencies before running it:

```console
ansible-galaxy collection install -r collections.yml
```

The role requires `jomrr.ca >=1.1.1,<2.0.0` and ansible-core >=2.20.
The CA host needs Python >=3.12 with `cryptography>=43` in its Ansible
interpreter. Distribution packages are installed by the role.

## Role Flow

1. Validate the configured authorities, certificate names, and revocation targets.
2. Prepare the host packages and CA working directory.
3. Create or renew authorities with `jomrr.ca.authority`, then derive their chains
   with `jomrr.ca.chain`.
4. Process `ca_certificates` with `jomrr.ca.certificate_batch`. Optional FritzBox
   deployment uses `jomrr.ca.fritzbox_deploy`.
5. Generate or renew CRLs with `jomrr.ca.crl`.
6. Build public archives with `jomrr.ca.publish_archive` and transfer them to
   `ca_publish_targets`.

For standalone certificate issuance, use `jomrr.ca.certificate`. The role
contains no production modules or private copies of collection utilities.

## Configuration and Operation

The [role README](../README.md) documents variables, profiles, renewal, policies,
revocation, approved external CSR identities, and example playbooks.
Certificates and CRLs renew seven days before expiry by default when the role
runs; schedule runs frequently enough to complete renewal and publication.

The collection owns the persistent inventory and issuer generation state.
The role passes its configured authorities to CRL generation and publishing,
which preserve the public issuer certificates and CRLs for retained generations.
See [AIA/CDP publishing](publishing.md) for the target model and transfer behavior.
