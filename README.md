# ansible-role-ca

![GitHub](https://img.shields.io/github/license/jomrr/ansible-role-ca) [![Build Status](https://travis-ci.org/jomrr/ansible-role-ca.svg?branch=master)](https://travis-ci.org/jomrr/ansible-role-ca)

**Ansible role for setting up a Certificate Authority with openssl.**

This role is flexible to set up a single tier CA, a 2-tier CA like

* Root CA
  * Intermediate CA

or a 3 CA with openssl consisting of

* Root CA
  * Intermediate CA
    * Component CA
    * Identity CA
    * Software CA

You could go further, but you would have to add additional config files in `templates/etc/`. Just have a look on the `ca_init_names` list of
dictionaries in the [defaults/main.yml](https://github.com/jomrr/ansible-role-ca/blob/master/defaults/main.yml) file.

The default is to set up a 3-tier CA like mentioned above.

The role is mainly created for use with a Samba AD in personal environments.

I know storing passwords on disk is not considered super safe, even with root-only permissions.
This is just a convenient way to operate and automate it...
if anyone gets root access to my systems, then sniffing my network traffic is the smaller problem.

If you want to operate an OCSP Responder as well, you have to configure it yourself, but you can include the URL of it already.

## Supported Platforms

* Archlinux
* CentOS 7, 8 (all with EPEL for pwgen)
* Debian 9, 10
* OpenSuse Leap 15.1, Tumbleweed
* Ubuntu 18.04, 20.04

## Requirements

Ansible 2.7 or higher is recommended.

## Variables

Variables and default for this role are:

```yaml
---
# role: ansible-role-ca
# file: defaults/main.yml

# The role is disabled by default, so you do not get in trouble.
# Checked in tasks/main.yml which includes tasks.yml if enabled.
ca_enabled: False

# ca configuration
ca_init_names:
  - name: '{{ ca_name }} Root CA'
    path: 'root'
    param: '-selfsign'
    sign: 'root'
    ext: 'root_ca_ext'
  - name: '{{ ca_name }} Intermediate CA'
    path: 'intermediate'
    param: ''
    sign: "root"
    ext: 'intermediate_ca_ext'
  - name: '{{ ca_name }} Component CA'
    path: 'component'
    param: ''
    sign: 'intermediate'
    ext: 'signing_ca_ext'
  - name: '{{ ca_name }} Identity CA'
    path: 'identity'
    param: ''
    sign: 'intermediate'
    ext: 'signing_ca_ext'
  - name: '{{ ca_name }} Software CA'
    path: 'software'
    param: ''
    sign: 'intermediate'
    ext: 'signing_ca_ext'

# general settings
ca_country: 'DE'
ca_state: 'Bayern'
ca_locality: 'Erlangen'
ca_organization: 'Yourdomain SE'
ca_organizational_unit: 'Yourdomain Certificate Authority'
ca_name: 'Yourdomain'  # display name
ca_dir: 'your'  # small letter, i.e. ca_base_dir = /etc/ssl/{{ ca_dir }}
ca_base_url: 'http://pki.yourdomain.tld'
ca_oscp_enable: False
ca_oscp_openssl_responder: False
ca_oscp_url: 'http://oscp.yourdomain.tld'
ca_default_bits: 4096
ca_default_md: 'sha512'
ca_unique_subject: 'yes'
ca_link_crls_to_webdir: ''
ca_create_dhparams: False
ca_cron_jobs:
  - name: "Generate CRLs for {{ ca_name }} CA"
    day: '*'
    hour: '0'
    minute: '1'
    job: "/usr/local/bin/{{ ca_dir }}-ca -g"
    state: present

# root-ca specific settings
ca_root_default_days: 3652
ca_root_default_crl_days: 30

# intermediate-ca specific tower_settings
ca_intermediate_default_days: 3652
ca_intermediate_default_crl_days: 30

# identity-ca specific settings
ca_identity_default_days: 1095
ca_identity_default_crl_days: 30

# component-ca specific settings
ca_component_default_days: 730
ca_component_default_crl_days: 30

# software-ca specific settings
ca_software_default_days: 1826
ca_software_default_crl_days: 30

# dictionary for certificate management
ca_certs: {}

# list of dicts of certs to revoke
ca_revoke: []
```

## Dependencies

None.

## Example Playbook

Executing the role with default values does not make much sense.

Here is an example ready to use:

The OIDs in the mskdc cert SubjectAlternativeName are

* Kerberos principalname = 1.3.6.1.5.2.2
* msADGUID = 1.3.6.1.4.1.311.25.1

and in the identity cert it is the user principal name

* msUPN = 1.3.6.1.4.1.311.20.2.3

I had some difficulties adding them as new OIDs to an openssl.cnf as described in many HowTos with openssl always complaining, that the OID already exists, so I chose to insert them directly...

Feel free to suggest a better solution, if you know one.

```yaml
---
# role: ansible-role-ca
# file: site.yml

- hosts: ca_system
  become: True
  vars:
    ca_enabled: True
    ca_country: 'DE'
    ca_state: 'Bayern'
    ca_locality: 'Erlangen'
    ca_organization: 'Homebase'
    ca_organizational_unit: 'Homebase Certificate Authority'
    ca_name: 'Homebase'
    ca_dir: 'home'
    ca_base_url: 'http://pki.yourdomain.tld'
    ca_certs:
      component:
        client:
          - cn: 'My Mobile'
            export:
              - DER
              - PEM
              - P12
          - cn: 'My Tablet'
        mskdc:
          - cn: 'dc.yourdomain.tld'
            san:
              - 'DNS = dc'
              - 'DNS = ad.yourdomain.tld'
              - 'IP = 192.168.10.10'
              - 'otherName = 1.3.6.1.5.2.2;UTF8:dc.yourdomain.tld'
              - 'otherName = 1.3.6.1.4.1.311.25.1;FORMAT:HEX,OCTETSTRING:2BEA00D953125447A22BCF28508DFED3'
        server:
          - cn: 'server.yourdomain.tld'
            san:
              - 'DNS = server.yourdomain.tld'
              - 'DNS = mail.yourdomain.tld'
              - 'IP = 192.168.10.11'
        timestamp:
          - cn: 'My Software Timestamp'
        ocsp:
          - cn: 'My OCSP Signature'
      identity:
        email:
          - cn: 'Jonas Mauer (Mail)'
            email: 'jonas@yourdomain.tld'
            san:
              - 'email:move'
              - 'email:jam@yourdomain.tld'
            protect_key: True
            export:
              - P12
        identity:
          - cn: 'Jonas Mauer (ID)'
            email: 'jonas@yourdomain.tld'
            san:
              - 'email:move'
              - 'otherName:1.3.6.1.4.1.311.20.2.3;UTF8:jonas@dc.yourdomain.tld'
            protect_key: True
            export:
              - P12
      software:
        codesign:
          - cn: 'My Software'
            protect_key: True
  roles:
    - role: ansible-role-ca
```

If you want to revoke keys:

```yaml
---
# role: ansible-role-ca
# file: site.yml

- hosts: ca_system
  become: True
  vars:
    ca_enabled: True
    ca_dir: 'home'
    ca_revoke:
      - { file: 'my-tablet', ca: 'component' }
      - { file: 'my-software', ca: 'software' }
  roles:
    - role: ansible-role-ca
```

You can also combine `ca_certs` and `ca_revoke`, then the keys named in both
dictionary lists will be renewed.

## License and Author

* Author:: [jomrr](https://github.com/jomrr/)
* Copyright:: 2020, [jomrr](https://github.com/jomrr/)

Licensed under [MIT License](https://opensource.org/licenses/MIT).
See [LICENSE](https://github.com/jomrr/ansible-role-ca/blob/master/LICENSE) file in repository.

## References

* [OpenSSL PKI Tutorial v1.1](https://pki-tutorial.readthedocs.io/en/latest/)
* [SambaWiki](https://wiki.samba.org/index.php/Samba_AD_Smart_Card_Login)
* [University of Birmingham](https://www.cs.bham.ac.uk/~smp/resources/peap/)
* [Wawszcak Tech Blog](http://wawszczak.pr0.pl/en/2016/05/17/openssl-msentca-gen-req/)
* [Microsoft Support](https://support.microsoft.com/en-us/help/291010/requirements-for-domain-controller-certificates-from-a-third-party-ca)
* [CAcert Wiki](http://wiki.cacert.org/DomainController)
* [heimdal](https://github.com/heimdal/heimdal/wiki/Setting-up-PK-INIT-and-Certificates)
