# ansible-role-ca ![GitHub](https://img.shields.io/github/license/jam82/ansible-role-ca) [![Build Status](https://travis-ci.org/jam82/ansible-role-ca.svg?branch=master)](https://travis-ci.org/jam82/ansible-role-ca)

Ansible role for setting up a Certificate Authority with openssl.

This roles can felxibly set up a single tier CA, a 2-tier CA like:

* Root CA
  * Intermediate CA

or a 3/multi-tier CA with openssl consisting of

* Root CA
  * Intermediate CA
    * Component CA
    * Identity CA
    * Software CA

You can even go further, just have a look on the `ca_init_names` list of
dictionaries in the [defaults/main.yml](https://github.com/jam82/ansible-role-ca/blob/master/defaults/main.yml) file.

The default is to set up a 3-tier CA like mentioned above.

The role is mainly created for use with a Samba AD in personal environments.

I know storing passwords on disk is not considered super safe, even with root only permissions.
This is just a convenient way to operate and automate it...
if anyone gets root access to my systems, then sniffing my network traffic is the smaller problem.

If you want to operate an OCSP Responder as well, you have to configure it yourself, but you can include the URL of it already.

## Supported Platforms

* Archlinux
* CentOS 8 with EPEL Repo
* Debian 10
* Ubuntu 18.04

## Requirements

Ansible 2.7 or higher is recommended.

## Variables

Variables for this

| variable | default value in defaults/main.yml | description |
| -------- | ---------------------------------- | ----------- |
| ca_enabled | False | Determine whether role is enabled (True) or not (False) |
| ca_country | 'DE' | Country in distginguished name |
| ca_state | 'Bayern' | StateOrProvince in distginguished name |
| ca_locality | 'Erlangen' | City in distginguished name |
| ca_organization | 'Yourdomain Private' | Oragnization in distginguished name |
| ca_organizational_unit | 'Yourdomain Certificate Authority' | OragnizationalUnit in distginguished name |
| ca_name | 'Yourdomain' | DisplayName of the CA, in this case "Mustermann Root CA", etc. |
| ca_dir | 'your'  | Foldername/filename to store the CA in in /etc/ssl/ and for the scripts |
| ca_base_url | '<http://pki.yourdomain.tld>' | Base URL used for building CRL path, etc. |
| ca_ocsp_enable | False | Add OCSP Information to openssl config files |
| ca_ocsp_url | '<http://oscp.yourdomain.tld>' | FQDN of OCSP responder |
| ca_default_bits | 4096 | Default key size of RSA keys |
| ca_default_md | 'sha512' | Default hash algorithm to use, SHA2-512 |
| ca_unique_subject | 'yes' | Unique subjects mean, that two certificates cannot have the same CommonName |
| ca_link_crls_to_webdir | '' | Create symlinks for CRLs to Webserver directory (see ca_base_url) |
| ca_create_dhparams | False | When True creates a 4096 bit Diffie-Hellman parameters file (takes a long time, ~12 min) |
| ca_cron_jobs | [{ name: "Generate CRLs for {{ ca_name }} CA", day: '*', hour: '0', minute: '1', job: "/usr/local/bin/{{ ca_dir }}-ca -g", state: present }] | List of cronjobs to generate CRLs (run daily/weekly) |
| ca_root_default_days | 3652 | No of days the root CA and its signed certs are valid |
| ca_root_default_crl_days | 30 | No of days the root CA CRLs are valid |
| ca_intermediate_default_days | 3652 | No of days certificates from Intermediate CA are valid |
| ca_intermediate_default_crl_days | 30 | No of days the Intermediate CA CRLs are valid |
| ca_identity_default_days | 1095 | No of days certificates from Identity CA are valid |
| ca_identity_default_crl_days | 30 | No of days the Identity CA CRLs are valid |
| ca_component_default_days | 730 | No of days certificates from Component CA are valid |
| ca_component_default_crl_days | 30 | No of days the Component CA CRLs are valid |
| ca_software_default_days | 1826 | No of days certificates from Software CA are valid |
| ca_software_default_crl_days | 30 | No of days the Software CA CRLs are valid |
| ca_certs | {} | Dictionary of certificate infos, for certs to create. See [Example](#example) |
| ca_revoke | [] | List of dicts, i.e. `- { file: 'my-phone', ca: 'component' }`. Looks for `file`.pem in `/etc/ssl/{{ca_dir}}/certs`. |

## Dependencies

None.

## Example Playbook

Executing the role with default values does not make much sense.

Here is an example ready to use: <a name="example"></a>

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

You can also combine ca_certs and ca_revoke, then the keys named in both
dictionary lists will be renewed.

## License and Author

* Author:: Jonas Mauer (<jam@kabelmail.net>)
* Copyright:: 2019, Jonas Mauer

Licensed under MIT License;
See LICENSE file in repository.

## References

* [OpenSSL PKI Tutorial v1.1](https://pki-tutorial.readthedocs.io/en/latest/)
* [SambaWiki](https://wiki.samba.org/index.php/Samba_AD_Smart_Card_Login)
* [University of Birmingham](https://www.cs.bham.ac.uk/~smp/resources/peap/)
* [Wawszcak Tech Blog](http://wawszczak.pr0.pl/en/2016/05/17/openssl-msentca-gen-req/)
* [Microsoft Support](https://support.microsoft.com/en-us/help/291010/requirements-for-domain-controller-certificates-from-a-third-party-ca)
* [CAcert Wiki](http://wiki.cacert.org/DomainController)
* [heimdal](https://github.com/heimdal/heimdal/wiki/Setting-up-PK-INIT-and-Certificates)
