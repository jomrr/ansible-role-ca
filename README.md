# ansible-role-ca

![GitHub](https://img.shields.io/github/license/jam82/ansible-role-ca) [![Build Status](https://travis-ci.org/jam82/ansible-role-ca.svg)](https://travis-ci.org/jam82/ansible-role-ca)

**Ansible role for setting up a certificate authority.**

## Supported Platforms

- Alpine
- Archlinux
- CentOS
- Debian
- Fedora
- OpenSuse Leap, Tumbleweed
- OracleLinux
- Ubuntu

## Requirements

Ansible 2.9 or higher.

## Variables

Variables and defaults for this role.

### defaults/main.yml

```yaml
ca_role_enabled: false
```

## Dependencies

None.

## Example Playbook

```yaml
---
# role: ansible-role-ca
# file: site.yml

- hosts: all
  become: true
  gather_facts: true
  vars:
    ca_role_enabled: true
  roles:
    - role: ansible-role-ca
```

## License and Author

- Author:: [jam82](https://github.com/jam82/)
- Copyright:: 2021, [jam82](https://github.com/jam82/)

Licensed under [MIT License](https://opensource.org/licenses/MIT).
See [LICENSE](https://github.com/jam82/ansible-role-ca/blob/master/LICENSE) file in repository.

## References

- [ArchWiki](https://wiki.archlinux.org/)
