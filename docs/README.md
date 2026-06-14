# CA Role Module Documentation

This directory documents the custom Ansible modules shipped with the CA role.

The documentation follows the same practical shape as Ansible module
documentation: each callable module has a purpose, behavior notes, accepted
parameters, defaults, secret handling notes, derived paths, and return values.
The source of truth remains the module `argument_spec` in `library/` and the
shared X.509 helpers in `module_utils/`.

The role currently ships these callable modules:

- `ca_authority`
- `ca_certificate`
- `ca_chain`
- `ca_crl`
- `ca_pkcs12_bundle`
- `ca_fullchain_bundle`
- `ca_fritzbox_bundle`
- `ca_fritzbox_deploy`
- `ca_dhparam`

`module_utils/` and `filter_plugins/` contain internal helpers. They are not
documented as user-facing modules here, but their behavior is reflected where it
affects module parameters or generated artifacts.

See [modules.md](modules.md) for the module reference.

Reference material used for this documentation style:

- Ansible Developer Guide, Module format and documentation:
  https://docs.ansible.com/projects/ansible/latest/dev_guide/developing_modules_documenting.html
- Ansible Developer Guide, Conventions, tips, and pitfalls:
  https://docs.ansible.com/projects/ansible/latest/dev_guide/developing_modules_best_practices.html
