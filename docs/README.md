# CA Role Module Documentation

Start with [index.md](index.md).

The documentation follows the same practical shape as Ansible module
documentation: each public module has a purpose, behavior notes, accepted
parameters, defaults, allowed values, return values, and examples. Internal
`module_utils/` and `filter_plugins/` files are documented separately because
they define shared behavior such as locking, path derivation, certificate
profile defaults, and CA inventory state.

Reference material used for this documentation style:

- Ansible Developer Guide, Module format and documentation:
  https://docs.ansible.com/projects/ansible/latest/dev_guide/developing_modules_documenting.html
- Ansible Developer Guide, Conventions, tips, and pitfalls:
  https://docs.ansible.com/projects/ansible/latest/dev_guide/developing_modules_best_practices.html
