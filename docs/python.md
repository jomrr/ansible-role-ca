# Python type checking

Run from the role repository:

```console
uv run --no-project --with mypy --with ansible-core --with cryptography python tools/check_mypy.py
```

With those dependencies already installed, run `python tools/check_mypy.py`.
`--python-executable /path/to/python` selects another interpreter for dependency
resolution.

Ansible loads role and playbook `module_utils` under `ansible.module_utils`.
The checker assigns these module names directly to the existing source files.
It checks modules, filters, shared helpers, the existing Molecule verifier and
the checker itself without copying Ansible or modifying its installation.

The check includes unannotated function bodies and follows untyped installed
imports. It uses no import ignores, rule exclusions or substitute type stubs.
As in a normal mypy run, diagnostics concern project sources; installed
dependencies supply their available type information. See mypy's documentation
on [import handling](https://mypy.readthedocs.io/en/stable/running_mypy.html)
and [installed packages](https://mypy.readthedocs.io/en/stable/installed_packages.html).

Dynamic Ansible parameter dictionaries still use `Any`; passing this check does
not imply strict typing of every input and return value.
