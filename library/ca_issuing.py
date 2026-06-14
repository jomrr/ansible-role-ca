#!/usr/bin/python
"""Manage an Issuing CA certificate signed by a parent CA."""

from __future__ import annotations

from ansible.module_utils.x509_common import (  # type: ignore[import-not-found,import-untyped]
    run_ca_authority_module,
)

ISSUING_CA_DEFAULTS = {
    "basic_constraints": ["CA:TRUE", "pathlen:0"],
    "key_usage": ["keyCertSign", "cRLSign"],
    "digest": "sha384",
}


def run_module():
    """Run the Ansible module for an issuing CA."""
    run_ca_authority_module(defaults=ISSUING_CA_DEFAULTS, signed=True)


def main():
    """Execute the module entry point."""
    run_module()


if __name__ == "__main__":
    main()
