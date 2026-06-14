#!/usr/bin/python
"""Manage a self-signed Root CA certificate."""

from __future__ import annotations

from ansible.module_utils.x509_common import (  # type: ignore[import-not-found,import-untyped]
    run_ca_authority_module,
)

ROOT_CA_DEFAULTS = {
    "basic_constraints": ["CA:TRUE", "pathlen:1"],
    "key_usage": ["keyCertSign", "cRLSign"],
    "digest": "sha384",
}


def run_module():
    """Run the Ansible module for a self-signed Root CA."""
    run_ca_authority_module(defaults=ROOT_CA_DEFAULTS)


def main():
    """Execute the module entry point."""
    run_module()


if __name__ == "__main__":
    main()
