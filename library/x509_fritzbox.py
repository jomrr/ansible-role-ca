#!/usr/bin/python
"""Manage a FritzBox certificate signed by an issuing CA."""

from __future__ import annotations

from ansible.module_utils.x509_common import (  # type: ignore[import-not-found,import-untyped]
    run_x509_certificate_module,
)


def run_module():
    """Run the Ansible module for FritzBox certificate profiles."""
    run_x509_certificate_module(fixed_profile="fritzbox")


def main():
    """Execute the module entry point."""
    run_module()


if __name__ == "__main__":
    main()
