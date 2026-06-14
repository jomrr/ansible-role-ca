#!/usr/bin/python
"""Manage an identity certificate signed by an issuing CA."""

from __future__ import annotations

from ansible.module_utils.x509_common import (  # type: ignore[import-not-found,import-untyped]
    IDENTITY_CERTIFICATE_DEFAULTS,
    run_x509_certificate_module,
)


PROFILE_DEFAULTS = IDENTITY_CERTIFICATE_DEFAULTS


def run_module():
    """Run the Ansible module for identity certificate profiles."""
    run_x509_certificate_module(
        profile_defaults=PROFILE_DEFAULTS,
        default_profile="identity",
    )


def main():
    """Execute the module entry point."""
    run_module()


if __name__ == "__main__":
    main()
