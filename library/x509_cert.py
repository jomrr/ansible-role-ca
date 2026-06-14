#!/usr/bin/python
"""Manage a certificate signed by an issuing CA."""

from __future__ import annotations

from ansible.module_utils.x509_common import run_x509_certificate_module  # type: ignore[import-not-found,import-untyped]
from ansible.module_utils.x509_profiles import (  # type: ignore[import-not-found,import-untyped]
    STANDARD_CERTIFICATE_DEFAULTS,
)


PROFILE_DEFAULTS = STANDARD_CERTIFICATE_DEFAULTS


def run_module():
    """Run the Ansible module for standard certificates."""
    run_x509_certificate_module(
        profile_defaults=PROFILE_DEFAULTS,
        default_profile="tls_server",
    )


def main():
    """Execute the module entry point."""
    run_module()


if __name__ == "__main__":
    main()
