#!/usr/bin/python
"""Manage an MSKDC/Samba AD domain controller certificate."""

from __future__ import annotations

from ansible.module_utils.x509_common import (  # type: ignore[import-not-found,import-untyped]
    run_x509_certificate_module,
)


def run_module():
    """Run the Ansible module for MSKDC domain controller certificates."""
    run_x509_certificate_module(
        fixed_profile="mskdc",
        extra_spec={
            "krb5_realm": {"type": "str", "required": True},
            "ad_object_guid": {"type": "str", "required": True},
        },
    )


def main():
    """Execute the module entry point."""
    run_module()


if __name__ == "__main__":
    main()
