#!/usr/bin/env python3
"""Type-check role sources under their Ansible runtime module names."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from mypy.build import build
from mypy.modulefinder import BuildSource
from mypy.options import Options


def role_sources(root: Path) -> list[BuildSource]:
    """Map role and playbook module_utils to Ansible's shared import namespace."""
    sources: list[BuildSource] = []
    for directory in (
        root / "module_utils",
        root / "molecule/resources/playbooks/module_utils",
    ):
        sources.extend(
            BuildSource(str(path), f"ansible.module_utils.{path.stem}", None)
            for path in sorted(directory.glob("*.py"))
        )
    for directory in (
        root / "library",
        root / "filter_plugins",
        root / "molecule/resources/playbooks/library",
        root / "tools",
    ):
        sources.extend(
            BuildSource(str(path), path.stem, None)
            for path in sorted(directory.glob("*.py"))
        )
    return sources


def main() -> int:
    """Run mypy, including unannotated bodies and installed untyped imports."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python-executable", default=sys.executable)
    arguments = parser.parse_args()
    sources = role_sources(Path(__file__).resolve().parents[1])
    options = Options()
    options.python_executable = arguments.python_executable
    options.check_untyped_defs = True
    options.follow_untyped_imports = True
    options.warn_unused_ignores = True
    result = build(sources=sources, options=options)
    if result.errors:
        print("\n".join(result.errors))
        return 1
    print(f"Success: no issues found in {len(sources)} source files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
