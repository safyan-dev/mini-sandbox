"""Shared helpers for the sandbox tests."""

from __future__ import annotations

import json


def facts(stdout: str) -> dict:
    """Parse the `FACTS=<json>` line a probe program prints."""
    for line in stdout.splitlines():
        if line.startswith("FACTS="):
            return json.loads(line[len("FACTS="):])
    return {}


def checks_report(results: list) -> str:
    """Render (name, ok, detail) tuples the same way the CLI does."""
    lines = []
    for name, ok, detail in results:
        lines.append("  [%s] %-30s %s" % ("PASS" if ok else "FAIL", name, detail))
    return "\n".join(lines)


def all_pass(results: list) -> bool:
    return all(ok for _, ok, _ in results)
