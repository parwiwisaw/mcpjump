"""Fail unless a cargo-llvm-cov JSON report shows 100% branch coverage.

A missing report, a missing branch summary, or zero instrumented branches
also fails, so a silent change in instrumentation cannot pass as 100%.

Usage: python ci/branch_gate.py <coverage.json>
"""

import json
import sys


def branch_totals(path):
    try:
        with open(path, encoding="utf-8") as report:
            data = json.load(report)
        return data["data"][0]["totals"]["branches"]
    except (OSError, ValueError, KeyError, IndexError, TypeError) as error:
        sys.exit(f"branch gate: unreadable report {path!r}: {error!r}")


def main(argv):
    if len(argv) != 2:
        sys.exit("usage: branch_gate.py <coverage.json>")
    totals = branch_totals(argv[1])
    count, covered = totals.get("count"), totals.get("covered")
    if not isinstance(count, int) or not isinstance(covered, int):
        sys.exit(f"branch gate: branch counts missing: {totals!r}")
    if count == 0:
        sys.exit("branch gate: no branches instrumented; is --branch on?")
    if covered != count:
        sys.exit(f"branch gate: {covered}/{count} branches covered, need all")
    print(f"branch gate: {covered}/{count} branches covered")


if __name__ == "__main__":
    main(sys.argv)
