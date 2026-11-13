"""CLI entry point. Owner: Person 3.

    python -m src.main scenarios/home.yaml --out out/

Runs every case under every policy, collects blast radius, laptop outbound MB and
alerts, calls report.write_all, and prints the before-and-after table.
"""
from __future__ import annotations


def main(argv: list[str] | None = None) -> int:
    raise NotImplementedError


if __name__ == "__main__":
    raise SystemExit(main())
