"""CLI for rmm-abuse-map."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .parse import RelayObservation, cluster_by_relay, parse_cmdline


def _load_lines(path: Path) -> list[str]:
    lines: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        lines.append(line)
    return lines


def cmd_parse(args: argparse.Namespace) -> int:
    observations: list[RelayObservation] = []
    if args.string:
        observations.append(parse_cmdline(args.string, source="cli"))
    if args.file:
        for i, line in enumerate(_load_lines(Path(args.file)), 1):
            observations.append(parse_cmdline(line, source=f"{args.file}:{i}"))
    if not observations:
        print("Provide --string and/or --file", file=sys.stderr)
        return 2

    out = [o.to_dict() for o in observations]
    if args.cluster:
        payload = {"version": __version__, "clusters": cluster_by_relay(observations)}
    else:
        payload = {"version": __version__, "observations": out}

    text = json.dumps(payload, indent=2)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="rmm-abuse-map",
        description="Map ScreenConnect / RMM client indicators to relay hosts",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    parse_p = sub.add_parser("parse", help="Parse command lines / installer URLs")
    parse_p.add_argument("-s", "--string", help="Single command line or URL")
    parse_p.add_argument("-f", "--file", help="File with one cmdline/URL per line")
    parse_p.add_argument("-c", "--cluster", action="store_true", help="Cluster by relay host")
    parse_p.add_argument("-o", "--output", help="Write JSON to path")
    parse_p.set_defaults(func=cmd_parse)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
