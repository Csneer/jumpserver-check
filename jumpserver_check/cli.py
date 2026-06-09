"""Thin unified command facade for legacy JumpServer check entrypoints."""

from __future__ import annotations

import argparse
import importlib
import sys
from collections.abc import Sequence

COMMAND_MODULES = {
    "preflight": "scripts.preflight_check",
    "detect": "scripts.jms_host_ip_check",
    "weekly": "scripts.run_weekly_check",
    "multi": "scripts.run_multi_check",
    "cleanup": "scripts.host_cleanup",
    "admin": "scripts.cleanup_admin_server",
    "notify": "scripts.wecom_notify",
    "yuque": "scripts.yuque_markdown_sync",
}


def run_legacy_module(module_name: str, argv: Sequence[str]) -> int:
    module = importlib.import_module(module_name)
    old_argv = sys.argv[:]
    sys.argv = [module_name.rsplit(".", 1)[-1] + ".py", *argv]
    try:
        try:
            module.main()
        except SystemExit as exc:
            code = exc.code
            if code is None:
                return 0
            if isinstance(code, int):
                return code
            return 1
        return 0
    finally:
        sys.argv = old_argv


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="jumpserver-check",
        description="Unified facade for JumpServer check workflows; legacy scripts remain compatible wrappers.",
    )
    parser.add_argument("command", choices=sorted(COMMAND_MODULES), help="workflow command to dispatch")
    parser.add_argument("args", nargs=argparse.REMAINDER, help="arguments passed through to the selected workflow")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    values = list(sys.argv[1:] if argv is None else argv)
    if len(values) >= 2 and values[0] == "admin" and values[1] == "serve":
        values = ["admin", *values[2:]]
    parser = build_parser()
    args = parser.parse_args(values)
    return run_legacy_module(COMMAND_MODULES[args.command], args.args)
