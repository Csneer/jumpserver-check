#!/usr/bin/env python3
"""Unified JumpServer check management facade.

This facade is intentionally thin: it normalizes the management command surface,
constructs no business rules, and mechanically dispatches to the existing
service entrypoints. Runtime defaults and profile-aware paths remain owned by
``scripts.profile_env.RuntimeContext`` and the service modules.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence
from contextlib import contextmanager
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import (  # noqa: E402
    cleanup_admin_server,
    host_cleanup,
    jms_host_ip_check,
    preflight_check,
    profile_env,
    run_multi_check,
    run_weekly_check,
    wecom_notify,
    yuque_markdown_sync,
)

DispatchMain = Callable[[], None]


COMMANDS: dict[str, tuple[DispatchMain, str]] = {
    "weekly": (run_weekly_check.main, "Run one profile weekly workflow"),
    "multi": (run_multi_check.main, "Run weekly workflows for multiple profiles"),
    "detect": (jms_host_ip_check.main, "Forward to host detection CLI"),
    "cleanup": (host_cleanup.main, "Evaluate/apply cleanup plans"),
    "admin": (cleanup_admin_server.main, "Run cleanup confirmation admin UI"),
    "preflight": (preflight_check.main, "Validate local/profile configuration"),
    "notify": (wecom_notify.main, "Send WeCom notification"),
    "yuque": (yuque_markdown_sync.main, "Sync a Markdown report to Yuque"),
}


@contextmanager
def forwarded_argv(argv: Sequence[str]):
    previous = sys.argv[:]
    sys.argv = [previous[0], *argv]
    try:
        yield
    finally:
        sys.argv = previous


def dispatch(command: str, argv: Sequence[str]) -> int:
    """Dispatch a facade command without adding defaults or business rules."""
    if command not in COMMANDS:
        raise SystemExit(f"unknown command: {command}")
    main, _ = COMMANDS[command]
    forwarded = [*argv]
    if command == "detect" and not any(item in {"validate-auth", "list-assets", "detect"} for item in forwarded):
        forwarded.insert(0, "detect")
    with forwarded_argv(forwarded):
        try:
            main()
        except SystemExit as exc:
            code = exc.code
            if code is None:
                return 0
            if isinstance(code, int):
                return code
            print(code, file=sys.stderr)
            return 1
    return 0


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Unified JumpServer check management facade.")
    parser.add_argument("command", choices=sorted(COMMANDS), help="Management command to dispatch")
    parser.add_argument("args", nargs=argparse.REMAINDER, help="Arguments forwarded to the selected command")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    return dispatch(args.command, args.args)


if __name__ == "__main__":
    raise SystemExit(main())
