#!/usr/bin/env python3
"""Run weekly checks for multiple JumpServer profiles concurrently."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import profile_env  # noqa: E402


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def parse_profiles(value: str) -> list[str]:
    profiles = [profile_env.normalize_profile(item.strip()) for item in value.split(",") if item.strip()]
    if not profiles:
        raise argparse.ArgumentTypeError("--profiles 至少要包含一个 profile")
    return profiles


def build_profile_command(args: argparse.Namespace, profile: str) -> list[str]:
    command = [
        sys.executable,
        str(PROJECT_ROOT / "scripts" / "run_weekly_check.py"),
        "--profile",
        profile,
    ]
    if args.no_proxy:
        command.append("--no-proxy")
    if args.require_wecom:
        command.append("--require-wecom")
    if args.dry_run_yuque:
        command.append("--dry-run-yuque")
    if args.dry_run_notify:
        command.append("--dry-run-notify")
    if getattr(args, "cleanup_evaluate", False):
        command.append("--cleanup-evaluate")
    if getattr(args, "cleanup_apply_confirmed", False):
        command.append("--cleanup-apply-confirmed")
    if getattr(args, "cleanup_dry_run", False):
        command.append("--cleanup-dry-run")
    if getattr(args, "cleanup_allow_delete", False):
        command.append("--cleanup-allow-delete")
    if getattr(args, "run_source", ""):
        command.extend(["--run-source", args.run_source])
    if getattr(args, "cleanup_evidence_eligible", False):
        command.append("--cleanup-evidence-eligible")
    if getattr(args, "ip_reachability_check", False):
        command.append("--ip-reachability-check")
    else:
        command.append("--no-ip-reachability-check")
    command.extend(["--ip-ping-count", str(getattr(args, "ip_ping_count", 1))])
    command.extend(["--ip-ping-timeout", str(getattr(args, "ip_ping_timeout", 1))])
    command.extend(["--ip-ping-workers", str(getattr(args, "ip_ping_workers", 32))])
    if getattr(args, "tcp_reachability_check", False):
        command.append("--tcp-reachability-check")
    else:
        command.append("--no-tcp-reachability-check")
    command.extend(["--tcp-reachability-ports", str(getattr(args, "tcp_reachability_ports", "22"))])
    command.extend(["--tcp-reachability-timeout", str(getattr(args, "tcp_reachability_timeout", 1))])
    command.extend(["--tcp-reachability-workers", str(getattr(args, "tcp_reachability_workers", 32))])
    if args.no_resume:
        command.append("--no-resume")
    if args.wait_timeout is not None:
        command.extend(["--wait-timeout", str(args.wait_timeout)])
    if args.poll_interval is not None:
        command.extend(["--poll-interval", str(args.poll_interval)])
    return command


def run_profile(args: argparse.Namespace, profile: str) -> dict[str, Any]:
    command = build_profile_command(args, profile)
    print(f"[multi-check] start profile={profile}", flush=True)
    completed = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    record: dict[str, Any] = {}
    if completed.stdout:
        start = completed.stdout.rfind("\n{")
        raw_json = completed.stdout[start + 1 :] if start >= 0 else completed.stdout
        try:
            record = json.loads(raw_json)
        except json.JSONDecodeError:
            record = {}
    result = {
        "profile": profile,
        "returncode": completed.returncode,
        "status": record.get("status") or ("success" if completed.returncode == 0 else "failed"),
        "workflow_record": record.get("workflow_record", ""),
        "stdout_tail": completed.stdout[-2000:],
        "stderr_tail": completed.stderr[-2000:],
    }
    print(f"[multi-check] finish profile={profile} status={result['status']} returncode={completed.returncode}", flush=True)
    return result


def run_multi(args: argparse.Namespace) -> dict[str, Any]:
    profiles = parse_profiles(args.profiles)
    worker_count = max(1, min(args.parallel, len(profiles)))
    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {executor.submit(run_profile, args, profile): profile for profile in profiles}
        for future in as_completed(future_map):
            results.append(future.result())
    results.sort(key=lambda item: profiles.index(str(item["profile"])))
    status = "success" if all(item["returncode"] == 0 and item["status"] == "success" for item in results) else "failed"
    summary = {"status": status, "profiles": results}
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run weekly JumpServer checks for multiple profiles.")
    parser.add_argument("--profiles", required=True, help="逗号分隔的 profile 列表，例如 prod,test")
    parser.add_argument("--parallel", type=int, default=2, help="并发 profile 数")
    parser.add_argument("--no-proxy", action="store_true")
    parser.add_argument("--require-wecom", action="store_true")
    parser.add_argument("--dry-run-yuque", action="store_true")
    parser.add_argument("--dry-run-notify", action="store_true")
    parser.add_argument("--cleanup-evaluate", action="store_true")
    parser.add_argument("--cleanup-apply-confirmed", action="store_true")
    parser.add_argument("--cleanup-dry-run", action="store_true")
    parser.add_argument("--cleanup-allow-delete", action="store_true")
    parser.add_argument("--run-source", choices=("weekly_scheduled", "manual", "dry_run", "tmp_probe"), default="")
    parser.add_argument("--cleanup-evidence-eligible", action="store_true")
    parser.add_argument("--ip-reachability-check", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--ip-ping-count", type=int, default=1)
    parser.add_argument("--ip-ping-timeout", type=int, default=1)
    parser.add_argument("--ip-ping-workers", type=int, default=32)
    parser.add_argument("--tcp-reachability-check", action=argparse.BooleanOptionalAction, default=False)
    parser.add_argument("--tcp-reachability-ports", default="22")
    parser.add_argument("--tcp-reachability-timeout", type=int, default=1)
    parser.add_argument("--tcp-reachability-workers", type=int, default=32)
    parser.add_argument("--no-resume", action="store_true")
    parser.add_argument("--wait-timeout", type=int)
    parser.add_argument("--poll-interval", type=int)
    return parser.parse_args()


def main() -> None:
    result = run_multi(parse_args())
    raise SystemExit(0 if result.get("status") == "success" else 1)


if __name__ == "__main__":
    main()
