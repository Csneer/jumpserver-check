#!/usr/bin/env python3
"""Run the weekly JumpServer check end to end."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import preflight_check, profile_env, wecom_notify, yuque_markdown_sync  # noqa: E402


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TITLE = "JumpServer 主机探测与 IP 配置检测报告"
DEFAULT_SLUG = "jumpserver-host-ip-check"


def load_dotenv() -> None:
    for env_path in (Path.cwd() / ".env", PROJECT_ROOT / ".env"):
        if not env_path.exists():
            continue
        for raw in env_path.read_text(encoding="utf-8-sig").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            if key and not os.environ.get(key):
                os.environ[key] = value.strip().strip('"').strip("'")


def load_runtime_env(profile: str | None = None, env_file: str | None = None) -> profile_env.ProfileEnv:
    return profile_env.load_profile_env(profile, env_file)


def env_int(name: str, default: int) -> int:
    value = os.getenv(name, "").strip()
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def run_detect_subprocess(args: argparse.Namespace, timeout_seconds: int) -> dict[str, Any]:
    command = [
        sys.executable,
        str(PROJECT_ROOT / "scripts" / "jms_host_ip_check.py"),
    ]
    if args.no_proxy:
        command.append("--no-proxy")
    command.extend(
        [
            "detect",
            "--execution-mode",
            "batch",
            "--batch-size",
            "0",
            "--timeout",
            "-1",
            "--wait-timeout",
            str(timeout_seconds),
            "--poll-interval",
            str(args.poll_interval),
            "--output-dir",
            args.output_dir,
            "--raw-output-dir",
            args.raw_output_dir,
            "--retention-count",
            str(args.retention_count),
            "--resume-state",
            args.resume_state,
        ]
    )
    if args.no_resume:
        command.append("--no-resume")
    if args.query:
        command.extend(["--query", args.query])
    if args.max_assets is not None:
        command.extend(["--max-assets", str(args.max_assets)])

    print(f"[weekly-check] start detect subprocess, timeout={timeout_seconds}s, poll_interval={args.poll_interval}s", flush=True)
    started = time.time()
    process = subprocess.Popen(
        command,
        cwd=PROJECT_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        while True:
            returncode = process.poll()
            if returncode is not None:
                break
            elapsed = time.time() - started
            if elapsed > timeout_seconds:
                process.kill()
                process.communicate()
                raise TimeoutError(f"探测流程超过 {timeout_seconds}s 未完成")
            print(f"[weekly-check] detect still running, elapsed={elapsed:.0f}s/{timeout_seconds}s", flush=True)
            time.sleep(min(max(args.poll_interval, 1), 30))
        stdout, stderr = process.communicate()
    except KeyboardInterrupt:
        process.kill()
        process.communicate()
        raise
    if process.returncode != 0:
        raise RuntimeError(f"探测命令失败：{stderr.strip() or stdout.strip()}")
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"探测命令输出不是 JSON：{stdout[-1000:]}") from exc


def write_workflow_record(record: dict[str, Any], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    run_id = time.strftime("%Y%m%d-%H%M%S")
    path = output_dir / f"weekly-workflow-{run_id}.json"
    path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def build_notify_summary(detect_result: dict[str, Any] | None) -> dict[str, Any]:
    if not detect_result:
        return {}
    return {
        "summary": detect_result.get("summary") or {},
        "status_counts": detect_result.get("status_counts") or {},
        "paths": detect_result.get("paths") or {},
    }


def run_workflow(args: argparse.Namespace) -> dict[str, Any]:
    started = time.time()
    load_dotenv()
    detect_result: dict[str, Any] | None = None
    yuque_result: dict[str, Any] | None = None
    notify_result: dict[str, Any] | None = None
    status = "success"
    error_message = ""
    report_path = ""
    yuque_url = ""

    try:
        runtime_env = load_runtime_env(args.profile, args.env_file)
        preflight = preflight_check.validate_config(require_wecom=args.require_wecom, profile=args.profile, env_file=args.env_file)
        if not preflight.get("ok"):
            raise RuntimeError("前置配置检查失败：" + "；".join(preflight.get("errors") or []))
        detect_result = run_detect_subprocess(args, args.wait_timeout)
        paths = detect_result.get("paths") or {}
        report_path = str(paths.get("latest") or paths.get("report") or "")
        if not report_path:
            raise RuntimeError("探测完成但未返回报告路径")
        if args.dry_run_yuque:
            yuque_result = yuque_markdown_sync.sync_markdown(
                Path(report_path),
                title=args.yuque_title,
                slug=args.yuque_slug,
                toc_uuid=args.toc_uuid,
                sibling_url=args.sibling_url,
                audit_timestamp=True,
                dry_run=True,
            )
        else:
            yuque_result = yuque_markdown_sync.sync_markdown(
                Path(report_path),
                title=args.yuque_title,
                slug=args.yuque_slug,
                toc_uuid=args.toc_uuid,
                sibling_url=args.sibling_url,
                audit_timestamp=True,
                dry_run=False,
            )
        yuque_url = str((yuque_result or {}).get("url") or "")
    except TimeoutError as exc:
        status = "timeout"
        error_message = str(exc)
    except KeyboardInterrupt:
        status = "failed"
        error_message = "用户中断执行"
    except Exception as exc:
        status = "failed"
        error_message = str(exc)

    duration = time.time() - started
    notify_summary = build_notify_summary(detect_result)
    try:
        notify_result = wecom_notify.notify(
            status=status,
            title=args.notify_title,
            summary_json=json.dumps(notify_summary, ensure_ascii=False),
            report_path=report_path,
            yuque_url=yuque_url,
            error_message=error_message,
            duration_seconds=duration,
            dry_run=args.dry_run_notify,
        )
    except Exception as exc:
        notify_result = {"status": "failed", "error": str(exc)}
        print(f"提示：企业微信推送失败：{exc}", file=sys.stderr)

    record = {
        "profile": args.profile,
        "env_file": runtime_env.env_file if "runtime_env" in locals() else args.env_file,
        "loaded_env_files": runtime_env.loaded_files if "runtime_env" in locals() else [],
        "status": status,
        "duration_seconds": duration,
        "error_message": error_message,
        "detect": detect_result,
        "yuque": yuque_result,
        "wecom": notify_result,
    }
    record_path = write_workflow_record(record, PROJECT_ROOT / profile_env.profile_path("artifacts/workflow", args.profile))
    record["workflow_record"] = str(record_path)
    print(json.dumps(record, ensure_ascii=False, indent=2))
    return record


def parse_args() -> argparse.Namespace:
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument("--profile", default=profile_env.DEFAULT_PROFILE)
    pre_parser.add_argument("--env-file", default="")
    pre_args, _ = pre_parser.parse_known_args()
    runtime_env = load_runtime_env(pre_args.profile, pre_args.env_file)
    profile = runtime_env.profile
    parser = argparse.ArgumentParser(description="Run JumpServer check, sync Yuque report, and notify WeCom.")
    parser.add_argument("--profile", default=profile)
    parser.add_argument("--env-file", default=pre_args.env_file)
    parser.add_argument("--no-proxy", action="store_true")
    parser.add_argument("--wait-timeout", type=int, default=env_int("CHECK_WAIT_TIMEOUT", 1200))
    parser.add_argument("--poll-interval", type=int, default=env_int("CHECK_POLL_INTERVAL", 30))
    parser.add_argument("--output-dir", default=profile_env.profile_default_path(runtime_env, "CHECK_OUTPUT_DIR", "reports/yuque"))
    parser.add_argument("--raw-output-dir", default=profile_env.profile_default_path(runtime_env, "CHECK_RAW_OUTPUT_DIR", "artifacts/raw"))
    parser.add_argument(
        "--resume-state",
        default=str(PROJECT_ROOT / profile_env.profile_path("artifacts/state", profile) / "jms-host-ip-check-inflight.json"),
    )
    parser.add_argument("--retention-count", type=int, default=env_int("CHECK_RETENTION_COUNT", 12))
    parser.add_argument("--query", default="")
    parser.add_argument("--max-assets", type=int)
    parser.add_argument("--yuque-title", default=profile_env.profile_default_name(runtime_env, "CHECK_YUQUE_TITLE", DEFAULT_TITLE))
    parser.add_argument("--yuque-slug", default=profile_env.profile_default_name(runtime_env, "CHECK_YUQUE_SLUG", DEFAULT_SLUG, slug=True))
    parser.add_argument("--toc-uuid", default=os.getenv("YUQUE_TARGET_TOC_UUID", ""))
    parser.add_argument("--sibling-url", default=os.getenv("YUQUE_SIBLING_URL", ""))
    parser.add_argument(
        "--notify-title",
        default=profile_env.profile_default_name(runtime_env, "CHECK_NOTIFY_TITLE", "JumpServer 每周主机巡检"),
    )
    parser.add_argument("--dry-run-yuque", action="store_true")
    parser.add_argument("--dry-run-notify", action="store_true")
    parser.add_argument("--require-wecom", action="store_true", help="强制要求 WECOM_WEBHOOK_URL 已配置")
    parser.add_argument("--no-resume", action="store_true", help="不接续未解析的 JumpServer Ops job，强制新建任务")
    return parser.parse_args()


def main() -> None:
    record = run_workflow(parse_args())
    raise SystemExit(0 if record.get("status") == "success" else 1)


if __name__ == "__main__":
    main()
