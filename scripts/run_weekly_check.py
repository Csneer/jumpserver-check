#!/usr/bin/env python3
"""Run the weekly JumpServer check end to end."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import host_cleanup, preflight_check, profile_env, wecom_notify, yuque_markdown_sync  # noqa: E402
from jumpserver_check.runtime import RuntimeContext  # noqa: E402


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
    return RuntimeContext.for_profile(profile, env_file).env


def load_runtime_context(profile: str | None = None, env_file: str | None = None) -> RuntimeContext:
    return RuntimeContext.for_profile(profile, env_file)



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
            "--profile",
            args.profile,
            "--run-id",
            getattr(args, "run_id", ""),
            "--run-source",
            getattr(args, "run_source", "manual"),
            "--resume-state",
            args.resume_state,
        ]
    )
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


HOST_SNAPSHOT_FIELDS = (
    "asset_id",
    "asset_name",
    "asset_ip",
    "actual_ips",
    "ip_match",
    "ip_type",
    "ops_connectivity",
    "ip_reachability",
    "tcp_reachability",
    "probe_status",
    "original_probe_status",
    "node",
    "remark",
)
UNCHANGED_YUQUE_NOTE = "与上一轮结果对比无主机信息变动，已跳过语雀归档"


def stable_snapshot_path(profile: str) -> Path:
    return PROJECT_ROOT / profile_env.profile_path("artifacts/state", profile) / "last-stable-host-snapshot.json"


def normalize_host_result(result: dict[str, Any]) -> dict[str, Any]:
    return {field: result.get(field) for field in HOST_SNAPSHOT_FIELDS if result.get(field) not in (None, "")}


def has_host_identity(result: dict[str, Any]) -> bool:
    return any(str(result.get(field) or "").strip() for field in ("asset_id", "asset_ip", "asset_name"))


def normalized_host_results(detect_result: dict[str, Any]) -> list[dict[str, Any]]:
    items = [item for item in detect_result.get("results") or [] if isinstance(item, dict) and has_host_identity(item)]
    normalized = [normalize_host_result(item) for item in items]
    return sorted(normalized, key=lambda item: (str(item.get("asset_id") or ""), str(item.get("asset_ip") or ""), str(item.get("asset_name") or "")))


def has_host_results(payload: dict[str, Any]) -> bool:
    results = payload.get("results")
    return isinstance(results, list) and any(isinstance(item, dict) and has_host_identity(item) for item in results)


def detect_result_with_raw_results(detect_result: dict[str, Any], *, require_results: bool = False) -> dict[str, Any]:
    if isinstance(detect_result.get("results"), list):
        if require_results and not has_host_results(detect_result):
            raise RuntimeError("weekly stable snapshot requires raw host results: inline results does not contain any host result objects")
        return detect_result
    raw_path = str((detect_result.get("paths") or {}).get("raw") or "")
    if not raw_path:
        if require_results:
            raise RuntimeError("weekly stable snapshot requires raw host results: detect result omitted inline results and paths.raw is empty")
        return detect_result
    try:
        raw_payload = json.loads(Path(raw_path).read_text(encoding="utf-8"))
    except OSError as exc:
        if require_results:
            raise RuntimeError(f"weekly stable snapshot requires raw host results: cannot read paths.raw {raw_path}: {exc}") from exc
        return detect_result
    except json.JSONDecodeError as exc:
        if require_results:
            raise RuntimeError(f"weekly stable snapshot requires raw host results: paths.raw {raw_path} is invalid JSON: {exc}") from exc
        return detect_result
    if isinstance(raw_payload, dict) and isinstance(raw_payload.get("results"), list):
        if require_results and not has_host_results(raw_payload):
            raise RuntimeError(f"weekly stable snapshot requires raw host results: paths.raw {raw_path} does not contain any host result objects")
        merged = dict(detect_result)
        merged["results"] = raw_payload["results"]
        return merged
    if require_results:
        raise RuntimeError(f"weekly stable snapshot requires raw host results: paths.raw {raw_path} does not contain a results list")
    return detect_result


def host_hash(hosts: list[dict[str, Any]]) -> str:
    raw = json.dumps(hosts, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def build_host_snapshot(profile: str, detect_result: dict[str, Any], *, run_id: str = "", recovery_reason: str = "") -> dict[str, Any]:
    hosts = normalized_host_results(detect_result)
    snapshot = {
        "profile": profile,
        "host_hash": host_hash(hosts),
        "hosts": hosts,
        "last_run_id": run_id or str(detect_result.get("run_id") or ""),
        "last_checked_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    if recovery_reason:
        snapshot["recovery_reason"] = recovery_reason
    return snapshot


def load_host_snapshot(path: Path) -> tuple[dict[str, Any] | None, str]:
    if not path.exists():
        return None, "missing_snapshot"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None, "corrupt_snapshot"
    return (payload if isinstance(payload, dict) else None), "loaded"


def compare_host_snapshot(previous: dict[str, Any] | None, current: dict[str, Any], *, recovery_reason: str = "") -> dict[str, Any]:
    current_hosts = current.get("hosts") if isinstance(current.get("hosts"), list) else []
    previous_hosts = previous.get("hosts") if isinstance(previous, dict) and isinstance(previous.get("hosts"), list) else []
    previous_by_id = {str(item.get("asset_id") or item.get("asset_ip") or item.get("asset_name")): item for item in previous_hosts if isinstance(item, dict)}
    current_by_id = {str(item.get("asset_id") or item.get("asset_ip") or item.get("asset_name")): item for item in current_hosts if isinstance(item, dict)}
    added_keys = set(current_by_id) - set(previous_by_id)
    removed_keys = set(previous_by_id) - set(current_by_id)
    changed_keys = {key for key in set(current_by_id) & set(previous_by_id) if current_by_id[key] != previous_by_id[key]}
    changed = previous is None or previous.get("host_hash") != current.get("host_hash")
    diff = {
        "changed": changed,
        "host_hash": current.get("host_hash"),
        "previous_host_hash": previous.get("host_hash") if isinstance(previous, dict) else "",
        "added": len(added_keys) if previous is not None else len(current_by_id),
        "removed": len(removed_keys),
        "status_changed": len(changed_keys),
    }
    if not changed:
        diff["note"] = UNCHANGED_YUQUE_NOTE
    if recovery_reason and recovery_reason != "loaded":
        diff["recovery_reason"] = recovery_reason
    return diff


def update_snapshot_metadata(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    updated = dict(previous)
    updated["last_checked_at"] = current.get("last_checked_at")
    updated["last_run_id"] = current.get("last_run_id")
    return updated


def build_notify_summary(detect_result: dict[str, Any] | None) -> dict[str, Any]:
    if not detect_result:
        return {}
    return {
        "summary": detect_result.get("summary") or {},
        "status_counts": detect_result.get("status_counts") or {},
        "paths": detect_result.get("paths") or {},
    }


def run_cleanup_steps(args: argparse.Namespace, detect_result: dict[str, Any] | None) -> dict[str, Any]:
    if not (getattr(args, "cleanup_evaluate", False) or getattr(args, "cleanup_apply_confirmed", False)):
        return {"status": "skipped", "reason": "cleanup not requested"}
    raw_dir = Path(args.raw_output_dir)
    state_dir = host_cleanup.cleanup_profile_state_dir(args.profile)
    output_dir = host_cleanup.cleanup_output_dir(args.profile)
    plan = host_cleanup.evaluate_cleanup(args.profile, raw_dir, state_dir, output_dir, write_plan=True)
    result: dict[str, Any] | None = None
    if getattr(args, "cleanup_apply_confirmed", False):
        result = host_cleanup.apply_cleanup_plan(
            plan,
            profile=args.profile,
            state_dir=state_dir,
            output_dir=output_dir,
            dry_run=getattr(args, "cleanup_dry_run", False),
            allow_delete=getattr(args, "cleanup_allow_delete", False),
        )
    return {"status": "completed", "plan": plan, "apply": result}


def run_workflow(args: argparse.Namespace) -> dict[str, Any]:
    started = time.time()
    load_dotenv()
    if not getattr(args, "run_id", ""):
        args.run_id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]
    detect_result: dict[str, Any] | None = None
    yuque_result: dict[str, Any] | None = None
    notify_result: dict[str, Any] | None = None
    cleanup_result: dict[str, Any] | None = None
    host_snapshot_diff: dict[str, Any] | None = None
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
        use_stable_snapshot_diff = getattr(args, "run_source", "manual") == "weekly_scheduled"
        if use_stable_snapshot_diff:
            snapshot_source = detect_result_with_raw_results(detect_result, require_results=True)
            current_snapshot = build_host_snapshot(args.profile, snapshot_source, run_id=str(detect_result.get("run_id") or args.run_id))
            snapshot_path = stable_snapshot_path(args.profile)
            previous_snapshot, snapshot_state = load_host_snapshot(snapshot_path)
            host_snapshot_diff = compare_host_snapshot(previous_snapshot, current_snapshot, recovery_reason=snapshot_state)
        if not use_stable_snapshot_diff or (host_snapshot_diff and host_snapshot_diff.get("changed")):
            try:
                yuque_result = yuque_markdown_sync.sync_markdown(
                    Path(report_path),
                    title=args.yuque_title,
                    slug=args.yuque_slug,
                    toc_uuid=args.toc_uuid,
                    sibling_url=args.sibling_url,
                    audit_timestamp=True,
                    dry_run=bool(args.dry_run_yuque),
                )
            except Exception as exc:
                if not use_stable_snapshot_diff:
                    raise
                yuque_result = {"status": "failed", "error": str(exc)}
            if use_stable_snapshot_diff:
                host_cleanup.atomic_write_json(snapshot_path, current_snapshot)
        else:
            yuque_result = {"status": "skipped", "reason": "unchanged_host_snapshot", "note": UNCHANGED_YUQUE_NOTE}
            if previous_snapshot is not None:
                host_cleanup.atomic_write_json(snapshot_path, update_snapshot_metadata(previous_snapshot, current_snapshot))
        yuque_url = str((yuque_result or {}).get("url") or "")
        cleanup_result = run_cleanup_steps(args, detect_result)
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
    if host_snapshot_diff:
        notify_summary["host_snapshot_diff"] = host_snapshot_diff
    if cleanup_result and cleanup_result.get("status") != "skipped":
        notify_summary["cleanup"] = cleanup_result
    apply_result = cleanup_result.get("apply") if isinstance(cleanup_result, dict) and isinstance(cleanup_result.get("apply"), dict) else {}
    if apply_result:
        host_cleanup.notify_cleanup_delete_result(apply_result)
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
        "run_id": args.run_id,
        "run_source": getattr(args, "run_source", "manual"),
        "cleanup_evidence_eligible": bool(getattr(args, "cleanup_evidence_eligible", False)),
        "env_file": runtime_env.env_file if "runtime_env" in locals() else args.env_file,
        "loaded_env_files": runtime_env.loaded_files if "runtime_env" in locals() else [],
        "status": status,
        "duration_seconds": duration,
        "error_message": error_message,
        "detect": detect_result,
        "host_snapshot_diff": host_snapshot_diff,
        "yuque": yuque_result,
        "wecom": notify_result,
        "cleanup": cleanup_result,
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
    runtime_context = load_runtime_context(pre_args.profile, pre_args.env_file)
    runtime_env = runtime_context.env
    profile = runtime_context.profile
    parser = argparse.ArgumentParser(description="Run JumpServer check, sync Yuque report, and notify WeCom.")
    parser.add_argument("--profile", default=profile)
    parser.add_argument("--env-file", default=pre_args.env_file)
    parser.add_argument("--no-proxy", action="store_true")
    parser.add_argument("--wait-timeout", type=int, default=env_int("CHECK_WAIT_TIMEOUT", 1200))
    parser.add_argument("--poll-interval", type=int, default=env_int("CHECK_POLL_INTERVAL", 30))
    parser.add_argument("--output-dir", default=profile_env.display_path(runtime_context.output_dir, PROJECT_ROOT))
    parser.add_argument("--raw-output-dir", default=profile_env.display_path(runtime_context.raw_output_dir, PROJECT_ROOT))
    parser.add_argument(
        "--resume-state",
        default=str(runtime_context.resume_state),
    )
    parser.add_argument("--retention-count", type=int, default=env_int("CHECK_RETENTION_COUNT", 12))
    parser.add_argument("--run-id", default="")
    parser.add_argument(
        "--run-source",
        choices=("weekly_scheduled", "manual", "dry_run", "tmp_probe"),
        default=runtime_context.run_source,
    )
    parser.add_argument("--cleanup-evidence-eligible", action="store_true")
    parser.add_argument("--ip-reachability-check", action=argparse.BooleanOptionalAction, default=runtime_context.ip_reachability_check)
    parser.add_argument("--ip-ping-count", type=int, default=runtime_context.ip_ping_count)
    parser.add_argument("--ip-ping-timeout", type=int, default=runtime_context.ip_ping_timeout)
    parser.add_argument("--ip-ping-workers", type=int, default=runtime_context.ip_ping_workers)
    parser.add_argument("--tcp-reachability-check", action=argparse.BooleanOptionalAction, default=runtime_context.tcp_reachability_check)
    parser.add_argument("--tcp-reachability-ports", default=runtime_context.tcp_reachability_ports)
    parser.add_argument("--tcp-reachability-timeout", type=int, default=runtime_context.tcp_reachability_timeout)
    parser.add_argument("--tcp-reachability-workers", type=int, default=runtime_context.tcp_reachability_workers)
    parser.add_argument("--query", default="")
    parser.add_argument("--max-assets", type=int)
    parser.add_argument("--yuque-title", default=runtime_context.yuque_title)
    parser.add_argument("--yuque-slug", default=runtime_context.yuque_slug)
    parser.add_argument("--toc-uuid", default=os.getenv("YUQUE_TARGET_TOC_UUID", ""))
    parser.add_argument("--sibling-url", default=os.getenv("YUQUE_SIBLING_URL", ""))
    parser.add_argument(
        "--notify-title",
        default=runtime_context.notify_title,
    )
    parser.add_argument("--dry-run-yuque", action="store_true")
    parser.add_argument("--dry-run-notify", action="store_true")
    parser.add_argument("--cleanup-evaluate", action="store_true", help="巡检后生成废弃主机清理候选计划")
    parser.add_argument("--cleanup-apply-confirmed", action="store_true", help="巡检后对已确认废弃且通过门控的资产执行清理")
    parser.add_argument("--cleanup-dry-run", action="store_true", help="清理 apply 只演练，不调用 JumpServer mutation API")
    parser.add_argument("--cleanup-allow-delete", action="store_true", help="允许通过五重门控的 delete 动作")
    parser.add_argument("--require-wecom", action="store_true", help="强制要求 WECOM_WEBHOOK_URL 已配置")
    parser.add_argument("--no-resume", action="store_true", help="不接续未解析的 JumpServer Ops job，强制新建任务")
    return parser.parse_args()


def main() -> None:
    record = run_workflow(parse_args())
    raise SystemExit(0 if record.get("status") == "success" else 1)


if __name__ == "__main__":
    main()
