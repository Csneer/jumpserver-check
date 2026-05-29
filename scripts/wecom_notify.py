#!/usr/bin/env python3
"""Send reusable WeCom webhook notifications for scheduled checks."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib import error, request


PROJECT_ROOT = Path(__file__).resolve().parents[1]
STATUS_COUNT_LABELS = {
    "ok_static": "静态IP正常",
    "warn_dhcp": "DHCP告警",
    "manual_check": "需人工复核",
    "ip_mismatch": "IP不匹配",
    "duplicate_asset": "重复资产",
    "jumpserver_unreachable_ip_reachable": "JumpServer不可达但IP可达",
    "unreachable": "不可达",
    "api_error": "API异常",
    "log_fetch_error": "日志拉取异常",
    "probe_timeout": "探测超时",
    "ops_no_output": "Ops无输出",
    "ops_module_error": "Ops模块错误",
    "ops_task_failed": "Ops任务失败",
    "permission_denied": "未授权",
    "no_account": "无账号",
    "parse_error": "解析失败",
    "probe_script_error": "探测脚本异常",
    "skipped_non_linux": "跳过非Linux",
    "skipped_windows": "跳过Windows",
}

ACTION_LABELS = {
    "confirm": "确认废弃",
    "protect": "保护",
    "review": "标记复查",
}


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


def load_summary(summary_json: str) -> dict[str, Any]:
    if not summary_json:
        return {}
    source = summary_json.strip()
    try:
        payload = json.loads(source)
    except json.JSONDecodeError as json_error:
        try:
            path = Path(source)
            if not path.is_file():
                raise ValueError("--summary-json 必须是 JSON 字符串或可读取的 JSON 文件路径") from json_error
            payload = json.loads(path.read_text(encoding="utf-8"))
        except OSError as path_error:
            raise ValueError("--summary-json 必须是 JSON 字符串或可读取的 JSON 文件路径") from path_error
    return payload if isinstance(payload, dict) else {}


def cleanup_plan_summary_text(plan_summary: dict[str, Any]) -> str:
    parts = [
        f"候选 {plan_summary.get('candidates', 0)}",
        f"需人工复核 {plan_summary.get('review_required', 0)}",
        f"跳过 {plan_summary.get('skipped', 0)}",
    ]
    return " / ".join(parts)


def review_required_preview(plan: dict[str, Any], limit: int = 5) -> str:
    items = plan.get("review_required") if isinstance(plan.get("review_required"), list) else []
    previews: list[str] = []
    for item in items[:limit]:
        if not isinstance(item, dict):
            continue
        label = str(item.get("asset_name") or item.get("asset_id") or "-")
        ip = str(item.get("asset_ip") or "")
        previews.append(f"{label}({ip})" if ip else label)
    if len(items) > limit:
        previews.append(f"等{len(items)}台")
    return "，".join(previews)

def status_label(status: str) -> str:
    labels = {"success": "成功", "failed": "失败", "timeout": "超时"}
    return labels.get(status, status)


def status_count_label(key: str) -> str:
    return STATUS_COUNT_LABELS.get(key, key)


def build_markdown_message(
    status: str,
    title: str,
    summary: dict[str, Any] | None = None,
    report_path: str = "",
    yuque_url: str = "",
    error_message: str = "",
    duration_seconds: float | None = None,
) -> str:
    summary = summary or {}
    status_counts = summary.get("status_counts") if isinstance(summary.get("status_counts"), dict) else {}
    run_summary = summary.get("summary") if isinstance(summary.get("summary"), dict) else summary
    lines = [f"## {title}", "", f"> 状态：**{status_label(status)}**"]
    if duration_seconds is not None:
        lines.append(f"> 耗时：{duration_seconds:.1f}s")
    if error_message:
        lines.extend(["", f"**错误**：{error_message}"])
    if run_summary:
        total_assets = run_summary.get("total_assets", "")
        linux_assets = run_summary.get("linux_assets", "")
        unauthorized = run_summary.get("unauthorized_assets", "")
        lines.extend(["", f"- 活跃资产：{total_assets}", f"- 参与探测：{linux_assets}", f"- 未授权资产：{unauthorized}"])
    if status_counts:
        ordered = [
            "ok_static",
            "warn_dhcp",
            "manual_check",
            "ip_mismatch",
            "duplicate_asset",
            "jumpserver_unreachable_ip_reachable",
            "unreachable",
            "api_error",
            "log_fetch_error",
            "probe_timeout",
            "ops_no_output",
            "ops_module_error",
            "ops_task_failed",
            "permission_denied",
            "no_account",
            "parse_error",
            "probe_script_error",
            "skipped_non_linux",
            "skipped_windows",
        ]
        count_text = "，".join(
            f"{status_count_label(key)}: {status_counts.get(key, 0)}" for key in ordered if status_counts.get(key, 0)
        )
        lines.extend(["", f"- 分类：{count_text or '无异常分类'}"])
    cleanup = summary.get("cleanup") if isinstance(summary.get("cleanup"), dict) else {}
    if cleanup:
        plan = cleanup.get("plan") if isinstance(cleanup.get("plan"), dict) else {}
        apply = cleanup.get("apply") if isinstance(cleanup.get("apply"), dict) else {}
        plan_summary = plan.get("summary") if isinstance(plan.get("summary"), dict) else {}
        apply_results = apply.get("results") if isinstance(apply.get("results"), list) else []
        lines.extend(
            [
                "",
                "- 清理候选："
                + cleanup_plan_summary_text(plan_summary)
                + (f" / 执行结果 {len(apply_results)}" if apply else ""),
            ]
        )
        preview = review_required_preview(plan)
        if preview:
            lines.append(f"- IP可达需复核：{preview}")
        if plan.get("plan_path"):
            lines.append(f"- 清理计划：`{plan.get('plan_path')}`")
        if apply.get("result_path"):
            lines.append(f"- 清理结果：`{apply.get('result_path')}`")
    if yuque_url:
        lines.append(f"- 语雀：[{yuque_url}]({yuque_url})")
    if report_path:
        lines.append(f"- 本地报告：`{report_path}`")
    return "\n".join(lines)


def ordered_status_counts(status_counts: dict[str, Any]) -> list[tuple[str, int]]:
    ordered = [
        "ok_static",
        "warn_dhcp",
        "manual_check",
        "ip_mismatch",
        "duplicate_asset",
        "jumpserver_unreachable_ip_reachable",
        "unreachable",
        "api_error",
        "log_fetch_error",
        "probe_timeout",
        "ops_no_output",
        "ops_module_error",
        "ops_task_failed",
        "permission_denied",
        "no_account",
        "parse_error",
        "probe_script_error",
        "skipped_non_linux",
        "skipped_windows",
    ]
    result: list[tuple[str, int]] = []
    for key in ordered:
        value = status_counts.get(key, 0)
        if isinstance(value, int) and value:
            result.append((key, value))
    return result


def build_relay_message(
    status: str,
    summary: dict[str, Any] | None = None,
    yuque_url: str = "",
    error_message: str = "",
    duration_seconds: float | None = None,
) -> str:
    summary = summary or {}
    status_counts = summary.get("status_counts") if isinstance(summary.get("status_counts"), dict) else {}
    run_summary = summary.get("summary") if isinstance(summary.get("summary"), dict) else summary

    status_text = f"**状态**：{status_label(status)}"
    if duration_seconds is not None:
        status_text += f"（耗时 {duration_seconds:.1f}s）"
    lines = [status_text]
    if error_message:
        lines.append(f"**错误**：{error_message}")
    if run_summary:
        total_assets = run_summary.get("total_assets", "")
        linux_assets = run_summary.get("linux_assets", "")
        unauthorized = run_summary.get("unauthorized_assets", "")
        lines.append(f"**资产**：活跃 {total_assets} / 探测 {linux_assets} / 未授权 {unauthorized}")
    if status_counts:
        ok_count = status_counts.get("ok_static", 0) if isinstance(status_counts.get("ok_static", 0), int) else 0
        attention_count = sum(
            value for key, value in status_counts.items() if key != "ok_static" and isinstance(value, int)
        )
        issue_counts = [(key, value) for key, value in ordered_status_counts(status_counts) if key != "ok_static"]
        issue_text = "，".join(f"{status_count_label(key)}: {value}" for key, value in issue_counts) or "无"
        lines.extend([f"**概览**：正常 {ok_count} / 需关注 {attention_count}", f"**问题分类**：{issue_text}"])
    cleanup = summary.get("cleanup") if isinstance(summary.get("cleanup"), dict) else {}
    if cleanup:
        plan = cleanup.get("plan") if isinstance(cleanup.get("plan"), dict) else {}
        plan_summary = plan.get("summary") if isinstance(plan.get("summary"), dict) else {}
        if plan_summary:
            lines.append(f"**清理候选**：{cleanup_plan_summary_text(plan_summary)}")
    if yuque_url:
        lines.append(f"[查看语雀报告]({yuque_url})")
    return "\n\n".join(lines)


def build_alert_summary(status: str, summary: dict[str, Any] | None = None) -> str:
    summary = summary or {}
    run_summary = summary.get("summary") if isinstance(summary.get("summary"), dict) else summary
    status_counts = summary.get("status_counts") if isinstance(summary.get("status_counts"), dict) else {}
    parts = [status_label(status)]
    if run_summary.get("total_assets"):
        parts.append(f"资产 {run_summary.get('total_assets')}")
    if status_counts.get("unreachable"):
        parts.append(f"不可达 {status_counts.get('unreachable')}")
    if status_counts.get("jumpserver_unreachable_ip_reachable"):
        parts.append(f"IP可达需复核 {status_counts.get('jumpserver_unreachable_ip_reachable')}")
    cleanup = summary.get("cleanup") if isinstance(summary.get("cleanup"), dict) else {}
    plan = cleanup.get("plan") if isinstance(cleanup.get("plan"), dict) else {}
    plan_summary = plan.get("summary") if isinstance(plan.get("summary"), dict) else {}
    if plan_summary.get("review_required") and not status_counts.get("jumpserver_unreachable_ip_reachable"):
        parts.append(f"需人工复核 {plan_summary.get('review_required')}")
    if status_counts.get("duplicate_asset"):
        parts.append(f"重复 {status_counts.get('duplicate_asset')}")
    return " / ".join(parts)


def strip_markdown(content: str) -> str:
    text = content.replace("**", "").replace("`", "")
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1", text)
    cleaned = []
    for line in text.splitlines():
        line = re.sub(r"^\s{0,3}#{1,6}\s*", "", line)
        line = re.sub(r"^\s*>\s?", "", line)
        line = re.sub(r"^\s*[-*]\s+", "", line)
        cleaned.append(line)
    return "\n".join(cleaned).strip()


def build_alertmanager_payload(title: str, content: str, status: str, alert_summary: str = "") -> dict[str, Any]:
    now = datetime.now(timezone(timedelta(hours=8))).isoformat(timespec="seconds")
    alert_status = "firing"
    return {
        "status": alert_status,
        "alerts": [
            {
                "status": alert_status,
                "startsAt": now,
                "labels": {
                    "alertname": title,
                    "severity": "info" if status == "success" else "warning",
                    "source": "jumpserver-check",
                    "instance": "jumpserver-check",
                },
                "annotations": {
                    "summary": alert_summary or title,
                    "description": content,
                    "started_at": now.replace("T", " "),
                },
            }
        ],
    }


def build_wecom_payload(
    channel: str,
    title: str,
    content: str,
    status: str = "success",
    alert_summary: str = "",
) -> dict[str, Any]:
    normalized = channel.strip().lower() or "wecom"
    if normalized in {"wecom_relay", "relay", "alertmanager"}:
        return build_alertmanager_payload(title, content, status, alert_summary)
    if normalized in {"wecom_text", "text"}:
        return {"msgtype": "text", "text": {"content": strip_markdown(content)}}
    return {"msgtype": "markdown", "markdown": {"content": content}}


def send_wecom_message(webhook_url: str, payload: dict[str, Any], timeout: int = 20) -> dict[str, Any]:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = request.Request(webhook_url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            result = json.loads(raw) if raw else {}
    except error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"企业微信推送失败：HTTP {exc.code} {raw.strip()}") from exc
    except error.URLError as exc:
        raise RuntimeError(f"企业微信推送失败：{exc.reason}") from exc
    if isinstance(result, dict) and result.get("errcode") not in (None, 0):
        raise RuntimeError(f"企业微信推送失败：{result}")
    return result if isinstance(result, dict) else {"response": result}


def build_admin_action_message(action: str, record: dict[str, Any], admin_url: str = "") -> str:
    label = ACTION_LABELS.get(action, action)
    lines = [f"**操作**：{label}"]
    asset_name = record.get("asset_name", "")
    asset_ip = record.get("asset_ip", "")
    if asset_name and asset_ip:
        lines.append(f"**资产**：{asset_name}（{asset_ip}）")
    elif asset_name:
        lines.append(f"**资产**：{asset_name}")
    elif asset_ip:
        lines.append(f"**资产IP**：{asset_ip}")
    asset_id = record.get("asset_id", "")
    if asset_id:
        lines.append(f"**资产ID**：{asset_id}")
    profile = record.get("profile", "")
    if profile:
        lines.append(f"**Profile**：{profile}")
    operator = record.get("operator", "")
    if operator:
        lines.append(f"**操作人**：{operator}")
    reason = record.get("reason", "")
    if reason:
        lines.append(f"**原因**：{reason}")
    timestamp = record.get("confirmed_at") or record.get("protected_at") or record.get("reviewed_at") or ""
    if timestamp:
        lines.append(f"**时间**：{timestamp}")
    if admin_url:
        lines.append(f"\n[查看管理页面]({admin_url})")
    return "\n".join(lines)


def send_admin_action_notification(
    action: str,
    record: dict[str, Any],
    *,
    webhook_url: str = "",
    channel: str = "",
    admin_url: str = "",
) -> dict[str, Any]:
    webhook_url = webhook_url or os.getenv("WECOM_WEBHOOK_URL", "").strip()
    channel = channel or os.getenv("WECOM_CHANNEL", "wecom")
    admin_url = admin_url or os.getenv("ACCESS_URL", "").strip()
    if not webhook_url:
        return {"status": "skipped", "reason": "WECOM_WEBHOOK_URL not configured"}
    content = build_admin_action_message(action, record, admin_url=admin_url)
    payload = build_wecom_payload(channel, "主机清理管理操作", content)
    send_wecom_message(webhook_url, payload, timeout=10)
    return {"status": "sent", "action": action}


def notify(
    status: str,
    title: str,
    summary_json: str = "",
    report_path: str = "",
    yuque_url: str = "",
    error_message: str = "",
    duration_seconds: float | None = None,
    channel: str = "",
    dry_run: bool = False,
) -> dict[str, Any]:
    load_dotenv()
    summary = load_summary(summary_json)
    webhook_url = os.getenv("WECOM_WEBHOOK_URL", "").strip()
    channel = channel or os.getenv("WECOM_CHANNEL", "wecom")
    normalized_channel = channel.strip().lower() or "wecom"
    if normalized_channel in {"wecom_relay", "relay", "alertmanager"}:
        content = build_relay_message(status, summary, yuque_url, error_message, duration_seconds)
        payload = build_wecom_payload(channel, title, content, status, build_alert_summary(status, summary))
    else:
        content = build_markdown_message(status, title, summary, report_path, yuque_url, error_message, duration_seconds)
        payload = build_wecom_payload(channel, title, content, status)
    if dry_run:
        result = {"status": "dry_run", "configured": bool(webhook_url), "channel": channel, "payload": payload, "content": content}
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return result
    if not webhook_url:
        result = {"status": "skipped", "reason": "WECOM_WEBHOOK_URL not configured", "channel": channel, "payload": payload, "content": content}
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return result
    response = send_wecom_message(webhook_url, payload)
    result = {"status": "sent", "channel": channel, "response": response}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="发送企业微信 Markdown 通知。")
    parser.add_argument("--status", choices=("success", "failed", "timeout"), required=True)
    parser.add_argument("--title", required=True)
    parser.add_argument("--summary-json", default="", help="JSON 字符串或 JSON 文件路径")
    parser.add_argument("--report-path", default="")
    parser.add_argument("--yuque-url", default="")
    parser.add_argument("--error-message", default="")
    parser.add_argument("--duration-seconds", type=float)
    parser.add_argument("--channel", default="", help="wecom/markdown、wecom_text/text、wecom_relay/relay/alertmanager")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        notify(
            status=args.status,
            title=args.title,
            summary_json=args.summary_json,
            report_path=args.report_path,
            yuque_url=args.yuque_url,
            error_message=args.error_message,
            duration_seconds=args.duration_seconds,
            channel=args.channel,
            dry_run=args.dry_run,
        )
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
