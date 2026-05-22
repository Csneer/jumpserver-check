#!/usr/bin/env python3
"""Send reusable WeCom webhook notifications for scheduled checks."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any
from urllib import error, request


PROJECT_ROOT = Path(__file__).resolve().parents[1]


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
    path = Path(summary_json)
    text = path.read_text(encoding="utf-8") if path.exists() else summary_json
    payload = json.loads(text)
    return payload if isinstance(payload, dict) else {}


def status_label(status: str) -> str:
    labels = {"success": "成功", "failed": "失败", "timeout": "超时"}
    return labels.get(status, status)


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
            "unreachable",
            "probe_timeout",
            "ops_no_output",
            "ops_module_error",
            "permission_denied",
            "no_account",
            "parse_error",
            "skipped_windows",
        ]
        count_text = "，".join(f"{key}: {status_counts.get(key, 0)}" for key in ordered if status_counts.get(key, 0))
        lines.extend(["", f"- 分类：{count_text or '无异常分类'}"])
    if yuque_url:
        lines.append(f"- 语雀：[{yuque_url}]({yuque_url})")
    if report_path:
        lines.append(f"- 本地报告：`{report_path}`")
    return "\n".join(lines)


def send_wecom_markdown(webhook_url: str, content: str, timeout: int = 20) -> dict[str, Any]:
    payload = {"msgtype": "markdown", "markdown": {"content": content}}
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


def notify(
    status: str,
    title: str,
    summary_json: str = "",
    report_path: str = "",
    yuque_url: str = "",
    error_message: str = "",
    duration_seconds: float | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    load_dotenv()
    summary = load_summary(summary_json)
    content = build_markdown_message(status, title, summary, report_path, yuque_url, error_message, duration_seconds)
    webhook_url = os.getenv("WECOM_WEBHOOK_URL", "").strip()
    if dry_run:
        result = {"status": "dry_run", "configured": bool(webhook_url), "content": content}
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return result
    if not webhook_url:
        result = {"status": "skipped", "reason": "WECOM_WEBHOOK_URL not configured", "content": content}
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return result
    response = send_wecom_markdown(webhook_url, content)
    result = {"status": "sent", "response": response}
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
            dry_run=args.dry_run,
        )
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
