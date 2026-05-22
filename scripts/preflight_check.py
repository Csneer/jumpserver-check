#!/usr/bin/env python3
"""Validate local configuration before running the scheduled check."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import profile_env  # noqa: E402


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PLACEHOLDER_PREFIXES = ("replace-with-", "your-login-or-group/", "jumpserver.example.com")


def env_candidates() -> list[Path]:
    return [Path.cwd() / ".env", PROJECT_ROOT / ".env"]


def load_env_files() -> dict[str, str]:
    values: dict[str, str] = dict(os.environ)
    seen: set[Path] = set()
    for path in env_candidates():
        resolved = path.resolve()
        if resolved in seen or not resolved.exists():
            continue
        seen.add(resolved)
        for raw in resolved.read_text(encoding="utf-8-sig").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            cleaned = value.strip().strip('"').strip("'")
            if key:
                values[key] = cleaned
            if key and not os.environ.get(key):
                os.environ[key] = cleaned
    return values


def is_placeholder(value: str) -> bool:
    lowered = value.strip().lower()
    return any(lowered.startswith(prefix) for prefix in PLACEHOLDER_PREFIXES)


def require_key(values: dict[str, str], key: str, errors: list[str]) -> None:
    value = values.get(key) or os.getenv(key, "")
    if not value:
        errors.append(f"{key} 未配置")
    elif is_placeholder(value):
        errors.append(f"{key} 仍是示例占位值")


def check_int(values: dict[str, str], key: str, default: int, errors: list[str]) -> None:
    value = values.get(key) or os.getenv(key, "") or str(default)
    try:
        parsed = int(value)
    except ValueError:
        errors.append(f"{key} 必须是整数")
        return
    if parsed <= 0:
        errors.append(f"{key} 必须大于 0")


def validate_config(require_wecom: bool = False, profile: str = profile_env.DEFAULT_PROFILE, env_file: str = "") -> dict[str, Any]:
    runtime_env = profile_env.load_profile_env(profile, env_file)
    values = runtime_env.values
    errors: list[str] = []
    warnings: list[str] = []

    if not runtime_env.loaded_files:
        errors.append("项目 .env 或 profile env 文件不存在")

    for key in ("JMS_URL", "JMS_ACCESS_KEY_ID", "JMS_ACCESS_KEY_SECRET"):
        require_key(values, key, errors)

    require_key(values, "YUQUE_TOKEN", errors)
    yuque_repo = values.get("YUQUE_REPO_NAMESPACE") or os.getenv("YUQUE_REPO_NAMESPACE", "")
    yuque_url = values.get("YUQUE_URL") or os.getenv("YUQUE_URL", "")
    if not yuque_repo and not yuque_url:
        errors.append("YUQUE_REPO_NAMESPACE 或 YUQUE_URL 至少配置一个")
    if yuque_repo and is_placeholder(yuque_repo):
        errors.append("YUQUE_REPO_NAMESPACE 仍是示例占位值")

    if require_wecom:
        require_key(values, "WECOM_WEBHOOK_URL", errors)
    elif not (values.get("WECOM_WEBHOOK_URL") or os.getenv("WECOM_WEBHOOK_URL", "")):
        warnings.append("WECOM_WEBHOOK_URL 未配置，本次将跳过企业微信真实推送")

    check_int(values, "CHECK_WAIT_TIMEOUT", 1200, errors)
    check_int(values, "CHECK_POLL_INTERVAL", 30, errors)
    check_int(values, "CHECK_RETENTION_COUNT", 12, errors)

    for path in (
        PROJECT_ROOT / "scripts" / "jms_host_ip_check.py",
        PROJECT_ROOT / "scripts" / "yuque_markdown_sync.py",
        PROJECT_ROOT / "scripts" / "wecom_notify.py",
    ):
        if not path.exists():
            errors.append(f"必要脚本不存在：{path}")

    return {
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        "checked": {
            "profile": runtime_env.profile,
            "env_file": runtime_env.env_file,
            "loaded_env_files": runtime_env.loaded_files,
            "jumpserver": True,
            "yuque": True,
            "wecom_required": require_wecom,
            "wecom_configured": bool(values.get("WECOM_WEBHOOK_URL") or os.getenv("WECOM_WEBHOOK_URL", "")),
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="检查 JumpServer 巡检所需 .env 配置是否完整。")
    parser.add_argument("--profile", default=profile_env.DEFAULT_PROFILE, help="JumpServer 环境 profile 名称")
    parser.add_argument("--env-file", default="", help="指定 profile env 文件；默认 configs/profiles/<profile>.env")
    parser.add_argument("--require-wecom", action="store_true", help="强制要求 WECOM_WEBHOOK_URL 已配置")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    result = validate_config(require_wecom=args.require_wecom, profile=args.profile, env_file=args.env_file)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        status = "OK" if result["ok"] else "FAILED"
        print(f"preflight: {status}")
        for warning in result["warnings"]:
            print(f"warning: {warning}")
        for error in result["errors"]:
            print(f"error: {error}")
    raise SystemExit(0 if result["ok"] else 1)


if __name__ == "__main__":
    main()
