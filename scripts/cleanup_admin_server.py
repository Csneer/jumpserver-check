#!/usr/bin/env python3
"""Lightweight local admin UI for abandoned-host cleanup confirmation."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import host_cleanup, profile_env, wecom_notify  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parents[1]


SESSION_COOKIE = "cleanup_admin_session"


def default_raw_dir(profile: str) -> Path:
    return PROJECT_ROOT / profile_env.profile_path("artifacts/raw", profile)


def discover_profiles(default_profile: str, configured_profiles: tuple[str, ...] | list[str] | None = None) -> list[str]:
    """Return safe JumpServer profile names the admin UI may switch between."""
    discovered: set[str] = {profile_env.normalize_profile(default_profile)}
    for item in configured_profiles or ():
        discovered.add(profile_env.normalize_profile(str(item)))
    if profile_env.PROFILE_ENV_DIR.exists():
        for path in profile_env.PROFILE_ENV_DIR.glob("*.env"):
            if path.name.endswith(".example") or path.name.endswith(".example.env"):
                continue
            try:
                discovered.add(profile_env.normalize_profile(path.stem))
            except ValueError:
                continue
    return sorted(discovered)


def profile_from_query(path: str, context: "AdminContext") -> str:
    parsed = urlparse(path)
    values = parse_qs(parsed.query).get("profile") or []
    return profile_env.normalize_profile(values[0] if values else context.profile)


def make_session_cookie(token: str, ttl_seconds: int) -> tuple[str, str]:
    csrf = secrets.token_hex(32)
    expires_at = int(time.time()) + ttl_seconds
    payload = json.dumps({"exp": expires_at, "csrf": csrf}, separators=(",", ":")).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    sig = hmac.new(token.encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{payload_b64}.{sig}", csrf


def parse_cookie_header(headers: dict[str, str]) -> dict[str, str]:
    raw = headers.get("cookie") or headers.get("Cookie") or ""
    cookies: dict[str, str] = {}
    for part in raw.split(";"):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        cookies[key.strip()] = value.strip()
    return cookies


def valid_session(headers: dict[str, str], context: "AdminContext") -> bool:
    if not context.token:
        return False
    value = parse_cookie_header(headers).get(SESSION_COOKIE, "")
    if "." not in value:
        return False
    payload_b64, sig = value.rsplit(".", 1)
    expected = hmac.new(context.token.encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return False
    try:
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    except (ValueError, json.JSONDecodeError):
        return False
    return int(payload.get("exp") or 0) >= int(time.time())


def csrf_from_session(headers: dict[str, str]) -> str:
    value = parse_cookie_header(headers).get(SESSION_COOKIE, "")
    if "." not in value:
        return ""
    payload_b64 = value.rsplit(".", 1)[0]
    try:
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    except (ValueError, json.JSONDecodeError):
        return ""
    return str(payload.get("csrf") or "")


def is_authenticated(headers: dict[str, str], context: "AdminContext") -> bool:
    if context.token and hmac.compare_digest(token_from_headers(headers), context.token):
        return True
    return valid_session(headers, context)


def require_authenticated(headers: dict[str, str], context: "AdminContext") -> Response | None:
    if not context.token:
        return json_response(403, {"error": "admin_token_not_configured"})
    if not is_authenticated(headers, context):
        return json_response(401, {"error": "login_required"})
    return None


def require_csrf(headers: dict[str, str]) -> Response | None:
    expected = csrf_from_session(headers)
    if not expected:
        return json_response(403, {"error": "csrf_token_missing"})
    supplied = headers.get("x-csrf-token") or headers.get("X-CSRF-Token") or ""
    if not supplied:
        return json_response(403, {"error": "csrf_token_missing"})
    if not hmac.compare_digest(supplied, expected):
        return json_response(403, {"error": "csrf_token_invalid"})
    return None


def profile_metadata(context: "AdminContext") -> list[dict[str, str | bool]]:
    return [
        {
            "name": profile,
            "label": profile,
            "current": profile == context.profile,
            "has_config": profile_env.default_profile_env(profile).exists(),
        }
        for profile in context.profiles()
    ]


@dataclass
class AdminContext:
    profile: str
    raw_dir: Path | None
    state_dir: Path | None
    output_dir: Path | None
    token: str = ""
    session_ttl_seconds: int = 12 * 60 * 60
    allowed_profiles: tuple[str, ...] = ()

    def profiles(self) -> tuple[str, ...]:
        return tuple(discover_profiles(self.profile, self.allowed_profiles))

    def scoped_path(self, base: Path | None, profile: str, default: Path) -> Path:
        if base is None:
            return default
        if profile == self.profile:
            return base
        return base / profile

    def for_profile(self, profile: str) -> "AdminContext":
        normalized = profile_env.normalize_profile(profile)
        if normalized not in self.profiles():
            raise ValueError(f"profile not allowed: {normalized}")
        return AdminContext(
            profile=normalized,
            raw_dir=self.scoped_path(self.raw_dir, normalized, default_raw_dir(normalized)),
            state_dir=self.scoped_path(self.state_dir, normalized, host_cleanup.cleanup_profile_state_dir(normalized)),
            output_dir=self.scoped_path(self.output_dir, normalized, host_cleanup.cleanup_output_dir(normalized)),
            token=self.token,
            session_ttl_seconds=self.session_ttl_seconds,
            allowed_profiles=self.profiles(),
        )


@dataclass
class Response:
    status: int
    body: bytes
    headers: dict[str, str]


def json_response(status: int, payload: Any) -> Response:
    return Response(status=status, body=json.dumps(payload, ensure_ascii=False).encode("utf-8"), headers={"Content-Type": "application/json; charset=utf-8"})


def html_response(content: str) -> Response:
    return Response(status=200, body=content.encode("utf-8"), headers={"Content-Type": "text/html; charset=utf-8"})


def parse_json_body(body: bytes) -> dict[str, Any]:
    if not body:
        return {}
    payload = json.loads(body.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("JSON body must be an object")
    return payload


def token_from_headers(headers: dict[str, str]) -> str:
    value = headers.get("authorization") or headers.get("Authorization") or ""
    if value.lower().startswith("bearer "):
        return value.split(" ", 1)[1].strip()
    return headers.get("x-cleanup-admin-token") or headers.get("X-Cleanup-Admin-Token") or ""


def require_write_token(headers: dict[str, str], context: AdminContext) -> Response | None:
    auth_error = require_authenticated(headers, context)
    if auth_error:
        return auth_error
    return None


def write_review(state_dir: Path, *, profile: str, asset_id: str, reason: str, operator: str = "") -> dict[str, Any]:
    if not asset_id or not reason:
        raise host_cleanup.CleanupError("asset_id and reason are required")
    path = state_dir / "cleanup_review_hosts.json"
    payload = host_cleanup.load_json_file(path, {"review_hosts": []})
    records = payload.get("review_hosts") if isinstance(payload, dict) else []
    if not isinstance(records, list):
        records = []
    record = {"profile": profile, "asset_id": asset_id, "reason": reason, "operator": operator, "reviewed_at": host_cleanup.now_iso()}
    records = [item for item in records if item.get("asset_id") != asset_id or item.get("profile") != profile]
    records.append(record)
    host_cleanup.atomic_write_json(path, {"review_hosts": records})
    return record


def _notify_admin_action(action: str, record: dict[str, Any]) -> None:
    if not os.getenv("WECOM_NOTIFY_ADMIN_ACTIONS", ""):
        return
    try:
        wecom_notify.send_admin_action_notification(action, record)
    except Exception as exc:
        print(f"[cleanup-admin] wecom notify failed: {exc}", file=sys.stderr)


def handle_request(method: str, path: str, headers: dict[str, str], body: bytes, context: AdminContext) -> Response:
    parsed = urlparse(path)
    route = parsed.path
    try:
        if method == "GET" and route == "/":
            return html_response(INDEX_HTML)
        if method == "GET" and route == "/favicon.ico":
            return Response(status=204, body=b"", headers={})
        if method == "GET" and route == "/api/health":
            return json_response(200, {"status": "ok", "auth_required": bool(context.token)})
        if method == "POST" and route == "/api/login":
            payload = parse_json_body(body)
            supplied = str(payload.get("token") or "")
            if not context.token:
                return json_response(403, {"error": "admin_token_not_configured"})
            if not hmac.compare_digest(supplied, context.token):
                return json_response(401, {"error": "invalid_token"})
            cookie, csrf = make_session_cookie(context.token, context.session_ttl_seconds)
            response = json_response(200, {"status": "ok", "profile": context.profile, "profiles": profile_metadata(context), "csrf_token": csrf})
            response.headers["Set-Cookie"] = f"{SESSION_COOKIE}={cookie}; HttpOnly; SameSite=Strict; Path=/; Max-Age={context.session_ttl_seconds}"
            return response
        if method == "POST" and route == "/api/logout":
            response = json_response(200, {"status": "ok"})
            response.headers["Set-Cookie"] = f"{SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
            return response
        if method == "GET" and route == "/api/session":
            auth_error = require_authenticated(headers, context)
            if auth_error:
                return auth_error
            csrf = csrf_from_session(headers)
            return json_response(200, {"status": "ok", "profile": context.profile, "profiles": profile_metadata(context), "csrf_token": csrf})
        if method == "GET" and route == "/api/profiles":
            auth_error = require_authenticated(headers, context)
            if auth_error:
                return auth_error
            return json_response(200, {"profiles": profile_metadata(context)})
        if method == "GET" and route == "/api/candidates":
            auth_error = require_authenticated(headers, context)
            if auth_error:
                return auth_error
            profile_context = context.for_profile(profile_from_query(path, context))
            plan = host_cleanup.evaluate_cleanup(
                profile=profile_context.profile,
                raw_dir=profile_context.raw_dir or default_raw_dir(profile_context.profile),
                state_dir=profile_context.state_dir or host_cleanup.cleanup_profile_state_dir(profile_context.profile),
                output_dir=profile_context.output_dir or host_cleanup.cleanup_output_dir(profile_context.profile),
                write_plan=False,
            )
            plan["profiles"] = profile_metadata(profile_context)
            return json_response(200, plan)
        if method == "POST" and route in {"/api/confirm", "/api/protect", "/api/review"}:
            auth_error = require_write_token(headers, context)
            if auth_error:
                return auth_error
            csrf_error = require_csrf(headers)
            if csrf_error:
                return csrf_error
            payload = parse_json_body(body)
            profile_context = context.for_profile(str(payload.get("profile") or context.profile))
            if route == "/api/confirm":
                record = host_cleanup.write_confirmation(
                    profile_context.state_dir or host_cleanup.cleanup_profile_state_dir(profile_context.profile),
                    profile=profile_context.profile,
                    asset=payload.get("asset") or payload,
                    operator=str(payload.get("operator") or ""),
                    reason=str(payload.get("reason") or ""),
                    action=str(payload.get("action") or "disable"),
                    source_evidence_run_ids=[str(item) for item in payload.get("source_evidence_run_ids") or []],
                    source_evidence_paths=[str(item) for item in payload.get("source_evidence_paths") or []],
                    delete_ack=str(payload.get("delete_ack") or ""),
                )
                _notify_admin_action("confirm", record)
                return json_response(200, {"status": "confirmed", "record": record})
            if route == "/api/protect":
                record = host_cleanup.write_protection(
                    profile_context.state_dir or host_cleanup.cleanup_profile_state_dir(profile_context.profile),
                    profile=profile_context.profile,
                    asset_id=str(payload.get("asset_id") or ""),
                    reason=str(payload.get("reason") or ""),
                    operator=str(payload.get("operator") or ""),
                )
                _notify_admin_action("protect", record)
                return json_response(200, {"status": "protected", "record": record})
            record = write_review(
                profile_context.state_dir or host_cleanup.cleanup_profile_state_dir(profile_context.profile),
                profile=profile_context.profile,
                asset_id=str(payload.get("asset_id") or ""),
                reason=str(payload.get("reason") or ""),
                operator=str(payload.get("operator") or ""),
            )
            _notify_admin_action("review", record)
            return json_response(200, {"status": "needs_review", "record": record})
        return json_response(404, {"error": "not_found"})
    except (ValueError, host_cleanup.CleanupError) as exc:
        return json_response(400, {"error": str(exc)})


INDEX_HTML = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>JumpServer 废弃主机确认</title>
<style>
:root{
  color-scheme: light;
  --bg:#eef3f8;--panel:#ffffff;--panel-soft:#f8fafc;--text:#0f172a;--muted:#64748b;
  --line:#dbe4ee;--brand:#2563eb;--brand-dark:#1d4ed8;--ok:#16a34a;--warn:#d97706;--danger:#dc2626;--purple:#7c3aed;
  --shadow:0 20px 50px rgba(15,23,42,.10);--shadow-sm:0 8px 24px rgba(15,23,42,.08);--radius:18px;
}
*{box-sizing:border-box} body{margin:0;min-height:100vh;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:var(--text);background:radial-gradient(circle at top left,#dbeafe 0,#eef3f8 34%,#f8fafc 100%)}
.shell{max-width:1440px;margin:0 auto;padding:28px}.hero{display:grid;grid-template-columns:minmax(0,1fr) 420px;gap:22px;align-items:stretch;margin-bottom:22px}.hero-card,.control-card,.panel{background:rgba(255,255,255,.92);border:1px solid rgba(219,228,238,.9);box-shadow:var(--shadow);border-radius:var(--radius);backdrop-filter:blur(10px)}
.hero-card{padding:28px;position:relative;overflow:hidden}.hero-card:after{content:"";position:absolute;right:-80px;top:-90px;width:260px;height:260px;border-radius:50%;background:linear-gradient(135deg,rgba(37,99,235,.16),rgba(124,58,237,.12))}.eyebrow{display:inline-flex;gap:8px;align-items:center;padding:7px 12px;border-radius:999px;background:#eff6ff;color:#1d4ed8;font-weight:700;font-size:13px}.hero h1{font-size:34px;letter-spacing:-.04em;margin:16px 0 10px}.hero p{color:var(--muted);font-size:15px;max-width:760px;line-height:1.7}.status-row{display:flex;gap:10px;flex-wrap:wrap;margin-top:18px}.pill{display:inline-flex;align-items:center;gap:7px;border-radius:999px;padding:7px 11px;font-weight:700;font-size:12px;border:1px solid var(--line);background:#fff}.pill.ok{color:var(--ok);background:#f0fdf4;border-color:#bbf7d0}.pill.warn{color:var(--warn);background:#fffbeb;border-color:#fed7aa}.pill.safe{color:#0369a1;background:#f0f9ff;border-color:#bae6fd}
.control-card{padding:18px}.control-card h2{font-size:16px;margin:0 0 12px}.form-grid{display:grid;grid-template-columns:1fr;gap:10px}.field label{display:block;font-size:12px;font-weight:800;color:#475569;margin-bottom:5px}.field input,.field select{width:100%;border:1px solid var(--line);border-radius:12px;padding:11px 12px;font-size:14px;background:#fff;outline:none}.field input:focus,.field select:focus{border-color:#93c5fd;box-shadow:0 0 0 4px rgba(37,99,235,.12)}
.stats{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:14px;margin:20px 0}.stat{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:16px;box-shadow:var(--shadow-sm)}.stat .label{font-size:12px;color:var(--muted);font-weight:800}.stat .value{font-size:28px;font-weight:900;letter-spacing:-.04em;margin-top:6px}.stat .hint{font-size:12px;color:var(--muted);margin-top:4px}.stat.danger .value{color:var(--danger)}.stat.warn .value{color:var(--warn)}.stat.ok .value{color:var(--ok)}
.toolbar{display:flex;gap:12px;align-items:center;justify-content:space-between;margin:18px 0}.search{flex:1;min-width:260px;border:1px solid var(--line);border-radius:14px;padding:12px 14px;font-size:14px;background:#fff}.btn{border:0;border-radius:12px;padding:10px 13px;font-weight:800;cursor:pointer;background:#e2e8f0;color:#0f172a;transition:.15s transform,.15s box-shadow,.15s background}.btn:hover{transform:translateY(-1px);box-shadow:var(--shadow-sm)}.btn.primary{background:var(--brand);color:#fff}.btn.primary:hover{background:var(--brand-dark)}.btn.ghost{background:#f8fafc;border:1px solid var(--line)}.btn.warn{background:#f59e0b;color:#fff}.btn.danger{background:#fee2e2;color:#991b1b}.btn.danger-solid{background:var(--danger);color:#fff}.btn.small{padding:8px 10px;font-size:12px}
.panel{overflow:hidden}.panel-head{display:flex;align-items:center;justify-content:space-between;padding:18px 20px;border-bottom:1px solid var(--line);background:linear-gradient(180deg,#fff,#f8fafc)}.panel-head h2{margin:0;font-size:18px}.table-wrap{overflow:auto;max-height:680px}table{width:100%;border-collapse:separate;border-spacing:0}th,td{padding:14px 16px;text-align:left;border-bottom:1px solid #e8eef5;vertical-align:top}th{position:sticky;top:0;background:#f8fafc;z-index:1;font-size:12px;color:#64748b;text-transform:uppercase;letter-spacing:.05em}tbody tr:hover{background:#f8fbff}.asset-name{font-weight:900}.asset-id{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:#64748b;font-size:12px;margin-top:4px}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}.muted{color:var(--muted)}.reason{max-width:360px;line-height:1.55}.actions{display:flex;gap:7px;flex-wrap:wrap;min-width:280px}.chip{display:inline-flex;align-items:center;border-radius:999px;padding:5px 9px;font-size:12px;font-weight:900}.chip.confirmed{background:#dcfce7;color:#166534}.chip.missing_confirmation{background:#fef3c7;color:#92400e}.chip.confirmed_wait_next_scheduled_run{background:#dbeafe;color:#1d4ed8}.chip.stale_confirmation,.chip.invalid_confirmation{background:#fee2e2;color:#991b1b}.chip.delete{background:#f3e8ff;color:#6d28d9}.empty{padding:56px;text-align:center;color:var(--muted)}.toast{position:fixed;right:24px;bottom:24px;z-index:20;border-radius:14px;padding:13px 15px;background:#0f172a;color:white;box-shadow:var(--shadow);max-width:460px}.toast.error{background:#991b1b}.modal-overlay{position:fixed;inset:0;z-index:30;background:rgba(15,23,42,.45);display:grid;place-items:center;backdrop-filter:blur(2px)}.modal{width:min(420px,calc(100vw - 48px));background:#fff;border-radius:20px;box-shadow:0 24px 64px rgba(15,23,42,.18);padding:28px;animation:modalIn .2s ease-out}@keyframes modalIn{from{opacity:0;transform:translateY(12px) scale(.97)}to{opacity:1;transform:none}}.modal h3{margin:0 0 8px;font-size:18px;letter-spacing:-.03em}.modal p{color:var(--muted);font-size:14px;line-height:1.6;margin:0 0 20px}.modal-actions{display:flex;gap:10px;flex-wrap:wrap}.modal-actions .btn{flex:1;min-width:120px;text-align:center}.drawer{position:fixed;inset:auto 24px 24px auto;width:min(760px,calc(100vw - 48px));max-height:72vh;overflow:auto;background:#0f172a;color:#e2e8f0;border-radius:18px;box-shadow:var(--shadow);padding:18px;z-index:15}.drawer pre{white-space:pre-wrap;font-size:12px}.hidden{display:none!important}.mobile-card{display:none}.login-screen{position:fixed;inset:0;z-index:50;display:grid;place-items:center;background:radial-gradient(circle at 20% 10%,#bfdbfe 0,#eef3f8 38%,#f8fafc 100%);padding:20px}.login-card{width:min(460px,100%);background:rgba(255,255,255,.94);border:1px solid rgba(219,228,238,.95);border-radius:24px;box-shadow:var(--shadow);padding:30px}.login-card h1{font-size:28px;margin:12px 0 8px;letter-spacing:-.03em}.login-card p{color:var(--muted);line-height:1.7}.login-actions{display:flex;gap:10px;align-items:center;margin-top:14px}.app-locked{filter:blur(3px);pointer-events:none;user-select:none}
@media(max-width:980px){.shell{padding:16px}.hero{grid-template-columns:1fr}.stats{grid-template-columns:repeat(2,1fr)}.table-wrap{display:none}.mobile-card{display:block;padding:14px;border-bottom:1px solid var(--line)}.actions{min-width:auto}.toolbar{flex-direction:column;align-items:stretch}.hero h1{font-size:28px}}
</style>
</head>
<body>
<div class="login-screen" id="loginScreen">
  <div class="login-card">
    <span class="eyebrow">🔐 Cleanup Admin Login</span>
    <h1>登录后查看废弃主机候选</h1>
    <p>请输入服务端配置的 CLEANUP_ADMIN_TOKEN。登录前不会加载候选主机、原始 JSON 或多 JumpServer profile 数据。</p>
    <div class="field"><label for="loginToken">管理员 Token</label><input id="loginToken" type="password" autocomplete="current-password" placeholder="CLEANUP_ADMIN_TOKEN"></div>
    <div class="login-actions"><button class="btn primary" id="loginBtn">登录控制台</button><span class="muted" id="loginMsg"></span></div>
  </div>
</div>
<div class="shell app-locked" id="appShell">
  <section class="hero">
    <div class="hero-card">
      <span class="eyebrow">🛡️ JumpServer Cleanup Console</span>
      <h1>废弃主机确认中心</h1>
      <p>登录后按 JumpServer profile 分别查看连续不可达资产，维护确认、保护和复查清单。页面只写本地状态文件，不直接调用 JumpServer 清理接口；真正清理由定时任务在下一轮正式巡检复核和存档后执行。</p>
      <div class="status-row">
        <span class="pill safe">登录前不暴露候选数据</span>
        <span class="pill safe">浏览器不触达 JumpServer API</span>
        <span class="pill warn">确认后需下一次巡检复核</span>
        <span class="pill ok">Archive-before-mutate</span>
      </div>
    </div>
    <div class="control-card">
      <h2>管理员操作信息</h2>
      <div class="form-grid">
        <div class="field"><label for="profileSelect">JumpServer 配置</label><select id="profileSelect"></select></div>
        <div class="field"><label for="operator">操作人</label><input id="operator" placeholder="例如：admin / zhangsan"></div>
        <div class="field"><label for="reason">处理原因</label><input id="reason" placeholder="例如：业务下线，负责人确认废弃"></div>
        <div class="field"><label for="stateFilter">状态筛选</label><select id="stateFilter"><option value="">全部候选</option><option value="missing_confirmation">待确认</option><option value="confirmed">已确认</option><option value="confirmed_wait_next_scheduled_run">等待下次巡检</option><option value="stale_confirmation">确认已过期</option></select></div>
        <button class="btn ghost" id="logoutBtn" type="button">退出登录</button>
      </div>
    </div>
  </section>

  <section class="stats" id="stats"></section>

  <div class="toolbar">
    <input class="search" id="search" placeholder="搜索资产名 / IP / 节点 / 失败原因">
    <button class="btn ghost" id="refreshBtn">刷新候选</button>
    <button class="btn ghost" id="rawBtn">查看 JSON</button>
  </div>

  <section class="panel">
    <div class="panel-head"><h2>候选主机</h2><span class="muted" id="updatedAt">加载中...</span></div>
    <div class="table-wrap"><table><thead><tr><th>资产</th><th>IP / 节点</th><th>操作</th><th>确认状态</th><th>失败原因</th><th>证据 run</th></tr></thead><tbody id="rows"></tbody></table></div>
    <div id="cards"></div>
    <div class="empty hidden" id="empty">没有匹配的候选主机</div>
  </section>
</div>
<div class="modal-overlay hidden" id="modalOverlay"><div class="modal" id="modalBox"><h3 id="modalTitle"></h3><p id="modalDesc"></p><div class="modal-actions" id="modalActions"></div></div></div>
<div class="drawer hidden" id="drawer"><button class="btn small ghost" id="closeDrawer">关闭</button><pre id="out"></pre></div>
<script>
let latestData={candidates:[],skipped:[],summary:{},profiles:[]};
let currentProfile='';
function esc(s){return String(s ?? '').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function toast(msg,error=false){const t=document.createElement('div');t.className='toast'+(error?' error':'');t.textContent=msg;document.body.appendChild(t);setTimeout(()=>t.remove(),4200);}
function showModal(title,desc,actions){document.getElementById('modalTitle').textContent=title;document.getElementById('modalDesc').textContent=desc;const box=document.getElementById('modalActions');box.innerHTML=actions.map(a=>`<button class="btn ${a.cls||'ghost'}" data-modal-action="${a.key}">${a.label}</button>`).join('');document.getElementById('modalOverlay').classList.remove('hidden');return new Promise(resolve=>{const cleanup=v=>{document.getElementById('modalOverlay').classList.add('hidden');box.innerHTML='';resolve(v);};box.querySelectorAll('button').forEach(b=>b.onclick=()=>cleanup(b.dataset.modalAction));document.getElementById('modalOverlay').onclick=e=>{if(e.target===e.currentTarget)cleanup(null);};});}
function selectedProfile(){return document.getElementById('profileSelect').value||currentProfile;}
function authHeaders(){return {'Content-Type':'application/json','X-CSRF-Token':sessionStorage.getItem('csrf_token')||''};}
function basePayload(c){return {profile:selectedProfile(),asset:{asset_id:c.asset_id,asset_name:c.asset_name,asset_ip:c.asset_ip},asset_id:c.asset_id,operator:document.getElementById('operator').value.trim(),reason:document.getElementById('reason').value.trim(),source_evidence_run_ids:c.evidence_run_ids||[],source_evidence_paths:c.evidence_paths||[]};}
function validateForm(){if(!document.getElementById('operator').value.trim()) throw new Error('请填写操作人');if(!document.getElementById('reason').value.trim()) throw new Error('请填写处理原因');}
function postDecision(route,payload,okMsg){try{validateForm();}catch(e){toast(e.message,true);return;}fetch(route,{method:'POST',headers:authHeaders(),body:JSON.stringify(payload),credentials:'same-origin'}).then(r=>r.json().then(data=>({ok:r.ok,status:r.status,data}))).then(res=>{if(!res.ok)throw new Error(res.status+' '+JSON.stringify(res.data));toast(okMsg);load();}).catch(err=>toast(String(err),true));}
function confirmAbandon(c){showModal('确认废弃','选择对资产 '+(c.asset_name||c.asset_id)+' 的处理方式：',[{key:'disable',label:'禁用（推荐）',cls:'primary'},{key:'delete',label:'删除（危险）',cls:'danger-solid'}]).then(choice=>{if(!choice)return;const p=basePayload(c);p.action=choice;if(choice==='delete')p.delete_ack='DELETE '+c.asset_id;postDecision('/api/confirm',p,choice==='disable'?'已写入确认废弃/禁用清单':'已写入危险删除确认');});}
function protect(c){postDecision('/api/protect',basePayload(c),'已加入保护清单');}
function review(c){postDecision('/api/review',basePayload(c),'已标记为需复查');}
const STATE_LABELS={missing_confirmation:'待确认',confirmed:'已确认',confirmed_wait_next_scheduled_run:'等待下次巡检',stale_confirmation:'确认已过期',invalid_confirmation:'确认无效',delete:'待删除'};
function stateLabel(s){return STATE_LABELS[s||'missing_confirmation']||s||'待确认';}
function statusChip(state){const v=state||'missing_confirmation';return `<span class="chip ${esc(v)}">${esc(stateLabel(v))}</span>`;}
function filtered(){const q=document.getElementById('search').value.trim().toLowerCase();const sf=document.getElementById('stateFilter').value;return (latestData.candidates||[]).filter(c=>{const text=[c.asset_name,c.asset_id,c.asset_ip,c.node,c.latest_reason,c.confirmation_state,c.confirmation_reason].join(' ').toLowerCase();return (!q||text.includes(q))&&(!sf||c.confirmation_state===sf);});}
function renderProfiles(profiles){const sel=document.getElementById('profileSelect');const active=selectedProfile();sel.innerHTML=(profiles||[]).map(p=>`<option value="${esc(p.name)}" ${p.name===(active||currentProfile)?'selected':''}>${esc(p.label||p.name)}${p.has_config?'':'（仅运行参数）'}</option>`).join('');if(!sel.value&&profiles&&profiles[0])sel.value=profiles[0].name;currentProfile=sel.value||currentProfile;}
function renderStats(){const c=latestData.candidates||[];const counts=c.reduce((m,x)=>(m[x.confirmation_state||'missing_confirmation']=(m[x.confirmation_state||'missing_confirmation']||0)+1,m),{});const s=latestData.summary||{};document.getElementById('stats').innerHTML=[['候选总数',s.candidates??c.length,'当前 profile：'+(latestData.profile||selectedProfile()||'-'),'warn'],['待确认',counts.missing_confirmation||0,'需要管理员判断','danger'],['已确认',counts.confirmed||0,'下次 apply 可继续门控','ok'],['等待复核',counts.confirmed_wait_next_scheduled_run||0,'确认后仍需下一轮巡检',''],['已跳过',s.skipped??0,'保护/证据不足等','']].map(([a,b,h,cls])=>`<div class="stat ${cls}"><div class="label">${a}</div><div class="value">${b}</div><div class="hint">${h}</div></div>`).join('');}
function actionButtons(c,i){return `<div class="actions"><button class="btn primary small" data-action="confirm-abandon" data-index="${i}">确认废弃</button><button class="btn warn small" data-action="protect" data-index="${i}">保护</button><button class="btn ghost small" data-action="review" data-index="${i}">需复查</button></div>`;}
function bindActions(items){document.querySelectorAll('button[data-action]').forEach(btn=>{btn.onclick=()=>{const c=items[Number(btn.dataset.index)];if(btn.dataset.action==='confirm-abandon')confirmAbandon(c);if(btn.dataset.action==='protect')protect(c);if(btn.dataset.action==='review')review(c);};});}
function render(){renderStats();const items=filtered();document.getElementById('empty').classList.toggle('hidden',items.length!==0);document.getElementById('rows').innerHTML=items.map((c,i)=>`<tr><td><div class="asset-name">${esc(c.asset_name||'-')}</div><div class="asset-id">${esc(c.asset_id)}</div></td><td><div class="mono">${esc(c.asset_ip)}</div><div class="muted">${esc(c.node)}</div></td><td>${actionButtons(c,i)}</td><td>${statusChip(c.confirmation_state)}<br><span class="muted">${esc(c.confirmation_reason||c.planned_action||'disable')}</span></td><td class="reason">${esc(c.latest_reason||'-')}</td><td><div class="mono">${esc((c.evidence_run_ids||[]).join(' / '))}</div><div class="muted">${esc((c.evidence_paths||[]).slice(-1)[0]||'')}</div></td></tr>`).join('');document.getElementById('cards').innerHTML=items.map((c,i)=>`<article class="mobile-card"><div class="asset-name">${esc(c.asset_name||'-')}</div><div class="muted mono">${esc(c.asset_ip)} · ${esc(c.node)}</div><p>${esc(c.latest_reason||'-')}</p>${statusChip(c.confirmation_state)}${actionButtons(c,i)}</article>`).join('');bindActions(items);document.getElementById('out').textContent=JSON.stringify(latestData,null,2);}
function unlock(){document.getElementById('loginScreen').classList.add('hidden');document.getElementById('appShell').classList.remove('app-locked');}
function lock(msg=''){document.getElementById('loginScreen').classList.remove('hidden');document.getElementById('appShell').classList.add('app-locked');if(msg)document.getElementById('loginMsg').textContent=msg;}
function load(){document.getElementById('updatedAt').textContent='刷新中...';const p=encodeURIComponent(selectedProfile());fetch('/api/candidates?profile='+p,{credentials:'same-origin'}).then(r=>{if(r.status===401){lock('请先登录');throw new Error('login required');}return r.json().then(data=>({ok:r.ok,status:r.status,data}));}).then(res=>{if(!res.ok)throw new Error(res.status+' '+JSON.stringify(res.data));latestData=res.data;currentProfile=latestData.profile||selectedProfile();if(latestData.profiles)renderProfiles(latestData.profiles);document.getElementById('updatedAt').textContent='最近刷新 '+new Date().toLocaleString();render();}).catch(err=>{if(String(err)!=='Error: login required'){document.getElementById('updatedAt').textContent='加载失败';toast(String(err),true);}});}
function checkSession(){fetch('/api/session',{credentials:'same-origin'}).then(r=>r.ok?r.json():null).then(data=>{if(!data){lock();return;}currentProfile=data.profile;renderProfiles(data.profiles||[]);if(data.csrf_token)sessionStorage.setItem('csrf_token',data.csrf_token);unlock();load();}).catch(()=>lock());}
function login(){const token=document.getElementById('loginToken').value.trim();document.getElementById('loginMsg').textContent='登录中...';fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token}),credentials:'same-origin'}).then(r=>r.json().then(data=>({ok:r.ok,status:r.status,data}))).then(res=>{if(!res.ok)throw new Error(res.status+' '+JSON.stringify(res.data));currentProfile=res.data.profile;renderProfiles(res.data.profiles||[]);if(res.data.csrf_token)sessionStorage.setItem('csrf_token',res.data.csrf_token);document.getElementById('loginToken').value='';document.getElementById('loginMsg').textContent='';unlock();load();}).catch(err=>{document.getElementById('loginMsg').textContent='登录失败';toast(String(err),true);});}
function logout(){sessionStorage.removeItem('csrf_token');fetch('/api/logout',{method:'POST',credentials:'same-origin'}).finally(()=>lock('已退出'));}
document.getElementById('loginBtn').onclick=login;document.getElementById('loginToken').onkeydown=e=>{if(e.key==='Enter')login();};document.getElementById('logoutBtn').onclick=logout;document.getElementById('refreshBtn').onclick=load;document.getElementById('rawBtn').onclick=()=>document.getElementById('drawer').classList.remove('hidden');document.getElementById('closeDrawer').onclick=()=>document.getElementById('drawer').classList.add('hidden');document.getElementById('search').oninput=render;document.getElementById('stateFilter').onchange=render;document.getElementById('profileSelect').onchange=()=>{currentProfile=selectedProfile();load();};checkSession();
</script>
</body></html>
"""


class CleanupAdminHandler(BaseHTTPRequestHandler):
    context: AdminContext

    def do_GET(self) -> None:  # noqa: N802
        self._send(handle_request("GET", self.path, dict(self.headers), b"", self.context))

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        self._send(handle_request("POST", self.path, dict(self.headers), body, self.context))

    def _send(self, response: Response) -> None:
        self.send_response(response.status)
        for key, value in response.headers.items():
            self.send_header(key, value)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(response.body)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        print("[cleanup-admin] " + format % args, file=sys.stderr)


def validate_bind_security(host: str, token: str) -> None:
    if host not in {"127.0.0.1", "localhost", "::1"} and not token:
        print("Refusing to bind non-local address without CLEANUP_ADMIN_TOKEN", file=sys.stderr)
        raise SystemExit(2)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run local cleanup confirmation admin UI.")
    parser.add_argument("--profile", default=os.getenv("CLEANUP_ADMIN_PROFILE", profile_env.DEFAULT_PROFILE))
    parser.add_argument("--host", default=os.getenv("CLEANUP_ADMIN_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("CLEANUP_ADMIN_PORT", "8088")))
    parser.add_argument("--raw-dir", default="")
    parser.add_argument("--state-dir", default="")
    parser.add_argument("--output-dir", default="")
    parser.add_argument("--token", default=os.getenv("CLEANUP_ADMIN_TOKEN", ""))
    parser.add_argument("--profiles", default=os.getenv("CLEANUP_ADMIN_PROFILES", ""), help="Comma-separated extra profile names allowed in the UI.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    validate_bind_security(args.host, args.token)
    context = AdminContext(
        profile=args.profile,
        raw_dir=Path(args.raw_dir) if args.raw_dir else None,
        state_dir=Path(args.state_dir) if args.state_dir else None,
        output_dir=Path(args.output_dir) if args.output_dir else None,
        token=args.token,
        allowed_profiles=tuple(item.strip() for item in args.profiles.split(",") if item.strip()),
    )

    class Handler(CleanupAdminHandler):
        pass

    Handler.context = context
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"cleanup admin server listening on http://{args.host}:{args.port}/ profile={args.profile}")
    server.serve_forever()


if __name__ == "__main__":
    main()
