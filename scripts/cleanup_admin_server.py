#!/usr/bin/env python3
"""Lightweight local admin UI for abandoned-host cleanup confirmation."""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import host_cleanup, profile_env  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parents[1]


@dataclass
class AdminContext:
    profile: str
    raw_dir: Path
    state_dir: Path
    output_dir: Path
    token: str = ""


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
    if not context.token:
        return json_response(403, {"error": "write_token_not_configured"})
    if token_from_headers(headers) != context.token:
        return json_response(401, {"error": "invalid_token"})
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


def handle_request(method: str, path: str, headers: dict[str, str], body: bytes, context: AdminContext) -> Response:
    parsed = urlparse(path)
    route = parsed.path
    try:
        if method == "GET" and route == "/":
            return html_response(INDEX_HTML)
        if method == "GET" and route == "/api/candidates":
            plan = host_cleanup.evaluate_cleanup(
                profile=context.profile,
                raw_dir=context.raw_dir,
                state_dir=context.state_dir,
                output_dir=context.output_dir,
                write_plan=False,
            )
            return json_response(200, plan)
        if method == "POST" and route in {"/api/confirm", "/api/protect", "/api/review"}:
            auth_error = require_write_token(headers, context)
            if auth_error:
                return auth_error
            payload = parse_json_body(body)
            if route == "/api/confirm":
                record = host_cleanup.write_confirmation(
                    context.state_dir,
                    profile=context.profile,
                    asset=payload.get("asset") or payload,
                    operator=str(payload.get("operator") or ""),
                    reason=str(payload.get("reason") or ""),
                    action=str(payload.get("action") or "disable"),
                    source_evidence_run_ids=[str(item) for item in payload.get("source_evidence_run_ids") or []],
                    source_evidence_paths=[str(item) for item in payload.get("source_evidence_paths") or []],
                    delete_ack=str(payload.get("delete_ack") or ""),
                )
                return json_response(200, {"status": "confirmed", "record": record})
            if route == "/api/protect":
                record = host_cleanup.write_protection(
                    context.state_dir,
                    profile=context.profile,
                    asset_id=str(payload.get("asset_id") or ""),
                    reason=str(payload.get("reason") or ""),
                    operator=str(payload.get("operator") or ""),
                )
                return json_response(200, {"status": "protected", "record": record})
            record = write_review(
                context.state_dir,
                profile=context.profile,
                asset_id=str(payload.get("asset_id") or ""),
                reason=str(payload.get("reason") or ""),
                operator=str(payload.get("operator") or ""),
            )
            return json_response(200, {"status": "needs_review", "record": record})
        return json_response(404, {"error": "not_found"})
    except (ValueError, host_cleanup.CleanupError) as exc:
        return json_response(400, {"error": str(exc)})


INDEX_HTML = """<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>JumpServer 废弃主机确认</title>
<style>
body{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:24px;line-height:1.45}
table{border-collapse:collapse;width:100%;margin-top:16px}th,td{border:1px solid #ddd;padding:8px;vertical-align:top}th{background:#f7f7f7}
button{margin:2px 4px 2px 0}.muted{color:#666}.danger{color:#9b1c1c}.ok{color:#166534}
</style></head>
<body>
<h1>JumpServer 废弃主机确认</h1>
<p>本页面只维护本地确认/保护/复查清单，不直接调用 JumpServer API。</p>
<p>写操作需要服务端配置的管理员 Token。</p>
<label>管理员 Token <input id="token" type="password" autocomplete="off"></label>
<label>操作人 <input id="operator" placeholder="admin"></label>
<label>原因 <input id="reason" placeholder="确认废弃/保护/需复查原因"></label>
<div id="summary" class="muted">加载中...</div>
<table>
  <thead><tr><th>主机</th><th>IP/节点</th><th>证据</th><th>状态</th><th>操作</th></tr></thead>
  <tbody id="rows"></tbody>
</table>
<h2>原始 JSON</h2>
<pre id="out"></pre>
<script>
function esc(s){return String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
function authHeaders(){return {'Content-Type':'application/json','X-Cleanup-Admin-Token':document.getElementById('token').value};}
function basePayload(c){return {
  asset:{asset_id:c.asset_id,asset_name:c.asset_name,asset_ip:c.asset_ip},
  asset_id:c.asset_id,
  operator:document.getElementById('operator').value,
  reason:document.getElementById('reason').value,
  source_evidence_run_ids:c.evidence_run_ids || [],
  source_evidence_paths:c.evidence_paths || []
};}
function postDecision(route, payload){
  fetch(route,{method:'POST',headers:authHeaders(),body:JSON.stringify(payload)})
    .then(r => r.json().then(data => ({ok:r.ok,status:r.status,data})))
    .then(res => { if(!res.ok){throw new Error(res.status + ' ' + JSON.stringify(res.data));} load(); })
    .catch(err => alert(String(err)));
}
function confirmDisable(c){const p=basePayload(c);p.action='disable';postDecision('/api/confirm',p);}
function confirmDelete(c){const p=basePayload(c);p.action='delete';p.delete_ack='DELETE '+c.asset_id;postDecision('/api/confirm',p);}
function protect(c){postDecision('/api/protect',basePayload(c));}
function review(c){postDecision('/api/review',basePayload(c));}
function render(data){
  document.getElementById('summary').textContent = `候选 ${data.summary?.candidates ?? 0} / 跳过 ${data.summary?.skipped ?? 0} / eligible runs ${data.summary?.eligible_runs ?? 0}`;
  document.getElementById('rows').innerHTML = (data.candidates || []).map((c,i)=>`
    <tr>
      <td>${esc(c.asset_name)}<br><span class="muted">${esc(c.asset_id)}</span></td>
      <td>${esc(c.asset_ip)}<br>${esc(c.node)}</td>
      <td>${esc((c.evidence_run_ids||[]).join(', '))}<br><span class="muted">${esc(c.latest_reason)}</span></td>
      <td class="${c.confirmation_state==='confirmed'?'ok':''}">${esc(c.confirmation_state)}<br><span class="danger">${esc(c.confirmation_reason||'')}</span></td>
      <td>
        <button data-action="confirm-disable" data-index="${i}">确认废弃并禁用</button>
        <button data-action="protect" data-index="${i}">保护</button>
        <button data-action="review" data-index="${i}">需复查</button>
        <button data-action="confirm-delete" data-index="${i}" class="danger">危险：确认删除</button>
      </td>
    </tr>`).join('');
  document.querySelectorAll('button[data-action]').forEach(btn => {
    btn.onclick = () => {
      const c = data.candidates[Number(btn.dataset.index)];
      if(btn.dataset.action==='confirm-disable') confirmDisable(c);
      if(btn.dataset.action==='confirm-delete') confirmDelete(c);
      if(btn.dataset.action==='protect') protect(c);
      if(btn.dataset.action==='review') review(c);
    };
  });
}
function load(){fetch('/api/candidates').then(r => r.json()).then(data => {
  render(data);
  document.getElementById('out').textContent = JSON.stringify(data, null, 2);
}).catch(err => { document.getElementById('out').textContent = String(err); });}
load();
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
    parser.add_argument("--profile", default=profile_env.DEFAULT_PROFILE)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8088)
    parser.add_argument("--raw-dir", default="")
    parser.add_argument("--state-dir", default="")
    parser.add_argument("--output-dir", default="")
    parser.add_argument("--token", default=os.getenv("CLEANUP_ADMIN_TOKEN", ""))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    validate_bind_security(args.host, args.token)
    context = AdminContext(
        profile=args.profile,
        raw_dir=Path(args.raw_dir) if args.raw_dir else PROJECT_ROOT / profile_env.profile_path("artifacts/raw", args.profile),
        state_dir=Path(args.state_dir) if args.state_dir else host_cleanup.cleanup_profile_state_dir(args.profile),
        output_dir=Path(args.output_dir) if args.output_dir else host_cleanup.cleanup_output_dir(args.profile),
        token=args.token,
    )

    class Handler(CleanupAdminHandler):
        pass

    Handler.context = context
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"cleanup admin server listening on http://{args.host}:{args.port}/ profile={args.profile}")
    server.serve_forever()


if __name__ == "__main__":
    main()
