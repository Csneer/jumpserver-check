#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import datetime as dt
import email.utils
import hashlib
import hmac
import json
import os
import re
import socket
import ssl
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any
from urllib import error, parse, request


DEFAULT_ORG = "00000000-0000-0000-0000-000000000002"
DEFAULT_PAGE_SIZE = 100
DEFAULT_RESUME_STATE = "artifacts/state/jms-host-ip-check-inflight.json"
PROFILE_ENDPOINTS = (
    "/api/v1/users/profile/",
    "/api/v1/users/users/profile/",
    "/api/v1/authentication/users/profile/",
)
RETRYABLE_STATUSES = {0, 408, 429, 500, 502, 503, 504}
REQUEST_RETRY_DELAY = 0.2
DETECTION_COMMAND = r'''
set +e
export LC_ALL=C
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH

ip_type="unknown"
actual_ip=""
all_ips=""
if_name=""

route_line="$(ip route get 1.1.1.1 2>/dev/null | head -1)"
actual_ip="$(printf '%s\n' "$route_line" | sed -n 's/.* src \([0-9.]*\).*/\1/p')"
if_name="$(printf '%s\n' "$route_line" | sed -n 's/.* dev \([^ ]*\).*/\1/p')"

if command -v ip >/dev/null 2>&1; then
  all_ips="$(ip -o -4 addr show scope global 2>/dev/null | awk '{split($4, a, "/"); print a[1]}' | awk '$0 !~ /^172\.17\./ && !seen[$0]++' | paste -sd, -)"
fi

if [ -z "$all_ips" ] && command -v hostname >/dev/null 2>&1; then
  all_ips="$(hostname -I 2>/dev/null | tr ' ' '\n' | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && $0 !~ /^172\.17\./ && !seen[$0]++' | paste -sd, -)"
fi

if [ -n "$actual_ip" ] && ! printf '%s\n' "$actual_ip" | grep -q '^172\.17\.'; then
  case ",$all_ips," in
    *",$actual_ip,"*) ;;
    *) all_ips="${all_ips:+$all_ips,}$actual_ip" ;;
  esac
fi

if [ -z "$actual_ip" ] && [ -n "$all_ips" ]; then
  actual_ip="$(printf '%s\n' "$all_ips" | cut -d, -f1)"
fi

if [ "$ip_type" = "unknown" ] && [ -d /etc/NetworkManager/system-connections ]; then
  for f in /etc/NetworkManager/system-connections/*.nmconnection; do
    [ -f "$f" ] || continue
    conn_iface="$(sed -n 's/^interface-name=//p' "$f" 2>/dev/null | head -1)"
    method="$(awk 'BEGIN{s=0} /^\[ipv4\]/{s=1;next} /^\[/{s=0} s && /^method=/{print; exit}' "$f" 2>/dev/null | cut -d= -f2- | tr -d "\" " | tr '[:upper:]' '[:lower:]')"
    has_ip=0
    if [ -n "$actual_ip" ] && grep -q "$actual_ip/" "$f" 2>/dev/null; then has_ip=1; fi
    if { [ -n "$if_name" ] && [ "$conn_iface" = "$if_name" ]; } || [ "$has_ip" = 1 ]; then
      case "$method" in
        manual|static|none) ip_type="static"; break ;;
        auto|dhcp) ip_type="dhcp"; break ;;
      esac
    fi
  done
fi

if [ "$ip_type" = "unknown" ] && command -v nmcli >/dev/null 2>&1; then
  nm_out="$(nmcli -t -f GENERAL.DEVICES,ipv4.method conn show --active 2>/dev/null)"
  nm_method="$(printf '%s\n' "$nm_out" | awk -F: -v iface="$if_name" '/^GENERAL.DEVICES:/ {dev=$2} /^ipv4.method:/ {if (dev == iface) {print $2; exit}}' | tr -d "\" " | tr '[:upper:]' '[:lower:]')"
  if [ -z "$nm_method" ]; then
    nm_method="$(printf '%s\n' "$nm_out" | awk -F: '/^ipv4.method:/ {print $2; exit}' | tr -d "\" " | tr '[:upper:]' '[:lower:]')"
  fi
  if printf '%s\n' "$nm_method" | grep -qi 'manual\|static\|none'; then
    ip_type="static"
  elif printf '%s\n' "$nm_method" | grep -qi 'auto\|dhcp'; then
    ip_type="dhcp"
  fi
fi

if [ "$ip_type" = "unknown" ]; then
  for f in /etc/sysconfig/network-scripts/ifcfg-*; do
    [ -f "$f" ] || continue
    cfg_iface="$(grep -i '^DEVICE=' "$f" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d "\" ")"
    cfg_name="$(grep -i '^NAME=' "$f" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d "\" ")"
    cfg_ip="$(grep -i '^IPADDR=' "$f" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d "\" ")"
    if [ -n "$if_name" ] && [ "$cfg_iface" != "$if_name" ] && [ "$cfg_name" != "$if_name" ]; then
      if [ -z "$actual_ip" ] || [ "$cfg_ip" != "$actual_ip" ]; then continue; fi
    fi
    bootproto="$(grep -i '^BOOTPROTO=' "$f" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d "\" " | tr '[:upper:]' '[:lower:]')"
    case "$bootproto" in
      static|none) ip_type="static"; break ;;
      dhcp) ip_type="dhcp"; break ;;
    esac
  done
fi

if [ "$ip_type" = "unknown" ] && [ -d /etc/netplan ]; then
  netplan_type="$(awk -v iface="$if_name" -v ip="$actual_ip" '
    /^[[:space:]]*#/ { next }
    {
      line = $0
      sub(/[[:space:]]+#.*/, "", line)
      if (line ~ /^[[:space:]]*$/) next
      if (iface != "" && line ~ "^[[:space:]]*" iface ":[[:space:]]*$") in_iface = 1
      else if (line ~ /^[[:space:]]*[-A-Za-z0-9_.:]+:[[:space:]]*$/ && line !~ /^[[:space:]]*(network|version|renderer|ethernets|bonds|bridges|vlans|wifis):/) in_iface = 0
      if (ip != "" && line ~ /addresses:[[:space:]]*/ && index(line, ip) > 0) ip_method = "static"
      if (in_iface && line ~ /dhcp4:[[:space:]]*true/) iface_method = "dhcp"
      if (in_iface && line ~ /dhcp4:[[:space:]]*false/) iface_method = "static"
      if (in_iface && line ~ /addresses:[[:space:]]*/) iface_method = "static"
      if (first_method == "" && line ~ /dhcp4:[[:space:]]*true/) first_method = "dhcp"
      if (first_method == "" && line ~ /addresses:[[:space:]]*/) first_method = "static"
    }
    END {
      if (iface_method != "") print iface_method
      else if (ip_method != "") print ip_method
      else print first_method
    }
  ' /etc/netplan/*.yaml /etc/netplan/*.yml 2>/dev/null | head -1 | tr -d "\" " | tr '[:upper:]' '[:lower:]')"
  if [ "$netplan_type" = "dhcp" ]; then
    ip_type="dhcp"
  elif [ "$netplan_type" = "static" ]; then
    ip_type="static"
  fi
fi

if [ "$ip_type" = "unknown" ] && [ -f /etc/network/interfaces ]; then
  interfaces_type="$(awk -v iface="$if_name" -v ip="$actual_ip" '
    function flush() {
      if (method == "") return
      if (iface != "" && cur_iface == iface) iface_method = method
      if (ip != "" && has_ip == 1) ip_method = method
      if (first_method == "") first_method = method
    }
    /^[[:space:]]*#/ { next }
    {
      sub(/[[:space:]]+#.*/, "")
      if ($0 ~ /^[[:space:]]*$/) next
    }
    $1 == "iface" && $3 == "inet" {
      flush()
      cur_iface = $2
      method = tolower($4)
      has_ip = 0
      next
    }
    $1 == "address" && $2 == ip { has_ip = 1 }
    END {
      flush()
      if (iface_method != "") print iface_method
      else if (ip_method != "") print ip_method
      else print first_method
    }
  ' /etc/network/interfaces 2>/dev/null | head -1 | tr -d "\" " | tr '[:upper:]' '[:lower:]')"
  case "$interfaces_type" in
    static|manual|none) ip_type="static" ;;
    dhcp) ip_type="dhcp" ;;
  esac
fi

if [ "$ip_type" = "unknown" ] && command -v pgrep >/dev/null 2>&1; then
  if pgrep -x dhclient >/dev/null 2>&1; then
    ip_type="dhcp"
  fi
fi

printf '%s\n' 'DETECT_START'
printf 'IP_TYPE=%s\n' "$ip_type"
printf 'IP_ADDR=%s\n' "$actual_ip"
printf 'IP_ADDRS=%s\n' "$all_ips"
printf 'IF_NAME=%s\n' "$if_name"
printf '%s\n' 'DETECT_END'
'''.strip()


def load_dotenv() -> None:
    for env_path in (
        Path.cwd() / ".env",
        Path.home() / ".jumpserver-connect.env",
        Path.home() / ".codex" / "jumpserver.env",
    ):
        if not env_path.exists():
            continue
        for raw in env_path.read_text(encoding="utf-8-sig").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"Missing required environment variable: {name}")
    return value


def http_date() -> str:
    return email.utils.format_datetime(dt.datetime.now(dt.timezone.utc), usegmt=True)


def canonical_path(path: str, params: dict[str, Any] | None = None) -> str:
    if params:
        return f"{path}?{parse.urlencode(params, doseq=True)}"
    return path


def signature_header(key_id: str, secret: str, method: str, path_with_query: str, headers: dict[str, str]) -> str:
    signed_headers = ["(request-target)", "accept", "date"]
    lines = [f"(request-target): {method.lower()} {path_with_query}"]
    for name in signed_headers[1:]:
        lines.append(f"{name}: {headers[name]}")
    digest = hmac.new(secret.encode("utf-8"), "\n".join(lines).encode("utf-8"), hashlib.sha256).digest()
    signature = base64.b64encode(digest).decode("utf-8")
    return (
        f'Signature keyId="{key_id}",algorithm="hmac-sha256",'
        f'headers="{" ".join(signed_headers)}",signature="{signature}"'
    )


class JumpServerClient:
    def __init__(self, no_proxy: bool = False) -> None:
        load_dotenv()
        self.base = require_env("JMS_URL").rstrip("/")
        self.key_id = require_env("JMS_ACCESS_KEY_ID")
        self.secret = require_env("JMS_ACCESS_KEY_SECRET")
        self.org = os.environ.get("JMS_ORG_ID", DEFAULT_ORG)
        verify_tls = os.environ.get("JMS_VERIFY_TLS", "true").lower() not in {"0", "false", "no"}
        self.context = None if verify_tls else ssl._create_unverified_context()
        env_no_proxy = os.environ.get("JMS_NO_PROXY", "false").lower() in {"1", "true", "yes"}
        handlers: list[Any] = []
        if no_proxy or env_no_proxy:
            handlers.append(request.ProxyHandler({}))
        if self.context is not None:
            handlers.append(request.HTTPSHandler(context=self.context))
        self.opener = request.build_opener(*handlers) if handlers else None

    def request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        body: Any = None,
        timeout: int = 20,
        retries: int | None = None,
    ) -> tuple[int, Any]:
        path_with_query = canonical_path(path, params)
        headers = {
            "accept": "application/json",
            "date": http_date(),
            "X-JMS-ORG": self.org,
        }
        data = None
        if body is not None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        headers["Authorization"] = signature_header(self.key_id, self.secret, method, path_with_query, headers)
        max_attempts = 1 + (retries if retries is not None else (2 if method.upper() == "GET" else 0))
        last_status = 0
        last_payload: Any = None
        for attempt in range(max_attempts):
            req = request.Request(self.base + path_with_query, data=data, headers=headers, method=method.upper())
            try:
                opener = self.opener or request
                if self.opener:
                    response = opener.open(req, timeout=timeout)
                else:
                    response = opener.urlopen(req, timeout=timeout, context=self.context)
                with response as resp:
                    raw = resp.read().decode("utf-8", errors="replace")
                    if not raw:
                        return resp.status, None
                    try:
                        return resp.status, json.loads(raw)
                    except json.JSONDecodeError:
                        return resp.status, api_error_payload("non_json_response", "JumpServer API returned non-JSON response", body_excerpt=raw[:500])
            except error.HTTPError as exc:
                raw = exc.read().decode("utf-8", errors="replace")
                try:
                    payload: Any = json.loads(raw)
                except json.JSONDecodeError:
                    payload = api_error_payload("http_error", f"JumpServer API returned HTTP {exc.code}", body_excerpt=raw[:500])
                last_status, last_payload = exc.code, payload
            except error.URLError as exc:
                last_status = 0
                last_payload = api_error_payload("url_error", str(exc.reason))
            except (TimeoutError, socket.timeout) as exc:
                last_status = 0
                last_payload = api_error_payload("timeout", str(exc))
            except (ssl.SSLError, OSError) as exc:
                last_status = 0
                last_payload = api_error_payload(exc.__class__.__name__, str(exc))
            if attempt < max_attempts - 1 and is_retryable_status(last_status):
                time.sleep(REQUEST_RETRY_DELAY)
                continue
            return last_status, last_payload
        return last_status, last_payload

    def get(self, path: str, params: dict[str, Any] | None = None, timeout: int = 20) -> tuple[int, Any]:
        return self.request("GET", path, params=params, timeout=timeout)

    def post(self, path: str, body: Any, timeout: int = 20) -> tuple[int, Any]:
        return self.request("POST", path, body=body, timeout=timeout)

    def patch(self, path: str, body: Any, timeout: int = 20) -> tuple[int, Any]:
        return self.request("PATCH", path, body=body, timeout=timeout)

    def delete(self, path: str, timeout: int = 20) -> tuple[int, Any]:
        return self.request("DELETE", path, timeout=timeout)

def compact(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2)


def api_error_payload(kind: str, message: str, **extra: Any) -> dict[str, Any]:
    payload = {"error": kind, "message": message}
    payload.update({key: value for key, value in extra.items() if value is not None})
    return payload


def is_retryable_status(status: int) -> bool:
    return status in RETRYABLE_STATUSES


def api_error_remark(action: str, status: int, payload: Any) -> str:
    message = ""
    if isinstance(payload, dict):
        message = str(payload.get("message") or payload.get("error") or "")
    elif payload:
        message = str(payload)
    suffix = f"：{message}" if message else ""
    return f"{action}失败: HTTP {status}{suffix}"


def items_from_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("results", "data", "items"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []


def validate(client: JumpServerClient) -> dict[str, Any]:
    attempts = []
    for path in PROFILE_ENDPOINTS:
        status, payload = client.get(path)
        attempts.append({"endpoint": path, "status": status})
        if 200 <= status < 300 and isinstance(payload, dict):
            return {
                "ok": True,
                "endpoint": path,
                "profile": {
                    "id": payload.get("id"),
                    "username": payload.get("username"),
                    "name": payload.get("name"),
                    "is_valid": payload.get("is_valid"),
                    "is_active": payload.get("is_active"),
                    "is_expired": payload.get("is_expired"),
                },
            }
    return {"ok": False, "attempts": attempts}


def fetch_active_assets(client: JumpServerClient, page_size: int = DEFAULT_PAGE_SIZE, max_assets: int | None = None) -> list[dict[str, Any]]:
    assets: list[dict[str, Any]] = []
    offset = 0
    while True:
        params = {"is_active": "true", "limit": page_size, "offset": offset}
        status, payload = client.get("/api/v1/assets/assets/", params=params)
        if not (200 <= status < 300):
            raise SystemExit(f"Failed to fetch assets: HTTP {status} {compact(payload)}")
        items = items_from_payload(payload)
        if max_assets is not None:
            remaining = max_assets - len(assets)
            if remaining <= 0:
                break
            assets.extend(items[:remaining])
        else:
            assets.extend(items)
        if max_assets is not None and len(assets) >= max_assets:
            break
        if not isinstance(payload, dict) or not payload.get("next") or not items:
            break
        offset += page_size
    return assets


def fetch_authorized_assets(client: JumpServerClient, page_size: int = DEFAULT_PAGE_SIZE) -> list[dict[str, Any]]:
    assets: list[dict[str, Any]] = []
    offset = 0
    while True:
        params = {"limit": page_size, "offset": offset}
        status, payload = client.get("/api/v1/perms/users/self/assets/", params=params)
        if not (200 <= status < 300):
            raise SystemExit(f"Failed to fetch authorized assets: HTTP {status} {compact(payload)}")
        items = items_from_payload(payload)
        assets.extend(items)
        if not isinstance(payload, dict) or not payload.get("next") or not items:
            break
        offset += page_size
    return assets


def asset_matches_query(asset: dict[str, Any], query: str) -> bool:
    needle = query.strip().lower()
    if not needle:
        return True
    candidates = [
        asset.get("id"),
        asset.get("name"),
        asset.get("hostname"),
        asset.get("address"),
        asset.get("ip"),
    ]
    return any(needle in str(value).lower() for value in candidates if value)


def filter_assets_by_query(assets: list[dict[str, Any]], query: str | None) -> list[dict[str, Any]]:
    if not query:
        return assets
    return [asset for asset in assets if asset_matches_query(asset, query)]


def asset_ids(assets: list[dict[str, Any]]) -> set[str]:
    return {str(asset["id"]) for asset in assets if asset.get("id")}


def platform_text(asset: dict[str, Any]) -> str:
    platform = asset.get("platform")
    if isinstance(platform, dict):
        value = platform.get("name") or platform.get("display_name") or platform.get("id") or ""
    else:
        value = platform or ""
    os_value = asset.get("os") or asset.get("os_type") or ""
    return f"{value} {os_value}".strip()


def is_windows_asset(asset: dict[str, Any]) -> bool:
    return "windows" in platform_text(asset).lower()


def is_linux_asset(asset: dict[str, Any]) -> bool:
    text = platform_text(asset).lower()
    if not text or is_windows_asset(asset):
        return False
    linux_markers = (
        "linux",
        "ubuntu",
        "debian",
        "centos",
        "red hat",
        "redhat",
        "rhel",
        "rocky",
        "alma",
        "fedora",
        "suse",
        "opensuse",
        "oracle linux",
        "kylin",
        "anolis",
        "uos",
    )
    return any(marker in text for marker in linux_markers)


def asset_name(asset: dict[str, Any]) -> str:
    return str(asset.get("hostname") or asset.get("name") or asset.get("address") or asset.get("ip") or asset.get("id") or "")


def asset_ip(asset: dict[str, Any]) -> str:
    return str(asset.get("address") or asset.get("ip") or "")


def node_names(asset: dict[str, Any]) -> str:
    nodes = asset.get("nodes")
    if not isinstance(nodes, list):
        return ""
    names = []
    for node in nodes:
        if isinstance(node, dict):
            name = node.get("name") or node.get("full_value")
            if name:
                names.append(str(name))
        elif node:
            names.append(str(node))
    return ", ".join(names)


def node_ids(asset: dict[str, Any]) -> list[str]:
    nodes = asset.get("nodes")
    if not isinstance(nodes, list):
        return []
    ids: list[str] = []
    for node in nodes:
        if isinstance(node, dict):
            node_id = node.get("id")
            if node_id:
                ids.append(str(node_id))
        elif node:
            ids.append(str(node))
    return ids


def node_ids_for_assets(assets: list[dict[str, Any]]) -> list[str]:
    ids: list[str] = []
    for asset in assets:
        for node_id in node_ids(asset):
            if node_id not in ids:
                ids.append(node_id)
    return ids


def primary_node_key(asset: dict[str, Any]) -> str:
    ids = node_ids(asset)
    if ids:
        return ids[0]
    return "__no_node__"


def chunks_by_primary_node(assets: list[dict[str, Any]], max_size: int = 0) -> list[list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    order: list[str] = []
    for asset in assets:
        key = primary_node_key(asset)
        if key not in grouped:
            grouped[key] = []
            order.append(key)
        grouped[key].append(asset)
    batches: list[list[dict[str, Any]]] = []
    for key in order:
        group = grouped[key]
        if max_size and max_size > 0:
            batches.extend(chunks(group, max_size))
        else:
            batches.append(group)
    return batches


def summarize_assets(assets: list[dict[str, Any]]) -> dict[str, Any]:
    platforms = Counter(platform_text(asset) or "unknown" for asset in assets)
    nodes = Counter()
    linux = 0
    windows = 0
    for asset in assets:
        if is_linux_asset(asset):
            linux += 1
        elif is_windows_asset(asset):
            windows += 1
        for name in (node_names(asset) or "未分组").split(", "):
            if name:
                nodes[name] += 1
    return {
        "total": len(assets),
        "linux": linux,
        "windows": windows,
        "unsupported": len(assets) - linux - windows,
        "platforms": dict(platforms),
        "top_nodes": dict(nodes.most_common(20)),
    }


def duplicate_asset_map(assets: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for asset in assets:
        ip = asset_ip(asset)
        if not ip:
            continue
        grouped.setdefault(ip, []).append(asset)
    return {ip: group for ip, group in grouped.items() if len(group) > 1}


def apply_duplicate_asset_annotations(results: list[dict[str, Any]], duplicates: dict[str, list[dict[str, Any]]]) -> None:
    for result in results:
        ip = str(result.get("asset_ip") or "")
        group = duplicates.get(ip)
        if not group:
            continue
        original_status = result.get("probe_status") or ""
        original_remark = result.get("remark") or ""
        names = ", ".join(asset_name(asset) for asset in group)
        result["original_probe_status"] = original_status
        result["original_remark"] = original_remark
        result["probe_status"] = "duplicate_asset"
        detail = f"JumpServer 存在 {len(group)} 条相同资产 IP 记录，疑似历史遗留或重复录入：{names}"
        if original_status:
            detail = f"{detail}；原探测状态 {original_status}"
        result["remark"] = detail


def chunks(items: list[dict[str, Any]], size: int) -> list[list[dict[str, Any]]]:
    if size == 0:
        return [items] if items else []
    if size < 0:
        raise ValueError("batch size must be greater than 0")
    return [items[index : index + size] for index in range(0, len(items), size)]


def stable_asset_snapshot(assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "id": asset.get("id"),
            "name": asset.get("name"),
            "hostname": asset.get("hostname"),
            "address": asset.get("address"),
            "ip": asset.get("ip"),
            "platform": asset.get("platform"),
            "os": asset.get("os"),
            "os_type": asset.get("os_type"),
            "nodes": asset.get("nodes"),
        }
        for asset in assets
    ]


def resume_signature(assets: list[dict[str, Any]], *, runas: str, timeout: int) -> str:
    payload = {
        "asset_ids": [str(asset.get("id") or "") for asset in assets],
        "runas": runas,
        "timeout": timeout,
        "command_sha256": hashlib.sha256(DETECTION_COMMAND.encode("utf-8")).hexdigest(),
    }
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def load_resume_state(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def save_resume_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp_path.replace(path)


def mark_resume_state(path: Path, status: str, paths: dict[str, str] | None = None) -> None:
    state = load_resume_state(path) or {}
    state["status"] = status
    state["updated_at"] = dt.datetime.now().astimezone().isoformat()
    if paths:
        state["report_paths"] = paths
    save_resume_state(path, state)


def base_result(asset: dict[str, Any], status: str, connectivity: str = "unreachable", remark: str = "", source: str = "batch") -> dict[str, Any]:
    return {
        "asset_id": asset.get("id"),
        "asset_name": asset_name(asset),
        "asset_ip": asset_ip(asset),
        "actual_ip": "",
        "actual_ips": "",
        "ip_match": "",
        "if_name": "",
        "ip_type": "",
        "connectivity": connectivity,
        "probe_status": status,
        "probe_source": source,
        "original_probe_status": "",
        "original_remark": "",
        "node": node_names(asset),
        "remark": remark,
    }


def permission_denied_result(asset: dict[str, Any], remark: str = "当前账号未授权该资产，未提交 Ops 执行") -> dict[str, Any]:
    return base_result(asset, "permission_denied", remark=remark, source="preflight")


def skipped_non_linux_result(asset: dict[str, Any]) -> dict[str, Any]:
    platform = platform_text(asset) or "unknown"
    return base_result(
        asset,
        "skipped_non_linux",
        connectivity="skipped",
        remark=f"非 Linux 平台资产按 SOP 跳过：{platform}",
        source="skipped",
    )


def status_result(asset: dict[str, Any], status: str, remark: str, connectivity: str = "unknown") -> dict[str, Any]:
    return base_result(asset, status, connectivity=connectivity, remark=remark)


def ops_task_failed_result(asset: dict[str, Any], task_id: str, summary_message: str = "") -> dict[str, Any]:
    remark = f"Ops 任务整体失败，未按主机日志生成结论，task_id={task_id}"
    if summary_message:
        remark = f"{remark}；{summary_message}"
    return status_result(asset, "ops_task_failed", remark)


def build_ops_payload(batch: list[dict[str, Any]], batch_index: int, timeout: int, runas: str = "root") -> dict[str, Any]:
    asset_ids = [asset.get("id") for asset in batch if asset.get("id")]
    if len(asset_ids) != len(batch):
        raise ValueError("All assets must include id for Ops execution.")
    run_id = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    return {
        "name": f"jms-host-ip-check-{run_id}-batch-{batch_index:03d}",
        "type": "adhoc",
        "module": "shell",
        "args": DETECTION_COMMAND,
        "assets": asset_ids,
        "nodes": node_ids_for_assets(batch),
        "runas_policy": "skip",
        "runas": runas,
        "timeout": timeout,
        "chdir": "",
        "comment": "jumpserver-check read-only host connectivity and IP configuration probe. No remediation commands.",
        "instant": True,
        "is_periodic": False,
        "run_after_save": False,
        "use_parameter_define": False,
    }


def clean_ansible_log(text: Any) -> str:
    if not isinstance(text, str):
        return json.dumps(text, ensure_ascii=False)
    normalized = text.replace("\\r\\n", "\n").replace("\\n", "\n").replace("\x00", "")
    return re.sub(r"\x1b\[[0-9;]*m", "", normalized)


def fetch_full_job_log(client: JumpServerClient, task_id: str, max_pages: int = 200) -> tuple[int, str, list[dict[str, Any]]]:
    chunks_text: list[str] = []
    pages: list[dict[str, Any]] = []
    mark = None
    status = 0
    for page_index in range(max_pages):
        params = {"mark": mark} if mark else None
        status, payload = client.get(f"/api/v1/ops/ansible/job-execution/{task_id}/log/", params=params)
        if not (200 <= status < 300):
            text = compact(payload)
            chunks_text.append(text)
            pages.append({"status": status, "end": False, "mark": mark, "length": len(text), "error": True})
            break
        if not isinstance(payload, dict):
            chunks_text.append(clean_ansible_log(payload))
            pages.append({"status": status, "end": True, "mark": mark, "length": len(chunks_text[-1])})
            break
        data = payload.get("data", "")
        text = clean_ansible_log(data)
        chunks_text.append(text)
        pages.append({"status": status, "end": payload.get("end"), "mark": payload.get("mark"), "length": len(text)})
        if payload.get("end"):
            break
        next_mark = payload.get("mark")
        if not next_mark or next_mark == mark:
            pages[-1]["stalled"] = True
            break
        if page_index == max_pages - 1:
            pages[-1]["truncated"] = True
            break
        mark = str(next_mark)
    return status, "".join(chunks_text), pages


def log_fetch_failed(status: int, pages: list[dict[str, Any]]) -> bool:
    if not (200 <= status < 300):
        return True
    if not pages:
        return True
    last_page = pages[-1]
    if last_page.get("error"):
        return True
    if last_page.get("truncated"):
        return True
    if last_page.get("stalled"):
        return True
    if last_page.get("end") is False:
        return True
    return False


def parse_kv_block(text: str) -> dict[str, str] | None:
    match = re.search(r"DETECT_START\s*(.*?)\s*DETECT_END", text, flags=re.S)
    if not match:
        return None
    values: dict[str, str] = {}
    for raw in match.group(1).splitlines():
        line = raw.strip()
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def is_ignored_probe_ip(value: str) -> bool:
    return value.startswith("172.17.")


def split_ip_values(value: str, *, include_ignored: bool = False) -> list[str]:
    ips: list[str] = []
    for item in re.split(r"[,;\s]+", value.strip()):
        if item and (include_ignored or not is_ignored_probe_ip(item)) and item not in ips:
            ips.append(item)
    return ips


def host_labels(asset: dict[str, Any]) -> set[str]:
    labels = set()
    for value in (
        str(asset.get("name") or ""),
        str(asset.get("hostname") or ""),
        str(asset.get("address") or ""),
        str(asset.get("ip") or ""),
    ):
        if value:
            labels.add(value)
    name = asset_name(asset)
    ip = asset_ip(asset)
    if name and ip and name.startswith(f"{ip}_"):
        labels.add(name.removeprefix(f"{ip}_"))
    if name:
        match = re.match(r"^(\d{1,3})-(\d{1,3})-(\d{1,3})-(\d{1,3})[-_](.+)$", name)
        if match:
            labels.add(".".join(match.groups()[:4]))
            labels.add(f"{'.'.join(match.groups()[:4])}_{match.group(5)}")
    return {label for label in labels if label}


def normalize_host_label(value: str) -> str:
    text = clean_ansible_log(value).strip().lower()
    text = re.sub(r"\s+", "_", text)
    text = re.sub(r"[^a-z0-9_.\-\u4e00-\u9fff]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("_.-")
    return text


def section_lookup_keys(label: str) -> set[str]:
    normalized = normalize_host_label(label)
    keys = {normalized}
    if normalized:
        keys.add(normalized.replace("-", "_"))
        keys.add(normalized.replace("_", "-"))
        ip_match = re.search(r"\d{1,3}(?:[._-]\d{1,3}){3}", normalized)
        if ip_match:
            ip_key = ip_match.group(0).replace("_", ".").replace("-", ".")
            keys.add(ip_key)
            keys.add(normalized.replace(ip_match.group(0), ip_key))
    return {key for key in keys if key}


def split_ansible_host_sections(log_text: str) -> dict[str, str]:
    text = clean_ansible_log(log_text)
    pattern = re.compile(
        r"(?im)^(?:(?:changed|ok|fatal|unreachable|failed): \[(?P<bracket>[^\]]+)\]|(?P<pipe>[^|\r\n]+?)\s+\|\s+(?:CHANGED|SUCCESS|OK|UNREACHABLE|FAILED)!?)"
    )
    matches = list(pattern.finditer(text))
    sections: dict[str, str] = {}
    for index, match in enumerate(matches):
        start = match.start()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        label = (match.group("bracket") or match.group("pipe") or "").strip()
        if label:
            sections[label] = text[start:end]
    return sections


def indexed_sections(sections: dict[str, str]) -> dict[str, list[str]]:
    index: dict[str, list[str]] = {}
    for label in sections:
        for key in section_lookup_keys(label):
            index.setdefault(key, []).append(label)
    return index


def section_for_asset(asset: dict[str, Any], log_text: str, batch_size: int) -> str:
    sections = split_ansible_host_sections(log_text)
    cleaned = clean_ansible_log(log_text)
    if batch_size == 1:
        return next(iter(sections.values()), cleaned) if sections else cleaned
    for label in host_labels(asset):
        if label in sections:
            return sections[label]
    index = indexed_sections(sections)
    for label in host_labels(asset):
        for key in section_lookup_keys(label):
            labels = index.get(key) or []
            if len(labels) == 1:
                return sections[labels[0]]
    return ""


def summary_failure_messages(summary: Any) -> dict[str, str]:
    if not isinstance(summary, dict):
        return {}
    messages: dict[str, str] = {}
    for key in ("dark", "failures", "excludes"):
        value = summary.get(key)
        if isinstance(value, dict):
            for label, message in value.items():
                messages[str(label)] = str(message)
    return messages


def summary_message_for_asset(asset: dict[str, Any], summary: Any) -> str:
    messages = summary_failure_messages(summary)
    if not messages:
        return ""
    for label in host_labels(asset):
        if label in messages:
            return messages[label]
    index: dict[str, list[str]] = {}
    for label in messages:
        for key in section_lookup_keys(label):
            index.setdefault(key, []).append(label)
    for label in host_labels(asset):
        for key in section_lookup_keys(label):
            labels = index.get(key) or []
            if len(labels) == 1:
                return messages[labels[0]]
    return ""


def classify_probe_result(asset: dict[str, Any], log_segment: str, timed_out: bool = False, remark: str = "") -> dict[str, Any]:
    base = base_result(asset, "probe_timeout" if timed_out else "unreachable", remark=remark)
    if timed_out:
        return base
    if not log_segment:
        base["remark"] = remark or "未找到该主机的 Ops 输出"
        return base
    lowered = log_segment.lower()
    if "has no access permission" in lowered or "you do not have access rights" in lowered or "no access permission" in lowered:
        base["probe_status"] = "permission_denied"
        base["remark"] = remark or "JumpServer Ops 无资产访问权限"
        return base
    if "无可用账号" in log_segment or "no available account" in lowered or "no account" in lowered:
        base["probe_status"] = "no_account"
        base["remark"] = remark or "JumpServer Ops 无可用登录账号"
        return base
    if "traceback" in lowered or "ansiballz_command.py" in lowered or "module_stderr" in lowered:
        base["connectivity"] = "ok"
        base["probe_status"] = "ops_module_error"
        base["remark"] = remark or "Ops/Ansible 模块执行异常，未拿到有效探测输出"
        return base
    if "error! failed at splitting arguments" in lowered or "unbalanced jinja2 block or quotes" in lowered:
        base["connectivity"] = "ok"
        base["probe_status"] = "parse_error"
        base["remark"] = remark or "JumpServer Ops 未能解析探测命令参数"
        return base
    if (
        "syntax error" in lowered
        or "bad substitution" in lowered
        or "unexpected eof" in lowered
        or "unexpected end of file" in lowered
        or "command not found" in lowered
        or "not found" in lowered and "detect_start" in lowered
    ):
        base["connectivity"] = "ok"
        base["probe_status"] = "probe_script_error"
        base["remark"] = remark or "远端探测脚本执行异常，未拿到有效探测输出"
        return base
    if "unreachable" in lowered or "failed to connect" in lowered or "permission denied" in lowered:
        base["remark"] = remark or "JumpServer Ops 返回连接失败"
        return base
    values = parse_kv_block(log_segment)
    if values is None:
        if re.search(r"task\s+ops\.tasks\..*succeeded\s+in\s+\d+(?:\.\d+)?s:\s+none", lowered, flags=re.S):
            base["probe_status"] = "ops_no_output"
            base["remark"] = remark or "Ops 任务成功但未返回主机输出"
            return base
        base["connectivity"] = "ok"
        base["probe_status"] = "parse_error"
        base["remark"] = remark or "未找到 DETECT_START/DETECT_END 输出块"
        return base
    ip_type = (values.get("IP_TYPE") or "unknown").lower()
    actual_ip = values.get("IP_ADDR") or ""
    raw_actual_ips = values.get("IP_ADDRS") or ""
    actual_ips = split_ip_values(raw_actual_ips)
    if raw_actual_ips and actual_ip and not is_ignored_probe_ip(actual_ip) and actual_ip not in actual_ips:
        actual_ips.insert(0, actual_ip)
    recorded_ip = asset_ip(asset)
    ip_match: bool | str = ""
    if recorded_ip and actual_ips:
        ip_match = recorded_ip in actual_ips
    elif recorded_ip and is_ignored_probe_ip(recorded_ip):
        ip_match = False
    base.update(
        {
            "actual_ip": actual_ip,
            "actual_ips": ", ".join(actual_ips),
            "ip_match": ip_match,
            "if_name": values.get("IF_NAME") or "",
            "ip_type": ip_type,
            "connectivity": "ok",
        }
    )
    if recorded_ip and not actual_ips and not is_ignored_probe_ip(recorded_ip):
        base["probe_status"] = "manual_check"
        base["remark"] = remark or "未采集到可比对的主机 IP，无法确认资产 IP 是否一致"
        return base
    if ip_match is False:
        base["probe_status"] = "ip_mismatch"
        base["remark"] = remark or "实际 IP 与 JumpServer 资产 IP 不一致"
    elif ip_type == "static":
        base["probe_status"] = "ok_static"
        base["remark"] = remark
    elif ip_type == "dhcp":
        base["probe_status"] = "warn_dhcp"
        base["remark"] = remark or "检测到 DHCP"
    else:
        base["probe_status"] = "manual_check"
        base["remark"] = remark or "无法自动判断 IP 配置类型"
    return base


def run_batch(
    client: JumpServerClient,
    batch: list[dict[str, Any]],
    batch_index: int,
    timeout: int,
    poll_interval: int,
    runas: str,
    wait_timeout: int,
    resume_state_path: Path | None = None,
    signature: str = "",
) -> dict[str, Any]:
    payload = build_ops_payload(batch, batch_index, timeout, runas=runas)
    create_status, created = client.post("/api/v1/ops/jobs/", payload)
    task_id = created.get("task_id") if isinstance(created, dict) else None
    batch_record: dict[str, Any] = {
        "batch_index": batch_index,
        "asset_count": len(batch),
        "create_status": create_status,
        "task_id": task_id,
        "polls": [],
    }
    if not (200 <= create_status < 300) or not task_id:
        remark = api_error_remark("Ops 作业创建", create_status, created)
        batch_record["results"] = [
            status_result(asset, "api_error", remark) for asset in batch
        ]
        return batch_record
    if resume_state_path is not None:
        save_resume_state(
            resume_state_path,
            {
                "status": "submitted",
                "created_at": dt.datetime.now().astimezone().isoformat(),
                "updated_at": dt.datetime.now().astimezone().isoformat(),
                "task_id": task_id,
                "batch_index": batch_index,
                "asset_count": len(batch),
                "assets": stable_asset_snapshot(batch),
                "signature": signature,
                "runas": runas,
                "timeout": timeout,
                "execution_mode": "batch",
                "batch_size": 0,
            },
        )

    return collect_batch_result(client, batch, batch_record, task_id, poll_interval, wait_timeout)


def collect_batch_result(
    client: JumpServerClient,
    batch: list[dict[str, Any]],
    batch_record: dict[str, Any],
    task_id: str,
    poll_interval: int,
    wait_timeout: int,
) -> dict[str, Any]:
    deadline = time.time() + wait_timeout
    task: dict[str, Any] = {}
    while time.time() < deadline:
        task_status, task_payload = client.get(f"/api/v1/ops/job-execution/task-detail/{task_id}/")
        if not (200 <= task_status < 300):
            remark = api_error_remark("Ops 任务状态查询", task_status, task_payload)
            batch_record.setdefault("polls", []).append({"status": task_status, "error": task_payload})
            batch_record["task"] = {"status": "api_error", "is_finished": False, "is_success": False, "task_id": task_id}
            batch_record["results"] = [status_result(asset, "api_error", remark) for asset in batch]
            return batch_record
        task = task_payload if isinstance(task_payload, dict) else {}
        batch_record.setdefault("polls", []).append(
            {
                "status": task_status,
                "job_status": task.get("status"),
                "is_finished": task.get("is_finished"),
                "is_success": task.get("is_success"),
                "summary": task.get("summary"),
            }
        )
        if task.get("is_finished") or str(task.get("status") or "").lower() in {"success", "failed"}:
            break
        time.sleep(poll_interval)
    finished = bool(task.get("is_finished")) or str(task.get("status") or "").lower() in {"success", "failed"}
    timed_out = not finished
    batch_record["task"] = {
        "status": task.get("status"),
        "is_finished": task.get("is_finished"),
        "is_success": task.get("is_success"),
        "time_cost": task.get("time_cost"),
        "job_id": task.get("job_id"),
        "summary": task.get("summary"),
    }
    if task.get("job_id"):
        job_detail_status, job_detail = client.get(f"/api/v1/ops/jobs/{task['job_id']}/")
        batch_record["job_detail_status"] = job_detail_status
        if isinstance(job_detail, dict):
            batch_record["job_summary"] = job_detail.get("summary")
    if timed_out:
        batch_record["results"] = [
            classify_probe_result(asset, "", timed_out=True, remark=f"批次任务超时，task_id={task_id}") for asset in batch
        ]
        return batch_record

    log_status, log_text, log_pages = fetch_full_job_log(client, task_id)
    batch_record["log_status"] = log_status
    batch_record["log_pages"] = log_pages
    batch_record["log"] = log_text
    batch_record["log_excerpt"] = log_text[:2000]
    if log_fetch_failed(log_status, log_pages):
        remark = f"Ops 日志拉取失败或分页中断，task_id={task_id}, HTTP {log_status}"
        batch_record["results"] = [status_result(asset, "log_fetch_error", remark) for asset in batch]
        return batch_record
    results = []
    task_failed = not bool(task.get("is_success")) or str(task.get("status") or "").lower() == "failed"
    for asset in batch:
        segment = section_for_asset(asset, log_text, len(batch))
        summary_message = summary_message_for_asset(asset, task.get("summary"))
        if segment:
            results.append(classify_probe_result(asset, segment))
        elif summary_message:
            results.append(classify_probe_result(asset, summary_message, remark=summary_message))
        elif task_failed:
            results.append(ops_task_failed_result(asset, task_id))
        else:
            results.append(classify_probe_result(asset, segment, remark=summary_message))
    batch_record["results"] = results
    return batch_record


def run_single_asset_jobs(
    results_prefix: list[dict[str, Any]],
    assets: list[dict[str, Any]],
    timeout: int,
    poll_interval: int,
    runas: str,
    wait_timeout: int,
    concurrency: int,
    no_proxy: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not assets:
        return results_prefix, []
    worker_count = max(1, min(concurrency, len(assets)))
    indexed_results: list[dict[str, Any] | None] = [None] * len(assets)
    batch_records: list[dict[str, Any]] = []

    def run_one(item: tuple[int, dict[str, Any]]) -> tuple[int, dict[str, Any], dict[str, Any]]:
        index, asset = item
        worker_client = JumpServerClient(no_proxy=no_proxy)
        record = run_batch(worker_client, [asset], index + 1, timeout, poll_interval, runas, wait_timeout)
        result = (record.get("results") or [classify_probe_result(asset, "", timed_out=True, remark="单资产 Ops 任务无结果")])[0]
        return index, result, record

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = [executor.submit(run_one, item) for item in enumerate(assets)]
        for future in as_completed(futures):
            index, result, record = future.result()
            indexed_results[index] = result
            batch_records.append(record)

    return results_prefix + [result for result in indexed_results if result is not None], batch_records


def skipped_windows_result(asset: dict[str, Any]) -> dict[str, Any]:
    return {
        "asset_id": asset.get("id"),
        "asset_name": asset_name(asset),
        "asset_ip": asset_ip(asset),
        "actual_ip": "",
        "actual_ips": "",
        "ip_match": "",
        "if_name": "",
        "ip_type": "",
        "connectivity": "skipped",
        "probe_status": "skipped_windows",
        "probe_source": "skipped",
        "original_probe_status": "",
        "original_remark": "",
        "node": node_names(asset),
        "remark": "Windows 资产按 SOP 跳过",
    }


def md_escape(value: Any) -> str:
    if isinstance(value, bool):
        text = "true" if value else "false"
    elif value is None:
        text = ""
    else:
        text = str(value)
    return text.replace("\r\n", "<br>").replace("\n", "<br>").replace("|", "\\|")


def markdown_table(headers: list[str], rows: list[list[Any]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    if rows:
        lines.extend("| " + " | ".join(md_escape(item) for item in row) + " |" for row in rows)
    else:
        lines.append("| " + " | ".join(["无"] + [""] * (len(headers) - 1)) + " |")
    return "\n".join(lines) + "\n"


def result_row(result: dict[str, Any]) -> list[Any]:
    return [
        result.get("asset_name", ""),
        result.get("asset_ip", ""),
        result.get("actual_ip", ""),
        result.get("actual_ips", ""),
        result.get("ip_match", ""),
        result.get("if_name", ""),
        result.get("ip_type", ""),
        result.get("probe_status", ""),
        result.get("node", ""),
        result.get("probe_source", ""),
        result.get("remark", ""),
    ]


PROBLEM_STATUSES = (
    "warn_dhcp",
    "manual_check",
    "ip_mismatch",
    "duplicate_asset",
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
)


def issue_index_rows(results: list[dict[str, Any]], status: str, limit: int = 30) -> list[list[Any]]:
    rows = []
    for result in results:
        if not result_matches_status(result, status):
            continue
        rows.append(
            [
                result.get("asset_name", ""),
                result.get("asset_ip", ""),
                result.get("actual_ips") or result.get("actual_ip", ""),
                result.get("node", ""),
                result.get("remark", ""),
            ]
        )
        if len(rows) >= limit:
            break
    return rows


def result_matches_status(result: dict[str, Any], status: str) -> bool:
    if result.get("probe_status") == status:
        return True
    return result.get("probe_status") == "duplicate_asset" and result.get("original_probe_status") == status


def probe_status_counts(results: list[dict[str, Any]]) -> Counter[str]:
    counts = Counter(result["probe_status"] for result in results)
    for result in results:
        if result.get("probe_status") != "duplicate_asset":
            continue
        original_status = result.get("original_probe_status")
        if original_status in PROBLEM_STATUSES and original_status != "duplicate_asset":
            counts[str(original_status)] += 1
    return counts


def build_issue_index(results: list[dict[str, Any]], status_counts: Counter[str], limit: int = 30) -> list[str]:
    lines = ["## 问题分类索引", ""]
    issue_headers = ["资产名称", "资产IP", "探测IP列表", "节点", "备注"]
    has_issue = False
    for status in PROBLEM_STATUSES:
        count = status_counts.get(status, 0)
        if count <= 0:
            continue
        has_issue = True
        lines.extend([f"### {status}（{count}）", ""])
        lines.append(markdown_table(issue_headers, issue_index_rows(results, status, limit=limit)))
        if count > limit:
            lines.extend([f"> 仅展示前 {limit} 条，完整记录见下方异常主机表。", ""])
        else:
            lines.append("")
    if not has_issue:
        lines.append("无异常主机。")
        lines.append("")
    return lines


def build_markdown_report(results: list[dict[str, Any]], started_at: dt.datetime, finished_at: dt.datetime, summary: dict[str, Any]) -> str:
    status_counts = probe_status_counts(results)
    abnormal = [result for result in results if result.get("probe_status") not in {"ok_static"}]
    headers = ["资产名称", "资产IP", "默认IP", "探测IP列表", "IP一致", "网卡", "IP类型", "探测状态", "节点", "探测来源", "备注"]
    lines = [
        "# JumpServer 主机探测与 IP 配置检测报告",
        "",
        f"> 探测开始：`{started_at.strftime('%Y-%m-%d %H:%M:%S %z')}`；完成：`{finished_at.strftime('%Y-%m-%d %H:%M:%S %z')}`。",
        "",
        "## 汇总",
        "",
        f"- 活跃资产总数：{summary.get('total_assets', 0)}",
        f"- Linux 参与探测：{summary.get('linux_assets', 0)}",
        f"- Windows 跳过：{summary.get('windows_assets', 0)}",
        f"- 非 Linux 跳过：{summary.get('unsupported_assets', 0)}",
        f"- 执行模式：{summary.get('execution_mode', '')}",
        f"- 重复资产 IP 数：{summary.get('duplicate_ip_count', 0)}",
        f"- 报告记录数：{len(results)}",
        "",
        markdown_table(["分类", "数量"], [[key, status_counts.get(key, 0)] for key in (
            "ok_static",
            "warn_dhcp",
            "manual_check",
            "ip_mismatch",
            "duplicate_asset",
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
        )]),
        "",
        *build_issue_index(results, status_counts),
        "## 异常主机",
        "",
        markdown_table(headers, [result_row(result) for result in abnormal]),
        "",
        "## 全量明细",
        "",
        markdown_table(headers, [result_row(result) for result in results]),
    ]
    return "\n".join(lines).rstrip() + "\n"


def write_reports(
    results: list[dict[str, Any]],
    batches: list[dict[str, Any]],
    started_at: dt.datetime,
    output_dir: Path,
    raw_output_dir: Path,
    retention_count: int,
    summary: dict[str, Any],
    run_metadata: dict[str, Any] | None = None,
) -> dict[str, str]:
    finished_at = dt.datetime.now().astimezone()
    output_dir.mkdir(parents=True, exist_ok=True)
    raw_output_dir.mkdir(parents=True, exist_ok=True)
    run_id = started_at.strftime("%Y%m%d-%H%M%S")
    report_name = f"jumpserver-host-ip-check-{run_id}.md"
    report_path = output_dir / report_name
    latest_path = output_dir / "jumpserver-host-ip-check-latest.md"
    content = build_markdown_report(results, started_at, finished_at, summary)
    report_path.write_text(content, encoding="utf-8")
    latest_path.write_text(content, encoding="utf-8")
    raw_path = raw_output_dir / f"jumpserver-host-ip-check-{run_id}.json"
    raw_payload = {
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "summary": summary,
        "results": results,
        "batches": batches,
    }
    if run_metadata:
        raw_payload.update(run_metadata)
    raw_path.write_text(json.dumps(raw_payload, ensure_ascii=False, indent=2), encoding="utf-8")
    prune_old_reports(output_dir, retention_count)
    return {"report": str(report_path), "latest": str(latest_path), "raw": str(raw_path)}


def prune_old_reports(output_dir: Path, retention_count: int) -> None:
    if retention_count <= 0:
        return
    reports = sorted(
        output_dir.glob("jumpserver-host-ip-check-????????-??????.md"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    for path in reports[retention_count:]:
        path.unlink(missing_ok=True)


def run_detect(args: argparse.Namespace) -> dict[str, Any]:
    client = JumpServerClient(no_proxy=args.no_proxy)
    auth = validate(client)
    if not auth.get("ok"):
        raise SystemExit(f"Access Key validation failed: {compact(auth)}")
    started_at = dt.datetime.now().astimezone()
    assets = fetch_active_assets(client, page_size=args.page_size, max_assets=None)
    assets = filter_assets_by_query(assets, args.query)
    if args.max_assets is not None:
        assets = assets[: args.max_assets]
    if not assets:
        raise SystemExit(f"No active asset matched query: {args.query}")
    authorized_assets = fetch_authorized_assets(client, page_size=args.page_size)
    authorized = asset_ids(authorized_assets)
    windows_assets = [asset for asset in assets if is_windows_asset(asset)]
    target_linux_assets = [asset for asset in assets if is_linux_asset(asset)]
    unsupported_assets = [asset for asset in assets if not is_windows_asset(asset) and not is_linux_asset(asset)]
    unauthorized_assets = [
        asset for asset in target_linux_assets if asset.get("id") and str(asset["id"]) not in authorized
    ]
    linux_assets = [
        asset for asset in target_linux_assets if not asset.get("id") or str(asset["id"]) in authorized
    ]
    results = [skipped_windows_result(asset) for asset in windows_assets]
    results.extend(skipped_non_linux_result(asset) for asset in unsupported_assets)
    results.extend(permission_denied_result(asset) for asset in unauthorized_assets)
    batch_records = []
    resume_state_path = Path(args.resume_state)
    can_resume = args.resume and args.execution_mode == "batch" and args.batch_size == 0 and not args.query and args.max_assets is None
    signature = resume_signature(linux_assets, runas=args.runas, timeout=args.timeout)
    if args.execution_mode == "single":
        results, batch_records = run_single_asset_jobs(
            results,
            linux_assets,
            args.timeout,
            args.poll_interval,
            args.runas,
            args.wait_timeout,
            args.concurrency,
            args.no_proxy,
        )
    else:
        if args.execution_mode == "node-batch":
            linux_batches = chunks_by_primary_node(linux_assets, args.batch_size)
        else:
            linux_batches = chunks(linux_assets, args.batch_size)
        if can_resume:
            state = load_resume_state(resume_state_path)
            if state and state.get("status") != "parsed" and state.get("task_id") and state.get("signature") == signature:
                batch = state.get("assets") if isinstance(state.get("assets"), list) else linux_assets
                batch_record = {
                    "batch_index": state.get("batch_index", 1),
                    "asset_count": len(batch),
                    "create_status": "resumed",
                    "task_id": state["task_id"],
                    "polls": [],
                    "resumed": True,
                }
                batch_record = collect_batch_result(client, batch, batch_record, state["task_id"], args.poll_interval, args.wait_timeout)
                batch_records.append(batch_record)
                results.extend(batch_record.get("results", []))
            else:
                for index, batch in enumerate(linux_batches, start=1):
                    batch_record = run_batch(
                        client,
                        batch,
                        index,
                        args.timeout,
                        args.poll_interval,
                        args.runas,
                        args.wait_timeout,
                        resume_state_path=resume_state_path if index == 1 and len(linux_batches) == 1 else None,
                        signature=signature,
                    )
                    batch_records.append(batch_record)
                    results.extend(batch_record.get("results", []))
                    if args.batch_gap > 0 and index < len(linux_batches):
                        time.sleep(args.batch_gap)
        else:
            for index, batch in enumerate(linux_batches, start=1):
                batch_record = run_batch(client, batch, index, args.timeout, args.poll_interval, args.runas, args.wait_timeout)
                batch_records.append(batch_record)
                results.extend(batch_record.get("results", []))
                if args.batch_gap > 0 and index < len(linux_batches):
                    time.sleep(args.batch_gap)
    duplicates = duplicate_asset_map(assets)
    apply_duplicate_asset_annotations(results, duplicates)
    summary = {
        "total_assets": len(assets),
        "linux_assets": len(linux_assets),
        "windows_assets": len(windows_assets),
        "unsupported_assets": len(unsupported_assets),
        "authorized_assets": len(linux_assets),
        "unauthorized_assets": len(unauthorized_assets),
        "execution_mode": args.execution_mode,
        "batch_size": args.batch_size,
        "batch_count": len(batch_records),
        "concurrency": args.concurrency if args.execution_mode == "single" else "",
        "duplicate_ip_count": len(duplicates),
    }
    paths = write_reports(
        results,
        batch_records,
        started_at,
        Path(args.output_dir),
        Path(args.raw_output_dir),
        args.retention_count,
        summary,
        run_metadata={
            "run_id": getattr(args, "run_id", "") or started_at.strftime("%Y%m%d-%H%M%S"),
            "profile": getattr(args, "profile", "default"),
            "run_source": getattr(args, "run_source", "manual"),
            "cleanup_evidence_eligible": bool(getattr(args, "cleanup_evidence_eligible", False)),
        },
    )
    if can_resume and batch_records and all("results" in record for record in batch_records):
        mark_resume_state(resume_state_path, "parsed", paths)
    return {"summary": summary, "paths": paths, "status_counts": dict(probe_status_counts(results))}


def main() -> None:
    parser = argparse.ArgumentParser(description="JumpServer host connectivity and IP configuration checker")
    parser.add_argument("--no-proxy", action="store_true", help="disable urllib proxy handling for JumpServer requests")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("validate-auth")

    list_assets = sub.add_parser("list-assets")
    list_assets.add_argument("--page-size", type=int, default=DEFAULT_PAGE_SIZE)
    list_assets.add_argument("--max-assets", type=int)
    list_assets.add_argument("--query", help="filter active assets by id, name, hostname, address, or ip")

    detect = sub.add_parser("detect")
    detect.add_argument(
        "--execution-mode",
        choices=("node-batch", "batch", "single"),
        default="batch",
        help="node-batch matches the Web console node-scoped bulk execution; batch can use --batch-size 0 for all-in-one; single runs one Ops job per asset",
    )
    detect.add_argument("--batch-size", type=int, default=0, help="0 means all assets in one batch, or one batch per node in node-batch mode")
    detect.add_argument("--timeout", type=int, default=-1, help="JumpServer job timeout; -1 matches the Web console default")
    detect.add_argument("--wait-timeout", type=int, default=1200, help="local polling wait per Ops job")
    detect.add_argument("--poll-interval", type=int, default=30)
    detect.add_argument("--batch-gap", type=int, default=2)
    detect.add_argument("--concurrency", type=int, default=12, help="concurrent single-asset Ops jobs when --execution-mode single")
    detect.add_argument("--page-size", type=int, default=DEFAULT_PAGE_SIZE)
    detect.add_argument("--max-assets", type=int)
    detect.add_argument("--query", help="filter active assets by id, name, hostname, address, or ip")
    detect.add_argument("--output-dir", default="reports/yuque")
    detect.add_argument("--raw-output-dir", default="artifacts/raw")
    detect.add_argument("--retention-count", type=int, default=12)
    detect.add_argument("--runas", default="root")
    detect.add_argument("--profile", default="default", help="profile name recorded in raw provenance")
    detect.add_argument("--run-id", default="", help="stable workflow run id recorded in raw provenance")
    detect.add_argument(
        "--run-source",
        choices=("weekly_scheduled", "manual", "dry_run", "tmp_probe"),
        default="manual",
        help="source classification recorded in raw provenance; only weekly_scheduled can be cleanup evidence",
    )
    detect.add_argument(
        "--cleanup-evidence-eligible",
        action="store_true",
        help="mark this detect raw output as eligible evidence for cleanup evaluation",
    )
    detect.add_argument("--resume", action=argparse.BooleanOptionalAction, default=True, help="resume an unparsed all-in-one batch Ops task when possible")
    detect.add_argument("--resume-state", default=DEFAULT_RESUME_STATE, help="path to local inflight task state")

    args = parser.parse_args()
    if args.command == "validate-auth":
        client = JumpServerClient(no_proxy=args.no_proxy)
        result = validate(client)
        print(compact(result))
        if not result.get("ok"):
            raise SystemExit(1)
    elif args.command == "list-assets":
        client = JumpServerClient(no_proxy=args.no_proxy)
        auth = validate(client)
        if not auth.get("ok"):
            raise SystemExit(f"Access Key validation failed: {compact(auth)}")
        assets = fetch_active_assets(client, page_size=args.page_size, max_assets=None)
        assets = filter_assets_by_query(assets, args.query)
        if args.max_assets is not None:
            assets = assets[: args.max_assets]
        print(compact(summarize_assets(assets)))
    elif args.command == "detect":
        print(compact(run_detect(args)))


if __name__ == "__main__":
    main()
