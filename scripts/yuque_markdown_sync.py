#!/usr/bin/env python3
"""Sync a local Markdown report to Yuque.

This is intentionally self-contained so scheduled checks do not depend on the
separate yuqeu_sync workspace.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib import error, parse, request


DEFAULT_API_BASE = "https://www.yuque.com/api/v2"
DEFAULT_SLUG = "jumpserver-host-ip-check"
DEFAULT_TITLE = "JumpServer 主机探测与 IP 配置检测报告"
PROJECT_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Config:
    token: str
    api_base: str
    repo_namespace: str
    target_toc_uuid: str
    public: int
    fmt: str
    user_agent: str


@dataclass(frozen=True)
class SiblingTarget:
    repo_id: str
    doc_slug: str
    toc_node_uuid: str


def env_candidates() -> list[Path]:
    return [Path.cwd() / ".env", PROJECT_ROOT / ".env"]


def load_env_files() -> None:
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
            if key and not os.environ.get(key):
                os.environ[key] = value.strip().strip('"').strip("'")


def repo_from_url(url: str) -> str:
    if not url:
        return ""
    parsed = parse.urlparse(url)
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) < 2:
        return ""
    return "/".join(parts[:2])


def parse_sibling_url(url: str) -> SiblingTarget:
    parsed = parse.urlparse(url)
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) < 3:
        raise ValueError("sibling URL must include repo and document slug")
    return SiblingTarget(
        repo_id="/".join(parts[:2]),
        doc_slug=parts[2],
        toc_node_uuid=parse.parse_qs(parsed.query).get("toc_node_uuid", [""])[0],
    )


def load_config(repo_override: str = "") -> Config:
    load_env_files()
    token = os.getenv("YUQUE_TOKEN", "").strip() or os.getenv("YUQUE_PERSONAL_TOKEN", "").strip()
    repo_namespace = (
        repo_override.strip().strip("/")
        or repo_from_url(os.getenv("YUQUE_URL", "").strip())
        or os.getenv("YUQUE_REPO_NAMESPACE", "").strip().strip("/")
    )
    if not token:
        raise SystemExit("缺少 YUQUE_TOKEN：请在项目 .env 中配置语雀 token。")
    if not repo_namespace:
        raise SystemExit("缺少 YUQUE_REPO_NAMESPACE 或 YUQUE_URL。")
    return Config(
        token=token,
        api_base=os.getenv("YUQUE_API_BASE", DEFAULT_API_BASE).rstrip("/"),
        repo_namespace=repo_namespace,
        target_toc_uuid=os.getenv("YUQUE_TARGET_TOC_UUID", "").strip(),
        public=int(os.getenv("YUQUE_PUBLIC", "0") or "0"),
        fmt=os.getenv("YUQUE_FORMAT", "markdown").strip() or "markdown",
        user_agent=os.getenv("YUQUE_USER_AGENT", "jumpserver-check-yuque-sync/0.1").strip()
        or "jumpserver-check-yuque-sync/0.1",
    )


class YuqueMarkdownClient:
    def __init__(self, config: Config) -> None:
        self.config = config

    def _url(self, path: str) -> str:
        return f"{self.config.api_base}{path}"

    def _request(self, method: str, path: str, body: Any = None, timeout: int = 30) -> dict[str, Any]:
        data = None
        headers = {
            "X-Auth-Token": self.config.token,
            "User-Agent": self.config.user_agent,
            "Content-Type": "application/json",
        }
        if body is not None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        req = request.Request(self._url(path), data=data, headers=headers, method=method.upper())
        try:
            with request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                payload = json.loads(raw) if raw else {}
                return payload if isinstance(payload, dict) else {"data": payload}
        except error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"语雀 API 请求失败：HTTP {exc.code} {raw.strip()}") from exc
        except error.URLError as exc:
            raise RuntimeError(f"语雀 API 请求失败：{exc.reason}") from exc

    def get_doc_by_slug(self, slug: str) -> dict[str, Any] | None:
        path = f"/repos/{self.config.repo_namespace}/docs/{slug}"
        req = request.Request(self._url(path), headers={"X-Auth-Token": self.config.token, "User-Agent": self.config.user_agent})
        try:
            with request.urlopen(req, timeout=20) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                payload = json.loads(raw) if raw else {}
                return payload.get("data") if isinstance(payload, dict) else None
        except error.HTTPError as exc:
            if exc.code == 404:
                return None
            raw = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"语雀 API 请求失败：HTTP {exc.code} {raw.strip()}") from exc
        except error.URLError as exc:
            raise RuntimeError(f"语雀 API 请求失败：{exc.reason}") from exc

    def get_doc(self, doc_id_or_slug: str) -> dict[str, Any]:
        return self._request("GET", f"/repos/{self.config.repo_namespace}/docs/{doc_id_or_slug}", timeout=20).get("data", {})

    def list_toc(self) -> list[dict[str, Any]]:
        data = self._request("GET", f"/repos/{self.config.repo_namespace}/toc", timeout=20).get("data", [])
        return data if isinstance(data, list) else []

    def create_doc(self, title: str, slug: str, body: str) -> dict[str, Any]:
        payload = {"title": title, "slug": slug, "body": body, "format": self.config.fmt, "public": self.config.public}
        return self._request("POST", f"/repos/{self.config.repo_namespace}/docs", payload, timeout=30).get("data", {})

    def update_doc(self, doc_id: int | str, title: str, slug: str, body: str) -> dict[str, Any]:
        payload = {"title": title, "slug": slug, "body": body, "format": self.config.fmt, "public": self.config.public}
        return self._request("PUT", f"/repos/{self.config.repo_namespace}/docs/{doc_id}", payload, timeout=30).get("data", {})

    def update_toc(self, operation: dict[str, Any]) -> list[dict[str, Any]]:
        data = self._request("PUT", f"/repos/{self.config.repo_namespace}/toc", operation, timeout=30).get("data", [])
        return data if isinstance(data, list) else []


def extract_title(markdown: str, fallback: str = DEFAULT_TITLE) -> str:
    for line in markdown.splitlines():
        match = re.match(r"^#\s+(.+?)\s*$", line)
        if match:
            return match.group(1).strip()
    return fallback


def extract_report_timestamp(markdown: str) -> tuple[str, str]:
    match = re.search(r"探测开始：`(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})", markdown)
    if match:
        year, month, day, hour, minute, second = match.groups()
        return f"{year}-{month}-{day} {hour}:{minute}:{second}", f"{year}{month}{day}-{hour}{minute}{second}"
    return "", ""


def apply_audit_timestamp(title: str, slug: str, markdown: str) -> tuple[str, str]:
    display_time, slug_time = extract_report_timestamp(markdown)
    if not display_time or not slug_time:
        now = __import__("datetime").datetime.datetime.now()
        display_time = now.strftime("%Y-%m-%d %H:%M:%S")
        slug_time = now.strftime("%Y%m%d-%H%M%S")
    if display_time not in title:
        title = f"{title} {display_time}"
    if not slug.endswith(slug_time):
        slug = f"{slug}-{slug_time}"
    return title, slug


def slugify(text: str) -> str:
    value = re.sub(r"\s+", "-", text.strip().lower())
    value = re.sub(r"[^a-z0-9\-_.\u4e00-\u9fff]", "", value)
    value = re.sub(r"-+", "-", value).strip("-_.")
    return value or DEFAULT_SLUG


def find_toc_node(toc: list[dict[str, Any]], uuid: str) -> dict[str, Any] | None:
    return next((node for node in toc if str(node.get("uuid") or "") == uuid), None)


def find_doc_toc_node(toc: list[dict[str, Any]], doc_id: int | str) -> dict[str, Any] | None:
    return next((node for node in toc if str(node.get("doc_id") or "") == str(doc_id)), None)


def resolve_toc_uuid_from_sibling(client: Any, sibling_url: str) -> str:
    target = parse_sibling_url(sibling_url)
    if target.repo_id and target.repo_id != client.config.repo_namespace:
        raise ValueError(f"sibling URL repo {target.repo_id} does not match configured repo {client.config.repo_namespace}")
    toc = client.list_toc()
    if target.toc_node_uuid:
        node = find_toc_node(toc, target.toc_node_uuid)
        if node and str(node.get("type") or "").upper() == "TITLE":
            return target.toc_node_uuid
        if node:
            parent_uuid = str(node.get("parent_uuid") or "")
            if parent_uuid:
                return parent_uuid
    doc = client.get_doc(target.doc_slug)
    doc_node = find_doc_toc_node(toc, doc.get("id", ""))
    if doc_node:
        return str(doc_node.get("parent_uuid") or "")
    raise RuntimeError("无法从 sibling URL 定位同级目录。")


def attach_doc_to_toc(client: Any, doc: dict[str, Any], toc_uuid: str, title: str, dry_run: bool) -> None:
    if not toc_uuid:
        return
    doc_id = doc.get("id")
    if not doc_id:
        raise RuntimeError("语雀 API 返回中没有 doc id，无法挂载目录。")
    toc = client.list_toc()
    current = find_doc_toc_node(toc, doc_id)
    if current:
        operation = {"action": "appendNode", "action_mode": "child", "target_uuid": toc_uuid, "node_uuid": current["uuid"]}
    else:
        operation = {"action": "appendNode", "action_mode": "child", "target_uuid": toc_uuid, "type": "DOC", "title": title, "doc_id": doc_id}
    if dry_run:
        print("DRY-RUN toc:", json.dumps(operation, ensure_ascii=False, indent=2))
        return
    client.update_toc(operation)


def read_markdown(path: Path) -> str:
    if path.suffix.lower() != ".md":
        raise SystemExit(f"只支持 Markdown 文件：{path}")
    return path.read_text(encoding="utf-8-sig")


def sync_markdown(
    path: Path,
    title: str | None = None,
    slug: str | None = DEFAULT_SLUG,
    toc_uuid: str = "",
    sibling_url: str = "",
    dry_run: bool = False,
    audit_timestamp: bool = False,
    client: Any | None = None,
) -> dict[str, Any]:
    sibling = parse_sibling_url(sibling_url) if sibling_url else None
    config = load_config(repo_override=sibling.repo_id if sibling else "") if client is None else client.config
    body = read_markdown(path)
    final_title = title or extract_title(body, fallback=path.stem)
    final_slug = slug or slugify(final_title)
    if audit_timestamp:
        final_title, final_slug = apply_audit_timestamp(final_title, final_slug, body)
    client = client or YuqueMarkdownClient(config)

    target_toc_uuid = toc_uuid or config.target_toc_uuid
    if sibling_url and not target_toc_uuid and not dry_run:
        target_toc_uuid = resolve_toc_uuid_from_sibling(client, sibling_url)
    elif sibling_url and not target_toc_uuid and dry_run:
        target_toc_uuid = parse_sibling_url(sibling_url).toc_node_uuid

    plan = {
        "repo": config.repo_namespace,
        "title": final_title,
        "slug": final_slug,
        "toc_uuid": target_toc_uuid,
        "source": str(path),
        "format": config.fmt,
        "bytes": len(body.encode("utf-8")),
    }
    if dry_run:
        result = {"dry_run": True, **plan, "body_excerpt": body[:500]}
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return result

    existing = client.get_doc_by_slug(final_slug)
    if existing:
        doc_id = existing.get("id") or final_slug
        doc = client.update_doc(doc_id, final_title, final_slug, body)
        action = "updated"
    else:
        doc = client.create_doc(final_title, final_slug, body)
        action = "created"
    toc_attached = False
    if target_toc_uuid:
        try:
            attach_doc_to_toc(client, doc, target_toc_uuid, final_title, dry_run=False)
            toc_attached = True
        except Exception as exc:  # pragma: no cover - reported best-effort behavior
            print(f"提示：文档已同步，但目录挂载失败：{exc}", file=sys.stderr)
    doc_url = doc.get("url") or doc.get("html_url") or f"https://www.yuque.com/{config.repo_namespace}/{final_slug}"
    result = {**plan, "action": action, "toc_attached": toc_attached, "doc_id": doc.get("id"), "url": doc_url}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="将本地 Markdown 同步到语雀文档。")
    parser.add_argument("markdown_file", type=Path, help="本地 .md 文件路径")
    parser.add_argument("--title", help="语雀文档标题；不填则读取 Markdown 首个 H1")
    parser.add_argument("--slug", default=DEFAULT_SLUG, help=f"语雀文档 slug；默认 {DEFAULT_SLUG}")
    parser.add_argument("--toc-uuid", default="", help="目标目录节点 uuid")
    parser.add_argument("--sibling-url", default="", help="同级测试文档 URL，用于推导 repo 和目录")
    parser.add_argument("--audit-timestamp", action="store_true", help="从报告探测时间生成带时间的文档标题和 slug，用于审计留档")
    parser.add_argument("--dry-run", action="store_true", help="只打印同步计划，不调用语雀写接口")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    path = args.markdown_file.resolve()
    if not path.exists():
        raise SystemExit(f"文件不存在：{path}")
    sync_markdown(
        path=path,
        title=args.title,
        slug=args.slug,
        toc_uuid=args.toc_uuid,
        sibling_url=args.sibling_url,
        dry_run=args.dry_run,
        audit_timestamp=args.audit_timestamp,
    )


if __name__ == "__main__":
    main()
