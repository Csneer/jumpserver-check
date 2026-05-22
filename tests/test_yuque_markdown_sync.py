import json
from pathlib import Path

from scripts import yuque_markdown_sync as sync


class FakeConfig:
    repo_namespace = "user/repo"
    target_toc_uuid = ""
    fmt = "markdown"
    public = 0


class FakeClient:
    def __init__(self, existing=None):
        self.config = FakeConfig()
        self.existing = existing
        self.created = []
        self.updated = []

    def get_doc_by_slug(self, slug):
        return self.existing

    def create_doc(self, title, slug, body):
        self.created.append((title, slug, body))
        return {"id": 1, "url": f"https://www.yuque.com/user/repo/{slug}"}

    def update_doc(self, doc_id, title, slug, body):
        self.updated.append((doc_id, title, slug, body))
        return {"id": doc_id, "url": f"https://www.yuque.com/user/repo/{slug}"}


def test_apply_audit_timestamp_from_report():
    markdown = "探测开始：`2026-05-21 18:47:45 +0800`"

    title, slug = sync.apply_audit_timestamp("报告", "jumpserver-host-ip-check", markdown)

    assert title == "报告 2026-05-21 18:47:45"
    assert slug == "jumpserver-host-ip-check-20260521-184745"


def test_sync_markdown_dry_run_does_not_call_client(tmp_path: Path):
    path = tmp_path / "report.md"
    path.write_text("# Report\n\n探测开始：`2026-05-21 18:47:45 +0800`\n", encoding="utf-8")
    client = FakeClient()

    result = sync.sync_markdown(path, title="Report", slug="report", audit_timestamp=True, dry_run=True, client=client)

    assert result["dry_run"] is True
    assert result["slug"] == "report-20260521-184745"
    assert client.created == []
    assert client.updated == []


def test_sync_markdown_creates_new_doc(tmp_path: Path):
    path = tmp_path / "report.md"
    path.write_text("# Report\nbody", encoding="utf-8")
    client = FakeClient()

    result = sync.sync_markdown(path, title="Report", slug="report", client=client)

    assert result["action"] == "created"
    assert client.created[0][1] == "report"
    assert result["url"].endswith("/report")


def test_sync_markdown_updates_existing_doc(tmp_path: Path):
    path = tmp_path / "report.md"
    path.write_text("# Report\nbody", encoding="utf-8")
    client = FakeClient(existing={"id": 42})

    result = sync.sync_markdown(path, title="Report", slug="report", client=client)

    assert result["action"] == "updated"
    assert client.updated[0][0] == 42


def test_load_config_prefers_env_over_file(monkeypatch):
    monkeypatch.setenv("YUQUE_TOKEN", "token")
    monkeypatch.setenv("YUQUE_URL", "https://leyaoyao.yuque.com/vurq8u/tiatz9/")

    config = sync.load_config()

    assert config.token == "token"
    assert config.repo_namespace == "vurq8u/tiatz9"
