import json

import pytest

from scripts import wecom_notify as notify


def test_load_summary_prefers_inline_json_over_path_checks():
    payload = {
        "summary": {"total_assets": 353},
        "status_counts": {"ok_static": 222},
        "paths": {"report": "reports/yuque/jumpserver-host-ip-check.md"},
    }
    large_inline_json = json.dumps(payload) + (" " * 5000)

    assert notify.load_summary(large_inline_json) == payload


def test_load_summary_reads_json_file(tmp_path):
    summary_path = tmp_path / "summary.json"
    summary_path.write_text(json.dumps({"status_counts": {"unreachable": 1}}), encoding="utf-8")

    assert notify.load_summary(str(summary_path)) == {"status_counts": {"unreachable": 1}}


def test_load_summary_rejects_invalid_source():
    with pytest.raises(ValueError, match="JSON 字符串或可读取的 JSON 文件路径"):
        notify.load_summary("not json and not a file")


def test_build_markdown_message_includes_summary_and_links():
    summary = {
        "summary": {"total_assets": 353, "linux_assets": 344, "unauthorized_assets": 9},
        "status_counts": {"ok_static": 222, "unreachable": 78},
    }

    message = notify.build_markdown_message(
        "success",
        "JumpServer 每周主机巡检",
        summary,
        report_path="reports/yuque/latest.md",
        yuque_url="https://www.yuque.com/a/b/c",
        duration_seconds=12.3,
    )

    assert "成功" in message
    assert "活跃资产：353" in message
    assert "ok_static: 222" in message
    assert "unreachable: 78" in message
    assert "https://www.yuque.com/a/b/c" in message
    assert "reports/yuque/latest.md" in message


def test_notify_skips_when_webhook_missing(monkeypatch):
    monkeypatch.delenv("WECOM_WEBHOOK_URL", raising=False)

    result = notify.notify("success", "title", summary_json=json.dumps({}), dry_run=False)

    assert result["status"] == "skipped"


def test_notify_dry_run_reports_configuration(monkeypatch):
    monkeypatch.setenv("WECOM_WEBHOOK_URL", "https://example.com/webhook")

    result = notify.notify("failed", "title", error_message="boom", dry_run=True)

    assert result["status"] == "dry_run"
    assert result["configured"] is True
    assert "boom" in result["content"]


def test_notify_raises_when_send_fails(monkeypatch):
    monkeypatch.setenv("WECOM_WEBHOOK_URL", "https://example.com/webhook")

    def fail_send(webhook_url, content, timeout=20):
        raise RuntimeError("bad webhook")

    monkeypatch.setattr(notify, "send_wecom_markdown", fail_send)

    with pytest.raises(RuntimeError, match="bad webhook"):
        notify.notify("success", "title")
