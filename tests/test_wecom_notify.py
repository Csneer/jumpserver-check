import json

import pytest

from scripts import wecom_notify as notify


@pytest.fixture(autouse=True)
def isolate_dotenv(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(notify, "PROJECT_ROOT", tmp_path)
    monkeypatch.delenv("WECOM_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("WECOM_CHANNEL", raising=False)


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
    assert "静态IP正常: 222" in message
    assert "不可达: 78" in message
    assert "https://www.yuque.com/a/b/c" in message
    assert "reports/yuque/latest.md" in message


def test_new_probe_error_statuses_have_labels():
    assert notify.status_count_label("api_error") == "API异常"
    assert notify.status_count_label("log_fetch_error") == "日志拉取异常"
    assert notify.status_count_label("probe_script_error") == "探测脚本异常"
    assert notify.status_count_label("skipped_non_linux") == "跳过非Linux"

    summary = {
        "summary": {"total_assets": 3, "linux_assets": 3},
        "status_counts": {"api_error": 1, "log_fetch_error": 1, "probe_script_error": 1, "skipped_non_linux": 1},
    }

    message = notify.build_markdown_message("success", "JumpServer 每周主机巡检", summary)

    assert "API异常: 1" in message
    assert "日志拉取异常: 1" in message
    assert "探测脚本异常: 1" in message
    assert "跳过非Linux: 1" in message


def test_build_wecom_payload_defaults_to_markdown():
    payload = notify.build_wecom_payload("wecom", "title", "## title\n\ncontent")

    assert payload == {"msgtype": "markdown", "markdown": {"content": "## title\n\ncontent"}}


def test_build_wecom_payload_supports_text_channel():
    payload = notify.build_wecom_payload("wecom_text", "title", "**状态**：[doc](https://example.com)")

    assert payload == {"msgtype": "text", "text": {"content": "状态：doc"}}


def test_build_wecom_payload_supports_relay_channel():
    payload = notify.build_wecom_payload("wecom_relay", "JumpServer 每周主机巡检", "**状态**：成功", "success", "成功 / 资产 353")

    assert payload["status"] == "firing"
    assert payload["alerts"][0]["labels"]["source"] == "jumpserver-check"
    assert payload["alerts"][0]["annotations"]["summary"] == "成功 / 资产 353"
    assert payload["alerts"][0]["annotations"]["description"] == "**状态**：成功"


def test_build_relay_message_is_brief_and_linked():
    summary = {
        "summary": {"total_assets": 353, "linux_assets": 344, "unauthorized_assets": 9},
        "status_counts": {
            "ok_static": 222,
            "warn_dhcp": 1,
            "duplicate_asset": 40,
            "unreachable": 78,
        },
    }

    message = notify.build_relay_message(
        "success",
        summary,
        yuque_url="https://www.yuque.com/vurq8u/tiatz9/doc",
        duration_seconds=668.6,
    )

    assert "JumpServer 每周主机巡检" not in message
    assert "本地报告" not in message
    assert "**状态**：成功（耗时 668.6s）" in message
    assert "**资产**：活跃 353 / 探测 344 / 未授权 9" in message
    assert "**概览**：正常 222 / 需关注 119" in message
    assert "**问题分类**：DHCP告警: 1，重复资产: 40，不可达: 78" in message
    assert "[查看语雀报告](https://www.yuque.com/vurq8u/tiatz9/doc)" in message


def test_notify_relay_payload_omits_local_report(monkeypatch):
    summary = {
        "summary": {"total_assets": 353, "linux_assets": 344, "unauthorized_assets": 9},
        "status_counts": {"ok_static": 222, "unreachable": 78},
    }

    result = notify.notify(
        "success",
        "JumpServer 每周主机巡检",
        summary_json=json.dumps(summary),
        report_path="reports/yuque/latest.md",
        yuque_url="https://www.yuque.com/vurq8u/tiatz9/doc",
        duration_seconds=668.6,
        channel="wecom_relay",
        dry_run=True,
    )

    description = result["payload"]["alerts"][0]["annotations"]["description"]
    assert "本地报告" not in description
    assert "reports/yuque/latest.md" not in description
    assert "[查看语雀报告](https://www.yuque.com/vurq8u/tiatz9/doc)" in description


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

    monkeypatch.setattr(notify, "send_wecom_message", fail_send)

    with pytest.raises(RuntimeError, match="bad webhook"):
        notify.notify("success", "title")


def test_build_markdown_message_includes_cleanup_summary():
    message = notify.build_markdown_message(
        "success",
        "巡检",
        {
            "summary": {"total_assets": 1, "linux_assets": 1, "unauthorized_assets": 0},
            "status_counts": {},
            "cleanup": {
                "plan": {"summary": {"candidates": 2, "skipped": 1}, "plan_path": "artifacts/cleanup/local/plan.json"},
                "apply": {"results": [{"status": "disabled"}], "result_path": "artifacts/cleanup/local/result.json"},
            },
        },
    )

    assert "清理候选" in message
    assert "候选 2 / 跳过 1 / 执行结果 1" in message
    assert "artifacts/cleanup/local/plan.json" in message


def test_build_admin_action_message_confirm():
    record = {
        "profile": "local",
        "asset_id": "asset-1",
        "asset_name": "web-server",
        "asset_ip": "10.0.0.1",
        "operator": "admin",
        "reason": "业务下线",
        "confirmed_at": "2026-05-29T10:30:00+08:00",
    }

    msg = notify.build_admin_action_message("confirm", record, admin_url="http://10.0.0.100:8088/")

    assert "确认废弃" in msg
    assert "web-server" in msg
    assert "10.0.0.1" in msg
    assert "admin" in msg
    assert "业务下线" in msg
    assert "2026-05-29T10:30:00+08:00" in msg
    assert "[查看管理页面](http://10.0.0.100:8088/)" in msg


def test_build_admin_action_message_protect_and_review():
    protect_record = {"profile": "local", "asset_id": "asset-2", "reason": "仍在使用", "protected_at": "2026-05-29T11:00:00+08:00"}
    review_record = {"profile": "local", "asset_id": "asset-3", "reason": "需确认", "reviewed_at": "2026-05-29T11:30:00+08:00"}

    protect_msg = notify.build_admin_action_message("protect", protect_record)
    review_msg = notify.build_admin_action_message("review", review_record)

    assert "保护" in protect_msg
    assert "标记复查" in review_msg
    assert "asset-2" in protect_msg
    assert "asset-3" in review_record["asset_id"]


def test_build_admin_action_message_handles_missing_fields():
    msg = notify.build_admin_action_message("confirm", {"asset_id": "only-id"})

    assert "only-id" in msg
    assert "确认废弃" in msg
    assert "查看管理页面" not in msg


def test_send_admin_action_notification_skips_without_webhook(monkeypatch):
    monkeypatch.delenv("WECOM_WEBHOOK_URL", raising=False)

    result = notify.send_admin_action_notification("confirm", {"asset_id": "a1"})

    assert result["status"] == "skipped"


def test_send_admin_action_notification_sends_via_webhook(monkeypatch):
    monkeypatch.setenv("WECOM_WEBHOOK_URL", "https://example.com/webhook")
    monkeypatch.setenv("ACCESS_URL", "http://10.0.0.100:8088/")

    sent_payloads = []

    def mock_send(webhook_url, payload, timeout=20):
        sent_payloads.append({"url": webhook_url, "payload": payload, "timeout": timeout})
        return {"errcode": 0}

    monkeypatch.setattr(notify, "send_wecom_message", mock_send)

    record = {"profile": "local", "asset_id": "asset-1", "asset_name": "web", "confirmed_at": "2026-05-29T10:00:00+08:00"}
    result = notify.send_admin_action_notification("confirm", record)

    assert result["status"] == "sent"
    assert result["action"] == "confirm"
    assert len(sent_payloads) == 1
    assert sent_payloads[0]["url"] == "https://example.com/webhook"
    assert sent_payloads[0]["payload"]["msgtype"] == "markdown"
    assert "确认废弃" in sent_payloads[0]["payload"]["markdown"]["content"]
    assert "http://10.0.0.100:8088/" in sent_payloads[0]["payload"]["markdown"]["content"]
    assert sent_payloads[0]["timeout"] == 10



def test_new_ping_review_status_has_label():
    assert notify.status_count_label("jumpserver_unreachable_ip_reachable") == "JumpServer不可达但IP可达"

    summary = {
        "summary": {"total_assets": 3, "linux_assets": 3},
        "status_counts": {"jumpserver_unreachable_ip_reachable": 2},
    }
    message = notify.build_markdown_message("success", "JumpServer 每周主机巡检", summary)
    assert "JumpServer不可达但IP可达: 2" in message
