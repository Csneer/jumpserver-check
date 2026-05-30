import json

import pytest

from scripts import wecom_notify as notify

@pytest.fixture(autouse=True)
def isolate_dotenv(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(notify, "PROJECT_ROOT", tmp_path)
    monkeypatch.delenv("WECOM_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("WECOM_CHANNEL", raising=False)
    monkeypatch.delenv("WECOM_DELETE_DETAIL_LIMIT", raising=False)

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
    assert "候选 2 / 需人工复核 0 / 跳过 1 / 执行结果 1" in message
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

def test_markdown_message_highlights_review_required_cleanup_and_ip_reachable():
    summary = {
        "summary": {"total_assets": 10, "linux_assets": 10, "unauthorized_assets": 0},
        "status_counts": {"ok_static": 8, "jumpserver_unreachable_ip_reachable": 2, "unreachable": 1},
        "cleanup": {
            "plan": {
                "summary": {"candidates": 1, "review_required": 2, "skipped": 3},
                "review_required": [
                    {"asset_name": "host-a", "asset_ip": "192.0.2.10", "ip_reachability_remark": "ping reachable from deployment host"},
                    {"asset_name": "host-b", "asset_ip": "192.0.2.11", "ip_reachability_remark": "ping reachable from deployment host"},
                ],
                "plan_path": "artifacts/cleanup/local/plan.json",
            }
        },
    }

    message = notify.build_markdown_message("success", "JumpServer 每周主机巡检", summary)

    assert "JumpServer不可达但IP可达: 2" in message
    assert "候选 1 / 需人工复核 2 / 跳过 3" in message
    assert "IP可达需复核：host-a(192.0.2.10)，host-b(192.0.2.11)" in message

def test_relay_message_highlights_review_required_cleanup_and_alert_summary():
    summary = {
        "summary": {"total_assets": 10, "linux_assets": 10, "unauthorized_assets": 0},
        "status_counts": {"ok_static": 8, "jumpserver_unreachable_ip_reachable": 2, "unreachable": 1},
        "cleanup": {"plan": {"summary": {"candidates": 1, "review_required": 2, "skipped": 3}}},
    }

    message = notify.build_relay_message("success", summary)
    alert_summary = notify.build_alert_summary("success", summary)

    assert "**清理候选**：候选 1 / 需人工复核 2 / 跳过 3" in message
    assert "JumpServer不可达但IP可达: 2" in message
    assert "IP可达需复核 2" in alert_summary

def test_build_cleanup_delete_message_groups_deleted_assets():
    apply_result = {
        "profile": "local",
        "result_path": "artifacts/cleanup/local/result.json",
        "results": [
            {
                "status": "deleted",
                "profile": "local",
                "asset_id": "asset-1",
                "asset_name": "host-a",
                "asset_ip": "192.0.2.10",
                "operator": "admin",
                "reason": "decommissioned",
                "delete_ack": "DELETE asset-1",
                "archive_path": "artifacts/cleanup/local/archive.json",
                "result_path": "artifacts/cleanup/local/result.json",
            },
            {"status": "disabled", "asset_id": "asset-2"},
        ],
    }

    message = notify.build_cleanup_delete_message(apply_result)

    assert "删除资产" in message
    assert "host-a" in message
    assert "192.0.2.10" in message
    assert "asset-1" in message
    assert "admin" in message
    assert "decommissioned" in message
    assert "DELETE asset-1" in message
    assert "artifacts/cleanup/local/archive.json" in message
    assert "artifacts/cleanup/local/result.json" in message
    assert "asset-2" not in message


def test_build_cleanup_delete_message_truncates_large_batches_to_default_limit():
    attempts = [
        {
            "status": "deleted",
            "asset_id": f"asset-{idx}",
            "asset_name": f"host-{idx}",
            "asset_ip": f"192.0.2.{idx}",
            "operator": "admin",
            "reason": "batch cleanup",
            "delete_ack": f"DELETE asset-{idx}",
            "api_status": 204,
        }
        for idx in range(1, 8)
    ]
    apply_result = {"profile": "prod", "result_path": "artifacts/cleanup/prod/result.json", "results": attempts}

    message = notify.build_cleanup_delete_message(apply_result)

    assert "**删除尝试**：7" in message
    assert "**删除数量**：7" in message
    assert "前 5 条" in message
    assert "其余 2 条请查看清理结果 JSON" in message
    assert "host-1" in message
    assert "host-5" in message
    assert "host-6" not in message
    assert "DELETE asset-6" not in message
    assert "artifacts/cleanup/prod/result.json" in message


def test_build_cleanup_delete_message_honors_env_detail_limit(monkeypatch):
    monkeypatch.setenv("WECOM_DELETE_DETAIL_LIMIT", "2")
    attempts = [
        {"status": "deleted", "asset_id": f"asset-{idx}", "asset_name": f"host-{idx}", "asset_ip": f"192.0.2.{idx}"}
        for idx in range(1, 5)
    ]

    message = notify.build_cleanup_delete_message({"result_path": "result.json", "results": attempts})

    assert "前 2 条" in message
    assert "host-1" in message
    assert "host-2" in message
    assert "host-3" not in message
    assert "其余 2 条" in message


def test_send_cleanup_delete_notification_accepts_detail_limit(monkeypatch):
    sent = {}
    monkeypatch.setenv("WECOM_WEBHOOK_URL", "https://wecom.example/hook")
    monkeypatch.setattr(notify, "send_wecom_message", lambda url, payload, timeout=10: sent.update({"payload": payload}) or {"ok": True})
    apply_result = {
        "results": [
            {"status": "deleted", "asset_id": f"asset-{idx}", "asset_name": f"host-{idx}", "asset_ip": f"192.0.2.{idx}"}
            for idx in range(1, 5)
        ]
    }

    result = notify.send_cleanup_delete_notification(apply_result, detail_limit=2)

    assert result["status"] == "sent"
    assert result["detail_limit"] == 2
    assert result["truncated_count"] == 2
    content = sent["payload"]["markdown"]["content"]
    assert "host-1" in content
    assert "host-2" in content
    assert "host-3" not in content
    assert "其余 2 条" in content


def test_delete_attempt_items_ignores_pre_delete_fetch_failure():
    assert notify.delete_attempt_items({"results": [{"action": "delete", "status": "asset_fetch_failed", "api_status": 500}]}) == []

def test_send_cleanup_delete_notification_skips_without_deleted_assets(monkeypatch):
    monkeypatch.setenv("WECOM_WEBHOOK_URL", "https://example.com/webhook")

    result = notify.send_cleanup_delete_notification({"results": [{"status": "disabled", "asset_id": "asset-2"}]})

    assert result["status"] == "skipped"
    assert result["reason"] == "no delete attempts"

def test_send_cleanup_delete_notification_includes_failed_delete_attempt(monkeypatch):
    sent = {}
    monkeypatch.setenv("WECOM_WEBHOOK_URL", "https://wecom.example/hook")
    monkeypatch.setattr(notify, "send_wecom_message", lambda url, payload, timeout=10: sent.update({"url": url, "payload": payload}) or {"ok": True})

    result = notify.send_cleanup_delete_notification(
        {
            "profile": "local",
            "result_path": "artifacts/cleanup/local/result.json",
            "results": [
                {
                    "status": "delete_failed",
                    "action": "delete",
                    "api_operation": "delete",
                    "api_status": 500,
                    "asset_id": "asset-1",
                    "asset_name": "host-a",
                    "asset_ip": "192.0.2.10",
                    "operator": "admin",
                    "reason": "decommissioned",
                    "delete_ack": "DELETE asset-1",
                }
            ],
        }
    )

    assert result["status"] == "sent"
    assert result["delete_attempt_count"] == 1
    content = sent["payload"]["markdown"]["content"]
    assert "删除失败" in content
    assert "HTTP 500" in content
    assert "asset-1" in content

def test_send_cleanup_delete_notification_sends_grouped_message(monkeypatch):
    monkeypatch.setenv("WECOM_WEBHOOK_URL", "https://example.com/webhook")
    sent_payloads = []

    def mock_send(webhook_url, payload, timeout=20):
        sent_payloads.append({"url": webhook_url, "payload": payload, "timeout": timeout})
        return {"errcode": 0}

    monkeypatch.setattr(notify, "send_wecom_message", mock_send)
    result = notify.send_cleanup_delete_notification(
        {
            "results": [
                {
                    "status": "deleted",
                    "asset_id": "asset-1",
                    "asset_name": "host-a",
                    "asset_ip": "192.0.2.10",
                    "operator": "admin",
                    "reason": "decommissioned",
                    "delete_ack": "DELETE asset-1",
                    "archive_path": "archive.json",
                    "result_path": "result.json",
                }
            ]
        }
    )

    assert result["status"] == "sent"
    assert result["deleted_count"] == 1
    assert sent_payloads[0]["payload"]["msgtype"] == "markdown"
    assert "删除资产" in sent_payloads[0]["payload"]["markdown"]["content"]

def test_markdown_message_includes_host_snapshot_diff_notes():
    unchanged = notify.build_markdown_message(
        "success",
        "巡检",
        {"host_snapshot_diff": {"changed": False, "note": "与上一轮结果对比无主机信息变动，已跳过语雀归档"}},
    )
    changed = notify.build_markdown_message(
        "success",
        "巡检",
        {"host_snapshot_diff": {"changed": True, "added": 1, "removed": 2, "status_changed": 3}},
    )

    assert "无主机信息变动" in unchanged
    assert "已跳过语雀归档" in unchanged
    assert "新增 1 / 消失 2 / 状态变化 3" in changed

def test_new_tcp_review_status_has_label_and_alert_summary():
    assert notify.status_count_label("jumpserver_unreachable_tcp_open") == "JumpServer不可达但SSH端口开放"
    summary = {"summary": {"total_assets": 3, "linux_assets": 3}, "status_counts": {"jumpserver_unreachable_tcp_open": 2}}
    message = notify.build_markdown_message("success", "JumpServer 每周主机巡检", summary)
    alert_summary = notify.build_alert_summary("success", summary)
    assert "JumpServer不可达但SSH端口开放: 2" in message
    assert "SSH开放需复核 2" in alert_summary
