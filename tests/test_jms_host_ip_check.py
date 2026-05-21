import base64
import hashlib
import hmac
from pathlib import Path

from scripts import jms_host_ip_check as check


def test_canonical_path_and_signature_header():
    headers = {"accept": "application/json", "date": "Tue, 19 May 2026 08:00:00 GMT"}
    path = check.canonical_path("/api/v1/assets/assets/", {"is_active": "true", "limit": 100})
    signature = check.signature_header("key", "secret", "GET", path, headers)
    signed = "(request-target): get " + path + "\naccept: application/json\ndate: Tue, 19 May 2026 08:00:00 GMT"
    expected = base64.b64encode(hmac.new(b"secret", signed.encode("utf-8"), hashlib.sha256).digest()).decode("utf-8")

    assert path == "/api/v1/assets/assets/?is_active=true&limit=100"
    assert f'signature="{expected}"' in signature


def test_items_from_payload_variants():
    assert check.items_from_payload([{"id": "1"}]) == [{"id": "1"}]
    assert check.items_from_payload({"results": [{"id": "2"}]}) == [{"id": "2"}]
    assert check.items_from_payload({"data": [{"id": "3"}]}) == [{"id": "3"}]
    assert check.items_from_payload({"items": [{"id": "4"}]}) == [{"id": "4"}]


def test_asset_normalization_and_windows_detection():
    linux = {
        "id": "a1",
        "name": "host-a",
        "address": "192.0.2.10",
        "platform": {"name": "Linux"},
        "nodes": [{"name": "中间件"}, {"name": "运维"}],
    }
    windows = {"platform": "Windows Server", "ip": "192.0.2.20"}

    assert not check.is_windows_asset(linux)
    assert check.is_windows_asset(windows)
    assert check.asset_name(linux) == "host-a"
    assert check.asset_ip(linux) == "192.0.2.10"
    assert check.node_names(linux) == "中间件, 运维"


def test_filter_assets_by_query():
    assets = [
        {"id": "asset-1", "name": "rabbitmq-01", "address": "192.0.2.82"},
        {"id": "asset-2", "name": "mysql-01", "address": "192.0.2.83"},
    ]

    assert check.filter_assets_by_query(assets, "2.82") == [assets[0]]
    assert check.filter_assets_by_query(assets, "mysql") == [assets[1]]
    assert check.filter_assets_by_query(assets, None) == assets


def test_duplicate_asset_annotation_overrides_probe_status():
    assets = [
        {"id": "asset-1", "name": "old-record", "address": "192.0.2.162"},
        {"id": "asset-2", "name": "current-record", "address": "192.0.2.162"},
    ]
    results = [
        {"asset_name": "old-record", "asset_ip": "192.0.2.162", "probe_status": "warn_dhcp", "remark": ""},
        {"asset_name": "current-record", "asset_ip": "192.0.2.162", "probe_status": "ok_static", "remark": ""},
    ]

    check.apply_duplicate_asset_annotations(results, check.duplicate_asset_map(assets))

    assert results[0]["probe_status"] == "duplicate_asset"
    assert "原探测状态 warn_dhcp" in results[0]["remark"]
    assert "old-record" in results[1]["remark"]
    assert "current-record" in results[1]["remark"]


def test_detection_command_is_read_only_and_has_markers():
    command = check.DETECTION_COMMAND

    assert "DETECT_START" in command
    assert "DETECT_END" in command
    assert "IP_ADDRS=" in command
    assert "ip -o -4 addr show scope global" in command
    for forbidden in ("rm ", "mv ", "truncate", "reboot", "shutdown", "docker prune", "journalctl --vacuum"):
        assert forbidden not in command


def test_build_ops_payload_uses_asset_ids_and_batches():
    payload = check.build_ops_payload([{"id": "asset-1"}, {"id": "asset-2"}], batch_index=2, timeout=120)

    assert payload["module"] == "shell"
    assert payload["assets"] == ["asset-1", "asset-2"]
    assert payload["timeout"] == 120
    assert "read-only" in payload["comment"]
    assert payload["name"].endswith("batch-002")


def test_parse_probe_static_success():
    asset = {"id": "asset-1", "name": "host-a", "address": "192.0.2.10"}
    segment = """
changed: [host-a] => {"stdout": "DETECT_START\\nIP_TYPE=static\\nIP_ADDR=192.0.2.10\\nIF_NAME=ens3\\nDETECT_END"}
"""

    result = check.classify_probe_result(asset, check.clean_ansible_log(segment))

    assert result["probe_status"] == "ok_static"
    assert result["connectivity"] == "ok"
    assert result["ip_match"] is True
    assert result["if_name"] == "ens3"
    assert result["actual_ips"] == "192.0.2.10"


def test_parse_probe_matches_any_detected_ip():
    asset = {"id": "asset-1", "name": "host-a", "address": "192.0.2.10"}
    segment = "DETECT_START\nIP_TYPE=static\nIP_ADDR=198.51.100.8\nIP_ADDRS=198.51.100.8,192.0.2.10\nIF_NAME=eth0\nDETECT_END"

    result = check.classify_probe_result(asset, segment)

    assert result["probe_status"] == "ok_static"
    assert result["actual_ip"] == "198.51.100.8"
    assert result["actual_ips"] == "198.51.100.8, 192.0.2.10"
    assert result["ip_match"] is True


def test_parse_probe_dhcp_and_ip_mismatch_priority():
    asset = {"id": "asset-1", "name": "host-a", "address": "192.0.2.10"}
    segment = "DETECT_START\nIP_TYPE=dhcp\nIP_ADDR=192.0.2.99\nIP_ADDRS=192.0.2.99,198.51.100.99\nIF_NAME=eth0\nDETECT_END"

    result = check.classify_probe_result(asset, segment)

    assert result["probe_status"] == "ip_mismatch"
    assert result["ip_type"] == "dhcp"
    assert result["ip_match"] is False
    assert result["actual_ips"] == "192.0.2.99, 198.51.100.99"


def test_parse_probe_unknown_and_parse_error_and_unreachable():
    asset = {"id": "asset-1", "name": "host-a", "address": "192.0.2.10"}

    unknown = check.classify_probe_result(asset, "DETECT_START\nIP_TYPE=unknown\nIP_ADDR=192.0.2.10\nIF_NAME=\nDETECT_END")
    parse_error = check.classify_probe_result(asset, "changed: [host-a] => command output without markers")
    ansible_parse_error = check.classify_probe_result(
        asset,
        "ERROR! failed at splitting arguments, either an unbalanced jinja2 block or quotes: DETECT_START\nIP_TYPE=static\nDETECT_END",
    )
    unreachable = check.classify_probe_result(asset, "fatal: [host-a]: UNREACHABLE! Failed to connect")

    assert unknown["probe_status"] == "manual_check"
    assert parse_error["probe_status"] == "parse_error"
    assert ansible_parse_error["probe_status"] == "parse_error"
    assert unreachable["probe_status"] == "unreachable"


def test_split_sections_and_select_asset_section():
    log = """
changed: [host-a] => {"stdout": "DETECT_START\\nIP_TYPE=static\\nIP_ADDR=198.51.100.1\\nDETECT_END"}
changed: [198.51.100.2] => {"stdout": "DETECT_START\\nIP_TYPE=dhcp\\nIP_ADDR=198.51.100.2\\nDETECT_END"}
"""

    assert "IP_TYPE=static" in check.section_for_asset({"name": "host-a"}, log, batch_size=2)
    assert "IP_TYPE=dhcp" in check.section_for_asset({"address": "198.51.100.2"}, log, batch_size=2)
    assert check.section_for_asset({"name": "missing"}, log, batch_size=2) == ""


def test_split_sections_supports_pipe_style_jumpserver_logs():
    log = "\x1b[1;31mhost-a | UNREACHABLE! => {\x1b[0m\n  \"msg\": \"No route to host\"\n}\nhost-b | CHANGED | rc=0 >>\nDETECT_START\nIP_TYPE=static\nIP_ADDR=198.51.100.2\nDETECT_END\n"

    assert "No route" in check.section_for_asset({"name": "host-a"}, log, batch_size=2)
    assert "IP_TYPE=static" in check.section_for_asset({"name": "host-b"}, log, batch_size=2)


def test_section_matching_normalizes_jumpserver_labels():
    log = """
192.168.101.121_netty_Redis_Cluster | CHANGED | rc=0 >>
DETECT_START
IP_TYPE=static
IP_ADDR=192.168.101.121
IP_ADDRS=192.168.101.121,172.17.0.1
IF_NAME=ens18
DETECT_END
"""
    asset = {"name": "192.168.101.121_netty Redis Cluster", "address": "192.168.101.121"}

    section = check.section_for_asset(asset, log, batch_size=50)

    assert "IP_TYPE=static" in section
    assert "IF_NAME=ens18" in section


def test_section_matching_avoids_ambiguous_normalized_labels():
    log = """
host_a | CHANGED | rc=0 >>
DETECT_START
IP_TYPE=static
IP_ADDR=192.0.2.1
DETECT_END
host-a | CHANGED | rc=0 >>
DETECT_START
IP_TYPE=dhcp
IP_ADDR=192.0.2.2
DETECT_END
"""

    assert check.section_for_asset({"name": "host a"}, log, batch_size=2) == ""


def test_single_asset_recheck_recovers_missing_batch_output(monkeypatch):
    asset = {"id": "asset-1", "name": "host-a", "address": "192.0.2.10"}
    original = check.classify_probe_result(asset, "")
    batch_records = []

    def fake_run_batch(client, batch, batch_index, timeout, poll_interval, runas):
        assert batch == [asset]
        return {
            "batch_index": batch_index,
            "results": [
                check.classify_probe_result(
                    asset,
                    "DETECT_START\nIP_TYPE=static\nIP_ADDR=192.0.2.10\nIP_ADDRS=192.0.2.10\nIF_NAME=ens18\nDETECT_END",
                )
            ],
        }

    monkeypatch.setattr(check, "run_batch", fake_run_batch)

    results, stats = check.run_rechecks(
        client=object(),
        results=[original],
        asset_by_id={"asset-1": asset},
        timeout=90,
        poll_interval=2,
        runas="root",
        max_rechecks=None,
        batch_records=batch_records,
    )

    assert stats == {"recheck_count": 1, "recheck_recovered_count": 1}
    assert results[0]["probe_status"] == "ok_static"
    assert results[0]["connectivity"] == "ok"
    assert results[0]["probe_source"] == "single_recheck"
    assert results[0]["original_probe_status"] == "unreachable"
    assert "单主机复核恢复" in results[0]["remark"]
    assert batch_records[0]["recheck_for"]["asset_id"] == "asset-1"


def test_markdown_report_and_latest_written(tmp_path: Path):
    results = [
        {
            "asset_name": "host-a",
            "asset_ip": "198.51.100.1",
            "actual_ip": "198.51.100.1",
            "actual_ips": "198.51.100.1, 192.0.2.10",
            "ip_match": True,
            "if_name": "ens3",
            "ip_type": "static",
            "probe_status": "ok_static",
            "probe_source": "batch",
            "node": "中间件",
            "remark": "",
        },
        {
            "asset_name": "host-b",
            "asset_ip": "198.51.100.2",
            "actual_ip": "198.51.100.200",
            "actual_ips": "198.51.100.200, 192.0.2.20",
            "ip_match": False,
            "if_name": "eth0",
            "ip_type": "static",
            "probe_status": "ip_mismatch",
            "probe_source": "single_recheck",
            "node": "运维",
            "remark": "实际 IP 与 JumpServer 资产 IP 不一致",
        }
    ]
    started = check.dt.datetime(2026, 5, 19, 10, 0, tzinfo=check.dt.timezone.utc).astimezone()

    paths = check.write_reports(
        results,
        batches=[],
        started_at=started,
        output_dir=tmp_path / "reports",
        raw_output_dir=tmp_path / "raw",
        retention_count=12,
            summary={"total_assets": 1, "linux_assets": 1, "windows_assets": 0},
    )

    latest = Path(paths["latest"])
    report = Path(paths["report"])
    assert latest.exists()
    assert report.exists()
    content = latest.read_text(encoding="utf-8")
    assert content.startswith("# JumpServer 主机探测与 IP 配置检测报告")
    assert "## 问题分类索引" in content
    assert "### ip_mismatch（1）" in content
    assert "host-b" in content
    assert "探测IP列表" in content
    assert "探测来源" in content
    assert "single_recheck" in content
    assert "## 异常主机" in content
    assert "## 全量明细" in content
