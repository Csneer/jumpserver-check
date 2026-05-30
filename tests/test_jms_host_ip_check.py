import base64
import hashlib
import hmac
import json
import subprocess
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
    assert check.is_linux_asset(linux)
    assert not check.is_linux_asset(windows)


def test_unknown_or_network_platform_is_not_treated_as_linux():
    network_device = {"platform": {"name": "Cisco IOS"}, "address": "192.0.2.1"}
    unknown_platform = {"platform": "", "os": "", "address": "192.0.2.2"}

    assert not check.is_windows_asset(network_device)
    assert not check.is_linux_asset(network_device)
    assert not check.is_linux_asset(unknown_platform)


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
    assert results[0]["original_probe_status"] == "warn_dhcp"
    assert "原探测状态 warn_dhcp" in results[0]["remark"]
    assert results[1]["original_probe_status"] == "ok_static"
    assert "old-record" in results[1]["remark"]
    assert "current-record" in results[1]["remark"]





def test_ops_reached_error_paths_mark_ops_connectivity_ok():
    cases = [
        "Module is not supported",
        "bash: syntax error near unexpected token",
        "DETECT_START\nBROKEN=1",
    ]
    for log in cases:
        result = check.classify_probe_result({"id": "asset-1", "name": "host-a", "address": "192.0.2.10"}, log)
        assert result["connectivity"] == "ok"
        assert result["ops_connectivity"] == "ok"

def test_successful_parse_marks_ops_connectivity_ok():
    result = check.classify_probe_result(
        {"id": "asset-1", "name": "host-a", "address": "192.0.2.10"},
        "DETECT_START\nIP_ADDR=192.0.2.10\nIP_ADDRS=192.0.2.10\nIF_NAME=eth0\nIP_TYPE=static\nDETECT_END",
    )

    assert result["probe_status"] == "ok_static"
    assert result["connectivity"] == "ok"
    assert result["ops_connectivity"] == "ok"

def test_skipped_windows_result_uses_common_reachability_schema():
    result = check.skipped_windows_result({"id": "win-1", "name": "win", "address": "192.0.2.50", "platform": "Windows"})

    assert result["connectivity"] == "skipped"
    assert result["ops_connectivity"] == "skipped"
    assert result["ip_reachability"] == "not_checked"
    assert result["ip_reachability_command"] == []


def test_ping_worker_count_is_capped():
    assert check.bounded_ip_ping_workers(0) == 1
    assert check.bounded_ip_ping_workers(32) == 32
    assert check.bounded_ip_ping_workers(999) == 64

def test_detection_command_is_read_only_and_has_markers():
    command = check.DETECTION_COMMAND

    assert "DETECT_START" in command
    assert "DETECT_END" in command
    assert "IP_ADDRS=" in command
    assert "ip -o -4 addr show scope global" in command
    assert "$0 !~ /^172\\.17\\./" in command
    assert "$0 !~ /^172\\./" not in command
    for forbidden in ("rm ", "mv ", "truncate", "reboot", "shutdown", "docker prune", "journalctl --vacuum"):
        assert forbidden not in command


def test_detection_command_is_valid_posix_shell_syntax():
    completed = subprocess.run(
        ["/bin/sh", "-n"],
        input=check.DETECTION_COMMAND,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr


def test_detection_command_ignores_commented_debian_dhcp_config():
    command = check.DETECTION_COMMAND

    assert 'interfaces_type="$(awk' in command
    assert "/^[[:space:]]*#/ { next }" in command
    assert "cur_iface == iface" in command
    assert '$1 == "address" && $2 == ip' in command
    assert "grep -Eiq 'iface[[:space:]].*[[:space:]]dhcp' /etc/network/interfaces" not in command


def test_detection_command_prioritizes_route_interface_configs():
    command = check.DETECTION_COMMAND

    assert 'cfg_iface="$(grep -i \'^DEVICE=\'' in command
    assert 'cfg_ip="$(grep -i \'^IPADDR=\'' in command
    assert '[ "$cfg_iface" != "$if_name" ]' in command
    assert 'netplan_type="$(awk -v iface="$if_name" -v ip="$actual_ip"' in command
    assert 'iface_method = "dhcp"' in command
    assert 'ip_method = "static"' in command


def test_detection_command_does_not_scan_its_own_command_line_for_dhclient():
    command = check.DETECTION_COMMAND

    assert "pgrep -x dhclient" in command
    assert "ps aux" not in command
    assert "grep '[d]hclient'" not in command


def test_build_ops_payload_uses_asset_and_node_ids():
    payload = check.build_ops_payload(
        [
            {"id": "asset-1", "nodes": [{"id": "node-1", "name": "pve"}]},
            {"id": "asset-2", "nodes": [{"id": "node-1", "name": "pve"}, {"id": "node-2", "name": "ops"}]},
        ],
        batch_index=2,
        timeout=-1,
    )

    assert payload["module"] == "shell"
    assert payload["assets"] == ["asset-1", "asset-2"]
    assert payload["nodes"] == ["node-1", "node-2"]
    assert payload["timeout"] == -1
    assert "read-only" in payload["comment"]
    assert payload["name"].endswith("batch-002")


def test_fetch_full_job_log_follows_marks():
    class Client:
        def __init__(self):
            self.calls = []

        def get(self, path, params=None):
            self.calls.append((path, params))
            if params is None:
                return 200, {"data": "one\\n", "end": False, "mark": "m1"}
            return 200, {"data": "two\\n", "end": True, "mark": "m2"}

    client = Client()
    status, log, pages = check.fetch_full_job_log(client, "task-1")

    assert status == 200
    assert log == "one\ntwo\n"
    assert client.calls == [
        ("/api/v1/ops/ansible/job-execution/task-1/log/", None),
        ("/api/v1/ops/ansible/job-execution/task-1/log/", {"mark": "m1"}),
    ]
    assert pages[-1]["end"] is True


def test_fetch_full_job_log_records_http_error():
    class Client:
        def get(self, path, params=None):
            return 500, {"error": "temporary failure"}

    status, log, pages = check.fetch_full_job_log(Client(), "task-1")

    assert status == 500
    assert "temporary failure" in log
    assert pages[-1]["error"] is True
    assert check.log_fetch_failed(status, pages)


def test_fetch_full_job_log_marks_page_limit_truncation_as_failure():
    class Client:
        def get(self, path, params=None):
            mark = "m2" if params else "m1"
            return 200, {"data": "partial\\n", "end": False, "mark": mark}

    status, log, pages = check.fetch_full_job_log(Client(), "task-1", max_pages=2)

    assert status == 200
    assert log == "partial\npartial\n"
    assert pages[-1]["truncated"] is True
    assert check.log_fetch_failed(status, pages)


def test_fetch_full_job_log_marks_repeated_mark_as_failure():
    class Client:
        def get(self, path, params=None):
            return 200, {"data": "partial\\n", "end": False, "mark": "same-mark"}

    status, log, pages = check.fetch_full_job_log(Client(), "task-1")

    assert status == 200
    assert log == "partial\npartial\n"
    assert pages[-1]["stalled"] is True
    assert check.log_fetch_failed(status, pages)


def test_fetch_full_job_log_marks_missing_mark_as_failure():
    class Client:
        def get(self, path, params=None):
            return 200, {"data": "partial\\n", "end": False}

    status, log, pages = check.fetch_full_job_log(Client(), "task-1")

    assert status == 200
    assert log == "partial\n"
    assert pages[-1]["stalled"] is True
    assert check.log_fetch_failed(status, pages)


def test_jumpserver_client_get_retries_temporary_errors(monkeypatch):
    calls = {"count": 0}

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return b'{"ok": true}'

    def fake_urlopen(req, timeout=20, context=None):
        calls["count"] += 1
        if calls["count"] == 1:
            raise check.error.URLError("temporary network issue")
        return Response()

    monkeypatch.setattr(check.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(check.time, "sleep", lambda seconds: None)
    client = object.__new__(check.JumpServerClient)
    client.base = "https://jumpserver.example"
    client.key_id = "key"
    client.secret = "secret"
    client.org = check.DEFAULT_ORG
    client.context = None
    client.opener = None

    status, payload = client.get("/api/v1/users/profile/")

    assert calls["count"] == 2
    assert status == 200
    assert payload == {"ok": True}


def test_jumpserver_client_non_json_response_is_structured(monkeypatch):
    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return b"<html>bad gateway</html>"

    monkeypatch.setattr(check.request, "urlopen", lambda req, timeout=20, context=None: Response())
    client = object.__new__(check.JumpServerClient)
    client.base = "https://jumpserver.example"
    client.key_id = "key"
    client.secret = "secret"
    client.org = check.DEFAULT_ORG
    client.context = None
    client.opener = None

    status, payload = client.get("/api/v1/users/profile/")

    assert status == 200
    assert payload["error"] == "non_json_response"
    assert "bad gateway" in payload["body_excerpt"]


def test_run_batch_writes_resume_state(tmp_path: Path):
    class Client:
        def post(self, path, body):
            return 201, {"task_id": "task-1"}

        def get(self, path, params=None):
            if "task-detail" in path:
                return 200, {"status": "success", "is_finished": True, "is_success": True, "summary": {}}
            if "log" in path:
                return 200, {"data": "host-a | CHANGED | rc=0 >>\nDETECT_START\nIP_TYPE=static\nIP_ADDR=192.0.2.10\nIP_ADDRS=192.0.2.10\nIF_NAME=eth0\nDETECT_END\n", "end": True, "mark": "m1"}
            return 200, {}

    state_path = tmp_path / "state.json"
    asset = {"id": "asset-1", "name": "host-a", "address": "192.0.2.10"}

    record = check.run_batch(Client(), [asset], 1, -1, 0, "root", 1, resume_state_path=state_path, signature="sig")

    state = check.load_resume_state(state_path)
    assert record["task_id"] == "task-1"
    assert state["status"] == "submitted"
    assert state["task_id"] == "task-1"
    assert state["signature"] == "sig"
    assert state["assets"][0]["id"] == "asset-1"


def test_resume_signature_changes_with_command_or_assets():
    asset_a = {"id": "asset-a"}
    asset_b = {"id": "asset-b"}

    assert check.resume_signature([asset_a], runas="root", timeout=-1) != check.resume_signature([asset_b], runas="root", timeout=-1)
    assert check.resume_signature([asset_a], runas="root", timeout=-1) != check.resume_signature([asset_a], runas="admin", timeout=-1)


def test_chunks_zero_means_all_in_one():
    items = [{"id": "asset-1"}, {"id": "asset-2"}]

    assert check.chunks(items, 0) == [items]


def test_chunks_by_primary_node_groups_assets():
    assets = [
        {"id": "asset-1", "nodes": [{"id": "node-a"}]},
        {"id": "asset-2", "nodes": [{"id": "node-b"}]},
        {"id": "asset-3", "nodes": [{"id": "node-a"}]},
    ]

    batches = check.chunks_by_primary_node(assets)

    assert [[asset["id"] for asset in batch] for batch in batches] == [["asset-1", "asset-3"], ["asset-2"]]


def test_permission_denied_result_marks_preflight_source():
    result = check.permission_denied_result({"id": "asset-1", "name": "host-a", "address": "192.0.2.10"})

    assert result["probe_status"] == "permission_denied"
    assert result["probe_source"] == "preflight"
    assert "未授权" in result["remark"]


def test_parse_probe_static_success():
    asset = {"id": "asset-1", "name": "host-a", "address": "192.0.2.10"}
    segment = """
changed: [host-a] => {"stdout": "DETECT_START\\nIP_TYPE=static\\nIP_ADDR=192.0.2.10\\nIP_ADDRS=192.0.2.10\\nIF_NAME=ens3\\nDETECT_END"}
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


def test_parse_probe_ignores_172_docker_ips():
    asset = {"id": "asset-1", "name": "host-a", "address": "172.17.0.1"}
    segment = "DETECT_START\nIP_TYPE=static\nIP_ADDR=192.0.2.10\nIP_ADDRS=192.0.2.10,172.17.0.1,172.18.0.1\nIF_NAME=eth0\nDETECT_END"

    result = check.classify_probe_result(asset, segment)

    assert result["probe_status"] == "ip_mismatch"
    assert result["actual_ips"] == "192.0.2.10, 172.18.0.1"
    assert result["ip_match"] is False


def test_parse_probe_does_not_reinsert_ignored_actual_ip_for_matching():
    asset = {"id": "asset-1", "name": "host-a", "address": "172.17.0.1"}
    segment = "DETECT_START\nIP_TYPE=static\nIP_ADDR=172.17.0.1\nIP_ADDRS=172.17.0.1\nIF_NAME=docker0\nDETECT_END"

    result = check.classify_probe_result(asset, segment)

    assert result["probe_status"] == "ip_mismatch"
    assert result["actual_ip"] == "172.17.0.1"
    assert result["actual_ips"] == ""
    assert result["ip_match"] is False


def test_parse_probe_keeps_legitimate_172_private_host_ips():
    asset = {"id": "asset-1", "name": "host-a", "address": "172.20.10.5"}
    segment = "DETECT_START\nIP_TYPE=static\nIP_ADDR=172.20.10.5\nIP_ADDRS=172.20.10.5,192.0.2.10\nIF_NAME=eth0\nDETECT_END"

    result = check.classify_probe_result(asset, segment)

    assert result["probe_status"] == "ok_static"
    assert result["actual_ips"] == "172.20.10.5, 192.0.2.10"
    assert result["ip_match"] is True


def test_parse_probe_dhcp_and_ip_mismatch_priority():
    asset = {"id": "asset-1", "name": "host-a", "address": "192.0.2.10"}
    segment = "DETECT_START\nIP_TYPE=dhcp\nIP_ADDR=192.0.2.99\nIP_ADDRS=192.0.2.99,198.51.100.99\nIF_NAME=eth0\nDETECT_END"

    result = check.classify_probe_result(asset, segment)

    assert result["probe_status"] == "ip_mismatch"
    assert result["ip_type"] == "dhcp"
    assert result["ip_match"] is False
    assert result["actual_ips"] == "192.0.2.99, 198.51.100.99"


def test_parse_probe_requires_ip_evidence_before_static_or_dhcp_conclusion():
    asset = {"id": "asset-1", "name": "host-a", "address": "192.0.2.10"}
    segments = [
        "DETECT_START\nIP_TYPE=static\nIP_ADDR=\nIP_ADDRS=\nIF_NAME=\nDETECT_END",
        "DETECT_START\nIP_TYPE=dhcp\nIP_ADDR=\nIP_ADDRS=\nIF_NAME=\nDETECT_END",
        "DETECT_START\nIP_TYPE=static\nIP_ADDR=192.0.2.10\nIP_ADDRS=\nIF_NAME=eth0\nDETECT_END",
        "DETECT_START\nIP_TYPE=dhcp\nIP_ADDR=192.0.2.10\nIF_NAME=eth0\nDETECT_END",
    ]

    results = [check.classify_probe_result(asset, segment) for segment in segments]

    assert [result["probe_status"] for result in results] == ["manual_check"] * len(segments)
    assert all(result["actual_ips"] == "" for result in results)
    assert all("未采集到可比对的主机 IP" in result["remark"] for result in results)
    assert results[2]["actual_ip"] == "192.0.2.10"
    assert results[3]["actual_ip"] == "192.0.2.10"


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


def test_parse_probe_ops_failure_statuses():
    asset = {"id": "asset-1", "name": "host-a", "address": "192.0.2.10"}

    permission = check.classify_probe_result(asset, "Start adhoc execution error: You do not have access rights to 1 assets")
    no_account = check.classify_probe_result(asset, "host-a | FAILED! => 无可用账号")
    no_output = check.classify_probe_result(asset, "Task ops.tasks.run succeeded in 63.072868722025305s: None")
    module_error = check.classify_probe_result(asset, "module_stderr: Traceback\nAnsiballZ_command.py failed")
    script_error = check.classify_probe_result(asset, "host-a | FAILED | rc=2 >>\n/bin/sh: 1: Syntax error: unexpected EOF")

    assert permission["probe_status"] == "permission_denied"
    assert no_account["probe_status"] == "no_account"
    assert no_output["probe_status"] == "ops_no_output"
    assert module_error["probe_status"] == "ops_module_error"
    assert script_error["probe_status"] == "probe_script_error"


def test_run_batch_create_failure_maps_to_api_error():
    class Client:
        def post(self, path, body):
            return 500, {"message": "server busy"}

    asset = {"id": "asset-1", "name": "host-a", "address": "192.0.2.10"}

    record = check.run_batch(Client(), [asset], 1, -1, 0, "root", 1)

    assert record["results"][0]["probe_status"] == "api_error"
    assert "server busy" in record["results"][0]["remark"]


def test_collect_batch_log_failure_maps_to_log_fetch_error():
    class Client:
        def get(self, path, params=None):
            if "task-detail" in path:
                return 200, {"status": "success", "is_finished": True, "is_success": True, "summary": {}}
            if "log" in path:
                return 502, {"message": "gateway timeout"}
            return 200, {}

    asset = {"id": "asset-1", "name": "host-a", "address": "192.0.2.10"}
    record = {"batch_index": 1, "asset_count": 1, "polls": []}

    result = check.collect_batch_result(Client(), [asset], record, "task-1", 0, 1)

    assert result["results"][0]["probe_status"] == "log_fetch_error"
    assert "task-1" in result["results"][0]["remark"]


def test_collect_batch_failed_task_parses_available_logs():
    class Client:
        def get(self, path, params=None):
            if "task-detail" in path:
                return 200, {
                    "status": "failed",
                    "is_finished": True,
                    "is_success": False,
                    "summary": {"failures": {"host-b": "module failed"}},
                }
            if "log" in path:
                return 200, {
                    "data": (
                        "host-a | CHANGED | rc=0 >>\n"
                        "DETECT_START\n"
                        "IP_TYPE=static\n"
                        "IP_ADDR=192.0.2.10\n"
                        "IP_ADDRS=192.0.2.10\n"
                        "IF_NAME=eth0\n"
                        "DETECT_END\n"
                        "host-b | FAILED! => 无可用账号\n"
                    ),
                    "end": True,
                    "mark": "m1",
                }
            return 200, {}

    assets = [
        {"id": "asset-1", "name": "host-a", "address": "192.0.2.10"},
        {"id": "asset-2", "name": "host-b", "address": "192.0.2.11"},
        {"id": "asset-3", "name": "host-c", "address": "192.0.2.12"},
    ]
    record = {"batch_index": 1, "asset_count": 3, "polls": []}

    result = check.collect_batch_result(Client(), assets, record, "task-1", 0, 1)

    assert [item["probe_status"] for item in result["results"]] == ["ok_static", "no_account", "ops_task_failed"]
    assert result["results"][0]["actual_ips"] == "192.0.2.10"
    assert "task-1" not in result["results"][0]["remark"]
    assert result["results"][1]["remark"] == "JumpServer Ops 无可用登录账号"
    assert "task-1" in result["results"][2]["remark"]


def test_summary_message_for_asset_matches_normalized_labels():
    asset = {"name": "192.168.101.121_netty Redis Cluster", "address": "192.168.101.121"}
    summary = {
        "dark": {
            "192.168.101.121_netty_Redis_Cluster": "shell: Failed to connect to the host via ssh: No route to host"
        }
    }

    message = check.summary_message_for_asset(asset, summary)
    result = check.classify_probe_result(asset, message, remark=message)

    assert "No route" in message
    assert result["probe_status"] == "unreachable"
    assert "No route" in result["remark"]


def test_parse_probe_host_unreachable_wins_over_task_none_footer():
    asset = {"id": "asset-1", "name": "host-a", "address": "192.0.2.10"}
    log = """
host-a | UNREACHABLE! => {
    "msg": "Failed to connect to the host via ssh: No route to host",
    "unreachable": true
}
Task ops.tasks.run_ops_job_execution[abc] succeeded in 7.4s: None
"""

    result = check.classify_probe_result(asset, log)

    assert result["probe_status"] == "unreachable"
    assert result["remark"] == "JumpServer Ops 返回连接失败"


def test_parse_probe_marker_wins_over_task_none_footer():
    asset = {"id": "asset-1", "name": "host-a", "address": "192.0.2.10"}
    log = """
host-a | CHANGED | rc=0 >>
DETECT_START
IP_TYPE=static
IP_ADDR=192.0.2.10
IP_ADDRS=192.0.2.10
IF_NAME=ens18
DETECT_END
Task ops.tasks.run_ops_job_execution[abc] succeeded in 7.4s: None
"""

    result = check.classify_probe_result(asset, log)

    assert result["probe_status"] == "ok_static"
    assert result["actual_ips"] == "192.0.2.10"


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


def test_single_asset_section_uses_only_log_section_when_label_differs():
    log = """
192.168.101.121_netty_Redis_Cluster | CHANGED | rc=0 >>
DETECT_START
IP_TYPE=static
IP_ADDR=192.168.101.121
IP_ADDRS=192.168.101.121
IF_NAME=ens18
DETECT_END
"""
    asset = {"name": "192.168.101.121_netty Redis Cluster", "address": "192.168.101.121"}

    result = check.classify_probe_result(asset, check.section_for_asset(asset, log, batch_size=1))

    assert result["probe_status"] == "ok_static"
    assert result["actual_ips"] == "192.168.101.121"


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
            "probe_source": "batch",
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
    assert "batch" in content
    assert "## 异常主机" in content
    assert "## 全量明细" in content


def test_markdown_report_includes_new_error_statuses():
    started = check.dt.datetime(2026, 5, 19, 10, 0, tzinfo=check.dt.timezone.utc).astimezone()
    results = [
        check.base_result({"name": "api-host", "address": "192.0.2.1"}, "api_error", remark="Ops 作业创建失败"),
        check.base_result({"name": "log-host", "address": "192.0.2.2"}, "log_fetch_error", remark="日志拉取失败"),
        check.base_result({"name": "script-host", "address": "192.0.2.3"}, "probe_script_error", remark="语法错误"),
    ]

    content = check.build_markdown_report(
        results,
        started,
        started,
        summary={"total_assets": 3, "linux_assets": 3, "windows_assets": 0},
    )

    assert "| api_error | 1 |" in content
    assert "| log_fetch_error | 1 |" in content
    assert "| probe_script_error | 1 |" in content
    assert "### api_error（1）" in content
    assert "### log_fetch_error（1）" in content
    assert "### probe_script_error（1）" in content


def test_duplicate_assets_preserve_secondary_problem_counts_in_report():
    started = check.dt.datetime(2026, 5, 19, 10, 0, tzinfo=check.dt.timezone.utc).astimezone()
    results = [
        {
            **check.base_result({"name": "dup-a", "address": "192.0.2.10"}, "duplicate_asset", remark="duplicate"),
            "original_probe_status": "warn_dhcp",
        },
        {
            **check.base_result({"name": "dup-b", "address": "192.0.2.10"}, "duplicate_asset", remark="duplicate"),
            "original_probe_status": "ip_mismatch",
        },
    ]

    content = check.build_markdown_report(
        results,
        started,
        started,
        summary={"total_assets": 2, "linux_assets": 2, "windows_assets": 0},
    )

    assert "| duplicate_asset | 2 |" in content
    assert "| warn_dhcp | 1 |" in content
    assert "| ip_mismatch | 1 |" in content
    assert "### warn_dhcp（1）" in content
    assert "### ip_mismatch（1）" in content


def test_summarize_assets_uses_explicit_linux_scope():
    assets = [
        {"platform": {"name": "Linux"}, "address": "192.0.2.1"},
        {"platform": "Windows Server", "address": "192.0.2.2"},
        {"platform": {"name": "Cisco IOS"}, "address": "192.0.2.3"},
        {"platform": "", "os": "", "address": "192.0.2.4"},
    ]

    summary = check.summarize_assets(assets)

    assert summary["linux"] == 1
    assert summary["windows"] == 1
    assert summary["unsupported"] == 2
    assert "linux_or_non_windows" not in summary


def test_run_detect_resumes_matching_state(monkeypatch, tmp_path: Path):
    asset = {"id": "asset-1", "name": "host-a", "address": "192.0.2.10", "platform": {"name": "Linux"}, "nodes": [{"id": "node-1"}]}
    state_path = tmp_path / "resume.json"
    signature = check.resume_signature([asset], runas="root", timeout=-1)
    check.save_resume_state(
        state_path,
        {
            "status": "submitted",
            "task_id": "task-1",
            "batch_index": 1,
            "assets": [asset],
            "signature": signature,
        },
    )

    class Client:
        def __init__(self, no_proxy=False):
            pass

        def post(self, path, body):
            raise AssertionError("should not create a new job")

        def get(self, path, params=None):
            if "profile" in path:
                return 200, {"id": "user"}
            if "assets/assets" in path:
                return 200, {"results": [asset], "next": None}
            if "perms/users/self/assets" in path:
                return 200, {"results": [asset], "next": None}
            if "task-detail" in path:
                return 200, {"status": "success", "is_finished": True, "is_success": True, "summary": {}}
            if "log" in path:
                return 200, {"data": "host-a | CHANGED | rc=0 >>\nDETECT_START\nIP_TYPE=static\nIP_ADDR=192.0.2.10\nIP_ADDRS=192.0.2.10\nIF_NAME=eth0\nDETECT_END\n", "end": True, "mark": "m1"}
            return 200, {}

    monkeypatch.setattr(check, "JumpServerClient", Client)
    args = type(
        "Args",
        (),
        {
            "no_proxy": True,
            "page_size": 100,
            "query": None,
            "max_assets": None,
            "execution_mode": "batch",
            "batch_size": 0,
            "timeout": -1,
            "poll_interval": 0,
            "runas": "root",
            "wait_timeout": 1,
            "batch_gap": 0,
            "concurrency": 1,
            "output_dir": str(tmp_path / "reports"),
            "raw_output_dir": str(tmp_path / "raw"),
            "retention_count": 12,
            "resume": True,
            "resume_state": str(state_path),
        },
    )()

    result = check.run_detect(args)
    state = check.load_resume_state(state_path)

    assert result["status_counts"] == {"ok_static": 1}
    assert state["status"] == "parsed"


def test_run_detect_skips_non_linux_assets_without_ops_submission(monkeypatch, tmp_path: Path):
    linux_asset = {"id": "asset-1", "name": "linux-host", "address": "192.0.2.10", "platform": {"name": "Linux"}}
    network_asset = {"id": "asset-2", "name": "switch-1", "address": "192.0.2.20", "platform": {"name": "Cisco IOS"}}
    posted_assets = []

    class Client:
        def __init__(self, no_proxy=False):
            pass

        def post(self, path, body):
            posted_assets.extend(body["assets"])
            return 201, {"task_id": "task-1"}

        def get(self, path, params=None):
            if "profile" in path:
                return 200, {"id": "user"}
            if "assets/assets" in path:
                return 200, {"results": [linux_asset, network_asset], "next": None}
            if "perms/users/self/assets" in path:
                return 200, {"results": [linux_asset, network_asset], "next": None}
            if "task-detail" in path:
                return 200, {"status": "success", "is_finished": True, "is_success": True, "summary": {}}
            if "log" in path:
                return 200, {"data": "linux-host | CHANGED | rc=0 >>\nDETECT_START\nIP_TYPE=static\nIP_ADDR=192.0.2.10\nIP_ADDRS=192.0.2.10\nIF_NAME=eth0\nDETECT_END\n", "end": True, "mark": "m1"}
            return 200, {}

    monkeypatch.setattr(check, "JumpServerClient", Client)
    args = type(
        "Args",
        (),
        {
            "no_proxy": True,
            "page_size": 100,
            "query": None,
            "max_assets": None,
            "execution_mode": "batch",
            "batch_size": 0,
            "timeout": -1,
            "poll_interval": 0,
            "runas": "root",
            "wait_timeout": 1,
            "batch_gap": 0,
            "concurrency": 1,
            "output_dir": str(tmp_path / "reports"),
            "raw_output_dir": str(tmp_path / "raw"),
            "retention_count": 12,
            "resume": False,
            "resume_state": str(tmp_path / "resume.json"),
        },
    )()

    result = check.run_detect(args)

    assert posted_assets == ["asset-1"]
    assert result["summary"]["linux_assets"] == 1
    assert result["summary"]["unsupported_assets"] == 1
    assert result["status_counts"] == {"skipped_non_linux": 1, "ok_static": 1}


def test_jumpserver_client_patch_and_delete_use_signed_methods(monkeypatch):
    captured = []

    def fake_request(self, method, path, params=None, body=None, timeout=20, retries=None):
        captured.append({"method": method, "path": path, "body": body, "timeout": timeout, "retries": retries})
        return 200, {"ok": True}

    monkeypatch.setattr(check.JumpServerClient, "request", fake_request)
    client = object.__new__(check.JumpServerClient)

    assert client.patch("/api/v1/assets/assets/asset-1/", {"is_active": False}) == (200, {"ok": True})
    assert client.delete("/api/v1/assets/assets/asset-1/") == (200, {"ok": True})

    assert captured[0] == {
        "method": "PATCH",
        "path": "/api/v1/assets/assets/asset-1/",
        "body": {"is_active": False},
        "timeout": 20,
        "retries": None,
    }
    assert captured[1]["method"] == "DELETE"
    assert captured[1]["path"] == "/api/v1/assets/assets/asset-1/"


def test_write_reports_includes_cleanup_provenance(tmp_path: Path):
    started = check.dt.datetime(2026, 5, 28, 9, 0, tzinfo=check.dt.timezone.utc)
    paths = check.write_reports(
        [],
        [],
        started,
        tmp_path / "reports",
        tmp_path / "raw",
        12,
        {"total_assets": 0},
        run_metadata={
            "run_id": "run-1",
            "profile": "local",
            "run_source": "weekly_scheduled",
            "cleanup_evidence_eligible": True,
        },
    )

    payload = json.loads(Path(paths["raw"]).read_text(encoding="utf-8"))

    assert payload["run_id"] == "run-1"
    assert payload["profile"] == "local"
    assert payload["run_source"] == "weekly_scheduled"
    assert payload["cleanup_evidence_eligible"] is True



def test_check_ip_reachability_uses_argv_and_records_reachable(monkeypatch):
    called = {}

    class Done:
        returncode = 0

    def fake_run(cmd, capture_output, text, timeout, check):
        called["cmd"] = cmd
        called["timeout"] = timeout
        return Done()

    monkeypatch.setattr(check.subprocess, "run", fake_run)
    monkeypatch.setattr(check.time, "time", lambda: 100.0)

    result = check.check_ip_reachability("192.0.2.10", count=1, timeout=1)

    assert result["ip_reachability"] == "reachable"
    assert result["ip_reachability_source"] == "deployment_host_ping"
    assert result["ip_reachability_command"] == ["ping", "-c", "1", "-W", "1", "192.0.2.10"]
    assert result["ip_reachability_exit_code"] == 0
    assert called["cmd"] == ["ping", "-c", "1", "-W", "1", "192.0.2.10"]


def test_check_ip_reachability_handles_timeout_and_invalid_ip(monkeypatch):
    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=1)

    monkeypatch.setattr(check.subprocess, "run", fake_run)
    timeout_result = check.check_ip_reachability("192.0.2.10", count=1, timeout=1)
    invalid_result = check.check_ip_reachability("not-an-ip", count=1, timeout=1)

    assert timeout_result["ip_reachability"] == "unknown"
    assert "timeout" in timeout_result["ip_reachability_remark"].lower()
    assert invalid_result["ip_reachability"] == "unknown"
    assert "invalid" in invalid_result["ip_reachability_remark"].lower()


def test_classify_probe_result_downgrades_ops_unreachable_when_ping_reachable(monkeypatch):
    asset = {"id": "asset-1", "name": "host-a", "address": "192.0.2.10"}
    monkeypatch.setattr(check, "check_ip_reachability", lambda *args, **kwargs: {
        "ip_reachability": "reachable",
        "ip_reachability_source": "deployment_host_ping",
        "ip_reachability_checked_at": "2026-05-29T10:00:00+08:00",
        "ip_reachability_command": ["ping", "-c", "1", "-W", "1", "192.0.2.10"],
        "ip_reachability_exit_code": 0,
        "ip_reachability_duration_ms": 20,
        "ip_reachability_remark": "ping reachable from deployment host",
    })

    result = check.classify_probe_result(asset, "fatal: [192.0.2.10]: UNREACHABLE! => failed to connect", ping_check=True)

    assert result["probe_status"] == "jumpserver_unreachable_ip_reachable"
    assert result["connectivity"] == "unreachable"
    assert result["ops_connectivity"] == "unreachable"
    assert result["ip_reachability"] == "reachable"


def test_build_ops_payload_records_detection_command_hash():
    payload = check.build_ops_payload([{"id": "asset-1", "nodes": []}], batch_index=1, timeout=-1)

    assert payload["module"] == "shell"
    assert payload["args"] == check.DETECTION_COMMAND



def test_run_detect_uses_ip_ping_workers_executor(monkeypatch):
    assets = [{"id": "asset-1", "name": "host-a", "address": "192.0.2.10", "platform": {"name": "Linux"}, "nodes": []}]
    monkeypatch.setattr(check, "validate", lambda client: {"ok": True})
    monkeypatch.setattr(check, "fetch_active_assets", lambda client, page_size, max_assets=None: assets)
    monkeypatch.setattr(check, "fetch_authorized_assets", lambda client, page_size: assets)
    monkeypatch.setattr(check, "JumpServerClient", lambda no_proxy=False: object())
    monkeypatch.setattr(check, "run_batch", lambda *args, **kwargs: {"results": [{**check.base_result(assets[0], "unreachable"), "asset_ip": "192.0.2.10"}], "task_id": "t1"})
    monkeypatch.setattr(check, "duplicate_asset_map", lambda assets: {})
    monkeypatch.setattr(check, "apply_duplicate_asset_annotations", lambda results, duplicates: None)
    monkeypatch.setattr(check, "check_ip_reachability", lambda *args, **kwargs: {"ip_reachability": "unreachable", "ip_reachability_source": "deployment_host_ping", "ip_reachability_checked_at": "now", "ip_reachability_command": [], "ip_reachability_exit_code": 1, "ip_reachability_duration_ms": 1, "ip_reachability_remark": "x"})
    monkeypatch.setattr(check, "write_reports", lambda *args, **kwargs: {"report": "r", "latest": "l", "raw": "x"})
    captured = {}
    class FakeExecutor:
        def __init__(self, max_workers): captured['max_workers']=max_workers
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def submit(self, fn, *args, **kwargs):
            class F:
                def result(self_non): return fn(*args, **kwargs)
            return F()
    monkeypatch.setattr(check, "ThreadPoolExecutor", FakeExecutor)
    monkeypatch.setattr(check, "as_completed", lambda futures: futures)
    args = check.argparse.Namespace(command='detect', no_proxy=True, page_size=100, max_assets=None, query='', output_dir='reports/yuque', raw_output_dir='artifacts/raw', retention_count=12, runas='root', profile='local', run_id='rid', run_source='manual', cleanup_evidence_eligible=False, resume=True, resume_state='artifacts/state/x.json', execution_mode='batch', batch_size=0, timeout=-1, wait_timeout=1200, poll_interval=30, batch_gap=0, concurrency=12, ip_reachability_check=True, ip_ping_count=1, ip_ping_timeout=1, ip_ping_workers=7)
    result = check.run_detect(args)
    assert captured['max_workers'] == 7
    assert result['status_counts']['unreachable'] == 1


def test_check_tcp_reachability_uses_socket_and_records_open(monkeypatch):
    calls = []

    class FakeSocket:
        def __init__(self):
            self.timeout = None

        def settimeout(self, timeout):
            self.timeout = timeout

        def connect_ex(self, address):
            calls.append((address, self.timeout))
            return 0

        def close(self):
            pass

    monkeypatch.setattr(check.socket, "socket", lambda *args, **kwargs: FakeSocket())

    result = check.check_tcp_reachability("192.0.2.10", ports=[22], timeout=1)

    assert result["tcp_reachability"] == "open"
    assert result["tcp_reachability_source"] == "deployment_host_socket"
    assert result["tcp_reachability_ports"] == [22]
    assert "ssh port open" in result["tcp_reachability_remark"]
    assert calls == [(('192.0.2.10', 22), 1)]


def test_check_tcp_reachability_handles_invalid_ip_port_and_closed(monkeypatch):
    invalid_ip = check.check_tcp_reachability("not-an-ip", ports=[22], timeout=1)
    invalid_port = check.check_tcp_reachability("192.0.2.10", ports=[0], timeout=1)

    class FakeSocket:
        def settimeout(self, timeout):
            pass

        def connect_ex(self, address):
            return 111

        def close(self):
            pass

    monkeypatch.setattr(check.socket, "socket", lambda *args, **kwargs: FakeSocket())
    closed = check.check_tcp_reachability("192.0.2.10", ports=[22], timeout=1)

    assert invalid_ip["tcp_reachability"] == "unknown"
    assert "invalid asset ip" in invalid_ip["tcp_reachability_remark"]
    assert invalid_port["tcp_reachability"] == "unknown"
    assert "invalid tcp port" in invalid_port["tcp_reachability_remark"]
    assert closed["tcp_reachability"] == "closed"


def test_run_detect_marks_tcp_open_review_required_after_ping_not_reachable(monkeypatch):
    assets = [{"id": "asset-1", "name": "host-a", "address": "192.0.2.10", "platform": {"name": "Linux"}, "nodes": []}]
    monkeypatch.setattr(check, "validate", lambda client: {"ok": True})
    monkeypatch.setattr(check, "fetch_active_assets", lambda client, page_size, max_assets=None: assets)
    monkeypatch.setattr(check, "fetch_authorized_assets", lambda client, page_size: assets)
    monkeypatch.setattr(check, "JumpServerClient", lambda no_proxy=False: object())
    monkeypatch.setattr(check, "run_batch", lambda *args, **kwargs: {"results": [{**check.base_result(assets[0], "unreachable"), "asset_ip": "192.0.2.10"}], "task_id": "t1"})
    monkeypatch.setattr(check, "duplicate_asset_map", lambda assets: {})
    monkeypatch.setattr(check, "apply_duplicate_asset_annotations", lambda results, duplicates: None)
    monkeypatch.setattr(check, "check_ip_reachability", lambda *args, **kwargs: {"ip_reachability": "unreachable", "ip_reachability_source": "deployment_host_ping", "ip_reachability_checked_at": "now", "ip_reachability_command": [], "ip_reachability_exit_code": 1, "ip_reachability_duration_ms": 1, "ip_reachability_remark": "x"})
    monkeypatch.setattr(check, "check_tcp_reachability", lambda *args, **kwargs: {"tcp_reachability": "open", "tcp_reachability_source": "deployment_host_socket", "tcp_reachability_ports": [22], "tcp_reachability_checked_at": "now", "tcp_reachability_duration_ms": 1, "tcp_reachability_remark": "ssh port open from deployment host"})
    captured = {}
    monkeypatch.setattr(check, "write_reports", lambda results, *args, **kwargs: captured.setdefault("results", results) or {"report": "r", "latest": "l", "raw": "x"})

    args = check.argparse.Namespace(command='detect', no_proxy=True, page_size=100, max_assets=None, query='', output_dir='reports/yuque', raw_output_dir='artifacts/raw', retention_count=12, runas='root', profile='local', run_id='rid', run_source='manual', cleanup_evidence_eligible=False, resume=True, resume_state='artifacts/state/x.json', execution_mode='batch', batch_size=0, timeout=-1, wait_timeout=1200, poll_interval=30, batch_gap=0, concurrency=12, ip_reachability_check=True, ip_ping_count=1, ip_ping_timeout=1, ip_ping_workers=7, tcp_reachability_check=True, tcp_reachability_ports='22', tcp_reachability_timeout=1, tcp_reachability_workers=7)
    result = check.run_detect(args)

    assert result['status_counts']['jumpserver_unreachable_tcp_open'] == 1
    assert captured["results"][0]["probe_status"] == "jumpserver_unreachable_tcp_open"
    assert captured["results"][0]["tcp_reachability"] == "open"


def test_run_detect_does_not_tcp_probe_non_unreachable_error_states(monkeypatch):
    assets = [{"id": "asset-1", "name": "host-a", "address": "192.0.2.10", "platform": {"name": "Linux"}, "nodes": []}]
    monkeypatch.setattr(check, "validate", lambda client: {"ok": True})
    monkeypatch.setattr(check, "fetch_active_assets", lambda client, page_size, max_assets=None: assets)
    monkeypatch.setattr(check, "fetch_authorized_assets", lambda client, page_size: assets)
    monkeypatch.setattr(check, "JumpServerClient", lambda no_proxy=False: object())
    monkeypatch.setattr(check, "run_batch", lambda *args, **kwargs: {"results": [{**check.base_result(assets[0], "ops_module_error"), "asset_ip": "192.0.2.10"}], "task_id": "t1"})
    monkeypatch.setattr(check, "duplicate_asset_map", lambda assets: {})
    monkeypatch.setattr(check, "apply_duplicate_asset_annotations", lambda results, duplicates: None)
    monkeypatch.setattr(check, "check_tcp_reachability", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("must not probe tcp")))
    monkeypatch.setattr(check, "write_reports", lambda *args, **kwargs: {"report": "r", "latest": "l", "raw": "x"})

    args = check.argparse.Namespace(command='detect', no_proxy=True, page_size=100, max_assets=None, query='', output_dir='reports/yuque', raw_output_dir='artifacts/raw', retention_count=12, runas='root', profile='local', run_id='rid', run_source='manual', cleanup_evidence_eligible=False, resume=True, resume_state='artifacts/state/x.json', execution_mode='batch', batch_size=0, timeout=-1, wait_timeout=1200, poll_interval=30, batch_gap=0, concurrency=12, ip_reachability_check=False, ip_ping_count=1, ip_ping_timeout=1, ip_ping_workers=7, tcp_reachability_check=True, tcp_reachability_ports='22', tcp_reachability_timeout=1, tcp_reachability_workers=7)
    result = check.run_detect(args)

    assert result['status_counts']['ops_module_error'] == 1
