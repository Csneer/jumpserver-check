import argparse
import json
import time

from scripts import run_weekly_check as weekly

def make_args(**overrides):
    values = {
        "no_proxy": True,
        "profile": "default",
        "env_file": "",
        "wait_timeout": 1200,
        "poll_interval": 30,
        "output_dir": "reports/yuque",
        "raw_output_dir": "artifacts/raw",
        "resume_state": "artifacts/state/jms-host-ip-check-inflight.json",
        "retention_count": 12,
        "run_id": "",
        "run_source": "manual",
        "cleanup_evidence_eligible": False,
        "query": "",
        "max_assets": None,
        "yuque_title": "Report",
        "yuque_slug": "jumpserver-host-ip-check",
        "toc_uuid": "",
        "sibling_url": "",
        "notify_title": "Notify",
        "dry_run_yuque": False,
        "dry_run_notify": False,
        "cleanup_evaluate": False,
        "cleanup_apply_confirmed": False,
        "cleanup_dry_run": False,
        "cleanup_allow_delete": False,
        "require_wecom": False,
        "no_resume": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)

def test_run_workflow_success(monkeypatch, tmp_path):
    detect = {
        "summary": {"total_assets": 1, "linux_assets": 1, "unauthorized_assets": 0},
        "paths": {"latest": str(tmp_path / "latest.md")},
        "status_counts": {"ok_static": 1},
    }
    (tmp_path / "latest.md").write_text("# report", encoding="utf-8")
    monkeypatch.setattr(weekly, "run_detect_subprocess", lambda args, timeout: detect)
    monkeypatch.setattr(
        weekly,
        "load_runtime_env",
        lambda profile, env_file: type("Env", (), {"env_file": "configs/profiles/prod.env", "loaded_files": ["prod.env"]})(),
    )
    monkeypatch.setattr(
        weekly.preflight_check,
        "validate_config",
        lambda require_wecom=False, profile="default", env_file="": {"ok": True, "errors": []},
    )
    monkeypatch.setattr(
        weekly.yuque_markdown_sync,
        "sync_markdown",
        lambda *args, **kwargs: {"url": "https://www.yuque.com/u/r/doc", "action": "created"},
    )
    monkeypatch.setattr(weekly.wecom_notify, "notify", lambda **kwargs: {"status": "sent"})
    monkeypatch.setattr(weekly, "write_workflow_record", lambda record, output_dir: tmp_path / "workflow.json")

    record = weekly.run_workflow(make_args(profile="prod", env_file="configs/profiles/prod.env"))

    assert record["status"] == "success"
    assert record["profile"] == "prod"
    assert record["env_file"] == "configs/profiles/prod.env"
    assert record["yuque"]["url"].endswith("/doc")
    assert record["wecom"]["status"] == "sent"

def test_run_workflow_detect_failure_still_notifies(monkeypatch, tmp_path):
    def fail_detect(args, timeout):
        raise RuntimeError("detect failed")

    calls = []
    monkeypatch.setattr(weekly, "run_detect_subprocess", fail_detect)
    monkeypatch.setattr(weekly, "load_runtime_env", lambda profile, env_file: type("Env", (), {"env_file": "", "loaded_files": []})())
    monkeypatch.setattr(weekly.preflight_check, "validate_config", lambda require_wecom=False, profile="default", env_file="": {"ok": True, "errors": []})
    monkeypatch.setattr(weekly.wecom_notify, "notify", lambda **kwargs: calls.append(kwargs) or {"status": "sent"})
    monkeypatch.setattr(weekly, "write_workflow_record", lambda record, output_dir: tmp_path / "workflow.json")

    record = weekly.run_workflow(make_args())

    assert record["status"] == "failed"
    assert "detect failed" in record["error_message"]
    assert calls[0]["status"] == "failed"

def test_run_workflow_timeout_notifies_timeout(monkeypatch, tmp_path):
    def timeout(args, timeout):
        raise TimeoutError("too slow")

    calls = []
    monkeypatch.setattr(weekly, "run_detect_subprocess", timeout)
    monkeypatch.setattr(weekly, "load_runtime_env", lambda profile, env_file: type("Env", (), {"env_file": "", "loaded_files": []})())
    monkeypatch.setattr(weekly.preflight_check, "validate_config", lambda require_wecom=False, profile="default", env_file="": {"ok": True, "errors": []})
    monkeypatch.setattr(weekly.wecom_notify, "notify", lambda **kwargs: calls.append(kwargs) or {"status": "sent"})
    monkeypatch.setattr(weekly, "write_workflow_record", lambda record, output_dir: tmp_path / "workflow.json")

    record = weekly.run_workflow(make_args())

    assert record["status"] == "timeout"
    assert calls[0]["status"] == "timeout"

def test_run_workflow_yuque_failure_notifies_failure(monkeypatch, tmp_path):
    latest = tmp_path / "latest.md"
    latest.write_text("# report", encoding="utf-8")
    detect = {"summary": {}, "paths": {"latest": str(latest)}, "status_counts": {}}

    def fail_sync(*args, **kwargs):
        raise RuntimeError("yuque failed")

    calls = []
    monkeypatch.setattr(weekly, "run_detect_subprocess", lambda args, timeout: detect)
    monkeypatch.setattr(weekly, "load_runtime_env", lambda profile, env_file: type("Env", (), {"env_file": "", "loaded_files": []})())
    monkeypatch.setattr(weekly.preflight_check, "validate_config", lambda require_wecom=False, profile="default", env_file="": {"ok": True, "errors": []})
    monkeypatch.setattr(weekly.yuque_markdown_sync, "sync_markdown", fail_sync)
    monkeypatch.setattr(weekly.wecom_notify, "notify", lambda **kwargs: calls.append(kwargs) or {"status": "sent"})
    monkeypatch.setattr(weekly, "write_workflow_record", lambda record, output_dir: tmp_path / "workflow.json")

    record = weekly.run_workflow(make_args())

    assert record["status"] == "failed"
    assert "yuque failed" in record["error_message"]
    assert calls[0]["status"] == "failed"

def test_run_workflow_preflight_failure_does_not_detect(monkeypatch, tmp_path):
    def should_not_run(args, timeout):
        raise AssertionError("detect should not run")

    calls = []
    monkeypatch.setattr(weekly, "load_runtime_env", lambda profile, env_file: type("Env", (), {"env_file": "", "loaded_files": []})())
    monkeypatch.setattr(weekly.preflight_check, "validate_config", lambda require_wecom=False, profile="default", env_file="": {"ok": False, "errors": ["missing"]})
    monkeypatch.setattr(weekly, "run_detect_subprocess", should_not_run)
    monkeypatch.setattr(weekly.wecom_notify, "notify", lambda **kwargs: calls.append(kwargs) or {"status": "sent"})
    monkeypatch.setattr(weekly, "write_workflow_record", lambda record, output_dir: tmp_path / "workflow.json")

    record = weekly.run_workflow(make_args())

    assert record["status"] == "failed"
    assert "前置配置检查失败" in record["error_message"]
    assert calls[0]["status"] == "failed"

def test_run_detect_subprocess_timeout_kills_process(monkeypatch):
    class FakeProcess:
        returncode = None

        def __init__(self):
            self.killed = False

        def poll(self):
            return None

        def kill(self):
            self.killed = True

        def communicate(self):
            return "", ""

    process = FakeProcess()
    monkeypatch.setattr(weekly.subprocess, "Popen", lambda *args, **kwargs: process)
    times = iter([0, 2])
    monkeypatch.setattr(weekly.time, "time", lambda: next(times))
    monkeypatch.setattr(weekly.time, "sleep", lambda seconds: None)

    try:
        weekly.run_detect_subprocess(make_args(poll_interval=1), timeout_seconds=1)
    except TimeoutError:
        pass
    else:
        raise AssertionError("expected TimeoutError")

    assert process.killed is True

def test_run_detect_subprocess_passes_profile_resume_state(monkeypatch):
    captured = {}

    class FakeProcess:
        returncode = 0

        def poll(self):
            return 0

        def communicate(self):
            return '{"summary": {}, "paths": {}, "status_counts": {}}', ""

    def fake_popen(command, **kwargs):
        captured["command"] = command
        return FakeProcess()

    monkeypatch.setattr(weekly.subprocess, "Popen", fake_popen)

    weekly.run_detect_subprocess(
        make_args(profile="prod", resume_state="artifacts/state/prod/jms-host-ip-check-inflight.json"),
        timeout_seconds=1,
    )

    command = captured["command"]
    assert "--resume-state" in command
    assert command[command.index("--resume-state") + 1] == "artifacts/state/prod/jms-host-ip-check-inflight.json"

def test_run_detect_subprocess_passes_cleanup_provenance_flags(monkeypatch):
    captured = {}

    class FakeProcess:
        returncode = 0

        def poll(self):
            return 0

        def communicate(self):
            return '{"summary": {}, "paths": {}, "status_counts": {}, "run_id": "run-1"}', ""

    def fake_popen(command, **kwargs):
        captured["command"] = command
        return FakeProcess()

    monkeypatch.setattr(weekly.subprocess, "Popen", fake_popen)

    weekly.run_detect_subprocess(
        make_args(run_id="run-1", run_source="weekly_scheduled", cleanup_evidence_eligible=True),
        timeout_seconds=1,
    )

    command = captured["command"]
    assert "--run-id" in command
    assert command[command.index("--run-id") + 1] == "run-1"
    assert "--run-source" in command
    assert command[command.index("--run-source") + 1] == "weekly_scheduled"
    assert "--cleanup-evidence-eligible" in command

def test_run_workflow_cleanup_evaluate_records_summary(monkeypatch, tmp_path):
    latest = tmp_path / "latest.md"
    latest.write_text("# report", encoding="utf-8")
    detect = {"summary": {}, "paths": {"latest": str(latest), "raw": str(tmp_path / "raw.json")}, "status_counts": {}}
    cleanup_plan = {"summary": {"candidates": 1, "skipped": 0}, "plan_path": str(tmp_path / "plan.json"), "candidates": []}
    notify_calls = []

    monkeypatch.setattr(weekly, "run_detect_subprocess", lambda args, timeout: detect)
    monkeypatch.setattr(weekly, "load_runtime_env", lambda profile, env_file: type("Env", (), {"env_file": "", "loaded_files": []})())
    monkeypatch.setattr(weekly.preflight_check, "validate_config", lambda require_wecom=False, profile="default", env_file="": {"ok": True, "errors": []})
    monkeypatch.setattr(weekly.yuque_markdown_sync, "sync_markdown", lambda *args, **kwargs: {"url": "https://yuque/doc"})
    monkeypatch.setattr(weekly.host_cleanup, "evaluate_cleanup", lambda *args, **kwargs: cleanup_plan)
    monkeypatch.setattr(weekly.wecom_notify, "notify", lambda **kwargs: notify_calls.append(kwargs) or {"status": "sent"})
    monkeypatch.setattr(weekly, "write_workflow_record", lambda record, output_dir: tmp_path / "workflow.json")

    record = weekly.run_workflow(make_args(cleanup_evaluate=True, raw_output_dir=str(tmp_path / "raw")))

    assert record["cleanup"]["plan"]["summary"]["candidates"] == 1
    summary = json.loads(notify_calls[0]["summary_json"])
    assert summary["cleanup"]["plan"]["plan_path"] == str(tmp_path / "plan.json")

def test_run_detect_subprocess_passes_ip_reachability_flags(monkeypatch, tmp_path):
    captured = {}

    class FakeProcess:
        returncode = 0
        def poll(self): return 0
        def communicate(self): return ('{}', '')

    def fake_popen(command, cwd, text, stdout, stderr):
        captured['command'] = command
        return FakeProcess()

    monkeypatch.setattr(weekly.subprocess, 'Popen', fake_popen)
    args = weekly.parse_args.__globals__['argparse'].Namespace(
        no_proxy=True, poll_interval=30, output_dir='reports/yuque', raw_output_dir='artifacts/raw', retention_count=12,
        profile='local', run_id='rid', run_source='weekly_scheduled', resume_state='artifacts/state/x.json', cleanup_evidence_eligible=True,
        no_resume=False, query='', max_assets=None, ip_reachability_check=True, ip_ping_count=1, ip_ping_timeout=1, ip_ping_workers=32
    )
    weekly.run_detect_subprocess(args, 1200)
    cmd = captured['command']
    assert '--ip-reachability-check' in cmd
    assert '--ip-ping-count' in cmd and '1' in cmd
    assert '--ip-ping-timeout' in cmd and '1' in cmd
    assert '--ip-ping-workers' in cmd and '32' in cmd

def test_run_workflow_sends_delete_notification_and_records_failure(monkeypatch, tmp_path):
    latest = tmp_path / "latest.md"
    latest.write_text("# report", encoding="utf-8")
    detect = {"summary": {}, "paths": {"latest": str(latest)}, "status_counts": {}}
    apply_result = {
        "results": [{"status": "deleted", "asset_id": "asset-1"}],
        "result_path": str(tmp_path / "cleanup-result.json"),
    }
    cleanup_payload = {"status": "completed", "plan": {"summary": {}}, "apply": apply_result}

    monkeypatch.setattr(weekly, "run_detect_subprocess", lambda args, timeout: detect)
    monkeypatch.setattr(weekly, "load_runtime_env", lambda profile, env_file: type("Env", (), {"env_file": "", "loaded_files": []})())
    monkeypatch.setattr(weekly.preflight_check, "validate_config", lambda require_wecom=False, profile="default", env_file="": {"ok": True, "errors": []})
    monkeypatch.setattr(weekly.yuque_markdown_sync, "sync_markdown", lambda *args, **kwargs: {"url": "https://yuque/doc"})
    monkeypatch.setattr(weekly, "run_cleanup_steps", lambda args, detect_result: cleanup_payload)
    monkeypatch.setattr(weekly.wecom_notify, "notify", lambda **kwargs: {"status": "sent"})

    def fail_delete_notify(apply_payload):
        raise RuntimeError("delete notify failed")

    monkeypatch.setattr(weekly.wecom_notify, "send_cleanup_delete_notification", fail_delete_notify)
    monkeypatch.setattr(weekly, "write_workflow_record", lambda record, output_dir: tmp_path / "workflow.json")

    record = weekly.run_workflow(make_args(cleanup_apply_confirmed=True))

    assert record["status"] == "success"
    assert record["cleanup"]["apply"]["delete_notification"]["status"] == "failed"
    assert "delete notify failed" in record["cleanup"]["apply"]["delete_notification"]["error"]

def test_run_workflow_first_stable_run_writes_snapshot_and_syncs_yuque(monkeypatch, tmp_path):
    latest = tmp_path / "latest.md"
    latest.write_text("# report", encoding="utf-8")
    detect = {
        "run_id": "run-1",
        "summary": {},
        "paths": {"latest": str(latest)},
        "status_counts": {"ok_static": 1},
        "results": [{"asset_id": "a1", "asset_name": "host-a", "asset_ip": "10.0.0.1", "probe_status": "ok_static"}],
    }
    sync_calls = []
    monkeypatch.setattr(weekly, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(weekly, "run_detect_subprocess", lambda args, timeout: detect)
    monkeypatch.setattr(weekly, "load_runtime_env", lambda profile, env_file: type("Env", (), {"env_file": "", "loaded_files": []})())
    monkeypatch.setattr(weekly.preflight_check, "validate_config", lambda require_wecom=False, profile="default", env_file="": {"ok": True, "errors": []})
    monkeypatch.setattr(weekly.yuque_markdown_sync, "sync_markdown", lambda *args, **kwargs: sync_calls.append(kwargs) or {"url": "https://yuque/doc"})
    monkeypatch.setattr(weekly.wecom_notify, "notify", lambda **kwargs: {"status": "sent"})
    monkeypatch.setattr(weekly, "write_workflow_record", lambda record, output_dir: tmp_path / "workflow.json")

    record = weekly.run_workflow(make_args(profile="prod", run_source="weekly_scheduled"))

    assert sync_calls
    assert record["yuque"]["url"] == "https://yuque/doc"
    assert record["host_snapshot_diff"]["changed"] is True
    snapshot_path = tmp_path / "artifacts" / "state" / "prod" / "last-stable-host-snapshot.json"
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    assert snapshot["profile"] == "prod"
    assert snapshot["host_hash"] == record["host_snapshot_diff"]["host_hash"]

def test_run_workflow_unchanged_stable_snapshot_skips_yuque_and_notifies_note(monkeypatch, tmp_path):
    latest = tmp_path / "latest.md"
    latest.write_text("# report", encoding="utf-8")
    detect = {
        "run_id": "run-2",
        "summary": {},
        "paths": {"latest": str(latest)},
        "status_counts": {"ok_static": 1},
        "results": [{"asset_id": "a1", "asset_name": "host-a", "asset_ip": "10.0.0.1", "probe_status": "ok_static"}],
    }
    snapshot_path = tmp_path / "artifacts" / "state" / "prod" / "last-stable-host-snapshot.json"
    baseline = weekly.build_host_snapshot("prod", detect, run_id="run-1", recovery_reason="initial")
    snapshot_path.parent.mkdir(parents=True)
    snapshot_path.write_text(json.dumps(baseline, ensure_ascii=False), encoding="utf-8")
    notify_calls = []

    monkeypatch.setattr(weekly, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(weekly, "run_detect_subprocess", lambda args, timeout: detect)
    monkeypatch.setattr(weekly, "load_runtime_env", lambda profile, env_file: type("Env", (), {"env_file": "", "loaded_files": []})())
    monkeypatch.setattr(weekly.preflight_check, "validate_config", lambda require_wecom=False, profile="default", env_file="": {"ok": True, "errors": []})
    monkeypatch.setattr(weekly.yuque_markdown_sync, "sync_markdown", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("Yuque sync must be skipped")))
    monkeypatch.setattr(weekly.wecom_notify, "notify", lambda **kwargs: notify_calls.append(kwargs) or {"status": "sent"})
    monkeypatch.setattr(weekly, "write_workflow_record", lambda record, output_dir: tmp_path / "workflow.json")

    record = weekly.run_workflow(make_args(profile="prod", run_source="weekly_scheduled"))

    assert record["yuque"]["status"] == "skipped"
    assert record["host_snapshot_diff"]["changed"] is False
    assert record["host_snapshot_diff"]["note"] == "与上一轮结果对比无主机信息变动，已跳过语雀归档"
    summary = json.loads(notify_calls[0]["summary_json"])
    assert summary["host_snapshot_diff"]["note"] == "与上一轮结果对比无主机信息变动，已跳过语雀归档"
    updated = json.loads(snapshot_path.read_text(encoding="utf-8"))
    assert updated["host_hash"] == baseline["host_hash"]
    assert updated["last_run_id"] == "run-2"

def test_run_workflow_changed_snapshot_syncs_yuque_and_counts_changes(monkeypatch, tmp_path):
    latest = tmp_path / "latest.md"
    latest.write_text("# report", encoding="utf-8")
    old_detect = {"results": [{"asset_id": "a1", "asset_name": "host-a", "asset_ip": "10.0.0.1", "probe_status": "ok_static"}]}
    detect = {
        "run_id": "run-2",
        "summary": {},
        "paths": {"latest": str(latest)},
        "status_counts": {"ok_static": 1},
        "results": [{"asset_id": "a2", "asset_name": "host-b", "asset_ip": "10.0.0.2", "probe_status": "ok_static"}],
    }
    snapshot_path = tmp_path / "artifacts" / "state" / "prod" / "last-stable-host-snapshot.json"
    baseline = weekly.build_host_snapshot("prod", old_detect, run_id="run-1")
    snapshot_path.parent.mkdir(parents=True)
    snapshot_path.write_text(json.dumps(baseline, ensure_ascii=False), encoding="utf-8")
    notify_calls = []
    sync_calls = []

    monkeypatch.setattr(weekly, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(weekly, "run_detect_subprocess", lambda args, timeout: detect)
    monkeypatch.setattr(weekly, "load_runtime_env", lambda profile, env_file: type("Env", (), {"env_file": "", "loaded_files": []})())
    monkeypatch.setattr(weekly.preflight_check, "validate_config", lambda require_wecom=False, profile="default", env_file="": {"ok": True, "errors": []})
    monkeypatch.setattr(weekly.yuque_markdown_sync, "sync_markdown", lambda *args, **kwargs: sync_calls.append(kwargs) or {"url": "https://yuque/doc2"})
    monkeypatch.setattr(weekly.wecom_notify, "notify", lambda **kwargs: notify_calls.append(kwargs) or {"status": "sent"})
    monkeypatch.setattr(weekly, "write_workflow_record", lambda record, output_dir: tmp_path / "workflow.json")

    record = weekly.run_workflow(make_args(profile="prod", run_source="weekly_scheduled"))

    assert sync_calls
    assert record["host_snapshot_diff"]["changed"] is True
    assert record["host_snapshot_diff"]["added"] == 1
    assert record["host_snapshot_diff"]["removed"] == 1
    summary = json.loads(notify_calls[0]["summary_json"])
    assert summary["host_snapshot_diff"]["added"] == 1
    assert summary["host_snapshot_diff"]["removed"] == 1

def test_run_detect_subprocess_passes_tcp_reachability_flags(monkeypatch):
    captured = {}

    class FakeProcess:
        returncode = 0
        def poll(self): return 0
        def communicate(self): return ('{}', '')

    def fake_popen(command, cwd, text, stdout, stderr):
        captured['command'] = command
        return FakeProcess()

    monkeypatch.setattr(weekly.subprocess, 'Popen', fake_popen)
    args = weekly.parse_args.__globals__['argparse'].Namespace(
        no_proxy=True, poll_interval=30, output_dir='reports/yuque', raw_output_dir='artifacts/raw', retention_count=12,
        profile='local', run_id='rid', run_source='weekly_scheduled', resume_state='artifacts/state/x.json', cleanup_evidence_eligible=True,
        no_resume=False, query='', max_assets=None, ip_reachability_check=True, ip_ping_count=1, ip_ping_timeout=1, ip_ping_workers=32,
        tcp_reachability_check=True, tcp_reachability_ports='22,2222', tcp_reachability_timeout=2, tcp_reachability_workers=8
    )
    weekly.run_detect_subprocess(args, 1200)
    cmd = captured['command']
    assert '--tcp-reachability-check' in cmd
    assert '--tcp-reachability-ports' in cmd and '22,2222' in cmd
    assert '--tcp-reachability-timeout' in cmd and '2' in cmd
    assert '--tcp-reachability-workers' in cmd and '8' in cmd

def test_weekly_snapshot_diff_loads_production_raw_results_when_detect_result_omits_inline_results(monkeypatch, tmp_path):
    latest = tmp_path / "latest.md"
    raw_path = tmp_path / "raw.json"
    latest.write_text("# report", encoding="utf-8")
    raw_path.write_text(
        json.dumps({"results": [{"asset_id": "a1", "asset_name": "host-a", "asset_ip": "10.0.0.1", "probe_status": "ok_static"}]}),
        encoding="utf-8",
    )
    detect = {"run_id": "run-1", "summary": {}, "paths": {"latest": str(latest), "raw": str(raw_path)}, "status_counts": {"ok_static": 1}}
    monkeypatch.setattr(weekly, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(weekly, "run_detect_subprocess", lambda args, timeout: detect)
    monkeypatch.setattr(weekly, "load_runtime_env", lambda profile, env_file: type("Env", (), {"env_file": "", "loaded_files": []})())
    monkeypatch.setattr(weekly.preflight_check, "validate_config", lambda require_wecom=False, profile="default", env_file="": {"ok": True, "errors": []})
    monkeypatch.setattr(weekly.yuque_markdown_sync, "sync_markdown", lambda *args, **kwargs: {"url": "https://yuque/doc"})
    monkeypatch.setattr(weekly.wecom_notify, "notify", lambda **kwargs: {"status": "sent"})
    monkeypatch.setattr(weekly, "write_workflow_record", lambda record, output_dir: tmp_path / "workflow.json")

    record = weekly.run_workflow(make_args(profile="prod", run_source="weekly_scheduled"))

    snapshot_path = tmp_path / "artifacts" / "state" / "prod" / "last-stable-host-snapshot.json"
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    assert snapshot["hosts"][0]["asset_id"] == "a1"
    assert record["host_snapshot_diff"]["added"] == 1

def test_weekly_snapshot_diff_fails_closed_when_raw_results_missing(monkeypatch, tmp_path):
    latest = tmp_path / "latest.md"
    latest.write_text("# report", encoding="utf-8")
    missing_raw = tmp_path / "missing-raw.json"
    detect = {"run_id": "run-raw-missing", "summary": {}, "paths": {"latest": str(latest), "raw": str(missing_raw)}, "status_counts": {"ok_static": 1}}
    snapshot_path = tmp_path / "artifacts" / "state" / "prod" / "last-stable-host-snapshot.json"
    baseline = weekly.build_host_snapshot(
        "prod",
        {"results": [{"asset_id": "a1", "asset_name": "host-a", "asset_ip": "10.0.0.1", "probe_status": "ok_static"}]},
        run_id="baseline-run",
    )
    snapshot_path.parent.mkdir(parents=True)
    snapshot_path.write_text(json.dumps(baseline, ensure_ascii=False), encoding="utf-8")
    notify_calls = []

    monkeypatch.setattr(weekly, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(weekly, "run_detect_subprocess", lambda args, timeout: detect)
    monkeypatch.setattr(weekly, "load_runtime_env", lambda profile, env_file: type("Env", (), {"env_file": "", "loaded_files": []})())
    monkeypatch.setattr(weekly.preflight_check, "validate_config", lambda require_wecom=False, profile="default", env_file="": {"ok": True, "errors": []})
    monkeypatch.setattr(weekly.yuque_markdown_sync, "sync_markdown", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("Yuque sync must not run without raw host results")))
    monkeypatch.setattr(weekly.wecom_notify, "notify", lambda **kwargs: notify_calls.append(kwargs) or {"status": "sent"})
    monkeypatch.setattr(weekly, "write_workflow_record", lambda record, output_dir: tmp_path / "workflow.json")

    record = weekly.run_workflow(make_args(profile="prod", run_source="weekly_scheduled"))

    assert record["status"] == "failed"
    assert "raw" in record["error_message"]
    assert "results" in record["error_message"]
    assert record["host_snapshot_diff"] is None
    assert record["yuque"] is None
    assert json.loads(snapshot_path.read_text(encoding="utf-8"))["last_run_id"] == "baseline-run"
    assert notify_calls[0]["status"] == "failed"

def test_weekly_snapshot_diff_fails_closed_when_raw_results_invalid(monkeypatch, tmp_path):
    latest = tmp_path / "latest.md"
    raw_path = tmp_path / "raw.json"
    latest.write_text("# report", encoding="utf-8")
    raw_path.write_text('{"summary": {}}', encoding="utf-8")
    detect = {"run_id": "run-raw-invalid", "summary": {}, "paths": {"latest": str(latest), "raw": str(raw_path)}, "status_counts": {"ok_static": 1}}
    snapshot_path = tmp_path / "artifacts" / "state" / "prod" / "last-stable-host-snapshot.json"
    baseline = weekly.build_host_snapshot(
        "prod",
        {"results": [{"asset_id": "a1", "asset_name": "host-a", "asset_ip": "10.0.0.1", "probe_status": "ok_static"}]},
        run_id="baseline-run",
    )
    snapshot_path.parent.mkdir(parents=True)
    snapshot_path.write_text(json.dumps(baseline, ensure_ascii=False), encoding="utf-8")

    monkeypatch.setattr(weekly, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(weekly, "run_detect_subprocess", lambda args, timeout: detect)
    monkeypatch.setattr(weekly, "load_runtime_env", lambda profile, env_file: type("Env", (), {"env_file": "", "loaded_files": []})())
    monkeypatch.setattr(weekly.preflight_check, "validate_config", lambda require_wecom=False, profile="default", env_file="": {"ok": True, "errors": []})
    monkeypatch.setattr(weekly.yuque_markdown_sync, "sync_markdown", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("Yuque sync must not run without raw host results")))
    monkeypatch.setattr(weekly.wecom_notify, "notify", lambda **kwargs: {"status": "sent"})
    monkeypatch.setattr(weekly, "write_workflow_record", lambda record, output_dir: tmp_path / "workflow.json")

    record = weekly.run_workflow(make_args(profile="prod", run_source="weekly_scheduled"))

    assert record["status"] == "failed"
    assert "results" in record["error_message"]
    assert record["host_snapshot_diff"] is None
    assert json.loads(snapshot_path.read_text(encoding="utf-8"))["last_run_id"] == "baseline-run"

def test_weekly_snapshot_diff_fails_closed_when_raw_results_empty(monkeypatch, tmp_path):
    latest = tmp_path / "latest.md"
    raw_path = tmp_path / "raw.json"
    latest.write_text("# report", encoding="utf-8")
    raw_path.write_text('{"results": []}', encoding="utf-8")
    detect = {"run_id": "run-raw-empty", "summary": {}, "paths": {"latest": str(latest), "raw": str(raw_path)}, "status_counts": {}}
    snapshot_path = tmp_path / "artifacts" / "state" / "prod" / "last-stable-host-snapshot.json"
    baseline = weekly.build_host_snapshot(
        "prod",
        {"results": [{"asset_id": "a1", "asset_name": "host-a", "asset_ip": "10.0.0.1", "probe_status": "ok_static"}]},
        run_id="baseline-run",
    )
    snapshot_path.parent.mkdir(parents=True)
    snapshot_path.write_text(json.dumps(baseline, ensure_ascii=False), encoding="utf-8")

    monkeypatch.setattr(weekly, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(weekly, "run_detect_subprocess", lambda args, timeout: detect)
    monkeypatch.setattr(weekly, "load_runtime_env", lambda profile, env_file: type("Env", (), {"env_file": "", "loaded_files": []})())
    monkeypatch.setattr(weekly.preflight_check, "validate_config", lambda require_wecom=False, profile="default", env_file="": {"ok": True, "errors": []})
    monkeypatch.setattr(weekly.yuque_markdown_sync, "sync_markdown", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("Yuque sync must not run without host results")))
    monkeypatch.setattr(weekly.wecom_notify, "notify", lambda **kwargs: {"status": "sent"})
    monkeypatch.setattr(weekly, "write_workflow_record", lambda record, output_dir: tmp_path / "workflow.json")

    record = weekly.run_workflow(make_args(profile="prod", run_source="weekly_scheduled"))

    assert record["status"] == "failed"
    assert "results" in record["error_message"]
    assert record["host_snapshot_diff"] is None
    assert json.loads(snapshot_path.read_text(encoding="utf-8"))["last_run_id"] == "baseline-run"

def test_weekly_snapshot_diff_fails_closed_when_inline_results_empty(monkeypatch, tmp_path):
    latest = tmp_path / "latest.md"
    latest.write_text("# report", encoding="utf-8")
    detect = {"run_id": "run-inline-empty", "summary": {}, "paths": {"latest": str(latest)}, "status_counts": {}, "results": []}

    monkeypatch.setattr(weekly, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(weekly, "run_detect_subprocess", lambda args, timeout: detect)
    monkeypatch.setattr(weekly, "load_runtime_env", lambda profile, env_file: type("Env", (), {"env_file": "", "loaded_files": []})())
    monkeypatch.setattr(weekly.preflight_check, "validate_config", lambda require_wecom=False, profile="default", env_file="": {"ok": True, "errors": []})
    monkeypatch.setattr(weekly.yuque_markdown_sync, "sync_markdown", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("Yuque sync must not run without host results")))
    monkeypatch.setattr(weekly.wecom_notify, "notify", lambda **kwargs: {"status": "sent"})
    monkeypatch.setattr(weekly, "write_workflow_record", lambda record, output_dir: tmp_path / "workflow.json")

    record = weekly.run_workflow(make_args(profile="prod", run_source="weekly_scheduled"))

    assert record["status"] == "failed"
    assert "results" in record["error_message"]
    assert record["host_snapshot_diff"] is None

def test_weekly_snapshot_diff_fails_closed_when_raw_results_have_no_host_fields(monkeypatch, tmp_path):
    latest = tmp_path / "latest.md"
    raw_path = tmp_path / "raw.json"
    latest.write_text("# report", encoding="utf-8")
    raw_path.write_text('{"results": [null, {}, {"probe_status": "ok_static", "remark": "identity missing"}]}', encoding="utf-8")
    detect = {"run_id": "run-raw-no-host-fields", "summary": {}, "paths": {"latest": str(latest), "raw": str(raw_path)}, "status_counts": {}}

    monkeypatch.setattr(weekly, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(weekly, "run_detect_subprocess", lambda args, timeout: detect)
    monkeypatch.setattr(weekly, "load_runtime_env", lambda profile, env_file: type("Env", (), {"env_file": "", "loaded_files": []})())
    monkeypatch.setattr(weekly.preflight_check, "validate_config", lambda require_wecom=False, profile="default", env_file="": {"ok": True, "errors": []})
    monkeypatch.setattr(weekly.yuque_markdown_sync, "sync_markdown", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("Yuque sync must not run without host results")))
    monkeypatch.setattr(weekly.wecom_notify, "notify", lambda **kwargs: {"status": "sent"})
    monkeypatch.setattr(weekly, "write_workflow_record", lambda record, output_dir: tmp_path / "workflow.json")

    record = weekly.run_workflow(make_args(profile="prod", run_source="weekly_scheduled"))

    assert record["status"] == "failed"
    assert "results" in record["error_message"]
    assert record["host_snapshot_diff"] is None

def test_yuque_failure_does_not_block_stable_snapshot_update_for_successful_weekly_run(monkeypatch, tmp_path):
    latest = tmp_path / "latest.md"
    latest.write_text("# report", encoding="utf-8")
    detect = {
        "run_id": "run-yuque-fail",
        "summary": {},
        "paths": {"latest": str(latest)},
        "status_counts": {"ok_static": 1},
        "results": [{"asset_id": "a1", "asset_name": "host-a", "asset_ip": "10.0.0.1", "probe_status": "ok_static"}],
    }
    monkeypatch.setattr(weekly, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(weekly, "run_detect_subprocess", lambda args, timeout: detect)
    monkeypatch.setattr(weekly, "load_runtime_env", lambda profile, env_file: type("Env", (), {"env_file": "", "loaded_files": []})())
    monkeypatch.setattr(weekly.preflight_check, "validate_config", lambda require_wecom=False, profile="default", env_file="": {"ok": True, "errors": []})
    monkeypatch.setattr(weekly.yuque_markdown_sync, "sync_markdown", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("yuque down")))
    monkeypatch.setattr(weekly.wecom_notify, "notify", lambda **kwargs: {"status": "sent"})
    monkeypatch.setattr(weekly, "write_workflow_record", lambda record, output_dir: tmp_path / "workflow.json")

    record = weekly.run_workflow(make_args(profile="prod", run_source="weekly_scheduled"))

    assert record["status"] == "success"
    assert record["yuque"]["status"] == "failed"
    assert "yuque down" in record["yuque"]["error"]
    snapshot_path = tmp_path / "artifacts" / "state" / "prod" / "last-stable-host-snapshot.json"
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    assert snapshot["last_run_id"] == "run-yuque-fail"


def test_run_cleanup_steps_default_is_fail_closed(monkeypatch):
    calls = []
    monkeypatch.setattr(weekly.host_cleanup, "evaluate_cleanup", lambda *args, **kwargs: calls.append("evaluate"))
    monkeypatch.setattr(weekly.host_cleanup, "apply_cleanup_plan", lambda *args, **kwargs: calls.append("apply"))

    result = weekly.run_cleanup_steps(make_args())

    assert result == {"status": "skipped", "reason": "cleanup not requested"}
    assert calls == []
