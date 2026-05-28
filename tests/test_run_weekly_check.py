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
