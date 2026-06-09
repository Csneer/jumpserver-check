from __future__ import annotations

import argparse
import ast
from pathlib import Path

import pytest

from scripts import profile_env, run_multi_check, run_weekly_check


def test_runtime_context_centralizes_profile_defaults_and_paths(monkeypatch, tmp_path: Path):
    """RuntimeContext is the single authority for profile env/default/path metadata."""
    runtime = pytest.importorskip("scripts.runtime_context")

    project_env = tmp_path / ".env"
    project_env.write_text(
        "CHECK_OUTPUT_DIR=reports/base\n"
        "CHECK_RAW_OUTPUT_DIR=artifacts/raw-base\n"
        "CHECK_YUQUE_TITLE=JumpServer 巡检\n"
        "CHECK_YUQUE_SLUG=jumpserver-check\n"
        "CHECK_WAIT_TIMEOUT=333\n",
        encoding="utf-8",
    )
    profile_file = tmp_path / "profiles" / "prod.env"
    profile_file.parent.mkdir()
    profile_file.write_text("CHECK_POLL_INTERVAL=44\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    context = runtime.RuntimeContext.from_profile("prod", env_file=str(profile_file), run_source="weekly_scheduled")

    assert context.profile == "prod"
    assert context.env.values["CHECK_OUTPUT_DIR"] == "reports/base"
    assert context.output_dir == Path("reports/base") / "prod"
    assert context.raw_output_dir == Path("artifacts/raw-base") / "prod"
    assert context.state_dir == Path("artifacts/state") / "prod"
    assert context.workflow_dir == Path("artifacts/workflows") / "prod"
    assert context.cleanup_state_dir == Path("artifacts/state") / "prod"
    assert context.cleanup_output_dir == Path("artifacts/cleanup") / "prod"
    assert context.resume_state == Path("artifacts/state") / "prod" / "jms-host-ip-check-inflight.json"
    assert context.wait_timeout == 333
    assert context.poll_interval == 44
    assert context.yuque_title == "JumpServer 巡检 - prod"
    assert context.yuque_slug == "jumpserver-check-prod"
    assert context.run_source == "weekly_scheduled"


def test_runtime_context_keeps_explicit_profile_paths_unmodified(tmp_path: Path, monkeypatch):
    """Profile-specific env values are explicit and must not receive another profile suffix."""
    runtime = pytest.importorskip("scripts.runtime_context")

    profile_file = tmp_path / "prod.env"
    profile_file.write_text(
        "CHECK_OUTPUT_DIR=/srv/jms/prod/reports\n"
        "CHECK_RAW_OUTPUT_DIR=/srv/jms/prod/raw\n"
        "CHECK_YUQUE_TITLE=Prod 巡检\n"
        "CHECK_YUQUE_SLUG=prod-check\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    context = runtime.RuntimeContext.from_profile("prod", env_file=str(profile_file))

    assert context.output_dir == Path("/srv/jms/prod/reports")
    assert context.raw_output_dir == Path("/srv/jms/prod/raw")
    assert context.yuque_title == "Prod 巡检"
    assert context.yuque_slug == "prod-check"


def test_unified_facade_preflight_and_weekly_dispatch_to_services(monkeypatch):
    """Unified facade parses/dispatches only; service modules keep business logic."""
    facade = pytest.importorskip("scripts.jumpserver_check")

    calls: list[tuple[str, object]] = []

    def fake_preflight(*, require_wecom: bool, profile: str, env_file: str):
        calls.append(("preflight", (require_wecom, profile, env_file)))
        return {"ok": True, "checked": {"profile": profile}}

    def fake_weekly(args: argparse.Namespace):
        calls.append(("weekly", args))
        return {"status": "success", "profile": args.profile}

    monkeypatch.setattr(facade.preflight_check, "validate_config", fake_preflight)
    monkeypatch.setattr(facade.run_weekly_check, "run_workflow", fake_weekly)

    assert facade.main(["preflight", "--profile", "prod", "--env-file", "prod.env", "--require-wecom", "--json"]) == 0
    assert calls[0] == ("preflight", (True, "prod", "prod.env"))

    assert facade.main(["weekly", "--profile", "prod", "--dry-run-yuque", "--dry-run-notify", "--max-assets", "1"]) == 0
    weekly_args = calls[1][1]
    assert weekly_args.profile == "prod"
    assert weekly_args.dry_run_yuque is True
    assert weekly_args.dry_run_notify is True
    assert weekly_args.max_assets == 1
    assert calls[1][0] == "weekly"


def test_facade_help_includes_legacy_command_mapping(capsys):
    facade = pytest.importorskip("scripts.jumpserver_check")

    assert facade.main(["--help"]) == 0
    output = capsys.readouterr().out

    assert "preflight" in output
    assert "detect" in output
    assert "weekly" in output
    assert "multi" in output
    assert "cleanup" in output
    assert "admin" in output
    assert "notify" in output
    assert "yuque" in output


def test_unified_facade_remains_thin_dispatch_layer():
    """The new facade must dispatch; it must not copy detect/cleanup/sync business rules."""
    facade_path = Path("scripts/jumpserver_check.py")
    if not facade_path.exists():
        pytest.skip("unified facade not implemented yet")

    source = facade_path.read_text(encoding="utf-8")
    forbidden = [
        "evaluate_cleanup(",
        "apply_cleanup_plan(",
        "sync_markdown(",
        "notify_cleanup_delete_result(",
        "run_detect(",
        "check_tcp_reachability(",
    ]
    for text in forbidden:
        assert text not in source

    tree = ast.parse(source)
    assert any(
        (isinstance(node, ast.Assign) and any(getattr(target, "id", "") == "COMMANDS" for target in node.targets))
        or (isinstance(node, ast.AnnAssign) and getattr(node.target, "id", "") == "COMMANDS")
        for node in tree.body
    )


def test_weekly_cleanup_flags_remain_explicit_fail_closed(monkeypatch, tmp_path: Path):
    """Weekly defaults are read-only: cleanup evaluate/apply are never called without explicit flags."""
    monkeypatch.setattr(run_weekly_check.preflight_check, "validate_config", lambda **kwargs: {"ok": True})
    monkeypatch.setattr(
        run_weekly_check,
        "run_detect_subprocess",
        lambda args, timeout_seconds: {
            "status": "success",
            "summary": {"total_assets": 0},
            "paths": {"latest": str(tmp_path / "report.md"), "report": str(tmp_path / "report.md"), "raw": str(tmp_path / "raw.json")},
            "duration_seconds": 0.1,
        },
    )
    monkeypatch.setattr(run_weekly_check.yuque_markdown_sync, "sync_markdown", lambda *args, **kwargs: {"status": "skipped"})
    notify_calls: list[dict[str, object]] = []
    monkeypatch.setattr(run_weekly_check.wecom_notify, "notify", lambda **kwargs: notify_calls.append(kwargs) or {"status": "skipped"})
    monkeypatch.setattr(run_weekly_check.host_cleanup, "notify_cleanup_delete_result", lambda *args, **kwargs: {"status": "skipped"})
    monkeypatch.setattr(run_weekly_check, "write_workflow_record", lambda record, output_dir: tmp_path / "workflow.json")

    cleanup_calls: list[str] = []
    monkeypatch.setattr(run_weekly_check.host_cleanup, "evaluate_cleanup", lambda **kwargs: cleanup_calls.append("evaluate") or {})
    monkeypatch.setattr(run_weekly_check.host_cleanup, "apply_cleanup_plan", lambda **kwargs: cleanup_calls.append("apply") or {})

    args = argparse.Namespace(
        profile="prod",
        env_file="",
        no_proxy=False,
        wait_timeout=1,
        poll_interval=1,
        output_dir=str(tmp_path / "reports" / "prod"),
        raw_output_dir=str(tmp_path / "raw" / "prod"),
        resume_state=str(tmp_path / "state" / "prod" / "resume.json"),
        retention_count=1,
        run_id="",
        run_source="manual",
        cleanup_evidence_eligible=False,
        ip_reachability_check=True,
        ip_ping_count=1,
        ip_ping_timeout=1,
        ip_ping_workers=1,
        tcp_reachability_check=False,
        tcp_reachability_ports="22",
        tcp_reachability_timeout=1,
        tcp_reachability_workers=1,
        query="",
        max_assets=1,
        yuque_title="title",
        yuque_slug="slug",
        toc_uuid="",
        sibling_url="",
        notify_title="notify",
        dry_run_yuque=True,
        dry_run_notify=True,
        cleanup_evaluate=False,
        cleanup_apply_confirmed=False,
        cleanup_dry_run=True,
        cleanup_allow_delete=False,
        require_wecom=False,
        no_resume=True,
    )

    result = run_weekly_check.run_workflow(args)

    assert result["status"] == "success"
    assert cleanup_calls == []
    assert result["cleanup"] == {"status": "skipped", "reason": "cleanup not requested"}
    assert notify_calls
    assert "cleanup" not in __import__("json").loads(str(notify_calls[0]["summary_json"]))


def test_multi_profile_command_uses_isolated_state_and_raw_paths():
    args = argparse.Namespace(
        no_proxy=False,
        require_wecom=False,
        dry_run_yuque=True,
        dry_run_notify=True,
        cleanup_evaluate=False,
        cleanup_apply_confirmed=False,
        cleanup_dry_run=True,
        cleanup_allow_delete=False,
        run_source="weekly_scheduled",
        cleanup_evidence_eligible=True,
        ip_reachability_check=True,
        ip_ping_count=1,
        ip_ping_timeout=1,
        ip_ping_workers=2,
        no_resume=False,
        wait_timeout=9,
        poll_interval=3,
    )

    prod = run_multi_check.build_profile_command(args, "prod")
    staging = run_multi_check.build_profile_command(args, "staging")

    assert prod != staging
    assert prod[prod.index("--profile") + 1] == "prod"
    assert staging[staging.index("--profile") + 1] == "staging"
    assert "--cleanup-apply-confirmed" not in prod
    assert "--cleanup-allow-delete" not in prod

    prod_env = profile_env.load_profile_env("prod", override=False)
    staging_env = profile_env.load_profile_env("staging", override=False)
    assert profile_env.profile_default_path(prod_env, "CHECK_RAW_OUTPUT_DIR", "artifacts/raw").endswith("prod")
    assert profile_env.profile_default_path(staging_env, "CHECK_RAW_OUTPUT_DIR", "artifacts/raw").endswith("staging")
    assert profile_env.profile_path("artifacts/state", "prod") != profile_env.profile_path("artifacts/state", "staging")
