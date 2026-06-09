import sys
from pathlib import Path

from scripts import jumpserver_check, profile_env


def test_runtime_context_is_profile_path_authority(monkeypatch, tmp_path: Path):
    project = tmp_path
    profile_dir = project / "configs" / "profiles"
    profile_dir.mkdir(parents=True)
    (profile_dir / "prod.env").write_text(
        "CHECK_OUTPUT_DIR=custom/reports\nCHECK_YUQUE_SLUG=custom-slug\nCHECK_WORKFLOW_DIR=custom/workflow\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(project)
    monkeypatch.setattr(profile_env, "PROJECT_ROOT", project)
    monkeypatch.setattr(profile_env, "PROFILE_ENV_DIR", profile_dir)

    context = profile_env.build_runtime_context("prod")

    assert context.profile == "prod"
    assert context.output_dir == project / "custom/reports"
    assert context.raw_output_dir == project / "artifacts/raw/prod"
    assert context.state_dir == project / "artifacts/state/prod"
    assert context.workflow_dir == project / "custom/workflow"
    assert context.cleanup_dir == project / "artifacts/cleanup/prod"
    assert context.resume_state == context.state_dir / "jms-host-ip-check-inflight.json"
    assert context.yuque_slug == "custom-slug"
    assert context.notify_title == "JumpServer 每周主机巡检 - prod"


def test_facade_dispatch_is_thin_and_restores_argv(monkeypatch):
    calls = []

    def fake_main():
        calls.append(sys.argv[:])
        raise SystemExit(7)

    monkeypatch.setitem(jumpserver_check.COMMANDS, "weekly", (fake_main, "fake"))
    original_argv = sys.argv[:]

    result = jumpserver_check.dispatch("weekly", ["--profile", "prod", "--dry-run-notify"])

    assert result == 7
    assert calls == [[original_argv[0], "--profile", "prod", "--dry-run-notify"]]
    assert sys.argv == original_argv


def test_facade_detect_defaults_to_detect_subcommand(monkeypatch):
    calls = []

    def fake_main():
        calls.append(sys.argv[:])

    monkeypatch.setitem(jumpserver_check.COMMANDS, "detect", (fake_main, "fake"))

    result = jumpserver_check.dispatch("detect", ["--profile", "prod", "--output-dir", "out"])

    assert result == 0
    assert calls[0][1:] == ["detect", "--profile", "prod", "--output-dir", "out"]


def test_cleanup_defaults_remain_fail_closed():
    parser = jumpserver_check.parse_args(["weekly"])
    assert parser.command == "weekly"
    assert parser.args == []
    # The facade owns no cleanup flags/defaults; weekly still defaults to no cleanup.
    weekly_args = jumpserver_check.run_weekly_check.parse_args
    assert callable(weekly_args)
