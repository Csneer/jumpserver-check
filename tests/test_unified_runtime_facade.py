from pathlib import Path

from jumpserver_check import cli
from jumpserver_check.runtime import RuntimeContext
from scripts import host_cleanup, profile_env, run_multi_check as multi, run_weekly_check as weekly


def test_runtime_context_profile_defaults_are_single_authority(monkeypatch, tmp_path):
    profile_dir = tmp_path / "configs" / "profiles"
    profile_dir.mkdir(parents=True)
    (profile_dir / "prod.env").write_text(
        "CHECK_WAIT_TIMEOUT=99\nCHECK_OUTPUT_DIR=custom/reports\nCHECK_YUQUE_SLUG=custom-slug\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(profile_env, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(profile_env, "PROFILE_ENV_DIR", profile_dir)

    ctx = RuntimeContext.for_profile("prod")

    assert ctx.profile == "prod"
    assert ctx.env.values["CHECK_WAIT_TIMEOUT"] == "99"
    assert ctx.output_dir == Path("custom/reports")
    assert ctx.raw_output_dir == Path("artifacts/raw/prod")
    assert ctx.resume_state == tmp_path / "artifacts/state/prod/jms-host-ip-check-inflight.json"
    assert ctx.workflow_dir == tmp_path / "artifacts/workflow/prod"
    assert ctx.cleanup_state_dir == tmp_path / "artifacts/state/prod/cleanup"
    assert ctx.cleanup_output_dir == tmp_path / "artifacts/cleanup/prod"
    assert ctx.yuque_slug == "custom-slug"
    assert ctx.yuque_title.endswith(" - prod")


def test_weekly_parser_uses_runtime_context_defaults(monkeypatch, tmp_path):
    profile_dir = tmp_path / "configs" / "profiles"
    profile_dir.mkdir(parents=True)
    (profile_dir / "prod.env").write_text("CHECK_RAW_OUTPUT_DIR=raw-prod\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(profile_env, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(profile_env, "PROFILE_ENV_DIR", profile_dir)
    monkeypatch.setattr(weekly, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr("sys.argv", ["run_weekly_check.py", "--profile", "prod"])

    args = weekly.parse_args()

    assert args.profile == "prod"
    assert args.raw_output_dir == "raw-prod"
    assert Path(args.output_dir) == Path("reports/yuque/prod")
    assert Path(args.resume_state) == tmp_path / "artifacts/state/prod/jms-host-ip-check-inflight.json"


def test_cleanup_default_is_fail_closed_without_flags(monkeypatch):
    called = False

    def should_not_evaluate(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("cleanup evaluation must be explicit")

    monkeypatch.setattr(weekly.host_cleanup, "evaluate_cleanup", should_not_evaluate)
    args = type("Args", (), {"cleanup_evaluate": False, "cleanup_apply_confirmed": False})()

    assert weekly.run_cleanup_steps(args, detect_result=None) == {"status": "skipped", "reason": "cleanup not requested"}
    assert called is False


def test_multi_profile_command_paths_are_isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(profile_env, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(weekly, "PROJECT_ROOT", tmp_path)
    args = multi.parse_args.__globals__["argparse"].Namespace(
        no_proxy=False,
        require_wecom=False,
        dry_run_yuque=True,
        dry_run_notify=True,
        cleanup_evaluate=False,
        cleanup_apply_confirmed=False,
        cleanup_dry_run=False,
        cleanup_allow_delete=False,
        run_source="",
        cleanup_evidence_eligible=False,
        no_resume=False,
        wait_timeout=None,
        poll_interval=None,
        ip_reachability_check=True,
        ip_ping_count=1,
        ip_ping_timeout=1,
        ip_ping_workers=32,
    )

    prod = multi.build_profile_command(args, "prod")
    pre = multi.build_profile_command(args, "pre")

    assert prod[prod.index("--profile") + 1] == "prod"
    assert pre[pre.index("--profile") + 1] == "pre"
    assert "prod" not in " ".join(pre)
    assert "pre" not in " ".join(prod)


def test_unified_facade_maps_commands_to_legacy_entrypoints(monkeypatch):
    calls = []

    def fake_run(module_name, argv):
        calls.append((module_name, argv))
        return 0

    monkeypatch.setattr(cli, "run_legacy_module", fake_run)

    assert cli.main(["preflight", "--json"]) == 0
    assert cli.main(["detect", "--no-proxy", "list-assets", "--max-assets", "1"]) == 0
    assert cli.main(["weekly", "--dry-run-yuque", "--dry-run-notify"]) == 0
    assert cli.main(["multi", "--profiles", "prod,test"]) == 0
    assert cli.main(["cleanup", "evaluate", "--profile", "prod"]) == 0
    assert cli.main(["admin", "serve", "--profile", "prod"]) == 0

    assert calls == [
        ("scripts.preflight_check", ["--json"]),
        ("scripts.jms_host_ip_check", ["--no-proxy", "list-assets", "--max-assets", "1"]),
        ("scripts.run_weekly_check", ["--dry-run-yuque", "--dry-run-notify"]),
        ("scripts.run_multi_check", ["--profiles", "prod,test"]),
        ("scripts.host_cleanup", ["evaluate", "--profile", "prod"]),
        ("scripts.cleanup_admin_server", ["--profile", "prod"]),
    ]
