from scripts import run_multi_check as multi


def test_parse_profiles_normalizes_names():
    assert multi.parse_profiles("prod,test") == ["prod", "test"]


def test_build_profile_command_passes_supported_flags():
    args = type(
        "Args",
        (),
        {
            "no_proxy": True,
            "require_wecom": True,
            "dry_run_yuque": True,
            "dry_run_notify": True,
            "no_resume": True,
            "wait_timeout": 60,
            "poll_interval": 10,
        },
    )()

    command = multi.build_profile_command(args, "prod")

    assert "--profile" in command
    assert command[command.index("--profile") + 1] == "prod"
    assert "--no-proxy" in command
    assert "--require-wecom" in command
    assert command[command.index("--wait-timeout") + 1] == "60"
    assert command[command.index("--poll-interval") + 1] == "10"


def test_run_multi_continues_when_one_profile_fails(monkeypatch):
    calls = []

    def fake_run_profile(args, profile):
        calls.append(profile)
        return {
            "profile": profile,
            "returncode": 1 if profile == "test" else 0,
            "status": "failed" if profile == "test" else "success",
            "workflow_record": "",
        }

    monkeypatch.setattr(multi, "run_profile", fake_run_profile)
    args = type(
        "Args",
        (),
        {
            "profiles": "prod,test,pre",
            "parallel": 3,
        },
    )()

    result = multi.run_multi(args)

    assert calls == ["prod", "test", "pre"]
    assert result["status"] == "failed"
    assert [item["profile"] for item in result["profiles"]] == ["prod", "test", "pre"]


def test_build_profile_command_passes_cleanup_flags():
    args = type(
        "Args",
        (),
        {
            "no_proxy": False,
            "require_wecom": False,
            "dry_run_yuque": False,
            "dry_run_notify": False,
            "no_resume": False,
            "wait_timeout": None,
            "poll_interval": None,
            "cleanup_evaluate": True,
            "cleanup_apply_confirmed": True,
            "cleanup_dry_run": True,
            "cleanup_allow_delete": True,
            "run_source": "weekly_scheduled",
            "cleanup_evidence_eligible": True,
        },
    )()

    command = multi.build_profile_command(args, "local")

    assert "--cleanup-evaluate" in command
    assert "--cleanup-apply-confirmed" in command
    assert "--cleanup-dry-run" in command
    assert "--cleanup-allow-delete" in command
    assert command[command.index("--run-source") + 1] == "weekly_scheduled"
    assert "--cleanup-evidence-eligible" in command
