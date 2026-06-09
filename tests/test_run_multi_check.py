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



def test_build_profile_command_passes_ip_reachability_flags():
    args = multi.parse_args.__globals__['argparse'].Namespace(
        no_proxy=True, require_wecom=True, dry_run_yuque=False, dry_run_notify=False, cleanup_evaluate=False, cleanup_apply_confirmed=False,
        cleanup_dry_run=False, cleanup_allow_delete=False, run_source='', cleanup_evidence_eligible=False, no_resume=False, wait_timeout=None,
        poll_interval=None, ip_reachability_check=True, ip_ping_count=1, ip_ping_timeout=1, ip_ping_workers=32
    )
    cmd = multi.build_profile_command(args, 'local')
    assert '--ip-reachability-check' in cmd
    assert '--ip-ping-count' in cmd and '1' in cmd
    assert '--ip-ping-timeout' in cmd and '1' in cmd
    assert '--ip-ping-workers' in cmd and '32' in cmd


def test_build_profile_command_passes_tcp_reachability_flags():
    args = multi.parse_args.__globals__['argparse'].Namespace(
        no_proxy=False, require_wecom=False, dry_run_yuque=False, dry_run_notify=False,
        cleanup_evaluate=False, cleanup_apply_confirmed=False, cleanup_dry_run=False, cleanup_allow_delete=False,
        run_source='', cleanup_evidence_eligible=False, ip_reachability_check=False, ip_ping_count=1,
        ip_ping_timeout=1, ip_ping_workers=32, tcp_reachability_check=True, tcp_reachability_ports='22,2222',
        tcp_reachability_timeout=2, tcp_reachability_workers=9, no_resume=False, wait_timeout=None, poll_interval=None,
    )

    cmd = multi.build_profile_command(args, 'local')

    assert '--tcp-reachability-check' in cmd
    assert cmd[cmd.index('--tcp-reachability-ports') + 1] == '22,2222'
    assert cmd[cmd.index('--tcp-reachability-timeout') + 1] == '2'
    assert cmd[cmd.index('--tcp-reachability-workers') + 1] == '9'
