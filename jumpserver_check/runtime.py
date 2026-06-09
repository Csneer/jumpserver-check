"""Profile-aware runtime context for JumpServer check commands.

This module is the single authority for profile/env/path/default/run metadata.
Legacy scripts may keep their business logic, but their defaults should derive from
``RuntimeContext`` instead of reimplementing profile path rules.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from scripts import host_cleanup, profile_env

DEFAULT_YUQUE_TITLE = "JumpServer 主机探测与 IP 配置检测报告"
DEFAULT_YUQUE_SLUG = "jumpserver-host-ip-check"
DEFAULT_NOTIFY_TITLE = "JumpServer 每周主机巡检"
DEFAULT_RESUME_FILENAME = "jms-host-ip-check-inflight.json"


def _env_bool(values: dict[str, str], name: str, default: bool) -> bool:
    value = values.get(name, "").strip().lower()
    if not value:
        return default
    return value in {"1", "true", "yes"}


def _env_int(values: dict[str, str], name: str, default: int) -> int:
    value = values.get(name, "").strip()
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        return default


@dataclass(frozen=True)
class RuntimeContext:
    profile: str
    env_file: str
    env: profile_env.ProfileEnv
    project_root: Path
    output_dir: Path
    raw_output_dir: Path
    state_dir: Path
    resume_state: Path
    workflow_dir: Path
    cleanup_state_dir: Path
    cleanup_output_dir: Path
    yuque_title: str
    yuque_slug: str
    notify_title: str
    wait_timeout: int
    poll_interval: int
    retention_count: int
    run_source: str
    ip_reachability_check: bool
    ip_ping_count: int
    ip_ping_timeout: int
    ip_ping_workers: int
    tcp_reachability_check: bool
    tcp_reachability_ports: str
    tcp_reachability_timeout: int
    tcp_reachability_workers: int

    @classmethod
    def for_profile(
        cls,
        profile: str | None = None,
        env_file: str | None = None,
        *,
        override_env: bool = False,
    ) -> "RuntimeContext":
        env = profile_env.load_profile_env(profile, env_file, override=override_env)
        project_root = profile_env.PROJECT_ROOT
        state_dir = project_root / profile_env.profile_path("artifacts/state", env.profile)
        return cls(
            profile=env.profile,
            env_file=env.env_file,
            env=env,
            project_root=project_root,
            output_dir=Path(profile_env.profile_default_path(env, "CHECK_OUTPUT_DIR", "reports/yuque")),
            raw_output_dir=Path(profile_env.profile_default_path(env, "CHECK_RAW_OUTPUT_DIR", "artifacts/raw")),
            state_dir=state_dir,
            resume_state=state_dir / DEFAULT_RESUME_FILENAME,
            workflow_dir=project_root / profile_env.profile_path("artifacts/workflow", env.profile),
            cleanup_state_dir=host_cleanup.cleanup_profile_state_dir("cleanup", state_dir),
            cleanup_output_dir=host_cleanup.cleanup_output_dir(env.profile, project_root / "artifacts" / "cleanup"),
            yuque_title=profile_env.profile_default_name(env, "CHECK_YUQUE_TITLE", DEFAULT_YUQUE_TITLE),
            yuque_slug=profile_env.profile_default_name(env, "CHECK_YUQUE_SLUG", DEFAULT_YUQUE_SLUG, slug=True),
            notify_title=profile_env.profile_default_name(env, "CHECK_NOTIFY_TITLE", DEFAULT_NOTIFY_TITLE),
            wait_timeout=_env_int(env.values, "CHECK_WAIT_TIMEOUT", 1200),
            poll_interval=_env_int(env.values, "CHECK_POLL_INTERVAL", 30),
            retention_count=_env_int(env.values, "CHECK_RETENTION_COUNT", 12),
            run_source=env.values.get("CHECK_RUN_SOURCE", "manual"),
            ip_reachability_check=_env_bool(env.values, "CHECK_IP_REACHABILITY", True),
            ip_ping_count=_env_int(env.values, "CHECK_IP_PING_COUNT", 1),
            ip_ping_timeout=_env_int(env.values, "CHECK_IP_PING_TIMEOUT", 1),
            ip_ping_workers=_env_int(env.values, "CHECK_IP_PING_WORKERS", 32),
            tcp_reachability_check=_env_bool(env.values, "CHECK_TCP_REACHABILITY", False),
            tcp_reachability_ports=env.values.get("CHECK_TCP_REACHABILITY_PORTS", "22"),
            tcp_reachability_timeout=_env_int(env.values, "CHECK_TCP_REACHABILITY_TIMEOUT", 1),
            tcp_reachability_workers=_env_int(env.values, "CHECK_TCP_REACHABILITY_WORKERS", 32),
        )

    def weekly_defaults(self) -> dict[str, object]:
        return {
            "profile": self.profile,
            "env_file": self.env_file,
            "wait_timeout": self.wait_timeout,
            "poll_interval": self.poll_interval,
            "output_dir": str(self.output_dir),
            "raw_output_dir": str(self.raw_output_dir),
            "resume_state": str(self.resume_state),
            "retention_count": self.retention_count,
            "run_source": self.run_source,
            "ip_reachability_check": self.ip_reachability_check,
            "ip_ping_count": self.ip_ping_count,
            "ip_ping_timeout": self.ip_ping_timeout,
            "ip_ping_workers": self.ip_ping_workers,
            "tcp_reachability_check": self.tcp_reachability_check,
            "tcp_reachability_ports": self.tcp_reachability_ports,
            "tcp_reachability_timeout": self.tcp_reachability_timeout,
            "tcp_reachability_workers": self.tcp_reachability_workers,
            "yuque_title": self.yuque_title,
            "yuque_slug": self.yuque_slug,
            "notify_title": self.notify_title,
        }

    def cleanup_defaults(self) -> dict[str, Path]:
        return {
            "raw_dir": self.project_root / profile_env.profile_path("artifacts/raw", self.profile),
            "state_dir": self.cleanup_state_dir,
            "output_dir": self.cleanup_output_dir,
        }
