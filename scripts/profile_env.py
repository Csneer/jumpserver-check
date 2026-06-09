#!/usr/bin/env python3
"""Shared profile-aware environment loading."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROFILE = "default"
PROFILE_ENV_DIR = PROJECT_ROOT / "configs" / "profiles"


@dataclass(frozen=True)
class ProfileEnv:
    profile: str
    env_file: str
    loaded_files: list[str]
    values: dict[str, str]
    sources: dict[str, str]


def normalize_profile(profile: str | None) -> str:
    value = (profile or DEFAULT_PROFILE).strip() or DEFAULT_PROFILE
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", value):
        raise ValueError("profile 只能包含字母、数字、点、下划线和短横线")
    return value


def project_env_candidates() -> list[Path]:
    return [Path.cwd() / ".env", PROJECT_ROOT / ".env"]


def default_profile_env(profile: str) -> Path:
    return PROFILE_ENV_DIR / f"{profile}.env"


def resolve_env_file(profile: str, env_file: str | None = None) -> Path:
    if env_file:
        return Path(env_file).expanduser()
    return default_profile_env(profile)


def parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key:
            values[key] = value.strip().strip('"').strip("'")
    return values


def load_profile_env(profile: str | None = None, env_file: str | None = None, *, override: bool = True) -> ProfileEnv:
    normalized = normalize_profile(profile)
    profile_path = resolve_env_file(normalized, env_file)
    values = dict(os.environ)
    sources = {key: "process" for key in values}
    loaded_files: list[str] = []
    loaded_keys: set[str] = set()
    seen: set[Path] = set()

    candidates = [*project_env_candidates(), profile_path]
    for path in candidates:
        resolved = path.resolve()
        if resolved in seen or not path.exists():
            continue
        seen.add(resolved)
        file_values = parse_env_file(path)
        source = "profile" if resolved == profile_path.resolve() else "project"
        loaded_files.append(str(path))
        for key, value in file_values.items():
            values[key] = value
            sources[key] = source
            loaded_keys.add(key)

    if override:
        for key in loaded_keys:
            os.environ[key] = values[key]

    return ProfileEnv(
        profile=normalized,
        env_file=str(profile_path),
        loaded_files=loaded_files,
        values=values,
        sources=sources,
    )


def profile_path(base: str, profile: str) -> str:
    normalized = normalize_profile(profile)
    if normalized == DEFAULT_PROFILE:
        return base
    return str(Path(base) / normalized)


def profile_default_path(env: ProfileEnv, key: str, fallback: str) -> str:
    base = env.values.get(key) or fallback
    explicit_profile_value = bool(env.values.get(key)) and env.sources.get(key) == "profile"
    if env.profile == DEFAULT_PROFILE or explicit_profile_value:
        return base
    return profile_path(base, env.profile)


def profile_default_name(env: ProfileEnv, key: str, fallback: str, *, slug: bool = False) -> str:
    value = env.values.get(key) or fallback
    explicit_profile_value = bool(env.values.get(key)) and env.sources.get(key) == "profile"
    if env.profile == DEFAULT_PROFILE or explicit_profile_value:
        return value
    separator = "-" if slug else " - "
    return f"{value}{separator}{env.profile}"


@dataclass(frozen=True)
class RuntimeContext:
    """Single authority for profile-aware runtime paths/defaults.

    The facade and orchestration scripts should derive profile/env/path/default
    values from this context instead of recomputing profile-specific paths in
    multiple entrypoints.
    """

    env: ProfileEnv
    project_root: Path
    output_dir: Path
    raw_output_dir: Path
    state_dir: Path
    workflow_dir: Path
    cleanup_dir: Path
    resume_state: Path
    yuque_title: str
    yuque_slug: str
    notify_title: str

    @property
    def profile(self) -> str:
        return self.env.profile

    @property
    def env_file(self) -> str:
        return self.env.env_file

    @property
    def loaded_files(self) -> list[str]:
        return self.env.loaded_files


def runtime_path(env: ProfileEnv, key: str, fallback: str) -> Path:
    return PROJECT_ROOT / profile_default_path(env, key, fallback)


def build_runtime_context(profile: str | None = None, env_file: str | None = None) -> RuntimeContext:
    env = load_profile_env(profile, env_file)
    state_dir = runtime_path(env, "CHECK_STATE_DIR", "artifacts/state")
    return RuntimeContext(
        env=env,
        project_root=PROJECT_ROOT,
        output_dir=runtime_path(env, "CHECK_OUTPUT_DIR", "reports/yuque"),
        raw_output_dir=runtime_path(env, "CHECK_RAW_OUTPUT_DIR", "artifacts/raw"),
        state_dir=state_dir,
        workflow_dir=runtime_path(env, "CHECK_WORKFLOW_DIR", "artifacts/workflow"),
        cleanup_dir=runtime_path(env, "CHECK_CLEANUP_DIR", "artifacts/cleanup"),
        resume_state=state_dir / "jms-host-ip-check-inflight.json",
        yuque_title=profile_default_name(env, "CHECK_YUQUE_TITLE", "JumpServer 主机探测与 IP 配置检测报告"),
        yuque_slug=profile_default_name(env, "CHECK_YUQUE_SLUG", "jumpserver-host-ip-check", slug=True),
        notify_title=profile_default_name(env, "CHECK_NOTIFY_TITLE", "JumpServer 每周主机巡检"),
    )


def display_path(path: Path, root: Path | None = None) -> str:
    """Return a CLI-friendly path while preserving absolute custom paths."""
    base = root or PROJECT_ROOT
    try:
        return str(path.relative_to(base))
    except ValueError:
        return str(path)
