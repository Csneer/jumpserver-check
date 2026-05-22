import os
from pathlib import Path

from scripts import profile_env


def test_load_profile_env_overrides_project_env(monkeypatch, tmp_path: Path):
    project = tmp_path / ".env"
    profile_dir = tmp_path / "configs" / "profiles"
    profile_dir.mkdir(parents=True)
    profile = profile_dir / "prod.env"
    project.write_text("JMS_URL=https://shared\nCHECK_WAIT_TIMEOUT=1200\n", encoding="utf-8")
    profile.write_text("JMS_URL=https://prod\nYUQUE_REPO_NAMESPACE=prod/repo\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(profile_env, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(profile_env, "PROFILE_ENV_DIR", profile_dir)
    monkeypatch.setenv("JMS_URL", "https://process")

    env = profile_env.load_profile_env("prod")

    assert env.values["JMS_URL"] == "https://prod"
    assert os.environ["JMS_URL"] == "https://prod"
    assert env.values["CHECK_WAIT_TIMEOUT"] == "1200"
    assert env.sources["JMS_URL"] == "profile"
    assert str(profile) in env.loaded_files


def test_profile_defaults_keep_default_compatible(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(profile_env, "PROJECT_ROOT", tmp_path)

    default_env = profile_env.ProfileEnv("default", "", [], {}, {})
    prod_env = profile_env.ProfileEnv("prod", "", [], {}, {})

    assert profile_env.profile_default_path(default_env, "CHECK_OUTPUT_DIR", "reports/yuque") == "reports/yuque"
    assert Path(profile_env.profile_default_path(prod_env, "CHECK_OUTPUT_DIR", "reports/yuque")) == Path("reports/yuque/prod")
    assert profile_env.profile_default_name(prod_env, "CHECK_YUQUE_TITLE", "Report") == "Report - prod"
    assert profile_env.profile_default_name(prod_env, "CHECK_YUQUE_SLUG", "report", slug=True) == "report-prod"


def test_profile_explicit_values_are_not_modified():
    env = profile_env.ProfileEnv(
        "prod",
        "",
        [],
        {"CHECK_OUTPUT_DIR": "custom/reports", "CHECK_YUQUE_SLUG": "custom-slug"},
        {"CHECK_OUTPUT_DIR": "profile", "CHECK_YUQUE_SLUG": "profile"},
    )

    assert profile_env.profile_default_path(env, "CHECK_OUTPUT_DIR", "reports/yuque") == "custom/reports"
    assert profile_env.profile_default_name(env, "CHECK_YUQUE_SLUG", "report", slug=True) == "custom-slug"
