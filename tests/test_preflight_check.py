from pathlib import Path

from scripts import preflight_check as preflight


def isolate_project_root(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(preflight.profile_env, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(preflight.profile_env, "PROFILE_ENV_DIR", tmp_path / "configs" / "profiles")
    for key in ("WECOM_WEBHOOK_URL", "WECOM_CHANNEL"):
        monkeypatch.delenv(key, raising=False)


def test_validate_config_accepts_missing_optional_wecom(monkeypatch, tmp_path: Path):
    env = tmp_path / ".env"
    env.write_text(
        "\n".join(
            [
                "JMS_URL=https://jumpserver.local",
                "JMS_ACCESS_KEY_ID=key",
                "JMS_ACCESS_KEY_SECRET=secret",
                "YUQUE_TOKEN=token",
                "YUQUE_REPO_NAMESPACE=user/repo",
                "CHECK_WAIT_TIMEOUT=1200",
                "CHECK_POLL_INTERVAL=30",
                "CHECK_RETENTION_COUNT=12",
            ]
        ),
        encoding="utf-8",
    )
    isolate_project_root(monkeypatch, tmp_path)

    result = preflight.validate_config(require_wecom=False)

    assert result["ok"] is True
    assert result["checked"]["wecom_configured"] is False
    assert result["checked"]["profile"] == "default"
    assert result["warnings"]


def test_validate_config_requires_wecom_when_requested(monkeypatch, tmp_path: Path):
    env = tmp_path / ".env"
    env.write_text(
        "\n".join(
            [
                "JMS_URL=https://jumpserver.local",
                "JMS_ACCESS_KEY_ID=key",
                "JMS_ACCESS_KEY_SECRET=secret",
                "YUQUE_TOKEN=token",
                "YUQUE_REPO_NAMESPACE=user/repo",
            ]
        ),
        encoding="utf-8",
    )
    isolate_project_root(monkeypatch, tmp_path)

    result = preflight.validate_config(require_wecom=True, profile="default")

    assert result["ok"] is False
    assert "WECOM_WEBHOOK_URL 未配置" in result["errors"]


def test_validate_config_rejects_placeholders(monkeypatch, tmp_path: Path):
    env = tmp_path / ".env"
    env.write_text(
        "\n".join(
            [
                "JMS_URL=https://jumpserver.example.com",
                "JMS_ACCESS_KEY_ID=replace-with-access-key-id",
                "JMS_ACCESS_KEY_SECRET=secret",
                "YUQUE_TOKEN=replace-with-yuque-token",
                "YUQUE_REPO_NAMESPACE=your-login-or-group/your-repo",
            ]
        ),
        encoding="utf-8",
    )
    isolate_project_root(monkeypatch, tmp_path)

    result = preflight.validate_config()

    assert result["ok"] is False
    assert any("占位值" in error for error in result["errors"])


def test_validate_config_profile_env_overrides_project_env(monkeypatch, tmp_path: Path):
    isolate_project_root(monkeypatch, tmp_path)
    profile_dir = tmp_path / "configs" / "profiles"
    profile_dir.mkdir(parents=True)
    (tmp_path / ".env").write_text(
        "\n".join(
            [
                "JMS_URL=https://shared",
                "JMS_ACCESS_KEY_ID=shared-key",
                "JMS_ACCESS_KEY_SECRET=shared-secret",
                "YUQUE_TOKEN=shared-token",
                "YUQUE_REPO_NAMESPACE=shared/repo",
            ]
        ),
        encoding="utf-8",
    )
    prod_env = profile_dir / "prod.env"
    prod_env.write_text(
        "\n".join(
            [
                "JMS_URL=https://prod",
                "JMS_ACCESS_KEY_ID=prod-key",
                "JMS_ACCESS_KEY_SECRET=prod-secret",
                "YUQUE_TOKEN=prod-token",
                "YUQUE_REPO_NAMESPACE=prod/repo",
            ]
        ),
        encoding="utf-8",
    )

    result = preflight.validate_config(profile="prod")

    assert result["ok"] is True
    assert result["checked"]["profile"] == "prod"
    assert result["checked"]["env_file"].endswith("prod.env")
