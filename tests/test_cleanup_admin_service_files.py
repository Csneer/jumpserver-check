from pathlib import Path


def test_systemd_unit_and_installer_are_present():
    unit = Path("deploy/systemd/jumpserver-cleanup-admin.service").read_text(encoding="utf-8")
    installer = Path("scripts/install_cleanup_admin_service.sh").read_text(encoding="utf-8")

    assert "cleanup_admin_server.py" in unit
    assert "Restart=always" in unit
    assert "EnvironmentFile=-/root/jumpserver-check/.env" in unit
    assert "CLEANUP_ADMIN_TOKEN must be set" in installer
    assert "systemctl enable --now" in installer
