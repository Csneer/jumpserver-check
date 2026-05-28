import json
from pathlib import Path

from scripts import cleanup_admin_server as admin


def test_get_candidates_returns_plan_without_cors_wildcard(tmp_path, monkeypatch):
    monkeypatch.setattr(
        admin.host_cleanup,
        "evaluate_cleanup",
        lambda **kwargs: {"profile": kwargs["profile"], "candidates": [{"asset_id": "asset-1"}], "skipped": []},
    )
    context = admin.AdminContext(profile="local", raw_dir=tmp_path, state_dir=tmp_path, output_dir=tmp_path, token="")

    response = admin.handle_request("GET", "/api/candidates", {}, b"", context)

    assert response.status == 200
    assert response.headers.get("Access-Control-Allow-Origin") != "*"
    assert json.loads(response.body)["candidates"][0]["asset_id"] == "asset-1"


def test_index_page_has_interactive_decision_buttons():
    response = admin.handle_request(
        "GET",
        "/",
        {},
        b"",
        admin.AdminContext(profile="local", raw_dir=Path("."), state_dir=Path("."), output_dir=Path("."), token=""),
    )

    body = response.body.decode("utf-8")
    assert "Cleanup Console" in body
    assert "废弃主机确认中心" in body
    assert "确认废弃并禁用" in body
    assert "保护" in body
    assert "需复查" in body
    assert "stateFilter" in body
    assert "/api/confirm" in body


def test_health_and_favicon_routes(tmp_path):
    context = admin.AdminContext(profile="local", raw_dir=tmp_path, state_dir=tmp_path, output_dir=tmp_path, token="")

    health = admin.handle_request("GET", "/api/health", {}, b"", context)
    favicon = admin.handle_request("GET", "/favicon.ico", {}, b"", context)

    assert health.status == 200
    assert json.loads(health.body) == {"status": "ok", "profile": "local"}
    assert favicon.status == 204


def test_write_endpoints_require_token(tmp_path):
    context = admin.AdminContext(profile="local", raw_dir=tmp_path, state_dir=tmp_path, output_dir=tmp_path, token="secret")

    response = admin.handle_request("POST", "/api/confirm", {}, b"{}", context)

    assert response.status == 401


def test_post_confirm_writes_confirmation(tmp_path):
    context = admin.AdminContext(profile="local", raw_dir=tmp_path, state_dir=tmp_path, output_dir=tmp_path, token="secret")
    payload = {
        "asset": {"asset_id": "asset-1", "asset_name": "host-a", "asset_ip": "192.0.2.10"},
        "operator": "admin",
        "reason": "decommissioned",
        "action": "disable",
        "source_evidence_run_ids": ["run-1"],
        "source_evidence_paths": ["raw.json"],
    }

    response = admin.handle_request(
        "POST",
        "/api/confirm",
        {"authorization": "Bearer secret"},
        json.dumps(payload).encode(),
        context,
    )

    assert response.status == 200
    registry = json.loads((tmp_path / "cleanup_confirmed_hosts.json").read_text(encoding="utf-8"))
    assert registry["confirmed_hosts"][0]["asset_id"] == "asset-1"


def test_post_confirm_rejects_delete_without_ack(tmp_path):
    context = admin.AdminContext(profile="local", raw_dir=tmp_path, state_dir=tmp_path, output_dir=tmp_path, token="secret")
    payload = {
        "asset": {"asset_id": "asset-1", "asset_name": "host-a", "asset_ip": "192.0.2.10"},
        "operator": "admin",
        "reason": "decommissioned",
        "action": "delete",
        "source_evidence_run_ids": ["run-1"],
        "source_evidence_paths": ["raw.json"],
    }

    response = admin.handle_request(
        "POST",
        "/api/confirm",
        {"authorization": "Bearer secret"},
        json.dumps(payload).encode(),
        context,
    )

    assert response.status == 400


def test_post_protect_and_review_require_reason(tmp_path):
    context = admin.AdminContext(profile="local", raw_dir=tmp_path, state_dir=tmp_path, output_dir=tmp_path, token="secret")
    headers = {"x-cleanup-admin-token": "secret"}

    bad = admin.handle_request("POST", "/api/protect", headers, b'{"asset_id":"asset-1"}', context)
    assert bad.status == 400

    good = admin.handle_request("POST", "/api/protect", headers, b'{"asset_id":"asset-1","reason":"keep"}', context)
    assert good.status == 200

    review = admin.handle_request("POST", "/api/review", headers, b'{"asset_id":"asset-1","reason":"check owner"}', context)
    assert review.status == 200
    assert (tmp_path / "cleanup_review_hosts.json").exists()


def test_public_bind_without_token_is_rejected():
    try:
        admin.validate_bind_security("0.0.0.0", "")
    except SystemExit as exc:
        assert exc.code == 2
    else:
        raise AssertionError("expected SystemExit")

    admin.validate_bind_security("127.0.0.1", "")
