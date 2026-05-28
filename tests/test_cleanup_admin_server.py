import json
from pathlib import Path

from scripts import cleanup_admin_server as admin


def auth_cookie(token="secret"):
    cookie, csrf = admin.make_session_cookie(token, 3600)
    return {"Cookie": f"{admin.SESSION_COOKIE}={cookie}", "X-CSRF-Token": csrf}


def test_get_candidates_requires_login_and_has_no_cors_wildcard(tmp_path, monkeypatch):
    monkeypatch.setattr(
        admin.host_cleanup,
        "evaluate_cleanup",
        lambda **kwargs: {"profile": kwargs["profile"], "candidates": [{"asset_id": "asset-1"}], "skipped": []},
    )
    context = admin.AdminContext(profile="local", raw_dir=tmp_path, state_dir=tmp_path, output_dir=tmp_path, token="secret")

    blocked = admin.handle_request("GET", "/api/candidates", {}, b"", context)
    response = admin.handle_request("GET", "/api/candidates", auth_cookie(), b"", context)

    assert blocked.status == 401
    assert response.status == 200
    assert response.headers.get("Access-Control-Allow-Origin") != "*"
    body = json.loads(response.body)
    assert body["candidates"][0]["asset_id"] == "asset-1"
    assert body["profiles"][0]["name"] == "local"


def test_login_sets_http_only_session_cookie(tmp_path):
    context = admin.AdminContext(profile="local", raw_dir=tmp_path, state_dir=tmp_path, output_dir=tmp_path, token="secret")

    bad = admin.handle_request("POST", "/api/login", {}, b'{"token":"wrong"}', context)
    good = admin.handle_request("POST", "/api/login", {}, b'{"token":"secret"}', context)

    assert bad.status == 401
    assert good.status == 200
    cookie = good.headers["Set-Cookie"]
    assert admin.SESSION_COOKIE in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=Strict" in cookie
    body = json.loads(good.body)
    assert body["csrf_token"]
    assert len(body["csrf_token"]) == 64


def test_index_page_has_login_profile_selector_and_interactive_decision_buttons():
    response = admin.handle_request(
        "GET",
        "/",
        {},
        b"",
        admin.AdminContext(profile="local", raw_dir=Path("."), state_dir=Path("."), output_dir=Path("."), token="secret"),
    )

    body = response.body.decode("utf-8")
    assert "Cleanup Console" in body
    assert "登录后查看废弃主机候选" in body
    assert "废弃主机确认中心" in body
    assert "profileSelect" in body
    assert "确认废弃并禁用" in body
    assert "保护" in body
    assert "需复查" in body
    assert "stateFilter" in body
    assert "/api/login" in body
    assert "/api/confirm" in body


def test_health_and_favicon_routes(tmp_path):
    context = admin.AdminContext(profile="local", raw_dir=tmp_path, state_dir=tmp_path, output_dir=tmp_path, token="secret")

    health = admin.handle_request("GET", "/api/health", {}, b"", context)
    favicon = admin.handle_request("GET", "/favicon.ico", {}, b"", context)

    assert health.status == 200
    assert json.loads(health.body) == {"status": "ok", "auth_required": True}
    assert favicon.status == 204


def test_write_endpoints_require_login(tmp_path):
    context = admin.AdminContext(profile="local", raw_dir=tmp_path, state_dir=tmp_path, output_dir=tmp_path, token="secret")

    response = admin.handle_request("POST", "/api/confirm", {}, b"{}", context)

    assert response.status == 401


def test_post_confirm_writes_confirmation_for_selected_profile(tmp_path):
    context = admin.AdminContext(profile="local", raw_dir=tmp_path, state_dir=tmp_path, output_dir=tmp_path, token="secret", allowed_profiles=("ops",))
    payload = {
        "profile": "ops",
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
        auth_cookie(),
        json.dumps(payload).encode(),
        context,
    )

    assert response.status == 200
    registry = json.loads((tmp_path / "ops" / "cleanup_confirmed_hosts.json").read_text(encoding="utf-8"))
    assert registry["confirmed_hosts"][0]["profile"] == "ops"
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
        auth_cookie(),
        json.dumps(payload).encode(),
        context,
    )

    assert response.status == 400


def test_post_protect_and_review_require_reason(tmp_path):
    context = admin.AdminContext(profile="local", raw_dir=tmp_path, state_dir=tmp_path, output_dir=tmp_path, token="secret")
    headers = auth_cookie()

    bad = admin.handle_request("POST", "/api/protect", headers, b'{"asset_id":"asset-1"}', context)
    assert bad.status == 400

    good = admin.handle_request("POST", "/api/protect", headers, b'{"asset_id":"asset-1","reason":"keep"}', context)
    assert good.status == 200

    review = admin.handle_request("POST", "/api/review", headers, b'{"asset_id":"asset-1","reason":"check owner"}', context)
    assert review.status == 200
    assert (tmp_path / "cleanup_review_hosts.json").exists()


def test_authenticated_profile_switch_uses_profile_specific_default_paths(tmp_path, monkeypatch):
    calls = []

    def fake_evaluate(**kwargs):
        calls.append(kwargs)
        return {"profile": kwargs["profile"], "candidates": [{"asset_id": kwargs["profile"]}], "skipped": [], "summary": {}}

    monkeypatch.setattr(admin.host_cleanup, "evaluate_cleanup", fake_evaluate)
    monkeypatch.setattr(admin, "default_raw_dir", lambda profile: tmp_path / "raw" / profile)
    monkeypatch.setattr(admin.host_cleanup, "cleanup_profile_state_dir", lambda profile: tmp_path / "state" / profile)
    monkeypatch.setattr(admin.host_cleanup, "cleanup_output_dir", lambda profile: tmp_path / "out" / profile)
    context = admin.AdminContext(profile="local", raw_dir=None, state_dir=None, output_dir=None, token="secret", allowed_profiles=("ops",))

    response = admin.handle_request("GET", "/api/candidates?profile=ops", auth_cookie(), b"", context)

    assert response.status == 200
    body = json.loads(response.body)
    assert body["profile"] == "ops"
    assert body["candidates"][0]["asset_id"] == "ops"
    assert calls[0]["raw_dir"] == tmp_path / "raw" / "ops"
    assert calls[0]["state_dir"] == tmp_path / "state" / "ops"
    assert calls[0]["output_dir"] == tmp_path / "out" / "ops"



def test_authenticated_profile_switch_scopes_explicit_base_dirs(tmp_path, monkeypatch):
    calls = []

    def fake_evaluate(**kwargs):
        calls.append(kwargs)
        return {"profile": kwargs["profile"], "candidates": [], "skipped": [], "summary": {}}

    monkeypatch.setattr(admin.host_cleanup, "evaluate_cleanup", fake_evaluate)
    context = admin.AdminContext(
        profile="local",
        raw_dir=tmp_path / "raw",
        state_dir=tmp_path / "state",
        output_dir=tmp_path / "out",
        token="secret",
        allowed_profiles=("ops",),
    )

    response = admin.handle_request("GET", "/api/candidates?profile=ops", auth_cookie(), b"", context)

    assert response.status == 200
    assert calls[0]["raw_dir"] == tmp_path / "raw" / "ops"
    assert calls[0]["state_dir"] == tmp_path / "state" / "ops"
    assert calls[0]["output_dir"] == tmp_path / "out" / "ops"

def test_unknown_profile_is_rejected_after_login(tmp_path):
    context = admin.AdminContext(profile="local", raw_dir=None, state_dir=None, output_dir=None, token="secret", allowed_profiles=("ops",))

    response = admin.handle_request("GET", "/api/candidates?profile=prod", auth_cookie(), b"", context)

    assert response.status == 400
    assert "profile not allowed" in json.loads(response.body)["error"]


def test_public_bind_without_token_is_rejected():
    try:
        admin.validate_bind_security("0.0.0.0", "")
    except SystemExit as exc:
        assert exc.code == 2
    else:
        raise AssertionError("expected SystemExit")

    admin.validate_bind_security("127.0.0.1", "")


def test_post_mutating_endpoints_reject_missing_csrf(tmp_path):
    context = admin.AdminContext(profile="local", raw_dir=tmp_path, state_dir=tmp_path, output_dir=tmp_path, token="secret")
    cookie, _ = admin.make_session_cookie("secret", 3600)
    headers_no_csrf = {"Cookie": f"{admin.SESSION_COOKIE}={cookie}"}

    response = admin.handle_request(
        "POST", "/api/confirm", headers_no_csrf,
        json.dumps({"asset_id": "x", "reason": "r", "action": "disable", "source_evidence_run_ids": ["r1"], "source_evidence_paths": ["p1"]}).encode(),
        context,
    )

    assert response.status == 403
    assert "csrf_token_missing" in json.loads(response.body)["error"]


def test_post_mutating_endpoints_reject_invalid_csrf(tmp_path):
    context = admin.AdminContext(profile="local", raw_dir=tmp_path, state_dir=tmp_path, output_dir=tmp_path, token="secret")
    cookie, _ = admin.make_session_cookie("secret", 3600)
    headers_bad_csrf = {"Cookie": f"{admin.SESSION_COOKIE}={cookie}", "X-CSRF-Token": "wrong"}

    response = admin.handle_request(
        "POST", "/api/protect", headers_bad_csrf,
        b'{"asset_id":"x","reason":"r"}',
        context,
    )

    assert response.status == 403
    assert "csrf_token_invalid" in json.loads(response.body)["error"]


def test_session_returns_csrf_token(tmp_path):
    context = admin.AdminContext(profile="local", raw_dir=tmp_path, state_dir=tmp_path, output_dir=tmp_path, token="secret")

    response = admin.handle_request("GET", "/api/session", auth_cookie(), b"", context)

    assert response.status == 200
    body = json.loads(response.body)
    assert body["csrf_token"]
    assert len(body["csrf_token"]) == 64


def test_logout_clears_cookie(tmp_path):
    context = admin.AdminContext(profile="local", raw_dir=tmp_path, state_dir=tmp_path, output_dir=tmp_path, token="secret")

    response = admin.handle_request("POST", "/api/logout", {}, b"", context)

    assert response.status == 200
    cookie = response.headers["Set-Cookie"]
    assert "Max-Age=0" in cookie


def test_health_without_token(tmp_path):
    context = admin.AdminContext(profile="local", raw_dir=tmp_path, state_dir=tmp_path, output_dir=tmp_path, token="")

    health = admin.handle_request("GET", "/api/health", {}, b"", context)

    assert health.status == 200
    assert json.loads(health.body) == {"status": "ok", "auth_required": False}


def test_login_rejected_when_no_token_configured(tmp_path):
    context = admin.AdminContext(profile="local", raw_dir=tmp_path, state_dir=tmp_path, output_dir=tmp_path, token="")

    response = admin.handle_request("POST", "/api/login", {}, b'{"token":"anything"}', context)

    assert response.status == 403
