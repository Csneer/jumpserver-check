import json
from pathlib import Path

from scripts import host_cleanup

def write_raw(path: Path, run_id: str, results: list[dict], *, eligible=True, source="weekly_scheduled", profile="local", started_at="2026-05-20T09:00:00+08:00"):
    path.write_text(
        json.dumps(
            {
                "run_id": run_id,
                "profile": profile,
                "run_source": source,
                "cleanup_evidence_eligible": eligible,
                "started_at": started_at,
                "finished_at": started_at,
                "results": results,
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

def result(asset_id="asset-1", status="unreachable", ip="192.0.2.10", name="host-a", remark="No route to host"):
    return {
        "asset_id": asset_id,
        "asset_name": name,
        "asset_ip": ip,
        "probe_status": status,
        "connectivity": "unreachable" if status == "unreachable" else "ok",
        "node": "Default",
        "remark": remark,
    }

def mark_confirmed_before_next_run(state_dir: Path, confirmed_at="2026-05-28T09:00:00+08:00"):
    path = state_dir / "cleanup_confirmed_hosts.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["confirmed_hosts"][0]["confirmed_at"] = confirmed_at
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

def test_evaluate_requires_two_distinct_eligible_scheduled_unreachable_runs(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    write_raw(raw / "r1.json", "run-1", [result()], started_at="2026-05-20T09:00:00+08:00")
    write_raw(raw / "r2.json", "run-2", [result()], started_at="2026-05-27T09:00:00+08:00")
    write_raw(raw / "manual.json", "run-3", [result("asset-2")], source="manual", started_at="2026-05-27T10:00:00+08:00")

    plan = host_cleanup.evaluate_cleanup(profile="local", raw_dir=raw, state_dir=tmp_path / "state", output_dir=tmp_path / "cleanup")

    assert [item["asset_id"] for item in plan["candidates"]] == ["asset-1"]
    assert plan["candidates"][0]["confirmation_state"] == "missing_confirmation"
    assert plan["candidates"][0]["evidence_run_ids"] == ["run-1", "run-2"]

def test_evaluate_rejects_ineligible_duplicate_run_and_non_unreachable(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    write_raw(raw / "r1.json", "same", [result("asset-1")], eligible=True)
    write_raw(raw / "r2.json", "same", [result("asset-1")], eligible=True, started_at="2026-05-27T09:00:00+08:00")
    write_raw(raw / "r3.json", "run-3", [result("asset-2")], eligible=False)
    write_raw(raw / "r4.json", "run-4", [result("asset-2")], eligible=True, started_at="2026-05-27T09:00:00+08:00")
    write_raw(raw / "r5.json", "run-5", [result("asset-3")], eligible=True)
    write_raw(raw / "r6.json", "run-6", [result("asset-3", status="ok_static")], eligible=True, started_at="2026-05-27T09:00:00+08:00")

    plan = host_cleanup.evaluate_cleanup(profile="local", raw_dir=raw, state_dir=tmp_path / "state", output_dir=tmp_path / "cleanup")

    assert plan["candidates"] == []
    reasons = {item["asset_id"]: item["reason"] for item in plan["skipped"]}
    assert reasons["asset-1"] == "duplicate_run_id"
    assert reasons["asset-2"] == "not_enough_eligible_unreachable_runs"
    assert reasons["asset-3"] == "latest_status_not_unreachable"

def test_evaluate_requires_recent_two_scheduled_runs_not_old_history(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    write_raw(raw / "r1.json", "run-1", [result("asset-1")], started_at="2026-05-20T09:00:00+08:00")
    write_raw(raw / "r2.json", "run-2", [result("asset-1")], started_at="2026-05-27T09:00:00+08:00")
    write_raw(raw / "r3.json", "run-3", [result("asset-2")], started_at="2026-05-28T09:00:00+08:00")

    plan = host_cleanup.evaluate_cleanup(profile="local", raw_dir=raw, state_dir=tmp_path / "state", output_dir=tmp_path / "cleanup")

    assert plan["candidates"] == []
    reasons = {item["asset_id"]: item["reason"] for item in plan["skipped"]}
    assert reasons["asset-1"] == "not_recent_two_scheduled_runs"

def test_registry_confirmation_and_protection_gates(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    write_raw(raw / "r1.json", "run-1", [result()], started_at="2026-05-20T09:00:00+08:00")
    write_raw(raw / "r2.json", "run-2", [result()], started_at="2026-05-27T09:00:00+08:00")
    state = tmp_path / "state"
    host_cleanup.write_confirmation(
        state,
        profile="local",
        asset={"asset_id": "asset-1", "asset_name": "host-a", "asset_ip": "192.0.2.10"},
        operator="admin",
        reason="decommissioned",
        action="disable",
        source_evidence_run_ids=["run-1"],
        source_evidence_paths=["r1.json"],
    )
    host_cleanup.write_protection(state, profile="local", asset_id="asset-1", reason="keep")

    plan = host_cleanup.evaluate_cleanup(profile="local", raw_dir=raw, state_dir=state, output_dir=tmp_path / "cleanup")

    assert plan["candidates"] == []
    assert plan["skipped"][0]["reason"] == "protected"

def test_archive_before_mutation_and_disable_patch(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    write_raw(raw / "r1.json", "run-1", [result()], started_at="2026-05-20T09:00:00+08:00")
    write_raw(raw / "r2.json", "run-2", [result()], started_at="2026-05-27T09:00:00+08:00")
    state = tmp_path / "state"
    host_cleanup.write_confirmation(
        state,
        profile="local",
        asset={"asset_id": "asset-1", "asset_name": "host-a", "asset_ip": "192.0.2.10"},
        operator="admin",
        reason="decommissioned",
        action="disable",
        source_evidence_run_ids=["run-1"],
        source_evidence_paths=["r1.json"],
    )
    mark_confirmed_before_next_run(state)
    write_raw(raw / "r3.json", "run-3", [result()], started_at="2026-05-29T09:00:00+08:00")
    plan = host_cleanup.evaluate_cleanup(profile="local", raw_dir=raw, state_dir=state, output_dir=tmp_path / "cleanup")

    class Client:
        def __init__(self):
            self.patched = []

        def get(self, path, params=None, timeout=20):
            return 200, {"id": "asset-1", "name": "host-a", "address": "192.0.2.10", "is_active": True, "secret": "must-not-store"}

        def patch(self, path, body, timeout=20):
            self.patched.append((path, body))
            return 200, {"ok": True}

    client = Client()
    result_payload = host_cleanup.apply_cleanup_plan(
        plan,
        profile="local",
        state_dir=state,
        output_dir=tmp_path / "cleanup",
        client=client,
    )

    assert client.patched == [("/api/v1/assets/assets/asset-1/", {"is_active": False})]
    item = result_payload["results"][0]
    assert item["status"] == "disabled"
    archive = json.loads(Path(item["archive_path"]).read_text(encoding="utf-8"))
    assert "secret" not in json.dumps(archive).lower()

def test_apply_waits_for_scheduled_run_after_confirmation(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    write_raw(raw / "r1.json", "run-1", [result()], started_at="2026-05-20T09:00:00+08:00")
    write_raw(raw / "r2.json", "run-2", [result()], started_at="2026-05-27T09:00:00+08:00")
    state = tmp_path / "state"
    host_cleanup.write_confirmation(
        state,
        profile="local",
        asset={"asset_id": "asset-1", "asset_name": "host-a", "asset_ip": "192.0.2.10"},
        operator="admin",
        reason="decommissioned",
        action="disable",
        source_evidence_run_ids=["run-1", "run-2"],
        source_evidence_paths=["r1.json", "r2.json"],
    )
    plan = host_cleanup.evaluate_cleanup(profile="local", raw_dir=raw, state_dir=state, output_dir=tmp_path / "cleanup")

    assert plan["candidates"][0]["confirmation_state"] == "confirmed_wait_next_scheduled_run"

    class Client:
        def get(self, *args, **kwargs):  # pragma: no cover - must not be called
            raise AssertionError("apply must not fetch before next scheduled evidence")

    result_payload = host_cleanup.apply_cleanup_plan(plan, profile="local", state_dir=state, output_dir=tmp_path / "cleanup", client=Client())

    assert result_payload["results"][0]["status"] == "skipped_wait_next_scheduled_run"

def test_apply_re_evaluates_confirmation_and_protection_before_mutation(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    write_raw(raw / "r1.json", "run-1", [result()], started_at="2026-05-20T09:00:00+08:00")
    write_raw(raw / "r2.json", "run-2", [result()], started_at="2026-05-27T09:00:00+08:00")
    state = tmp_path / "state"
    host_cleanup.write_confirmation(
        state,
        profile="local",
        asset={"asset_id": "asset-1", "asset_name": "host-a", "asset_ip": "192.0.2.10"},
        operator="admin",
        reason="decommissioned",
        action="disable",
        source_evidence_run_ids=["run-1"],
        source_evidence_paths=["r1.json"],
    )
    mark_confirmed_before_next_run(state)
    write_raw(raw / "r3.json", "run-3", [result()], started_at="2026-05-29T09:00:00+08:00")
    plan = host_cleanup.evaluate_cleanup(profile="local", raw_dir=raw, state_dir=state, output_dir=tmp_path / "cleanup")
    assert plan["candidates"][0]["confirmation_state"] == "confirmed"
    host_cleanup.write_protection(state, profile="local", asset_id="asset-1", reason="rescued")

    class Client:
        def get(self, *args, **kwargs):  # pragma: no cover - must not be called
            raise AssertionError("apply must re-check protection before API fetch")

    result_payload = host_cleanup.apply_cleanup_plan(plan, profile="local", state_dir=state, output_dir=tmp_path / "cleanup", client=Client())

    assert result_payload["results"][0]["status"] == "skipped_not_current_candidate"

def test_archive_failure_prevents_mutation(tmp_path, monkeypatch):
    plan = {
        "profile": "local",
        "candidates": [
            {
                "asset_id": "asset-1",
                "asset_name": "host-a",
                "asset_ip": "192.0.2.10",
                "node": "Default",
                "planned_action": "disable",
                "confirmation_state": "confirmed",
                "evidence_run_ids": ["run-1", "run-2"],
            }
        ],
    }

    class Client:
        patched = False

        def get(self, path, params=None, timeout=20):
            return 200, {"id": "asset-1", "name": "host-a", "address": "192.0.2.10", "is_active": True}

        def patch(self, path, body, timeout=20):
            self.patched = True
            return 200, {}

    def fail_archive(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(host_cleanup, "write_archive", fail_archive)
    client = Client()

    result_payload = host_cleanup.apply_cleanup_plan(
        plan,
        profile="local",
        state_dir=tmp_path / "state",
        output_dir=tmp_path / "cleanup",
        client=client,
    )

    assert client.patched is False
    assert result_payload["results"][0]["status"] == "archive_failed"

def test_delete_requires_all_gates(tmp_path, monkeypatch):
    plan = {
        "profile": "local",
        "candidates": [
            {
                "asset_id": "asset-1",
                "asset_name": "host-a",
                "asset_ip": "192.0.2.10",
                "planned_action": "delete",
                "confirmation_state": "confirmed",
                "confirmation": {"cleanup_action": "delete", "delete_ack": "DELETE asset-1"},
                "evidence_run_ids": ["run-1", "run-2"],
            }
        ],
    }

    class Client:
        def get(self, path, params=None, timeout=20):
            return 200, {"id": "asset-1", "name": "host-a", "address": "192.0.2.10", "is_active": True}

        def delete(self, path, timeout=20):
            raise AssertionError("delete should be gated")

    monkeypatch.delenv("CLEANUP_ALLOW_DELETE", raising=False)

    result_payload = host_cleanup.apply_cleanup_plan(
        plan,
        profile="local",
        state_dir=tmp_path / "state",
        output_dir=tmp_path / "cleanup",
        client=Client(),
        allow_delete=True,
    )

    assert result_payload["results"][0]["status"] == "skipped_delete_not_allowed"

def test_current_asset_matches_rejects_inactive():
    candidate = {"asset_id": "a1", "asset_ip": "10.0.0.1", "asset_name": "host-a"}
    assert host_cleanup.current_asset_matches(candidate, {"id": "a1", "address": "10.0.0.1", "name": "host-a", "is_active": False}) is False

def test_current_asset_matches_rejects_name_mismatch():
    candidate = {"asset_id": "a1", "asset_ip": "10.0.0.1", "asset_name": "host-a"}
    assert host_cleanup.current_asset_matches(candidate, {"id": "a1", "address": "10.0.0.1", "name": "host-b", "is_active": True}) is False

def test_current_asset_matches_rejects_ip_mismatch():
    candidate = {"asset_id": "a1", "asset_ip": "10.0.0.1", "asset_name": "host-a"}
    assert host_cleanup.current_asset_matches(candidate, {"id": "a1", "address": "10.0.0.2", "name": "host-a", "is_active": True}) is False

def test_stale_confirmation_candidate_when_ip_changed(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    state = tmp_path / "state"
    write_raw(raw / "r1.json", "run-1", [result()], started_at="2026-05-20T09:00:00+08:00")
    write_raw(raw / "r2.json", "run-2", [result()], started_at="2026-05-27T09:00:00+08:00")
    host_cleanup.write_confirmation(
        state,
        profile="local",
        asset={"asset_id": "asset-1", "asset_name": "host-a", "asset_ip": "10.0.0.99"},
        operator="admin",
        reason="decommissioned",
        action="disable",
        source_evidence_run_ids=["run-0"],
        source_evidence_paths=["old.json"],
    )

    plan = host_cleanup.evaluate_cleanup(profile="local", raw_dir=raw, state_dir=state, output_dir=tmp_path / "cleanup")

    stale = [c for c in plan["candidates"] if c.get("confirmation_state") == "stale_confirmation"]
    assert len(stale) == 1
    assert stale[0]["asset_id"] == "asset-1"
    assert stale[0]["confirmation_reason"] == "asset_ip_changed_since_confirmation"

def test_merge_fresh_candidate_flags_action_mismatch():
    plan_candidate = {"asset_id": "a1", "planned_action": "delete"}
    fresh_candidate = {"asset_id": "a1", "planned_action": "disable"}

    merged = host_cleanup.merge_fresh_candidate(plan_candidate, fresh_candidate)

    assert merged["planned_action_mismatch"]["plan"] == "delete"
    assert merged["planned_action_mismatch"]["fresh"] == "disable"

def test_parse_timestamp_edge_cases():
    assert host_cleanup.parse_timestamp(None) is None
    assert host_cleanup.parse_timestamp("") is None
    parsed_z = host_cleanup.parse_timestamp("2026-05-28T09:00:00Z")
    assert parsed_z is not None and parsed_z.tzinfo is not None
    parsed_naive = host_cleanup.parse_timestamp("2026-05-28T09:00:00")
    assert parsed_naive is not None and parsed_naive.tzinfo is not None
    assert host_cleanup.parse_timestamp("not-a-date") is None

def test_load_eligible_raw_records_skips_bad_json(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "good.json").write_text(json.dumps({
        "run_id": "run-1", "profile": "local", "run_source": "weekly_scheduled",
        "cleanup_evidence_eligible": True, "started_at": "2026-05-20T09:00:00+08:00",
        "results": [],
    }), encoding="utf-8")
    (raw / "bad.json").write_text("{invalid json", encoding="utf-8")
    (raw / "empty.json").write_text("", encoding="utf-8")

    records = host_cleanup.load_eligible_raw_records(raw, "local")

    assert len(records) == 1
    assert records[0]["run_id"] == "run-1"

def test_scrub_sensitive_removes_secret_keys():
    data = {
        "name": "host-a",
        "secret": "should-be-removed",
        "access_key": "also-removed",
        "nested": {"password": "gone", "safe": "kept"},
        "items": [{"token": "gone"}, {"ok": True}],
    }

    scrubbed = host_cleanup.scrub_sensitive(data)

    assert scrubbed == {"name": "host-a", "nested": {"safe": "kept"}, "items": [{}, {"ok": True}]}

def test_ping_reachable_evidence_requires_review_not_cleanup_candidate(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    write_raw(raw / "r1.json", "run-1", [result()], started_at="2026-05-20T09:00:00+08:00")
    write_raw(raw / "r2.json", "run-2", [{**result(), "probe_status": "jumpserver_unreachable_ip_reachable", "ip_reachability": "reachable", "ip_reachability_remark": "ping reachable"}], started_at="2026-05-27T09:00:00+08:00")

    plan = host_cleanup.evaluate_cleanup(profile="local", raw_dir=raw, state_dir=tmp_path / "state", output_dir=tmp_path / "cleanup")

    assert plan["candidates"] == []
    assert plan["review_required"][0]["reason"] == "ip_reachable_requires_review"
    assert plan["review_required"][0]["evidence_run_ids"] == ["run-1", "run-2"]

def test_ping_reachable_in_first_required_run_still_surfaces_review_required(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    write_raw(raw / "r1.json", "run-1", [{**result(), "probe_status": "jumpserver_unreachable_ip_reachable", "ip_reachability": "reachable", "ip_reachability_checked_at": "2026-05-20T09:00:01+08:00", "ip_reachability_remark": "ping reachable first"}], started_at="2026-05-20T09:00:00+08:00")
    write_raw(raw / "r2.json", "run-2", [result()], started_at="2026-05-27T09:00:00+08:00")

    plan = host_cleanup.evaluate_cleanup(profile="local", raw_dir=raw, state_dir=tmp_path / "state", output_dir=tmp_path / "cleanup")

    assert plan["candidates"] == []
    assert plan["review_required"][0]["reason"] == "ip_reachable_requires_review"
    assert plan["review_required"][0]["ip_reachability_remark"] == "ping reachable first"
    assert plan["review_required"][0]["ip_reachability_checked_at"] == "2026-05-20T09:00:01+08:00"
    assert plan["review_required"][0]["evidence_run_ids"] == ["run-1", "run-2"]

def test_apply_cleanup_plan_skips_when_fresh_required_run_has_ping_reachable(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    state = tmp_path / "state"
    output = tmp_path / "cleanup"
    write_raw(raw / "r1.json", "run-1", [{**result(), "probe_status": "jumpserver_unreachable_ip_reachable", "ip_reachability": "reachable"}], started_at="2026-05-20T09:00:00+08:00")
    write_raw(raw / "r2.json", "run-2", [result()], started_at="2026-05-27T09:00:00+08:00")
    stale_candidate = {
        "profile": "local",
        "asset_id": "asset-1",
        "asset_name": "host-a",
        "asset_ip": "192.0.2.10",
        "planned_action": "disable",
        "confirmation_state": "confirmed",
        "evidence_run_ids": ["old-1", "old-2"],
        "evidence_paths": ["old-1.json", "old-2.json"],
    }
    plan = {"profile": "local", "raw_dir": str(raw), "candidates": [stale_candidate]}

    payload = host_cleanup.apply_cleanup_plan(plan, profile="local", state_dir=state, output_dir=output, client=object())

    assert payload["results"][0]["status"] == "skipped_not_current_candidate"

def test_is_unreachable_result_rejects_ping_reachable():
    assert host_cleanup.is_unreachable_result({"probe_status": "unreachable", "connectivity": "unreachable", "ip_reachability": "reachable"}) is False
    assert host_cleanup.is_unreachable_result({"probe_status": "jumpserver_unreachable_ip_reachable", "connectivity": "unreachable", "ip_reachability": "reachable"}) is False

def test_latest_single_ping_reachable_still_surfaces_review_required(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    write_raw(raw / "r1.json", "run-1", [{**result(status="ok_static"), "connectivity": "ok"}], started_at="2026-05-20T09:00:00+08:00")
    write_raw(raw / "r2.json", "run-2", [{**result(), "probe_status": "jumpserver_unreachable_ip_reachable", "ip_reachability": "reachable", "ip_reachability_remark": "ping reachable"}], started_at="2026-05-27T09:00:00+08:00")

    plan = host_cleanup.evaluate_cleanup(profile="local", raw_dir=raw, state_dir=tmp_path / "state", output_dir=tmp_path / "cleanup")

    assert plan["review_required"][0]["reason"] == "ip_reachable_requires_review"

def test_delete_apply_result_includes_audit_fields_and_result_path(tmp_path, monkeypatch):
    plan = {
        "profile": "local",
        "candidates": [
            {
                "profile": "local",
                "asset_id": "asset-1",
                "asset_name": "host-a",
                "asset_ip": "192.0.2.10",
                "planned_action": "delete",
                "confirmation_state": "confirmed",
                "confirmation": {
                    "cleanup_action": "delete",
                    "operator": "admin",
                    "reason": "decommissioned",
                    "delete_ack": "DELETE asset-1",
                },
                "evidence_run_ids": ["run-1", "run-2"],
            }
        ],
    }

    class Client:
        def get(self, path, params=None, timeout=20):
            return 200, {"id": "asset-1", "name": "host-a", "address": "192.0.2.10", "is_active": True}

        def delete(self, path, timeout=20):
            return 204, {"ok": True}

    monkeypatch.setenv("CLEANUP_ALLOW_DELETE", "true")

    payload = host_cleanup.apply_cleanup_plan(
        plan,
        profile="local",
        state_dir=tmp_path / "state",
        output_dir=tmp_path / "cleanup",
        client=Client(),
        allow_delete=True,
    )

    item = payload["results"][0]
    assert item["status"] == "deleted"
    assert item["profile"] == "local"
    assert item["asset_id"] == "asset-1"
    assert item["asset_name"] == "host-a"
    assert item["asset_ip"] == "192.0.2.10"
    assert item["operator"] == "admin"
    assert item["reason"] == "decommissioned"
    assert item["delete_ack"] == "DELETE asset-1"
    assert item["archive_path"]
    assert item["result_path"] == payload["result_path"]
    written = json.loads(Path(payload["result_path"]).read_text(encoding="utf-8"))
    assert written["results"][0]["result_path"] == payload["result_path"]

def test_notify_cleanup_delete_result_records_standalone_delete_notification(tmp_path, monkeypatch):
    payload = {
        "profile": "local",
        "result_path": str(tmp_path / "cleanup-result.json"),
        "results": [{"status": "deleted", "asset_id": "asset-1", "asset_name": "host-a", "asset_ip": "192.0.2.10"}],
    }
    Path(payload["result_path"]).write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    calls = []

    def fake_notify(apply_result):
        calls.append(apply_result)
        return {"status": "sent", "deleted_count": 1}

    monkeypatch.setattr(host_cleanup.wecom_notify, "send_cleanup_delete_notification", fake_notify)

    result = host_cleanup.notify_cleanup_delete_result(payload)

    assert result == {"status": "sent", "deleted_count": 1}
    assert calls == [payload]
    written = json.loads(Path(payload["result_path"]).read_text(encoding="utf-8"))
    assert written["delete_notification"]["status"] == "sent"

def test_notify_cleanup_delete_result_records_notification_failure(tmp_path, monkeypatch):
    payload = {
        "profile": "local",
        "result_path": str(tmp_path / "cleanup-result.json"),
        "results": [{"status": "deleted", "asset_id": "asset-1"}],
    }
    Path(payload["result_path"]).write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    def fail_notify(apply_result):
        raise RuntimeError("wecom down")

    monkeypatch.setattr(host_cleanup.wecom_notify, "send_cleanup_delete_notification", fail_notify)

    result = host_cleanup.notify_cleanup_delete_result(payload)

    assert result["status"] == "failed"
    assert "wecom down" in result["error"]
    written = json.loads(Path(payload["result_path"]).read_text(encoding="utf-8"))
    assert written["delete_notification"]["status"] == "failed"

def test_has_delete_attempt_ignores_pre_delete_fetch_failure():
    assert host_cleanup.has_delete_attempt({"results": [{"action": "delete", "status": "asset_fetch_failed", "api_status": 500}]}) is False

def test_standalone_apply_notification_runs_for_failed_delete_attempt(tmp_path, monkeypatch):
    payload = {
        "profile": "local",
        "result_path": str(tmp_path / "cleanup-result.json"),
        "results": [{"status": "delete_failed", "action": "delete", "api_operation": "delete", "api_status": 500, "asset_id": "asset-1"}],
    }
    Path(payload["result_path"]).write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    calls = []
    monkeypatch.setattr(host_cleanup, "parse_args", lambda: type("Args", (), {"command": "apply", "profile": "local", "raw_dir": "", "state_dir": str(tmp_path / "state"), "output_dir": str(tmp_path / "cleanup"), "plan": str(tmp_path / "plan.json"), "dry_run": False, "allow_delete": True})())
    (tmp_path / "plan.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(host_cleanup, "apply_cleanup_plan", lambda *args, **kwargs: payload)
    monkeypatch.setattr(host_cleanup, "notify_cleanup_delete_result", lambda result: calls.append(result) or {"status": "sent"})

    host_cleanup.main()

    assert calls == [payload]

def test_notify_cleanup_delete_result_writeback_failure_is_best_effort(tmp_path, monkeypatch):
    payload = {
        "profile": "local",
        "result_path": str(tmp_path / "cleanup-result.json"),
        "results": [{"status": "deleted", "asset_id": "asset-1"}],
    }
    monkeypatch.setattr(host_cleanup.wecom_notify, "send_cleanup_delete_notification", lambda result: {"status": "sent"})

    def fail_write(path, value):
        raise OSError("disk read-only")

    monkeypatch.setattr(host_cleanup, "atomic_write_json", fail_write)

    result = host_cleanup.notify_cleanup_delete_result(payload)

    assert result["status"] == "sent"
    assert payload["delete_notification"]["status"] == "sent"
    assert payload["delete_notification_persist"]["status"] == "failed"
    assert "disk read-only" in payload["delete_notification_persist"]["error"]

def test_tcp_open_evidence_requires_review_not_cleanup_candidate(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    write_raw(raw / "r1.json", "run-1", [result()], started_at="2026-05-20T09:00:00+08:00")
    write_raw(raw / "r2.json", "run-2", [{**result(), "probe_status": "jumpserver_unreachable_tcp_open", "tcp_reachability": "open", "tcp_reachability_remark": "ssh port open"}], started_at="2026-05-27T09:00:00+08:00")

    plan = host_cleanup.evaluate_cleanup(profile="local", raw_dir=raw, state_dir=tmp_path / "state", output_dir=tmp_path / "cleanup")

    assert plan["candidates"] == []
    assert plan["review_required"][0]["reason"] == "tcp_open_requires_review"
    assert plan["review_required"][0]["tcp_reachability"] == "open"
    assert plan["review_required"][0]["tcp_reachability_remark"] == "ssh port open"

def test_is_unreachable_result_rejects_tcp_open():
    assert host_cleanup.is_unreachable_result({"probe_status": "jumpserver_unreachable_tcp_open", "connectivity": "unreachable", "tcp_reachability": "open"}) is False
    assert host_cleanup.is_unreachable_result({"probe_status": "unreachable", "connectivity": "unreachable", "tcp_reachability": "open"}) is False
