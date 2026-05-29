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
