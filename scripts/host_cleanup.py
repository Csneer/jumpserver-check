#!/usr/bin/env python3
"""Evaluate and safely apply JumpServer abandoned-host cleanup plans."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import jms_host_ip_check, profile_env, wecom_notify  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ELIGIBLE_SOURCE = "weekly_scheduled"
MUTATION_TIMEOUT = 20
SENSITIVE_KEY_PARTS = ("secret", "password", "private_key", "token", "access_key")


class CleanupError(RuntimeError):
    """Raised for cleanup plan or registry failures."""


def now_iso() -> str:
    return dt.datetime.now().astimezone().isoformat()


def cleanup_profile_state_dir(profile: str, base: Path | None = None) -> Path:
    root = base or (PROJECT_ROOT / "artifacts" / "state")
    return root / profile


def cleanup_output_dir(profile: str, base: Path | None = None) -> Path:
    root = base or (PROJECT_ROOT / "artifacts" / "cleanup")
    return root / profile


def load_json_file(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def atomic_write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
        tmp_name = handle.name
    Path(tmp_name).replace(path)


def registry_path(state_dir: Path, name: str) -> Path:
    return state_dir / name


def load_confirmations(state_dir: Path) -> list[dict[str, Any]]:
    payload = load_json_file(registry_path(state_dir, "cleanup_confirmed_hosts.json"), {"confirmed_hosts": []})
    items = payload.get("confirmed_hosts") if isinstance(payload, dict) else []
    return items if isinstance(items, list) else []


def load_protections(state_dir: Path) -> list[dict[str, Any]]:
    payload = load_json_file(registry_path(state_dir, "cleanup_protected_hosts.json"), {"protected_hosts": []})
    items = payload.get("protected_hosts") if isinstance(payload, dict) else []
    return items if isinstance(items, list) else []


def write_confirmation(
    state_dir: Path,
    *,
    profile: str,
    asset: dict[str, Any],
    operator: str,
    reason: str,
    action: str,
    source_evidence_run_ids: list[str],
    source_evidence_paths: list[str],
    delete_ack: str = "",
) -> dict[str, Any]:
    if not operator or not reason:
        raise CleanupError("operator and reason are required")
    if not source_evidence_run_ids or not source_evidence_paths:
        raise CleanupError("source_evidence_run_ids and source_evidence_paths are required")
    if action not in {"disable", "delete"}:
        raise CleanupError("action must be disable or delete")
    asset_id = str(asset.get("asset_id") or asset.get("id") or "")
    if not asset_id:
        raise CleanupError("asset_id is required")
    if action == "delete" and delete_ack != f"DELETE {asset_id}":
        raise CleanupError(f'delete_ack must be "DELETE {asset_id}"')
    record = {
        "profile": profile,
        "asset_id": asset_id,
        "asset_name": str(asset.get("asset_name") or asset.get("name") or ""),
        "asset_ip": str(asset.get("asset_ip") or asset.get("address") or ""),
        "decision": "confirmed_decommissioned",
        "cleanup_action": action,
        "operator": operator,
        "reason": reason,
        "confirmed_at": now_iso(),
        "source_evidence_run_ids": source_evidence_run_ids,
        "source_evidence_paths": source_evidence_paths,
    }
    if action == "delete":
        record["delete_ack"] = delete_ack
    records = [item for item in load_confirmations(state_dir) if item.get("asset_id") != asset_id or item.get("profile") != profile]
    records.append(record)
    atomic_write_json(registry_path(state_dir, "cleanup_confirmed_hosts.json"), {"confirmed_hosts": records})
    return record


def write_protection(state_dir: Path, *, profile: str, asset_id: str, reason: str, operator: str = "") -> dict[str, Any]:
    if not asset_id or not reason:
        raise CleanupError("asset_id and reason are required")
    record = {"profile": profile, "asset_id": asset_id, "reason": reason, "operator": operator, "protected_at": now_iso()}
    records = [item for item in load_protections(state_dir) if item.get("asset_id") != asset_id or item.get("profile") != profile]
    records.append(record)
    atomic_write_json(registry_path(state_dir, "cleanup_protected_hosts.json"), {"protected_hosts": records})
    return record


def raw_sort_key(raw: dict[str, Any]) -> str:
    return str(raw.get("started_at") or raw.get("finished_at") or raw.get("run_id") or "")


def parse_timestamp(value: Any) -> dt.datetime | None:
    if not value:
        return None
    text = str(value)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=dt.timezone.utc)
    return parsed


def load_eligible_raw_records(raw_dir: Path, profile: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in sorted(raw_dir.glob("jumpserver-host-ip-check-*.json")) + sorted(raw_dir.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if payload.get("profile") != profile:
            continue
        if payload.get("run_source") != ELIGIBLE_SOURCE:
            continue
        if payload.get("cleanup_evidence_eligible") is not True:
            continue
        payload["_path"] = str(path)
        records.append(payload)
    # De-duplicate paths when glob patterns overlap.
    unique = {item["_path"]: item for item in records}
    return sorted(unique.values(), key=raw_sort_key)


def result_asset_id(result: dict[str, Any]) -> str:
    return str(result.get("asset_id") or "")


def result_status(result: dict[str, Any]) -> str:
    return str(result.get("probe_status") or "")


def is_unreachable_result(result: dict[str, Any]) -> bool:
    return (
        result_status(result) == "unreachable"
        and str(result.get("connectivity") or "") == "unreachable"
        and str(result.get("ip_reachability") or "") != "reachable"
        and str(result.get("tcp_reachability") or "") != "open"
    )


def is_review_reachable_result(result: dict[str, Any]) -> bool:
    return result_status(result) in {"jumpserver_unreachable_ip_reachable", "jumpserver_unreachable_tcp_open"} and str(result.get("connectivity") or "") == "unreachable"


def index_unreachable(records: list[dict[str, Any]]) -> tuple[dict[str, list[dict[str, Any]]], dict[str, str]]:
    all_seen: dict[str, list[dict[str, Any]]] = {}
    latest_status: dict[str, str] = {}
    for raw in records:
        for result in raw.get("results") or []:
            if not isinstance(result, dict):
                continue
            asset_id = result_asset_id(result)
            if not asset_id:
                continue
            latest_status[asset_id] = result_status(result)
            if is_unreachable_result(result) or is_review_reachable_result(result):
                evidence = {
                    "run_id": raw.get("run_id"),
                    "run_source": raw.get("run_source"),
                    "started_at": raw.get("started_at"),
                    "raw_path": raw.get("_path"),
                    "result": result,
                }
                all_seen.setdefault(asset_id, []).append(evidence)
    return all_seen, latest_status


def matching_confirmation(confirmations: list[dict[str, Any]], profile: str, asset_id: str, asset_ip: str) -> dict[str, Any] | None:
    for item in confirmations:
        if item.get("profile") == profile and item.get("asset_id") == asset_id and str(item.get("asset_ip") or "") == asset_ip:
            return item
    return None


def is_protected(protections: list[dict[str, Any]], profile: str, asset_id: str) -> bool:
    return any(item.get("profile") == profile and item.get("asset_id") == asset_id for item in protections)


def confirmation_cleanup_state(confirmation: dict[str, Any] | None, evidences: list[dict[str, Any]]) -> tuple[str, str]:
    if not confirmation:
        return "missing_confirmation", ""
    source_run_ids = {str(item) for item in confirmation.get("source_evidence_run_ids") or []}
    latest_run_id = str(evidences[-1].get("run_id") or "")
    latest_started = parse_timestamp(evidences[-1].get("started_at"))
    confirmed_at = parse_timestamp(confirmation.get("confirmed_at"))
    if not source_run_ids:
        return "invalid_confirmation", "missing_source_evidence_run_ids"
    if latest_run_id in source_run_ids:
        return "confirmed_wait_next_scheduled_run", "confirmation_uses_latest_run"
    if confirmed_at and latest_started and confirmed_at > latest_started:
        return "confirmed_wait_next_scheduled_run", "confirmation_after_latest_run"
    return "confirmed", ""


def build_candidate(profile: str, asset_id: str, evidences: list[dict[str, Any]], confirmation: dict[str, Any] | None) -> dict[str, Any]:
    last_result = evidences[-1]["result"]
    action = str((confirmation or {}).get("cleanup_action") or "disable")
    confirmation_state, confirmation_reason = confirmation_cleanup_state(confirmation, evidences)
    candidate = {
        "profile": profile,
        "asset_id": asset_id,
        "asset_name": last_result.get("asset_name") or "",
        "asset_ip": last_result.get("asset_ip") or "",
        "node": last_result.get("node") or "",
        "planned_action": action,
        "confirmation_state": confirmation_state,
        "confirmation": confirmation or {},
        "evidence_run_ids": [str(item.get("run_id") or "") for item in evidences[-2:]],
        "evidence_paths": [str(item.get("raw_path") or "") for item in evidences[-2:]],
        "latest_reason": last_result.get("remark") or "",
        "ip_reachability": last_result.get("ip_reachability") or "",
        "ip_reachability_checked_at": last_result.get("ip_reachability_checked_at") or "",
        "ip_reachability_remark": last_result.get("ip_reachability_remark") or "",
    }
    if confirmation_reason:
        candidate["confirmation_reason"] = confirmation_reason
    return candidate


def build_stale_confirmation_candidate(profile: str, asset_id: str, evidences: list[dict[str, Any]], confirmation: dict[str, Any]) -> dict[str, Any]:
    candidate = build_candidate(profile, asset_id, evidences, None)
    candidate["confirmation_state"] = "stale_confirmation"
    candidate["confirmation"] = confirmation
    candidate["confirmation_reason"] = "asset_ip_changed_since_confirmation"
    return candidate


def index_candidates_by_asset(plan: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(item.get("asset_id") or ""): item for item in plan.get("candidates") or [] if isinstance(item, dict)}


def is_cleanup_ready_candidate(candidate: dict[str, Any]) -> bool:
    return candidate.get("confirmation_state") == "confirmed"


def has_ping_reachable_evidence(result: dict[str, Any]) -> bool:
    return str(result.get("ip_reachability") or "") == "reachable" or result_status(result) == "jumpserver_unreachable_ip_reachable"


def has_tcp_open_evidence(result: dict[str, Any]) -> bool:
    return str(result.get("tcp_reachability") or "") == "open" or result_status(result) == "jumpserver_unreachable_tcp_open"


def build_review_required_item(asset_id: str, evidences: list[dict[str, Any]]) -> dict[str, Any]:
    reachable = next((item for item in reversed(evidences) if has_ping_reachable_evidence(item["result"]) or has_tcp_open_evidence(item["result"])), evidences[-1])
    result = reachable["result"]
    tcp_open = has_tcp_open_evidence(result) and not has_ping_reachable_evidence(result)
    return {
        "asset_id": asset_id,
        "asset_name": result.get("asset_name") or "",
        "asset_ip": result.get("asset_ip") or "",
        "node": result.get("node") or "",
        "reason": "tcp_open_requires_review" if tcp_open else "ip_reachable_requires_review",
        "ip_reachability": result.get("ip_reachability") or ("reachable" if not tcp_open else ""),
        "ip_reachability_checked_at": result.get("ip_reachability_checked_at") or "",
        "ip_reachability_remark": result.get("ip_reachability_remark") or result.get("remark") or "",
        "tcp_reachability": result.get("tcp_reachability") or "",
        "tcp_reachability_checked_at": result.get("tcp_reachability_checked_at") or "",
        "tcp_reachability_remark": result.get("tcp_reachability_remark") or "",
        "evidence_run_ids": [str(item.get("run_id") or "") for item in evidences],
        "evidence_paths": [str(item.get("raw_path") or "") for item in evidences],
    }


def latest_review_required(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    latest_by_asset: dict[str, dict[str, Any]] = {}
    for raw in records:
        for result in raw.get("results") or []:
            if not isinstance(result, dict):
                continue
            asset_id = result_asset_id(result)
            if not asset_id:
                continue
            latest_by_asset[asset_id] = {
                "run_id": raw.get("run_id"),
                "raw_path": raw.get("_path"),
                "result": result,
            }
    reviews: list[dict[str, Any]] = []
    for asset_id, item in sorted(latest_by_asset.items()):
        if has_ping_reachable_evidence(item["result"]) or has_tcp_open_evidence(item["result"]):
            reviews.append(build_review_required_item(asset_id, [item]))
    return reviews


def merge_fresh_candidate(plan_candidate: dict[str, Any], fresh_candidate: dict[str, Any]) -> dict[str, Any]:
    # Use freshly re-evaluated evidence/confirmation for mutation, but keep the
    # caller-visible planned action only when it matches the current confirmed action.
    merged = dict(fresh_candidate)
    if plan_candidate.get("planned_action") != fresh_candidate.get("planned_action"):
        merged["planned_action_mismatch"] = {
            "plan": plan_candidate.get("planned_action"),
            "fresh": fresh_candidate.get("planned_action"),
        }
    return merged


def evaluate_cleanup(profile: str, raw_dir: Path, state_dir: Path, output_dir: Path, *, write_plan: bool = True) -> dict[str, Any]:
    records = load_eligible_raw_records(raw_dir, profile)
    unreachable, latest_status = index_unreachable(records)
    confirmations = load_confirmations(state_dir)
    protections = load_protections(state_dir)
    candidates: list[dict[str, Any]] = []
    review_required: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    generated_at = now_iso()
    latest_required_run_ids = [str(raw.get("run_id") or "") for raw in records[-2:]]
    review_by_asset = {str(item.get("asset_id") or ""): item for item in latest_review_required(records)}
    review_required.extend(review_by_asset.values())
    review_ids = set(review_by_asset)

    for asset_id, evidences in sorted(unreachable.items()):
        last_two_or_less = evidences[-2:]
        latest_reachable = any(has_ping_reachable_evidence(item["result"]) or has_tcp_open_evidence(item["result"]) for item in last_two_or_less)
        if latest_reachable:
            review_item = build_review_required_item(asset_id, last_two_or_less)
            if asset_id in review_by_asset:
                review_by_asset[asset_id].update(review_item)
            else:
                review_by_asset[asset_id] = review_item
                review_required.append(review_item)
                review_ids.add(asset_id)
            continue
        if asset_id in review_ids:
            continue
        if latest_status.get(asset_id) != "unreachable":
            skipped.append({"asset_id": asset_id, "reason": "latest_status_not_unreachable"})
            continue
        if len(evidences) < 2:
            skipped.append({"asset_id": asset_id, "reason": "not_enough_eligible_unreachable_runs"})
            continue
        last_two = evidences[-2:]
        run_ids = [item.get("run_id") for item in last_two]
        if len(set(run_ids)) != 2:
            skipped.append({"asset_id": asset_id, "reason": "duplicate_run_id"})
            continue
        if [str(item or "") for item in run_ids] != latest_required_run_ids:
            skipped.append({"asset_id": asset_id, "reason": "not_recent_two_scheduled_runs"})
            continue
        ips = {str(item["result"].get("asset_ip") or "") for item in last_two}
        if len(ips) != 1:
            skipped.append({"asset_id": asset_id, "reason": "asset_ip_changed"})
            continue
        if is_protected(protections, profile, asset_id):
            skipped.append({"asset_id": asset_id, "reason": "protected"})
            continue
        asset_ip = next(iter(ips))
        confirmation = matching_confirmation(confirmations, profile, asset_id, asset_ip)
        if not confirmation:
            stale = next((item for item in confirmations if item.get("profile") == profile and item.get("asset_id") == asset_id), None)
            if stale:
                candidates.append(build_stale_confirmation_candidate(profile, asset_id, last_two, stale))
                continue
        candidates.append(build_candidate(profile, asset_id, last_two, confirmation))

    plan = {
        "profile": profile,
        "generated_at": generated_at,
        "raw_dir": str(raw_dir),
        "state_dir": str(state_dir),
        "candidates": candidates,
        "review_required": review_required,
        "skipped": skipped,
        "summary": {"candidates": len(candidates), "review_required": len(review_required), "skipped": len(skipped), "eligible_runs": len(records)},
    }
    if write_plan:
        output_dir.mkdir(parents=True, exist_ok=True)
        plan_path = output_dir / f"cleanup-plan-{dt.datetime.now().astimezone().strftime('%Y%m%d-%H%M%S')}.json"
        atomic_write_json(plan_path, plan)
        plan["plan_path"] = str(plan_path)
    return plan


def scrub_sensitive(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            lower = str(key).lower()
            if any(part in lower for part in SENSITIVE_KEY_PARTS):
                continue
            cleaned[key] = scrub_sensitive(item)
        return cleaned
    if isinstance(value, list):
        return [scrub_sensitive(item) for item in value]
    return value


def write_archive(output_dir: Path, candidate: dict[str, Any], asset_snapshot: dict[str, Any]) -> Path:
    stamp = dt.datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
    archive_dir = output_dir / "archive" / stamp
    path = archive_dir / f"{candidate['asset_id']}.json"
    payload = {
        "archived_at": now_iso(),
        "candidate": candidate,
        "asset_snapshot": scrub_sensitive(asset_snapshot),
    }
    atomic_write_json(path, payload)
    # Read-back makes archive-before-mutate structural, not just best effort.
    json.loads(path.read_text(encoding="utf-8"))
    return path


def current_asset_matches(candidate: dict[str, Any], asset: dict[str, Any]) -> bool:
    if str(asset.get("id") or "") != candidate.get("asset_id"):
        return False
    if str(asset.get("address") or "") != candidate.get("asset_ip"):
        return False
    expected_name = str(candidate.get("asset_name") or "")
    if expected_name and str(asset.get("name") or "") != expected_name:
        return False
    if asset.get("is_active") is False:
        return False
    return True


def delete_allowed(candidate: dict[str, Any], *, allow_delete: bool) -> bool:
    confirmation = candidate.get("confirmation") if isinstance(candidate.get("confirmation"), dict) else {}
    return (
        os.getenv("CLEANUP_ALLOW_DELETE", "").lower() == "true"
        and allow_delete
        and candidate.get("planned_action") == "delete"
        and confirmation.get("cleanup_action") == "delete"
        and confirmation.get("delete_ack") == f"DELETE {candidate.get('asset_id')}"
    )


def cleanup_apply_audit_fields(candidate: dict[str, Any], *, profile: str) -> dict[str, Any]:
    confirmation = candidate.get("confirmation") if isinstance(candidate.get("confirmation"), dict) else {}
    fields = {
        "profile": str(candidate.get("profile") or profile),
        "asset_id": candidate.get("asset_id"),
        "asset_name": str(candidate.get("asset_name") or confirmation.get("asset_name") or ""),
        "asset_ip": str(candidate.get("asset_ip") or confirmation.get("asset_ip") or ""),
    }
    for key in ("operator", "reason", "delete_ack"):
        value = confirmation.get(key) or candidate.get(key)
        if value:
            fields[key] = value
    return fields


def apply_cleanup_plan(
    plan: dict[str, Any],
    *,
    profile: str,
    state_dir: Path,
    output_dir: Path,
    client: Any | None = None,
    dry_run: bool = False,
    allow_delete: bool = False,
) -> dict[str, Any]:
    client = client or jms_host_ip_check.JumpServerClient(no_proxy=True)
    results: list[dict[str, Any]] = []
    output_dir.mkdir(parents=True, exist_ok=True)
    raw_dir_text = str(plan.get("raw_dir") or "")
    fresh_candidates: dict[str, dict[str, Any]] = {}
    rechecked_plan = False
    if raw_dir_text:
        fresh_plan = evaluate_cleanup(profile, Path(raw_dir_text), state_dir, output_dir, write_plan=False)
        fresh_candidates = index_candidates_by_asset(fresh_plan)
        rechecked_plan = True
    path = output_dir / f"cleanup-result-{dt.datetime.now().astimezone().strftime('%Y%m%d-%H%M%S')}.json"
    for candidate in plan.get("candidates") or []:
        asset_id = candidate.get("asset_id")
        fresh_candidate = fresh_candidates.get(str(asset_id)) if rechecked_plan else candidate
        if not fresh_candidate:
            results.append({"asset_id": asset_id, "action": candidate.get("planned_action") or "disable", "status": "skipped_not_current_candidate"})
            continue
        candidate = merge_fresh_candidate(candidate, fresh_candidate)
        action = candidate.get("planned_action") or "disable"
        item = {**cleanup_apply_audit_fields(candidate, profile=profile), "action": action, "result_path": str(path)}
        if candidate.get("planned_action_mismatch"):
            item.update({"status": "skipped_plan_action_changed", "planned_action_mismatch": candidate["planned_action_mismatch"]})
            results.append(item)
            continue
        if not is_cleanup_ready_candidate(candidate):
            state = candidate.get("confirmation_state") or "missing_confirmation"
            status_by_state = {
                "missing_confirmation": "skipped_missing_confirmation",
                "confirmed_wait_next_scheduled_run": "skipped_wait_next_scheduled_run",
                "stale_confirmation": "skipped_stale_confirmation",
                "invalid_confirmation": "skipped_invalid_confirmation",
            }
            item["status"] = status_by_state.get(str(state), f"skipped_{state}")
            if candidate.get("confirmation_reason"):
                item["reason"] = candidate["confirmation_reason"]
            results.append(item)
            continue
        if dry_run:
            item["status"] = "dry_run"
            results.append(item)
            continue
        status, asset = client.get(f"/api/v1/assets/assets/{asset_id}/", timeout=MUTATION_TIMEOUT)
        if status == 404:
            item["status"] = "already_absent"
            results.append(item)
            continue
        if status >= 400 or not isinstance(asset, dict):
            item.update({"status": "asset_fetch_failed", "api_status": status, "api_response": asset})
            results.append(item)
            continue
        if not current_asset_matches(candidate, asset):
            item["status"] = "skipped_asset_changed"
            results.append(item)
            continue
        try:
            archive_path = write_archive(output_dir, candidate, asset)
        except Exception as exc:  # noqa: BLE001 - archive errors must fail closed with evidence.
            item.update({"status": "archive_failed", "error": str(exc)})
            results.append(item)
            continue
        item["archive_path"] = str(archive_path)
        if action == "delete":
            if not delete_allowed(candidate, allow_delete=allow_delete):
                item["status"] = "skipped_delete_not_allowed"
                results.append(item)
                continue
            mutate_status, payload = client.delete(f"/api/v1/assets/assets/{asset_id}/", timeout=MUTATION_TIMEOUT)
            item.update({"api_operation": "delete", "api_status": mutate_status, "api_response": payload, "status": "deleted" if mutate_status < 400 else "delete_failed"})
        else:
            mutate_status, payload = client.patch(f"/api/v1/assets/assets/{asset_id}/", {"is_active": False}, timeout=MUTATION_TIMEOUT)
            item.update({"api_status": mutate_status, "api_response": payload, "status": "disabled" if mutate_status < 400 else "disable_failed"})
        results.append(item)
    result_payload = {"profile": profile, "generated_at": now_iso(), "dry_run": dry_run, "results": results}
    result_payload["result_path"] = str(path)
    atomic_write_json(path, result_payload)
    return result_payload


def notify_cleanup_delete_result(result_payload: dict[str, Any]) -> dict[str, Any]:
    try:
        notification = wecom_notify.send_cleanup_delete_notification(result_payload)
    except Exception as exc:  # noqa: BLE001 - notification failure must not hide cleanup result.
        notification = {"status": "failed", "error": str(exc)}
        print(f"提示：企业微信删除操作通知失败：{exc}", file=sys.stderr)
    result_payload["delete_notification"] = notification
    result_path = str(result_payload.get("result_path") or "")
    if result_path:
        try:
            atomic_write_json(Path(result_path), result_payload)
        except Exception as exc:  # noqa: BLE001 - notification persistence is audit-only after mutation.
            result_payload["delete_notification_persist"] = {"status": "failed", "error": str(exc)}
            print(f"提示：企业微信删除操作通知结果回写失败：{exc}", file=sys.stderr)
    return notification


def has_delete_attempt(result_payload: dict[str, Any]) -> bool:
    return any(
        isinstance(item, dict)
        and (item.get("status") == "deleted" or item.get("api_operation") == "delete")
        for item in result_payload.get("results") or []
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate and apply abandoned JumpServer host cleanup plans.")
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("evaluate", "apply"):
        p = sub.add_parser(command)
        p.add_argument("--profile", default=profile_env.DEFAULT_PROFILE)
        p.add_argument("--raw-dir", default="")
        p.add_argument("--state-dir", default="")
        p.add_argument("--output-dir", default="")
        p.add_argument("--dry-run", action="store_true")
        if command == "apply":
            p.add_argument("--plan", required=True)
            p.add_argument("--allow-delete", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    raw_dir = Path(args.raw_dir) if args.raw_dir else PROJECT_ROOT / profile_env.profile_path("artifacts/raw", args.profile)
    state_dir = Path(args.state_dir) if args.state_dir else cleanup_profile_state_dir(args.profile)
    output_dir = Path(args.output_dir) if args.output_dir else cleanup_output_dir(args.profile)
    if args.command == "evaluate":
        payload = evaluate_cleanup(args.profile, raw_dir, state_dir, output_dir, write_plan=True)
    else:
        plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
        payload = apply_cleanup_plan(plan, profile=args.profile, state_dir=state_dir, output_dir=output_dir, dry_run=args.dry_run, allow_delete=args.allow_delete)
        if has_delete_attempt(payload):
            notify_cleanup_delete_result(payload)
    print(json.dumps(payload, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
