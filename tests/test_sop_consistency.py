from pathlib import Path


def test_sop_matches_default_read_only_boundary_and_cleanup_gate():
    sop = Path("SOP_JumpServer主机探测与IP配置检测.md").read_text(encoding="utf-8")

    assert "触发禁用" not in sop
    assert "默认巡检链路不自动修改 JumpServer 资产状态" in sop
    assert "只有显式启用废弃主机清理扩展" in sop
    assert "管理员确认" in sop
    assert "下一次正式巡检复核" in sop
    assert "PATCH is_active=false" in sop


from scripts import jms_host_ip_check as check


def test_sop_embeds_detection_command_hash_and_no_placeholder_args():
    sop = Path("SOP_JumpServer主机探测与IP配置检测.md").read_text(encoding="utf-8")
    command_hash = __import__("hashlib").sha256(check.DETECTION_COMMAND.encode("utf-8")).hexdigest()

    assert f"DETECTION_COMMAND_SHA256={command_hash}" in sop
    assert '"args": "<复合探测命令>"' not in sop
    assert "python3 scripts/run_multi_check.py --profiles local --no-proxy --require-wecom" in sop
