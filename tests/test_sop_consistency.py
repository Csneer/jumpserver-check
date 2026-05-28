from pathlib import Path


def test_sop_matches_default_read_only_boundary_and_cleanup_gate():
    sop = Path("SOP_JumpServer主机探测与IP配置检测.md").read_text(encoding="utf-8")

    assert "触发禁用" not in sop
    assert "默认巡检链路不自动修改 JumpServer 资产状态" in sop
    assert "只有显式启用废弃主机清理扩展" in sop
    assert "管理员确认" in sop
    assert "下一次正式巡检复核" in sop
    assert "PATCH is_active=false" in sop
