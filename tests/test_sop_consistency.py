from pathlib import Path


def test_sop_matches_read_only_operating_boundary():
    sop = Path("SOP_JumpServer主机探测与IP配置检测.md").read_text(encoding="utf-8")

    assert "触发禁用" not in sop
    assert "is_active=false" not in sop
    assert "PATCH /api/v1/assets/assets/{id}/" not in sop
    assert "本项目不自动修改 JumpServer 资产状态" in sop
