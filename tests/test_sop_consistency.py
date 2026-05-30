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
    assert check.DETECTION_COMMAND in sop
    assert '"args": "<复合探测命令>"' not in sop
    assert "python3 scripts/run_multi_check.py --profiles local --no-proxy --require-wecom" in sop


def test_sop_documents_ping_flags_and_raw_reachability_contract():
    sop = Path("SOP_JumpServer主机探测与IP配置检测.md").read_text(encoding="utf-8")

    for text in (
        "--ip-reachability-check",
        "--ip-ping-count",
        "--ip-ping-timeout",
        "--ip-ping-workers",
        "ops_connectivity",
        "ip_reachability",
        "ip_reachability_checked_at",
        "ip_reachability_remark",
        "ops_task_ids",
        "ip_reachability_config",
    ):
        assert text in sop


def test_sop_documents_diff_archive_wecom_delete_and_tcp_reachability_policy():
    sop = Path("SOP_JumpServer主机探测与IP配置检测.md").read_text(encoding="utf-8")

    required = [
        "对比上一轮稳定结果",
        "无主机信息变动",
        "已跳过语雀归档",
        "差异化通知",
        "真实删除动作必须推送企业微信管理操作通知",
        "delete_ack",
        "--tcp-reachability-check",
        "--tcp-reachability-ports 22",
        "tcp_reachability",
        "tcp_reachability_config",
        "jumpserver_unreachable_tcp_open",
        "部署机 TCP/SSH 端口开放，必须人工复核",
        "| unreachable | unknown/unreachable/not_checked | open | `jumpserver_unreachable_tcp_open`",
        "不得 shell 拼接",
        "官方资产探测 API",
        "/api/docs/",
        "artifacts/state/<profile>/last-stable-host-snapshot.json",
        "不得无条件为每次成功巡检创建新的语雀时间戳文档",
        "快照缺失或 JSON 损坏",
        "jumpserver_unreachable_ip_reachable  >  jumpserver_unreachable_tcp_open",
        "result_path",
        "workflow/apply 元数据",
    ]
    for text in required:
        assert text in sop


def test_sop_rejects_unconditional_weekly_yuque_archive_wording():
    sop = Path("SOP_JumpServer主机探测与IP配置检测.md").read_text(encoding="utf-8")

    assert "这样每周定时任务都会创建或更新独立的时间戳文档" not in sop
    assert "只有当本轮主机信息相对上一轮稳定快照发生变化" in sop
