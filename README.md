# JumpServer 主机探测与 IP 配置检测

这个项目通过 JumpServer REST API 和 Ops 作业批量检测纳管主机的连通性与 IP 配置类型，输出可归档、可同步到知识库的 Markdown 报告。

首版是只读工具：不会修改 JumpServer 资产，不会禁用主机，不会执行清理、重启或整改命令。

## 当前进展

- 已实现 JumpServer AccessKey HMAC-SHA256 签名鉴权。
- 已实现 `validate-auth`、`list-assets`、`detect` 三个 CLI 子命令。
- 已支持分页拉取活跃资产、按关键字筛选资产、跳过 Windows 资产。
- 已通过 JumpServer Ops 作业批量下发只读 Shell 探测命令。
- 已增强批量 Ops 日志分段匹配，兼容 JumpServer 将主机标签中的空格规范化为下划线等差异，减少不必要的单主机复核。
- 已支持对 `unreachable`、`probe_timeout`、`parse_error` 等不确定结果执行单主机 Ops 复核，复核成功后会更新为真实可达状态。
- 已支持提取主机所有全局 IPv4 地址，避免多 IP 主机只按默认路由 IP 比对导致误判。
- 已解析 Ops 日志并分类输出 `ok_static`、`warn_dhcp`、`manual_check`、`ip_mismatch`、`duplicate_asset`、`unreachable`、`probe_timeout`、`parse_error`、`skipped_windows`。
- 已生成带问题分类索引的 Markdown 报告和原始 JSON 运行记录，并自动维护 `jumpserver-host-ip-check-latest.md`。
- 已覆盖签名、资产归一化、重复资产标注、日志解析、报告写入等单元测试。

## 配置

复制示例配置后填写真实 JumpServer 地址和 Access Key：

```powershell
Copy-Item .env.example .env
```

```ini
JMS_URL=https://jumpserver.example.com
JMS_ACCESS_KEY_ID=replace-with-access-key-id
JMS_ACCESS_KEY_SECRET=replace-with-access-key-secret
JMS_NO_PROXY=true
JMS_ORG_ID=00000000-0000-0000-0000-000000000002
JMS_VERIFY_TLS=true
```

`.env` 已被 `.gitignore` 忽略，不要提交 Access Key。

## 常用命令

验证鉴权：

```powershell
python scripts/jms_host_ip_check.py --no-proxy validate-auth
```

查看活跃资产摘要：

```powershell
python scripts/jms_host_ip_check.py --no-proxy list-assets
```

指定单台资产摘要：

```powershell
python scripts/jms_host_ip_check.py --no-proxy list-assets --query 192.0.2.82
```

运行批量探测并生成 Markdown 报告：

```powershell
python scripts/jms_host_ip_check.py --no-proxy detect `
  --batch-size 50 `
  --timeout 120 `
  --poll-interval 3 `
  --recheck-timeout 60 `
  --recheck-concurrency 8 `
  --output-dir reports/yuque
```

默认会对批量探测中的不确定结果执行单主机复核，复核默认 8 并发、60 秒超时。若只想快速跑批量链路，可加 `--no-recheck`；若想先控制复核数量，可加 `--max-rechecks 20`。

小批量验收：

```powershell
python scripts/jms_host_ip_check.py --no-proxy detect --batch-size 1 --max-assets 1 --output-dir reports/yuque
```

指定单台主机验收：

```powershell
python scripts/jms_host_ip_check.py --no-proxy detect --query 192.0.2.82 --batch-size 1 --output-dir reports/yuque
```

## 同步到知识库

先生成最新报告，再交给你自己的 Markdown 同步脚本或知识库导入流程：

```powershell
python scripts\jms_host_ip_check.py --no-proxy detect --output-dir reports\yuque

python path\to\markdown_sync.py `
  reports\yuque\jumpserver-host-ip-check-latest.md `
  --title "JumpServer 主机探测与 IP 配置检测报告" `
  --slug jumpserver-host-ip-check `
  --audit-timestamp
```

测试单台主机并同步：

```powershell
python scripts\jms_host_ip_check.py --no-proxy detect --query 192.0.2.82 --batch-size 1 --output-dir reports\yuque

python path\to\markdown_sync.py `
  reports\yuque\jumpserver-host-ip-check-latest.md `
  --slug jumpserver-host-ip-check `
  --audit-timestamp
```

## 输出

默认输出目录：

```text
reports/yuque/
  jumpserver-host-ip-check-YYYYMMDD-HHMMSS.md
  jumpserver-host-ip-check-latest.md
artifacts/raw/
  jumpserver-host-ip-check-YYYYMMDD-HHMMSS.json
```

后续知识库同步脚本可以优先扫描或同步 `reports/yuque/jumpserver-host-ip-check-latest.md`，文档 slug 建议使用 `jumpserver-host-ip-check`。

Markdown 报告不包含 YAML front matter，首行固定为：

```markdown
# JumpServer 主机探测与 IP 配置检测报告
```

报告包含 `问题分类索引`、`异常主机`、`全量明细` 三块内容。`问题分类索引` 会按 `warn_dhcp`、`ip_mismatch`、`duplicate_asset`、`unreachable` 等状态给出简短主机列表，便于先定位问题类型；完整字段和全部记录仍在后面的明细表中。

## 分类

- `ok_static`：连通，固定 IP。
- `warn_dhcp`：连通，但检测到 DHCP。
- `manual_check`：连通，但无法自动判断 IP 类型。
- `ip_mismatch`：实际 IP 与 JumpServer 资产 IP 不一致。
- `duplicate_asset`：JumpServer 存在多条相同资产 IP 记录，优先作为历史遗留或重复录入问题标注。
- `unreachable`：Ops 返回连接失败或无主机输出。
- `probe_timeout`：批次任务创建失败或轮询超时。
- `parse_error`：主机有输出，但缺少固定探测 marker。
- `skipped_windows`：Windows 资产按 SOP 跳过。

`探测来源` 字段用于区分结果来源：`batch` 表示批量 Ops 探测；`single_recheck` 表示批量结果不确定但单主机复核成功；`batch+single_recheck` 表示单主机复核后仍未恢复。

## 测试

```powershell
python -m pytest
```
