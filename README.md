# JumpServer 主机探测与 IP 配置检测

这个项目通过 JumpServer REST API 和 Ops 作业批量检测纳管主机的连通性与 IP 配置类型，输出可归档、可同步到知识库的 Markdown 报告。

首版是只读工具：不会修改 JumpServer 资产，不会禁用主机，不会执行清理、重启或整改命令。

## 当前进展

- 已实现 JumpServer AccessKey HMAC-SHA256 签名鉴权。
- 已实现 `validate-auth`、`list-assets`、`detect` 三个 CLI 子命令。
- 已支持分页拉取活跃资产、按关键字筛选资产、跳过 Windows 资产。
- 已通过 JumpServer Ops 作业下发只读 Shell 探测命令；默认使用全量一次批量 job，payload 携带资产 ID 和节点 ID，对齐 Web 控制台链路。
- 已在执行前读取当前账号授权资产，未授权资产不提交 Ops，报告中标记为 `permission_denied`。
- 已支持提取主机所有全局 IPv4 地址，并默认排除 `172.*` Docker 常见地址段，避免多 IP 主机只按默认路由 IP 比对或容器网桥地址导致误判。
- 已解析 Ops 日志并分类输出 `ok_static`、`warn_dhcp`、`manual_check`、`ip_mismatch`、`duplicate_asset`、`unreachable`、`probe_timeout`、`ops_no_output`、`ops_module_error`、`permission_denied`、`no_account`、`parse_error`、`skipped_windows`。
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

运行准确探测并生成 Markdown 报告：

```powershell
python scripts/jms_host_ip_check.py --no-proxy detect `
  --execution-mode batch `
  --batch-size 0 `
  --timeout -1 `
  --wait-timeout 1200 `
  --poll-interval 30 `
  --output-dir reports/yuque
```

默认使用 `batch --batch-size 0`：所有当前账号有权限的非 Windows 资产一次提交 Ops job，payload 对齐 Web 控制台（`assets` + `nodes`、`timeout: -1`），本地默认 30 秒轮询一次，最多等待 1200 秒。

小批量验收：

```powershell
python scripts/jms_host_ip_check.py --no-proxy detect --max-assets 1 --output-dir reports/yuque
```

指定单台主机验收：

```powershell
python scripts/jms_host_ip_check.py --no-proxy detect --query 192.0.2.82 --output-dir reports/yuque
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
- `ops_no_output`：Ops 任务成功但没有返回主机输出，不等同于主机不可达。
- `ops_module_error`：Ops/Ansible 模块执行异常。
- `permission_denied`：当前 API/Ops 权限无法访问该资产。
- `no_account`：JumpServer 未找到该资产可用登录账号。
- `parse_error`：主机有输出，但缺少固定探测 marker。
- `skipped_windows`：Windows 资产按 SOP 跳过。

`探测来源` 字段目前固定为 `batch` 或 `skipped`。`ops_no_output` 表示 Ops 执行链路没有回传主机输出，需要通过 JumpServer 交互连接或其他链路抽样核查。

## 测试

```powershell
python -m pytest
```
