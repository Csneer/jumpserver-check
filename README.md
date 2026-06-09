# JumpServer 主机探测与 IP 配置检测

这个项目通过 JumpServer REST API 和 Ops 作业批量检测纳管主机的连通性与 IP 配置类型，输出可归档 Markdown/JSON 报告，并支持同步到语雀、推送企业微信结果通知。

首版是只读工具：不会修改 JumpServer 资产，不会禁用主机，不会执行清理、重启或整改命令。

## 当前进展

- 已实现 JumpServer AccessKey HMAC-SHA256 签名鉴权。
- 已实现 `validate-auth`、`list-assets`、`detect` 三个探测 CLI 子命令。
- 已实现 `run_weekly_check.py` 全流程编排：探测、语雀同步、企业微信通知。
- 已实现周巡检稳定快照对比：每次仍保留本地 raw/latest/workflow 证据；主机信息无变化时跳过新的语雀时间戳归档，并在企业微信中提示“与上一轮结果对比无主机信息变动，已跳过语雀归档”。
- 已支持分页拉取活跃资产、按关键字筛选资产、跳过 Windows 资产。
- 已通过 JumpServer Ops 作业下发只读 Shell 探测命令；默认使用全量一次批量 job，payload 携带资产 ID 和节点 ID，对齐 Web 控制台链路。
- 已在执行前读取当前账号授权资产，未授权资产不提交 Ops，报告中标记为 `permission_denied`。
- 已支持部署机侧 IP ping 与可选 TCP/SSH 端口探测证据；TCP 开放但 JumpServer Ops 不可达会标记为 `jumpserver_unreachable_tcp_open`，仅进入人工复核，不会进入自动清理候选。
- 已支持提取主机所有全局 IPv4 地址，并默认仅排除 Docker 默认 `172.17.*` 网桥地址，避免误过滤合法 `172.16.0.0/12` 内网主机 IP。
- 已解析 Ops 日志并分类输出 `ok_static`、`warn_dhcp`、`manual_check`、`ip_mismatch`、`duplicate_asset`、`jumpserver_unreachable_ip_reachable`、`jumpserver_unreachable_tcp_open`、`unreachable`、`api_error`、`log_fetch_error`、`probe_timeout`、`ops_no_output`、`ops_module_error`、`ops_task_failed`、`permission_denied`、`no_account`、`parse_error`、`probe_script_error`、`skipped_non_linux`、`skipped_windows`。
- 已生成带问题分类索引的 Markdown 报告和原始 JSON 运行记录，并自动维护 `jumpserver-host-ip-check-latest.md`。
- 已内置语雀 Markdown 同步和企业微信 Markdown 通知脚本，不依赖外部 `yuqeu_sync` 目录。
- 已实现废弃主机确认/清理扩展：默认只读；真实 delete/delete_failed 尝试会发送企业微信管理操作通知并把通知结果写入 cleanup result/workflow 元数据。
- 已覆盖签名、资产归一化、重复资产标注、日志解析、报告写入、周巡检快照、TCP 复核、清理门控、企业微信通知等单元测试。


## 统一入口与兼容脚本

阶段一新增统一 facade：优先使用 `python -m jumpserver_check <command>`（或安装后 `jumpserver-check <command>`）管理所有功能；历史 `scripts/*.py` 命令继续兼容，作为现有 cron/systemd/SOP 的兼容入口保留。facade 只做薄分发，不复制业务规则；profile/env/path/default/run metadata 由 `jumpserver_check.runtime.RuntimeContext` 统一计算。

| 功能 | 统一入口（优先） | 兼容旧入口 |
| --- | --- | --- |
| 配置预检 | `python -m jumpserver_check preflight --json` | `python scripts/preflight_check.py --json` |
| 资产探测/列表 | `python -m jumpserver_check detect --no-proxy detect ...` | `python scripts/jms_host_ip_check.py --no-proxy detect ...` |
| 单 profile 周巡检 | `python -m jumpserver_check weekly --profile prod --no-proxy` | `python scripts/run_weekly_check.py --profile prod --no-proxy` |
| 多 profile 并发 | `python -m jumpserver_check multi --profiles prod,test --parallel 2` | `python scripts/run_multi_check.py --profiles prod,test --parallel 2` |
| 清理计划/执行 | `python -m jumpserver_check cleanup evaluate --profile prod` | `python scripts/host_cleanup.py evaluate --profile prod` |
| 清理确认 UI | `python -m jumpserver_check admin serve --profile prod` | `python scripts/cleanup_admin_server.py --profile prod` |

安全边界不变：weekly 默认不执行 cleanup evaluate/apply；cleanup apply 默认 dry-run/禁删，真实 delete 仍必须同时满足环境变量、CLI、确认记录和审计通知门控。多 profile 默认路径继续隔离到 `reports/yuque/<profile>/`、`artifacts/raw/<profile>/`、`artifacts/state/<profile>/`、`artifacts/workflow/<profile>/` 和 `artifacts/cleanup/<profile>/`。

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

YUQUE_TOKEN=replace-with-yuque-token
YUQUE_REPO_NAMESPACE=your-login-or-group/your-repo
YUQUE_URL=
YUQUE_TARGET_TOC_UUID=
YUQUE_SIBLING_URL=
YUQUE_PUBLIC=0

WECOM_WEBHOOK_URL=
WECOM_CHANNEL=wecom
WECOM_DELETE_DETAIL_LIMIT=5

CHECK_WAIT_TIMEOUT=1200
CHECK_POLL_INTERVAL=30
CHECK_OUTPUT_DIR=reports/yuque
CHECK_IP_REACHABILITY=true
CHECK_IP_PING_COUNT=1
CHECK_IP_PING_TIMEOUT=1
CHECK_IP_PING_WORKERS=32
CHECK_TCP_REACHABILITY=false
CHECK_TCP_REACHABILITY_PORTS=22
CHECK_TCP_REACHABILITY_TIMEOUT=1
CHECK_TCP_REACHABILITY_WORKERS=32
```

`.env` 已被 `.gitignore` 忽略，不要提交 Access Key。

## 多环境配置

多套 JumpServer 不需要复制项目。每套环境使用一个 profile env：

```text
configs/profiles/prod.env
configs/profiles/test.env
```

可以从 `configs/profiles/example.env.example` 复制。`configs/profiles/*.env` 已被忽略，不会提交密钥。项目根目录 `.env` 可放共享默认值，profile env 中的同名配置会覆盖它。

单环境巡检：

```powershell
python scripts/jumpserver_check.py weekly --profile prod --no-proxy --require-wecom
```

显式指定配置文件：

```powershell
python scripts/jumpserver_check.py weekly --profile prod --env-file configs/profiles/prod.env --no-proxy
```

多环境并发巡检：

```powershell
python scripts/jumpserver_check.py multi --profiles prod,test,pre --parallel 3 --no-proxy --require-wecom
```

每个 profile 默认使用独立输出目录：

```text
reports/yuque/<profile>/
artifacts/raw/<profile>/
artifacts/state/<profile>/jms-host-ip-check-inflight.json
artifacts/state/<profile>/last-stable-host-snapshot.json
artifacts/workflow/<profile>/
```

语雀也按 profile 区分。每个 profile env 可单独配置 `YUQUE_REPO_NAMESPACE`、`YUQUE_TARGET_TOC_UUID` 或 `YUQUE_SIBLING_URL`，因此可以分布到不同知识库或不同目录。未显式配置标题和 slug 时，默认会自动带 profile，例如 `JumpServer 主机探测与 IP 配置检测报告 - prod`、`jumpserver-host-ip-check-prod-YYYYMMDD-HHMMSS`。

## 统一入口与兼容命令映射

第一阶段统一管理入口为 `scripts/jumpserver_check.py`。旧 `scripts/*.py` 命令继续兼容；推荐新 SOP/临时命令优先使用统一入口，已有 cron/systemd 可按原命令运行。Facade 只做命令分发，profile/env/path/defaults 由 `scripts/profile_env.py` 的 `RuntimeContext` 统一计算，cleanup 默认仍为只读且必须显式传入 cleanup flag 才会 evaluate/apply。

| 统一入口 | 兼容旧命令 | 说明 |
|---|---|---|
| `python scripts/jumpserver_check.py weekly ...` | `python scripts/run_weekly_check.py ...` | 单 profile 周巡检、语雀同步、企业微信通知 |
| `python scripts/jumpserver_check.py multi ...` | `python scripts/run_multi_check.py ...` | 多 profile 并发周巡检 |
| `python scripts/jumpserver_check.py detect ...` | `python scripts/jms_host_ip_check.py detect ...` | 手工探测；统一入口可省略 `detect` 子命令 |
| `python scripts/jumpserver_check.py preflight ...` | `python scripts/preflight_check.py ...` | profile 配置预检 |
| `python scripts/jumpserver_check.py cleanup evaluate/apply ...` | `python scripts/host_cleanup.py evaluate/apply ...` | cleanup 计划评估/执行；默认不删除，delete 仍需五重门控 |
| `python scripts/jumpserver_check.py admin ...` | `python scripts/cleanup_admin_server.py ...` | cleanup 确认管理页面 |
| `python scripts/jumpserver_check.py notify ...` | `python scripts/wecom_notify.py ...` | 企业微信通知 |
| `python scripts/jumpserver_check.py yuque ...` | `python scripts/yuque_markdown_sync.py ...` | Markdown 同步语雀 |

## 常用命令

每周全流程巡检、同步语雀并推送企业微信：

```powershell
python scripts/jumpserver_check.py weekly --no-proxy
```

正式周巡检建议显式标记来源，便于稳定快照对比和清理证据链使用：

```powershell
python scripts/jumpserver_check.py weekly `
  --profile prod `
  --no-proxy `
  --run-source weekly_scheduled `
  --cleanup-evidence-eligible
```

`weekly_scheduled` 模式会维护 `artifacts/state/<profile>/last-stable-host-snapshot.json`：

- 首次运行、快照缺失或主机信息变化：同步新的语雀时间戳归档，并更新稳定快照。
- 主机信息无变化：跳过新的语雀时间戳归档，只更新本地 workflow/raw/latest 证据和快照检查时间；企业微信会附带“与上一轮结果对比无主机信息变动，已跳过语雀归档”。
- 探测失败、raw JSON 缺失/损坏、或 raw 中没有带 `asset_id`/`asset_ip`/`asset_name` 的可用主机行：fail-closed，不会覆盖稳定快照。

部署机侧 TCP/SSH 端口探测默认关闭；需要用 SSH 端口开放状态辅助复核时显式启用：

```powershell
python scripts/jumpserver_check.py weekly `
  --profile prod `
  --no-proxy `
  --run-source weekly_scheduled `
  --tcp-reachability-check `
  --tcp-reachability-ports 22 `
  --tcp-reachability-timeout 1 `
  --tcp-reachability-workers 32
```

TCP 探测使用 Python socket，不依赖 `nc` 或 shell 拼接。它只会在 JumpServer Ops 已判定 `unreachable` 且 ping 未可达时运行；如果 SSH/TCP 端口开放，状态会降级为“需复核”，不会加速清理。

全量批量探测默认支持中断接续：创建 JumpServer Ops job 后会把 `task_id` 写入 `artifacts/state/jms-host-ip-check-inflight.json`。如果本地脚本中断但 JumpServer job 仍在或已完成，下次运行会优先接续该任务并解析日志，不会重复提交新 job。需要强制新建任务时使用：

```powershell
python scripts/jumpserver_check.py weekly --no-proxy --no-resume
```

全流程 dry-run 验证：

```powershell
python scripts/jumpserver_check.py weekly --no-proxy --max-assets 1 --dry-run-yuque --dry-run-notify
```

只检查 `.env` 配置是否完整：

```powershell
python scripts/preflight_check.py --json
```

检查指定 profile：

```powershell
python scripts/preflight_check.py --profile prod --require-wecom --json
```

企业微信默认可不配置；如果希望定时任务强制要求企业微信 Webhook：

```powershell
python scripts/preflight_check.py --require-wecom
python scripts/jumpserver_check.py weekly --no-proxy --require-wecom
```

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

默认使用 `batch --batch-size 0`：所有当前账号有权限且明确识别为 Linux 的资产一次提交 Ops job，payload 对齐 Web 控制台（`assets` + `nodes`、`timeout: -1`），本地默认 30 秒轮询一次，最多等待 1200 秒。

小批量验收：

```powershell
python scripts/jms_host_ip_check.py --no-proxy detect --max-assets 1 --output-dir reports/yuque
```

指定单台主机验收：

```powershell
python scripts/jms_host_ip_check.py --no-proxy detect --query 192.0.2.82 --output-dir reports/yuque
```

## 同步到知识库

先生成最新报告，再使用项目内置同步脚本上传语雀：

```powershell
python scripts\jms_host_ip_check.py --no-proxy detect --output-dir reports\yuque

python scripts\yuque_markdown_sync.py `
  reports\yuque\jumpserver-host-ip-check-latest.md `
  --title "JumpServer 主机探测与 IP 配置检测报告" `
  --slug jumpserver-host-ip-check `
  --audit-timestamp `
  --sibling-url "https://leyaoyao.yuque.com/vurq8u/tiatz9/jumpserver-host-ip-check-20260520-112511"
```

也可以在 `.env` 中配置 `YUQUE_SIBLING_URL`，`run_weekly_check.py` 会自动把新报告挂到该文档同级目录。

测试单台主机并同步：

```powershell
python scripts\jms_host_ip_check.py --no-proxy detect --query 192.0.2.82 --batch-size 1 --output-dir reports\yuque

python scripts\yuque_markdown_sync.py `
  reports\yuque\jumpserver-host-ip-check-latest.md `
  --slug jumpserver-host-ip-check `
  --audit-timestamp
```

企业微信通知脚本可单独复用：

```powershell
python scripts\wecom_notify.py `
  --status success `
  --title "JumpServer 每周主机巡检" `
  --report-path reports\yuque\jumpserver-host-ip-check-latest.md `
  --yuque-url "https://www.yuque.com/example/repo/doc"
```

`WECOM_CHANNEL` 默认是 `wecom`，发送企业微信原生 Markdown payload。如果 Webhook 指向自建转发器，可按转发器协议改为 `wecom_text` 或 `wecom_relay`；`wecom_relay` 使用 Alertmanager 风格 payload。

Linux crontab 示例（只读巡检，不含清理）：

```cron
0 9 * * 1 cd /path/to/jumpserver-check && flock -n /tmp/jumpserver-check.lock python3 scripts/jumpserver_check.py weekly --no-proxy --require-wecom >> logs/weekly-check.log 2>&1
```

多环境 crontab 示例（含废弃主机清理全流程）：

```cron
0 9 * * 1 cd /path/to/jumpserver-check && flock -n /tmp/jumpserver-check-all.lock python3 scripts/jumpserver_check.py multi --profiles prod,test --parallel 2 --no-proxy --require-wecom --run-source weekly_scheduled --cleanup-evidence-eligible --cleanup-evaluate --cleanup-apply-confirmed --cleanup-allow-delete >> logs/weekly-check.log 2>&1
```

## 输出

默认 profile 兼容原输出目录：

```text
reports/yuque/
  jumpserver-host-ip-check-YYYYMMDD-HHMMSS.md
  jumpserver-host-ip-check-latest.md
artifacts/raw/
  jumpserver-host-ip-check-YYYYMMDD-HHMMSS.json
artifacts/workflow/
  weekly-workflow-YYYYMMDD-HHMMSS.json
artifacts/state/
  jms-host-ip-check-inflight.json
  last-stable-host-snapshot.json
```

非 default profile 会自动隔离到 `<profile>` 子目录，见上方“多环境配置”。

后续知识库同步脚本可以优先扫描或同步 `reports/yuque/jumpserver-host-ip-check-latest.md`，文档 slug 建议使用 `jumpserver-host-ip-check`。

Markdown 报告不包含 YAML front matter，首行固定为：

```markdown
# JumpServer 主机探测与 IP 配置检测报告
```

报告包含 `问题分类索引`、`异常主机`、`全量明细` 三块内容。`问题分类索引` 会按 `warn_dhcp`、`ip_mismatch`、`duplicate_asset`、`jumpserver_unreachable_ip_reachable`、`jumpserver_unreachable_tcp_open`、`unreachable` 等状态给出简短主机列表，便于先定位问题类型；重复资产会同时保留原始异常状态，因此分类数量可能存在有意重叠，完整字段和全部记录仍在后面的明细表中。

raw JSON 还会保留正交可达性字段：

| 字段 | 说明 |
|---|---|
| `ops_connectivity` | JumpServer Ops 通道维度：`ok` / `unreachable` / `skipped` |
| `ip_reachability` | 部署机 ping 维度：`reachable` / `unreachable` / `unknown` / `not_checked` |
| `tcp_reachability` | 部署机 TCP 维度：`open` / `closed` / `unknown` / `not_checked` |
| `ip_reachability_config` / `tcp_reachability_config` | 本次部署机侧探测配置 |

## 分类

- `ok_static`：连通，采集到可比对主机 IP，且固定 IP。
- `warn_dhcp`：连通，采集到可比对主机 IP，但检测到 DHCP。
- `manual_check`：连通，但无法自动判断 IP 类型，或未采集到可比对的主机 IP。
- `ip_mismatch`：实际 IP 与 JumpServer 资产 IP 不一致。
- `duplicate_asset`：JumpServer 存在多条相同资产 IP 记录，优先作为历史遗留或重复录入问题标注；原始探测状态仍会保留并参与异常分类汇总。
- `jumpserver_unreachable_ip_reachable`：JumpServer Ops 不可达，但部署机侧 ping 可达；需要人工复核，不进入清理候选。
- `jumpserver_unreachable_tcp_open`：JumpServer Ops 不可达且 ping 未可达，但部署机侧 TCP/SSH 端口开放；需要人工复核，不进入清理候选。
- `unreachable`：Ops 返回连接失败或无主机输出。
- `api_error`：JumpServer API 或 Ops job 创建/状态查询异常。
- `log_fetch_error`：Ops 任务结束后日志接口失败或分页中断。
- `probe_timeout`：批次任务创建失败或轮询超时。
- `ops_no_output`：Ops 任务成功但没有返回主机输出，不等同于主机不可达。
- `ops_module_error`：Ops/Ansible 模块执行异常。
- `ops_task_failed`：JumpServer Ops 任务整体失败，只有没有可比对日志/摘要证据的资产才保留该状态；其余可解析资产仍按日志结果分类。
- `permission_denied`：当前 API/Ops 权限无法访问该资产。
- `no_account`：JumpServer 未找到该资产可用登录账号。
- `parse_error`：主机有输出，但缺少固定探测 marker。
- `probe_script_error`：远端只读探测脚本发生 shell 语法或关键命令执行异常。
- `skipped_non_linux`：非 Linux / 未知平台资产按 SOP 跳过，不提交 Linux shell Ops。
- `skipped_windows`：Windows 资产按 SOP 跳过。

`探测来源` 字段目前固定为 `batch` 或 `skipped`。`ops_no_output` 表示 Ops 执行链路没有回传主机输出，需要通过 JumpServer 交互连接或其他链路抽样核查。

探测命令调整请先阅读 [DETECTION_COMMAND_GUIDE.md](docs/DETECTION_COMMAND_GUIDE.md)。

## 测试

```powershell
python -m pytest
```

## 废弃主机确认与清理（可选扩展）

默认巡检仍然只读，不会修改 JumpServer 资产。废弃主机清理需要显式启用，并采用”最近两次 eligible 定时巡检不可达 + 页面确认 + 确认后的下次正式巡检复核 + apply 前重新门控 + 存档后清理”的五重门控。

### 完整流程

一个完整的清理周期跨越三次定时巡检：

```
第 1 周                          第 2 周                          第 3 周
┌──────────────────┐            ┌──────────────────┐            ┌──────────────────┐
│ 定时巡检 (带 eligible)        │ 定时巡检 (带 eligible)        │ 定时巡检 (带 eligible)        │
│ → 产出 eligible 证据          │ → 产出新 eligible 证据        │ → 产出新 eligible 证据        │
│ → cleanup-evaluate            │ → cleanup-evaluate            │ → cleanup-evaluate            │
│   生成候选计划                 │   候选状态更新                 │   门控通过                     │
└──────────────────┘            │                                │ → cleanup-apply-confirmed     │
         │                      │ 管理员在 Admin UI 确认         │   执行 disable/delete         │
         ▼                      │ （确认引用第 1 周证据）        └──────────────────┘
  Admin UI 展示候选              │                                │
  管理员可查看但                 └──────────────────┘                  │
  尚未确认                              │                             ▼
                                最新证据 ≠ 确认引用的证据        JumpServer 资产被禁用/删除
                                门控判定：需等待下一轮             企业微信通知已发送
```

关键规则：管理员确认时引用的证据 run 必须早于最新一次 eligible 巡检，门控才判定为”已确认”。如果确认引用的证据就是最新 run，系统会标记 `confirmed_wait_next_scheduled_run`，等待下一次巡检产生新证据。

### 环境变量

清理相关环境变量（在 `.env` 或 profile env 中配置）：

```env
# Admin UI 服务
CLEANUP_ADMIN_TOKEN=replace-with-a-strong-token
CLEANUP_ADMIN_PROFILE=local
# 可选：额外允许展示的 JumpServer 配置，逗号分隔；configs/profiles/*.env 也会自动发现。
CLEANUP_ADMIN_PROFILES=prod-a,prod-b
CLEANUP_ADMIN_HOST=127.0.0.1
CLEANUP_ADMIN_PORT=8088

# 企业微信通知（Admin UI 操作后推送）
WECOM_NOTIFY_ADMIN_ACTIONS=1
ACCESS_URL=http://192.168.1.10:8088

# 允许通过门控的 delete 动作（不配置则只允许 disable）
CLEANUP_ALLOW_DELETE=false
```

`ACCESS_URL` 是 admin 管理页面的访问地址，用于企业微信通知中的可点击链接，方便团队成员直接从通知进入管理页面。

### Admin UI 操作页面

启动本地确认页面（临时前台运行）：

```bash
CLEANUP_ADMIN_TOKEN=replace-with-local-token \
python scripts/jumpserver_check.py admin --profile local --host 127.0.0.1 --port 8088
```

页面默认会要求先登录，登录口令就是服务端配置的 `CLEANUP_ADMIN_TOKEN`。登录前不会加载候选主机、原始 JSON 或多 JumpServer profile 列表；登录后可以在页面右侧选择 JumpServer 配置分别查看各自的废弃候选。profile 来源包括启动参数 `--profile`、`CLEANUP_ADMIN_PROFILES` / `--profiles` 显式白名单，以及 `configs/profiles/*.env` 中发现的配置文件。

Admin UI 提供三个操作按钮：

| 按钮 | 作用 | 写入文件 |
|---|---|---|
| **确认废弃** | 弹出二级选择「禁用（推荐）」或「删除（危险）」 | `cleanup_confirmed_hosts.json` |
| **保护** | 标记为不应清理的主机 | `cleanup_protected_hosts.json` |
| **需复查** | 标记为需要进一步确认 | `cleanup_review_hosts.json` |

确认废弃时选择”删除”需要额外的 `delete_ack` 确认。所有写操作完成后会触发企业微信通知（需配置 `WECOM_NOTIFY_ADMIN_ACTIONS=1`）。

长期运行建议使用 systemd 服务：

```bash
sudo bash scripts/install_cleanup_admin_service.sh
sudo systemctl status jumpserver-cleanup-admin.service
```

默认监听 `127.0.0.1:8088`，推荐通过 SSH 端口转发访问；如果要直接访问 `http://<server>:8088/`，可将 `CLEANUP_ADMIN_HOST=0.0.0.0`，但必须配置强 token。

### CLI 参数说明

清理相关参数**必须与 `--run-source weekly_scheduled` 一起使用**：

| 参数 | 作用 |
|---|---|
| `--cleanup-evidence-eligible` | **必须**。将本次探测结果标记为 cleanup 有效证据。不带此参数的巡检结果不会进入证据链，cleanup evaluate 会忽略该次 run |
| `--cleanup-evaluate` | 巡检后生成废弃主机清理候选计划 |
| `--cleanup-apply-confirmed` | 对已确认且通过门控的资产执行清理 |
| `--cleanup-dry-run` | 清理 apply 只演练，不调用 JumpServer mutation API |
| `--cleanup-allow-delete` | 允许通过五重门控的 delete 动作 |
| `--run-source weekly_scheduled` | 标记为定时巡检来源，cleanup evaluate 只认此来源的 raw 数据 |

> **重要**：`--cleanup-evidence-eligible` 是整个清理流程的基础。不带此参数的巡检不会产出有效证据，导致 cleanup evaluate 看不到候选主机，已有确认也会因”确认引用最新 run”被门控跳过。

### 统一入口与兼容命令映射

第一阶段统一管理入口为 `scripts/jumpserver_check.py`。旧 `scripts/*.py` 命令继续兼容；推荐新 SOP/临时命令优先使用统一入口，已有 cron/systemd 可按原命令运行。Facade 只做命令分发，profile/env/path/defaults 由 `scripts/profile_env.py` 的 `RuntimeContext` 统一计算，cleanup 默认仍为只读且必须显式传入 cleanup flag 才会 evaluate/apply。

| 统一入口 | 兼容旧命令 | 说明 |
|---|---|---|
| `python scripts/jumpserver_check.py weekly ...` | `python scripts/run_weekly_check.py ...` | 单 profile 周巡检、语雀同步、企业微信通知 |
| `python scripts/jumpserver_check.py multi ...` | `python scripts/run_multi_check.py ...` | 多 profile 并发周巡检 |
| `python scripts/jumpserver_check.py detect ...` | `python scripts/jms_host_ip_check.py detect ...` | 手工探测；统一入口可省略 `detect` 子命令 |
| `python scripts/jumpserver_check.py preflight ...` | `python scripts/preflight_check.py ...` | profile 配置预检 |
| `python scripts/jumpserver_check.py cleanup evaluate/apply ...` | `python scripts/host_cleanup.py evaluate/apply ...` | cleanup 计划评估/执行；默认不删除，delete 仍需五重门控 |
| `python scripts/jumpserver_check.py admin ...` | `python scripts/cleanup_admin_server.py ...` | cleanup 确认管理页面 |
| `python scripts/jumpserver_check.py notify ...` | `python scripts/wecom_notify.py ...` | 企业微信通知 |
| `python scripts/jumpserver_check.py yuque ...` | `python scripts/yuque_markdown_sync.py ...` | Markdown 同步语雀 |

## 常用命令

单环境巡检 + 清理（先 dry-run 验证）：

```bash
python3 scripts/run_weekly_check.py \
  --profile local \
  --no-proxy \
  --run-source weekly_scheduled \
  --cleanup-evidence-eligible \
  --cleanup-evaluate \
  --cleanup-apply-confirmed \
  --cleanup-dry-run
```

正式执行（去掉 `--cleanup-dry-run`）：

```bash
python3 scripts/run_weekly_check.py \
  --profile local \
  --no-proxy \
  --require-wecom \
  --run-source weekly_scheduled \
  --cleanup-evidence-eligible \
  --cleanup-evaluate \
  --cleanup-apply-confirmed \
  --cleanup-allow-delete
```

多环境并发巡检 + 清理：

```bash
python3 scripts/run_multi_check.py \
  --profiles local,uat \
  --parallel 2 \
  --no-proxy \
  --require-wecom \
  --run-source weekly_scheduled \
  --cleanup-evidence-eligible \
  --cleanup-evaluate \
  --cleanup-apply-confirmed \
  --cleanup-allow-delete
```

只生成清理候选计划（不执行清理）：

```bash
python3 scripts/run_weekly_check.py \
  --profile local \
  --no-proxy \
  --run-source weekly_scheduled \
  --cleanup-evidence-eligible \
  --cleanup-evaluate
```

### 清理动作说明

真实清理默认执行 `PATCH is_active=false`，让资产退出后续巡检但保留 JumpServer 记录。`apply` 会重新读取最新 raw 与确认/保护清单，旧 plan 不能绕过保护或确认变更；确认后未经历下一次正式巡检会跳过。

`DELETE` 默认不启用；如需启用必须同时满足：
- 环境变量 `CLEANUP_ALLOW_DELETE=true`
- CLI 参数 `--cleanup-allow-delete`
- 确认记录中 `cleanup_action` 为 `delete`
- 确认记录中包含 `delete_ack` 字段
- 计划动作与确认动作一致

真实 DELETE API 尝试（包括 `deleted` 和 `delete_failed`）会触发企业微信“主机清理删除操作”通知。通知会汇总本次 apply 中的删除尝试数、删除成功数、删除失败数，并默认只展开前 5 条必要明细（可通过 `WECOM_DELETE_DETAIL_LIMIT` 调整）；超过上限时提示“其余 N 条请查看清理结果 JSON”。完整审计字段仍保存在 `cleanup-result-*.json`，包括 profile、资产 ID/名称/IP、操作人、原因、`delete_ack`、存档路径、结果路径和 HTTP 状态。通知发送失败或通知结果回写失败不会掩盖清理结果，会记录到 `delete_notification` / `delete_notification_persist` 元数据中。

### 目录结构

清理相关的文件按 profile 隔离：

```text
artifacts/
  raw/<profile>/                                    # 探测原始结果
    jumpserver-host-ip-check-YYYYMMDD-HHMMSS.json   # cleanup_evidence_eligible=True 才会被 cleanup 使用
  state/<profile>/
    cleanup_confirmed_hosts.json                     # 已确认废弃的主机
    cleanup_protected_hosts.json                     # 被保护的主机（不清理）
    cleanup_review_hosts.json                        # 需复查的主机
    jms-host-ip-check-inflight.json                  # Ops 任务接续状态
    last-stable-host-snapshot.json                    # 周巡检稳定主机快照
  cleanup/<profile>/
    cleanup-plan-YYYYMMDD-HHMMSS.json                # 清理候选计划
    cleanup-result-YYYYMMDD-HHMMSS.json              # 清理执行结果
```
