# SOP：JumpServer 主机存活探测与 IP 配置类型检测

**版本**：v1.0  
**适用系统**：JumpServer v3.x+  
**目标系统**：Linux（Windows 主机跳过）  
**更新日期**：2025-05

---

## 目录

1. [目标与范围](#1-目标与范围)
2. [前置条件](#2-前置条件)
3. [整体流程概览](#3-整体流程概览)
4. [阶段一：初始化与鉴权](#4-阶段一初始化与鉴权)
5. [阶段二：拉取并过滤资产列表](#5-阶段二拉取并过滤资产列表)
6. [阶段三：构造复合探测命令](#6-阶段三构造复合探测命令)
7. [阶段四：下发 Ops 任务并轮询结果](#7-阶段四下发-ops-任务并轮询结果)
8. [阶段五：解析输出与分类](#8-阶段五解析输出与分类)
9. [阶段六：结果处置](#9-阶段六结果处置)
10. [阶段七：汇总报告](#10-阶段七汇总报告)
11. [异常处理规范](#11-异常处理规范)
12. [配置参数参考](#12-配置参数参考)
13. [附录](#13-附录)

---

## 1. 目标与范围

### 1.1 目标

通过 JumpServer 的 REST API 和 Ops API，对纳管主机执行自动化批量检测，生成 Markdown/JSON 报告，同步到语雀，并推送企业微信通知，同时完成以下两项核查：

- **连通性检测**：判断主机是否可正常通过 JumpServer 建立 SSH 连接。
- **IP 配置类型检测**：判断主机当前使用的是固定 IP（static）还是动态分配（DHCP），识别存在网段隐患的主机。

### 1.2 范围说明

| 条目 | 说明 |
|------|------|
| 目标主机 | JumpServer 中 `is_active=true` 且 OS / platform 可明确识别为 Linux 的全量资产 |
| 排除主机 | OS 类型为 Windows、非 Linux 或未知平台的资产（在报告中单独列出，不做探测） |
| 触发方式 | 定时执行（建议每周一次）或运维手动触发 |
| 所需权限 | JumpServer API Key（需有资产读权限 + Ops 执行权限） |
| 报告流向 | 本地 `reports/yuque/` + 语雀时间戳文档 + 企业微信摘要 |


### 1.3 流程图

```text
初始化鉴权
  -> 拉取活跃资产
  -> 跳过 Windows / 非 Linux / 未知平台资产
  -> 当前账号已授权 Linux 资产一次提交 Ops job
  -> 创建 JumpServer Ops 作业
  -> 轮询任务状态
  -> 分页获取完整执行日志
  -> 解析并分类
  -> 生成 Markdown / JSON 报告
  -> 同步语雀文档
  -> 推送企业微信执行摘要
```

---

## 2. 前置条件

### 2.1 JumpServer 侧

- [ ] 已创建专用 API Key，权限范围：资产读取、Ops 任务创建与查询
- [ ] 存在一个具备目标主机 SSH 授权的**系统用户**（System User），用于 Ops 任务执行
- [ ] JumpServer 版本 ≥ v3.x（v2.x 的 Ops API 路径有差异，需适配）

### 2.2 被探测主机侧

- [ ] SSH 端口正常开放
- [ ] 系统用户具备执行以下命令的权限：
  - `nmcli`（若存在）
  - `cat /etc/sysconfig/network-scripts/ifcfg-*`
  - `cat /etc/netplan/*.yaml`
  - `cat /etc/network/interfaces`
  - `ps aux | grep dhclient`
- [ ] 无需 root 权限，普通用户即可（sudo 不是必须）

### 2.3 执行环境

- [ ] 执行脚本的机器可访问 JumpServer API 地址
- [ ] Python 3.10+ 或等效语言运行环境
- [ ] 可写的本地路径用于存储检测报告

---

## 3. 整体流程概览

```
初始化鉴权
    │
    ▼
拉取全量资产（分页）
    │
    ├─ Windows / 非 Linux / 未知平台 → 跳过，加入"已排除"列表
    │
    ▼
按授权资产 all-in-one 批量提交
    │
    ▼
构造复合 Shell 命令
（connectivity + IP 类型检测）
    │
    ▼
POST /api/v1/ops/jobs/  →  获取 task_id
    │
    ▼
轮询 Task 状态（本地最长等待 1200s）
    │
    ├─ FAILURE / 超时 → 记录"探测失败"，不重试本批（等下一轮）
    │
    ▼
SUCCESS → 按主机解析输出
    │
    ├─ 无输出 / exit code 非 0 → Ops 无结果或连接失败
    ├─ IP_TYPE=dhcp             → 动态IP告警
    ├─ IP_TYPE=static           → 正常
    └─ IP_TYPE=unknown          → 无法判断，人工核查
    │
    ▼
连续 2 次不可达 → 触发禁用 / 通知
    │
    ▼
汇总所有结果 → 生成报告 → 同步语雀 → 企业微信通知
```

---

## 4. 阶段一：初始化与鉴权

### 4.1 鉴权方式

JumpServer API 支持以下两种鉴权头，推荐使用 Token：

```
Authorization: Token <your-api-key>
```

或使用 AccessKey 方式（需要额外签名，适合安全要求更高的场景）：

```
Authorization: AccessKey <access_key_id>:<signature>
```

### 4.2 连通性预检

在正式开始前，先运行本地配置检查，确认 `.env` 关键项已填写且不是示例占位：

```bash
python scripts/preflight_check.py --json
```

企业微信默认是可选项；若定时任务必须推送企业微信，则使用：

```bash
python scripts/preflight_check.py --require-wecom
python scripts/run_weekly_check.py --no-proxy --require-wecom
```

通过本地配置检查后，再发一次简单 GET 请求验证 JumpServer 鉴权是否有效：

```
GET /api/v1/users/profile/
预期响应：200 OK，包含当前用户信息
```

若返回 401 / 403，应立即终止并告警，不进入后续流程。

### 4.3 初始化上下文

需在执行开始时确定并记录以下参数（从配置文件或环境变量读取，不硬编码）：

| 参数名 | 说明 |
|--------|------|
| `base_url` | JumpServer 地址，如 `https://jumpserver.example.com` |
| `api_token` | API Key |
| `system_user_id` | 执行 Ops 任务使用的系统用户 ID |
| `execution_mode` | 执行模式，默认 `batch` |
| `batch_size` | 默认 `0`，表示当前账号已授权资产全量一次提交 |
| `task_timeout` | JumpServer job timeout，建议 `-1` 对齐 Web 控制台 |
| `wait_timeout` | 本地轮询等待超时，建议 1200s |
| `poll_interval` | 轮询间隔，建议 30s |
| `report_path` | 报告输出路径 |
| `yuque_*` | 语雀同步 token、repo、目录配置 |
| `wecom_webhook_url` | 企业微信机器人 Webhook |

---

## 5. 阶段二：拉取并过滤资产列表

### 5.1 API 调用

```
GET /api/v1/assets/assets/
    ?is_active=true
    &limit=100
    &offset=0
```

采用分页方式拉取，直到 `next` 字段为 null。

同时拉取当前账号授权资产：

```
GET /api/v1/perms/users/self/assets/
    ?limit=100
    &offset=0
```

全量资产作为报告总口径；未出现在授权资产中的主机不提交 Ops，报告中标记为 `permission_denied`。

### 5.2 关键字段

| 字段 | 用途 |
|------|------|
| `id` | 唯一标识，Ops 任务中引用 |
| `hostname` | 主机名，报告展示 |
| `ip` | IP 地址，报告展示 |
| `platform` / `os` | 正向判断是否为 Linux，并过滤 Windows、非 Linux 和未知平台 |
| `connectivity` | JumpServer 记录的上次连通状态（仅参考，不代替本次探测） |
| `nodes` | 所属节点/分组，便于报告分类 |

### 5.3 过滤规则

```
若 platform 包含 "Windows" 或 os 包含 "windows"（大小写不敏感）
    → 加入 skipped_windows 列表
    → 不进入后续探测流程

若 platform / os 可明确识别为 Linux
    → 加入 linux_assets 列表

其余非 Windows 资产
    → 加入 skipped_non_linux 列表
    → 不进入后续探测流程
```

### 5.4 拉取后记录

- 总资产数
- Linux 资产数（待探测）
- Windows 资产数（已跳过）
- 非 Linux / 未知平台资产数（已跳过）
- 拉取时间戳（用于报告）

---

## 6. 阶段三：构造复合探测命令

### 6.1 设计原则

- 命令输出采用**固定前缀键值对**格式，便于解析，不依赖正则。
- 全程不需要 root/sudo。
- 单条命令完成两项检测，避免建立多次 SSH 连接。
- 输出保持幂等：无论主机发行版如何，输出格式统一。

### 6.2 输出格式约定

命令执行成功后，标准输出应包含以下行：

```
DETECT_START
IP_TYPE=static       # 或 dhcp / unknown
IP_ADDR=192.0.2.10   # 默认路由主 IP
IP_ADDRS=192.0.2.10,198.51.100.10
IF_NAME=ens3
DETECT_END
```

解析时只取 `DETECT_START` 和 `DETECT_END` 之间的内容，忽略其他噪声输出。

### 6.3 IP 类型检测逻辑（优先级从高到低）

| 优先级 | 检测方式 | 判断条件 | 适用系统 |
|--------|----------|----------|----------|
| 1 | `nmcli -f ipv4.method conn show --active` | 包含 `manual` → static；包含 `auto` → dhcp | 所有有 NetworkManager 的发行版 |
| 2 | `grep BOOTPROTO /etc/sysconfig/network-scripts/ifcfg-*` | `static` 或 `none` → static；`dhcp` → dhcp | CentOS / RHEL 7 及以下 |
| 3 | `cat /etc/netplan/*.yaml` | `dhcp4: true` → dhcp；`addresses:` 且无 dhcp4 → static | Ubuntu 18.04+ |
| 4 | `grep inet /etc/network/interfaces` | `dhcp` → dhcp；`static` → static | Debian / Ubuntu 旧版 |
| 兜底 | `ps aux \| grep dhclient` | 有进程在运行 → dhcp；否则 → unknown | 任意 |

命令内部按以上顺序依次尝试，遇到第一个有效结果即输出并退出判断。

### 6.4 获取主机 IP 的方法

命令同时采集默认路由主 IP 和全部全局 IPv4 地址：

```
ip route get 1.1.1.1 | grep -oP 'src \K[\d.]+'
ip -o -4 addr show scope global
```

`IP_ADDR` 用于展示默认路由主 IP，`IP_ADDRS` 用于记录主机当前所有全局 IPv4。比对时以 `IP_ADDRS` 为准：只要 JumpServer 资产记录 IP 存在于该列表，就认为 IP 匹配，避免多 IP 主机被误判为 `ip_mismatch`。

`IP_ADDRS` 默认仅排除 Docker 默认 `172.17.*` 网桥地址。不要排除整个 `172.16.0.0/12` 私网段；该网段可能是合法主机地址，必须保留用于和 JumpServer 资产 IP 比对。

---

## 7. 阶段四：下发 Ops 任务并轮询结果

### 7.1 下发 Ops 作业

```
POST /api/v1/ops/jobs/
Content-Type: application/json

{
  "name": "jms-host-ip-check-YYYYMMDD-HHMMSS-batch-001",
  "type": "adhoc",
  "module": "shell",
  "args": "<复合探测命令>",
  "assets": ["asset_id_1"],
  "nodes": ["node_id_1"],
  "runas_policy": "skip",
  "runas": "root",
  "timeout": -1,
  "instant": true,
  "is_periodic": false
}
```

**注意**：`assets` 字段传资产 `id` 列表，不是 IP。

### 7.2 获取 Task ID

响应体中提取 `task_id` 字段作为后续轮询的 ID：

```json
{
  "task_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
}
```

### 7.3 轮询 Task 状态

```
GET /api/v1/ops/job-execution/task-detail/{task_id}/
```

预期状态值：

| 状态 | 含义 | 处理方式 |
|------|------|----------|
| `PENDING` | 等待中 | 继续等待 |
| `STARTED` | 执行中 | 继续等待 |
| `SUCCESS` | 执行完成 | 进入解析阶段 |
| `FAILURE` | 任务失败 | 记录为"探测失败"，跳过本批 |

### 7.4 轮询超时处理

- 超时阈值：`wait_timeout`（建议 1200s，全量批量探测按实际执行约 10 分钟预留）
- 超过阈值后，无论状态如何，停止等待。
- 将本批所有主机记录为 `probe_timeout`，在报告中单独标记。
- **不主动取消 Task**，避免影响 JumpServer 队列状态。

### 7.5 并发控制

- 同时处理的批次数建议 ≤ 3，避免 JumpServer Celery 队列积压。
- 批次间建议间隔 2s 再下发下一批。

### 7.6 执行模式

准确报告默认使用 `batch --batch-size 0`：所有当前账号已授权且明确识别为 Linux 的资产一次提交 Ops job，payload 同时携带 `assets` 和 `nodes`，对齐 JumpServer Web 控制台作业链路。

执行前先从官方资产接口 `/api/v1/assets/assets/` 拉取全量活跃资产作为报告总口径，再从 `/api/v1/perms/users/self/assets/` 拉取当前账号可执行资产。全量资产中未授权的部分不提交 Ops，直接在报告中标记为 `permission_denied`。

轮询默认 30 秒一次。任务完成后优先读取 task summary 中的 `dark`、`failures`、`excludes`，再结合日志分段解析每台主机的 `DETECT_START/DETECT_END` 输出，避免明确的连接失败、无账号或模块失败被误判为无输出。

全量 `batch --batch-size 0` 默认启用本地接续：Ops job 创建成功后，脚本会立即写入 `artifacts/state/jms-host-ip-check-inflight.json`，记录 `task_id`、资产快照、命令签名和参数签名。如果本地进程中断但任务已经提交到 JumpServer，下次执行会先检查该状态文件；只要状态未标记为 `parsed` 且签名一致，就直接轮询旧 `task_id` 并解析日志，不重复创建 job。需要强制新建任务时，使用 `--no-resume`。

---

## 8. 阶段五：解析输出与分类

### 8.1 获取执行日志

Task 完成后，通过以下接口获取作业日志：

```
GET /api/v1/ops/ansible/job-execution/{task_id}/log/
```

该接口是分页/流式日志接口。响应包含：

```json
{
  "data": "...",
  "end": false,
  "mark": "next-page-mark"
}
```

必须在 `end=false` 时继续携带 `mark` 查询下一页，直到 `end=true`。只读取第一页会导致大量已成功主机没有日志分段，从而被误判为 `unreachable`。

批量日志解析会先按原始主机标签精确匹配，再使用规范化标签匹配：

- 空格与下划线差异，例如资产名 `192.168.101.121_netty Redis Cluster` 对应日志标签 `192.168.101.121_netty_Redis_Cluster`。
- 点分 IP 与横线/下划线 IP 差异，例如 `192.168.101.121`、`192-168-101-121`、`192_168_101_121`。
- 只有当规范化后的候选唯一时才使用该分段，避免重复资产或相近主机名导致错配。

### 8.2 解析规则

对每台主机的输出：

**步骤 1**：判断是否有有效输出

- 无输出 / 命令 exit code 非 0 → 归类为 `unreachable` 或对应 Ops 异常类型，不再执行单主机 Ops 复核。

**步骤 2**：从输出中提取 `DETECT_START` 到 `DETECT_END` 之间的内容

- 若找不到这两个标记 → 先识别 Ops 权限、账号、无输出、模块异常等固定失败特征；无法归因时归类为 `parse_error`（命令执行但输出格式异常）

**步骤 3**：解析键值对

```
IP_TYPE=static   → 归类为 ok_static
IP_TYPE=dhcp     → 归类为 warn_dhcp
IP_TYPE=unknown  → 归类为 manual_check（人工核查）
```

**步骤 4**：比对 IP

- 若 JumpServer 资产记录的 IP 不在命令输出的 `IP_ADDRS` 列表中 → 追加标记 `ip_mismatch`，无论 IP 类型如何都需人工核查

### 8.3 分类汇总

| 分类标识 | 含义 |
|----------|------|
| `ok_static` | 连通，固定 IP，正常 |
| `warn_dhcp` | 连通，但使用 DHCP，需整改 |
| `manual_check` | 连通，但无法自动判断 IP 类型 |
| `ip_mismatch` | 实际 IP 与 JumpServer 记录不一致 |
| `unreachable` | SSH 连接失败，主机不可达 |
| `probe_timeout` | 任务超时，未能探测 |
| `ops_no_output` | Ops 任务成功但没有返回主机输出 |
| `ops_module_error` | Ops/Ansible 模块执行异常 |
| `permission_denied` | 当前 API/Ops 权限无法访问该资产 |
| `no_account` | JumpServer 未找到该资产可用登录账号 |
| `parse_error` | 探测到主机但输出解析失败 |
| `skipped_non_linux` | 非 Linux / 未知平台资产按 SOP 跳过 |

---

## 9. 阶段六：结果处置

### 9.1 不可达主机处置流程

```
单次探测 unreachable
    │
    ▼
查询历史记录：该主机上次探测结果是否也为 unreachable？
    │
    ├─ 否（首次失败）→ 仅记录，下次任务再确认
    │
    └─ 是（连续 ≥ 2 次）→ 进入处置流程：
         ├─ 发送告警通知（Webhook / 邮件）
         └─ 可选：PATCH /api/v1/assets/assets/{id}/ is_active=false
```

> ⚠️ **is_active 设为 false 属于不可逆破坏性操作，建议默认关闭，需运维人员手动确认后执行。**

### 9.2 DHCP 主机处置建议

- 探测到 `warn_dhcp` 的主机，**不做自动处置**，生成整改工单由运维跟进。
- 运维整改后，下次探测周期自动验证是否修复。

### 9.3 IP 不一致处置建议

- 更新 JumpServer 中该资产的 IP 记录（PATCH 接口）。
- 或通知运维确认 IP 变更是否为预期行为。

### 9.4 通知渠道建议

| 分类 | 建议通知方式 |
|------|-------------|
| `unreachable`（连续 2 次） | 即时告警：飞书/钉钉 Webhook |
| `warn_dhcp` | 汇总发送：邮件 / 运维工单系统 |
| `ip_mismatch` | 汇总发送：邮件 |
| `probe_timeout` | 汇总发送：邮件，标注需人工复查 |

---

## 10. 阶段七：汇总报告

### 10.1 报告结构

报告文件命名格式：`jumpserver-host-ip-check-YYYYMMDD-HHMMSS.md`，同时写入 `jumpserver-host-ip-check-latest.md` 和原始 JSON 记录。

全流程编排还会写入：

```text
artifacts/workflow/weekly-workflow-YYYYMMDD-HHMMSS.json
```

该文件记录探测结果、语雀同步结果、企业微信通知结果和失败原因，便于定时任务审计。

接续状态文件：

```text
artifacts/state/jms-host-ip-check-inflight.json
```

报告成功生成后，状态会更新为 `parsed` 并记录报告路径。若要废弃旧 JumpServer job，可删除该状态文件或使用 `--no-resume`。

报告包含以下字段：

| 字段 | 说明 |
|------|------|
| `asset_id` | JumpServer 资产 ID |
| `hostname` | 主机名 |
| `asset_ip` | JumpServer 记录的 IP |
| `actual_ip` | 命令探测到的默认路由主 IP |
| `actual_ips` | 命令探测到的全局 IPv4 列表 |
| `ip_match` | IP 是否一致（true/false） |
| `if_name` | 网卡名称 |
| `ip_type` | static / dhcp / unknown |
| `connectivity` | ok / unreachable |
| `probe_status` | ok_static / warn_dhcp / unreachable / probe_timeout 等 |
| `probe_source` | batch / skipped |
| `original_probe_status` | 保留字段，当前批量-only 链路为空 |
| `original_remark` | 保留字段，当前批量-only 链路为空 |
| `node` | 所属节点/分组 |
| `remark` | 备注（如：连续 N 次失败） |

Markdown 报告先输出 `问题分类索引`，按异常分类列出简短主机列表；随后输出 `异常主机` 完整表和 `全量明细`。问题分类索引用于快速定位某类问题，完整排查仍以异常主机表和全量明细为准。

### 10.2 汇总统计（报告头部）

```
探测时间：2025-05-19 10:00:00
总资产数：350
  └─ Windows（已跳过）：2
  └─ Linux（参与探测）：347
  └─ 非 Linux / 未知平台（已跳过）：1
探测结果：
  ├─ 正常（固定 IP）：310
  ├─ 动态 IP 告警：15
  ├─ 主机不可达：18
  ├─ IP 与记录不一致：3
  ├─ 探测超时：1
  └─ 输出解析失败：1
```

### 10.3 报告保留策略

- 建议保留最近 12 次报告（约 3 个月，按每周执行计）。
- 超过保留期的历史报告自动归档或删除。

### 10.4 语雀同步

语雀同步使用项目内置脚本：

```bash
python scripts/yuque_markdown_sync.py reports/yuque/jumpserver-host-ip-check-latest.md \
  --slug jumpserver-host-ip-check \
  --audit-timestamp \
  --sibling-url "https://leyaoyao.yuque.com/vurq8u/tiatz9/jumpserver-host-ip-check-20260520-112511"
```

`--audit-timestamp` 会从报告中的探测开始时间生成标题和 slug，例如：

```text
JumpServer 主机探测与 IP 配置检测报告 2026-05-21 18:47:45
jumpserver-host-ip-check-20260521-184745
```

这样每周定时任务都会创建或更新独立的时间戳文档，不覆盖历史审计记录。

如果配置了 `YUQUE_SIBLING_URL`，脚本会自动读取该文档所在目录，并把新报告挂载到它的同级目录中。也可以直接配置 `YUQUE_TARGET_TOC_UUID` 固定目录 UUID。

### 10.5 企业微信通知

企业微信通知使用项目内置脚本：

```bash
python scripts/wecom_notify.py --status success --title "JumpServer 每周主机巡检"
```

通知包含执行状态、耗时、关键分类数量、语雀链接和本地报告路径。`WECOM_WEBHOOK_URL` 未配置时通知跳过，不影响探测和语雀同步；配置后推送失败会写入工作流记录。

### 10.6 定时任务

推荐每周一上午执行，并使用 `flock` 防止上次巡检未结束时重复启动：

```cron
0 9 * * 1 cd /path/to/jumpserver-check && flock -n /tmp/jumpserver-check.lock python scripts/run_weekly_check.py --no-proxy >> logs/weekly-check.log 2>&1
```

默认总流程超时 1200 秒。超时、失败、成功都会尝试推送企业微信通知。

---

## 11. 异常处理规范

### 11.1 API 请求失败

| 状态码 | 含义 | 处理方式 |
|--------|------|----------|
| 401 | 鉴权失败 | 立即终止，告警 |
| 403 | 权限不足 | 立即终止，告警 |
| 429 | 请求频率过高 | 指数退避重试，最多 3 次 |
| 5xx | 服务端错误 | 等待 10s 后重试，最多 3 次；仍失败则跳过本批 |
| 网络超时 | 连接失败 | 等待 5s 后重试，最多 3 次 |

### 11.2 重试策略

- 退避基数：5s
- 最大重试次数：3 次
- 退避倍数：2（即 5s → 10s → 20s）
- 超过最大重试次数后记录错误，不影响其他批次继续执行。

### 11.3 部分批次失败

- 单批次失败不中断整个探测流程。
- 失败批次中的所有主机记录为 `probe_timeout` 或对应错误类型。
- 最终报告中单独注明"以下主机因任务异常未能探测"。

### 11.4 JumpServer 队列繁忙

- 若 Task 长时间停留在 `PENDING`（超过 30s 未变为 STARTED），说明 Celery 队列可能积压。
- 建议此时暂停新批次下发，等待已有任务处理完毕。
- 可通过减小 `batch_size` 或降低并发批次数来缓解。

### 11.5 全流程失败处理

| 阶段 | 失败表现 | 处理方式 |
|------|----------|----------|
| JumpServer 鉴权 | `validate-auth` 失败 | 终止流程，企业微信推送失败 |
| Ops 执行 | 超过 1200s | 终止本次等待，企业微信推送超时 |
| 日志拉取 | 无法拉到 `end=true` | 记录 `probe_timeout` 或解析异常，不伪造成功 |
| 语雀同步 | API 失败或配置缺失 | 流程标记失败，企业微信推送失败摘要 |
| 企业微信通知 | Webhook 未配置 | 记录 skipped，不影响主流程状态 |
| 企业微信通知 | Webhook 返回错误 | 记录通知失败，不覆盖探测/语雀原始状态 |

`run_weekly_check.py` 会在下发 JumpServer Ops 前自动执行 preflight。若配置缺失或仍是占位值，流程会直接失败并尝试推送失败通知，不会创建 Ops job。

---

## 12. 配置参数参考

以下参数建议从配置文件（如 `config.yaml`）或环境变量读取，不写入代码：

```yaml
jumpserver:
  base_url: "https://jumpserver.example.com"
  api_token: "${JS_API_TOKEN}"   # 从环境变量读取，不明文写入
  system_user_id: "xxxx-xxxx-xxxx-xxxx"

detection:
  execution_mode: batch   # 默认全量一次批量提交
  batch_size: 0           # 0 表示当前账号已授权资产 all-in-one
  task_timeout: -1        # JumpServer job timeout，-1 对齐 Web 控制台
  wait_timeout: 1200      # 本地轮询等待超时（秒）
  poll_interval: 30       # 轮询间隔（秒）
  max_concurrent_batches: 3   # 最大并发批次数
  consecutive_fail_threshold: 2  # 连续失败多少次触发处置

report:
  output_dir: "./reports"
  retention_count: 12     # 保留最近 N 份报告
  format: "csv"           # csv 或 json

notification:
  wecom_webhook_url: "${WECOM_WEBHOOK_URL}"
  notify_on: always

yuque:
  token: "${YUQUE_TOKEN}"
  repo_namespace: "vurq8u/tiatz9"
  slug: "jumpserver-host-ip-check"
  audit_timestamp: true
  sibling_url: "https://leyaoyao.yuque.com/vurq8u/tiatz9/jumpserver-host-ip-check-20260520-112511"
```

---

## 13. 附录

### 附录 A：JumpServer API 关键端点速查

| 功能 | 方法 | 路径 |
|------|------|------|
| 拉取资产列表 | GET | `/api/v1/assets/assets/` |
| 获取资产详情 | GET | `/api/v1/assets/assets/{id}/` |
| 更新资产字段 | PATCH | `/api/v1/assets/assets/{id}/` |
| 触发内置连通性检测 | POST | `/api/v1/assets/assets/connectivity/` |
| 下发 Ops 作业 | POST | `/api/v1/ops/jobs/` |
| 查询 Task 状态 | GET | `/api/v1/ops/job-execution/task-detail/{task_id}/` |
| 获取 Task 日志 | GET | `/api/v1/ops/ansible/job-execution/{task_id}/log/` |
| 当前用户信息（鉴权验证） | GET | `/api/v1/users/profile/` |

### 附录 B：IP 类型判断命令逻辑伪代码

```
function detect_ip_type():
    # 优先级 1：NetworkManager
    if command_exists(nmcli):
        result = exec("nmcli -f ipv4.method,GENERAL.IP-IFACE conn show --active")
        if "manual" in result → return "static"
        if "auto" in result   → return "dhcp"

    # 优先级 2：CentOS/RHEL ifcfg 文件
    for file in /etc/sysconfig/network-scripts/ifcfg-*:
        bootproto = grep("BOOTPROTO", file)
        if bootproto in ["static", "none"] → return "static"
        if bootproto == "dhcp"             → return "dhcp"

    # 优先级 3：Ubuntu netplan
    for file in /etc/netplan/*.yaml:
        if "dhcp4: true" in file  → return "dhcp"
        if "addresses:" in file   → return "static"

    # 优先级 4：旧版 Debian interfaces
    if file_exists("/etc/network/interfaces"):
        content = read("/etc/network/interfaces")
        if "dhcp" in content   → return "dhcp"
        if "static" in content → return "static"

    # 兜底：检查 dhclient 进程
    if process_running("dhclient") → return "dhcp"

    return "unknown"
```

### 附录 C：报告分类优先级

当同一主机触发多个分类时，按以下优先级取最高级显示：

```
unreachable  >  probe_timeout  >  ip_mismatch  >  warn_dhcp  >  manual_check  >  ok_static
```

### 附录 D：与现有项目复用建议

- **鉴权模块**：直接复用已有项目的 API Key 初始化和 headers 构造部分。
- **分页拉取**：封装为通用方法，可复用于其他资源拉取（系统用户、节点等）。
- **轮询逻辑**：封装为通用 `wait_for_task(task_id, timeout)` 方法，与任务类型解耦。
- **通知模块**：若现有项目已有 Webhook/邮件通知，直接引用，不重复实现。
