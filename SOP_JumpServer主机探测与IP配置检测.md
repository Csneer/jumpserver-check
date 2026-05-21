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

通过 JumpServer 的 REST API 和 Ops API，对纳管主机执行自动化批量检测，同时完成以下两项核查：

- **连通性检测**：判断主机是否可正常通过 JumpServer 建立 SSH 连接。
- **IP 配置类型检测**：判断主机当前使用的是固定 IP（static）还是动态分配（DHCP），识别存在网段隐患的主机。

### 1.2 范围说明

| 条目 | 说明 |
|------|------|
| 目标主机 | JumpServer 中 `is_active=true` 且 OS 类型为 Linux 的全量资产 |
| 排除主机 | OS 类型为 Windows 的资产（在报告中单独列出，不做探测） |
| 触发方式 | 定时执行（建议每周一次）或运维手动触发 |
| 所需权限 | JumpServer API Key（需有资产读权限 + Ops 执行权限） |


### 1.3 流程图

```text
初始化鉴权
  -> 拉取活跃资产
  -> 跳过 Windows 资产
  -> Linux / 非 Windows 资产分批
  -> 创建 JumpServer Ops 作业
  -> 轮询任务状态
  -> 获取执行日志
  -> 解析并分类
  -> 对不确定结果执行单主机复核
  -> 合并复核结果
  -> 生成 Markdown / JSON 报告
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
    ├─ Windows → 跳过，加入"已排除"列表
    │
    ▼
按 ≤50 台分批
    │
    ▼
构造复合 Shell 命令
（connectivity + IP 类型检测）
    │
    ▼
POST /api/v1/ops/jobs/  →  获取 task_id
    │
    ▼
轮询 Task 状态（最长等待 120s）
    │
    ├─ FAILURE / 超时 → 记录"探测失败"，不重试本批（等下一轮）
    │
    ▼
SUCCESS → 按主机解析输出
    │
    ├─ 无输出 / exit code 非 0 → 主机不可达
    ├─ IP_TYPE=dhcp             → 动态IP告警
    ├─ IP_TYPE=static           → 正常
    └─ IP_TYPE=unknown          → 无法判断，人工核查
    │
    ▼
对 unreachable / probe_timeout / parse_error 执行单主机复核
    │
    ├─ 复核拿到 DETECT_START → 更新为真实 reachable 分类
    └─ 复核仍失败 → 保留不可达/异常状态并记录复核来源
    │
    ▼
连续 2 次不可达 → 触发禁用 / 通知
    │
    ▼
汇总所有批次结果 → 生成报告
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

在正式开始前，先发一次简单 GET 请求验证鉴权是否有效：

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
| `batch_size` | 每批主机数量，建议 30–50 |
| `task_timeout` | 单批任务等待超时，建议 120s |
| `poll_interval` | 轮询间隔，建议 3s |
| `report_path` | 报告输出路径 |

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

### 5.2 关键字段

| 字段 | 用途 |
|------|------|
| `id` | 唯一标识，Ops 任务中引用 |
| `hostname` | 主机名，报告展示 |
| `ip` | IP 地址，报告展示 |
| `platform` / `os` | 判断是否为 Linux，过滤 Windows |
| `connectivity` | JumpServer 记录的上次连通状态（仅参考，不代替本次探测） |
| `nodes` | 所属节点/分组，便于报告分类 |

### 5.3 过滤规则

```
若 platform 包含 "Windows" 或 os 包含 "windows"（大小写不敏感）
    → 加入 skipped_windows 列表
    → 不进入后续探测流程

其余资产
    → 加入 linux_assets 列表
```

### 5.4 拉取后记录

- 总资产数
- Linux 资产数（待探测）
- Windows 资产数（已跳过）
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
  "assets": ["asset_id_1", "asset_id_2"],
  "runas_policy": "skip",
  "runas": "root",
  "timeout": 120,
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

- 超时阈值：`task_timeout`（建议 120s）
- 超过阈值后，无论状态如何，停止等待。
- 将本批所有主机记录为 `probe_timeout`，在报告中单独标记。
- **不主动取消 Task**，避免影响 JumpServer 队列状态。

### 7.5 并发控制

- 同时处理的批次数建议 ≤ 3，避免 JumpServer Celery 队列积压。
- 批次间建议间隔 2s 再下发下一批。

### 7.6 单主机复核链路

批量 Ops 日志可能出现以下误判来源：

- 批次日志没有返回某台主机分段，但交互连接实际可达。
- Ansible/JMS 日志分段标签与资产名、主机名、IP 不一致，导致解析器无法定位主机输出。
- 批量任务中部分主机输出被截断或延迟，但单主机作业可正常返回。

因此批量探测完成后，对 `unreachable`、`probe_timeout`、`parse_error` 执行第二阶段单主机复核：

```text
批量结果为不确定状态
  -> 使用同一个资产 id 单独创建 Ops 作业
  -> 轮询单主机任务
  -> 获取单主机日志
  -> 若出现 DETECT_START/DETECT_END，重新分类为 ok_static / warn_dhcp / manual_check / ip_mismatch
  -> 若仍无输出或连接失败，保留异常状态，并记录 probe_source=batch+single_recheck
```

复核成功的记录会标记 `probe_source=single_recheck`，并保留 `original_probe_status` 与 `original_remark`，便于追溯批量链路原始结果。

---

## 8. 阶段五：解析输出与分类

### 8.1 获取执行日志

Task 完成后，通过以下接口获取作业日志：

```
GET /api/v1/ops/ansible/job-execution/{task_id}/log/
```

### 8.2 解析规则

对每台主机的输出：

**步骤 1**：判断是否有有效输出

- 无输出 / 命令 exit code 非 0 → 先归类为 `unreachable`，再进入单主机复核队列，不直接认定主机最终不可达。

**步骤 2**：从输出中提取 `DETECT_START` 到 `DETECT_END` 之间的内容

- 若找不到这两个标记 → 归类为 `parse_error`（命令执行但输出格式异常）

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
| `parse_error` | 探测到主机但输出解析失败 |

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
| `probe_source` | batch / single_recheck / batch+single_recheck / skipped |
| `original_probe_status` | 单主机复核前的批量探测状态 |
| `original_remark` | 单主机复核前的批量探测备注 |
| `node` | 所属节点/分组 |
| `remark` | 备注（如：连续 N 次失败） |

Markdown 报告先输出 `问题分类索引`，按异常分类列出简短主机列表；随后输出 `异常主机` 完整表和 `全量明细`。问题分类索引用于快速定位某类问题，完整排查仍以异常主机表和全量明细为准。

### 10.2 汇总统计（报告头部）

```
探测时间：2025-05-19 10:00:00
总资产数：350
  └─ Windows（已跳过）：2
  └─ Linux（参与探测）：348
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

---

## 12. 配置参数参考

以下参数建议从配置文件（如 `config.yaml`）或环境变量读取，不写入代码：

```yaml
jumpserver:
  base_url: "https://jumpserver.example.com"
  api_token: "${JS_API_TOKEN}"   # 从环境变量读取，不明文写入
  system_user_id: "xxxx-xxxx-xxxx-xxxx"

detection:
  batch_size: 50          # 每批主机数
  task_timeout: 120       # 单批任务超时（秒）
  poll_interval: 3        # 轮询间隔（秒）
  max_concurrent_batches: 3   # 最大并发批次数
  consecutive_fail_threshold: 2  # 连续失败多少次触发处置

report:
  output_dir: "./reports"
  retention_count: 12     # 保留最近 N 份报告
  format: "csv"           # csv 或 json

notification:
  webhook_url: "${NOTIFY_WEBHOOK}"
  email_to: ["ops@example.com"]
  notify_on:
    - unreachable_consecutive
    - warn_dhcp
    - ip_mismatch
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
