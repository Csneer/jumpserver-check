# JumpServer 探测命令调整指引

本文档说明 `scripts/jms_host_ip_check.py` 中 `DETECTION_COMMAND` 的输出契约、安全边界和调整方法。

## 输出契约

探测命令必须输出下面的固定标记，解析器只读取 `DETECT_START` 到 `DETECT_END` 之间的键值：

```text
DETECT_START
IP_TYPE=static
IP_ADDR=192.168.101.121
IP_ADDRS=192.168.101.121,10.0.0.1
IF_NAME=ens18
DETECT_END
```

字段含义：

- `IP_TYPE`：`static`、`dhcp` 或 `unknown`。
- `IP_ADDR`：默认路由主 IP，用于报告展示。
- `IP_ADDRS`：主机所有全局 IPv4，逗号分隔，用于和 JumpServer 资产 IP 比对。
- `IF_NAME`：默认路由出口网卡。

## 安全边界

命令必须保持只读，不允许加入以下操作：

- 文件/目录修改：`rm`、`mv`、`truncate`、重定向写文件。
- 服务或系统变更：`systemctl restart`、`reboot`、`shutdown`。
- 清理命令：`docker prune`、`journalctl --vacuum-*`。
- JumpServer 资产修改或远端配置修复。

## IP 提取规则

当前命令同时采集默认路由主 IP 和全局 IPv4：

```sh
ip route get 1.1.1.1
ip -o -4 addr show scope global
hostname -I
```

比对时以 `IP_ADDRS` 为准：只要 JumpServer 资产 IP 出现在 `IP_ADDRS` 中，就认为 IP 一致。这用于支持单主机多 IP 场景。

`172.*` 默认被排除，因为当前环境中基本来自 Docker/容器网桥地址。脚本侧也会二次过滤历史日志中的 `172.*`，避免容器地址造成误报。

## IP 类型判断优先级

当前判断顺序：

1. NetworkManager connection 文件：`/etc/NetworkManager/system-connections/*.nmconnection`
2. `nmcli -t -f GENERAL.DEVICES,ipv4.method conn show --active`
3. CentOS/RHEL ifcfg：`/etc/sysconfig/network-scripts/ifcfg-*`，优先匹配默认路由网卡或实际 IP 所在配置。
4. Ubuntu netplan：`/etc/netplan/*.yaml`、`*.yml`，优先匹配默认路由网卡或实际 IP 所在配置。
5. Debian interfaces：`/etc/network/interfaces`，忽略注释并优先匹配默认路由网卡或实际 IP 所在配置。
6. 兜底检查 `dhclient` 进程

如果后续优化命令，优先保持这套输出字段不变。需要新增字段时，应先补解析和测试，再上线定时任务。

如果 Ops 日志显示远端 shell 语法错误、`bad substitution`、`unexpected EOF`、关键命令缺失等脚本执行异常，报告会归类为 `probe_script_error`，不再混入主机不可达。JumpServer API 或日志接口异常会分别归类为 `api_error`、`log_fetch_error`。

## 修改后的验证要求

调整 `DETECTION_COMMAND` 后至少执行：

```powershell
python -m pytest
python scripts/jms_host_ip_check.py --no-proxy detect --query 192.168.101.121 --output-dir reports/yuque
python scripts/run_weekly_check.py --no-proxy --max-assets 1 --dry-run-yuque --dry-run-notify
```

验收点：

- 单主机报告能解析出 `IP_TYPE`、`IP_ADDR`、`IP_ADDRS`、`IF_NAME`。
- 多 IP 主机不因默认路由 IP 不同被误判为 `ip_mismatch`。
- `172.*` 不出现在最终 `探测IP列表`。
- dry-run 全流程能生成报告、语雀同步计划和企业微信消息内容。
