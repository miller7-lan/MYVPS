# Dazzle'VPS · MYVPS

服务器上的个人 VPS 双协议服务：**VLESS REALITY（常用）**、**TUIC v5（迅速）**，配套独立用户凭据、个人载荷额度和私密 HTTPS 订阅。

**使用入口：[V3.1 服务器使用指南](docs/V3.1-服务器使用.md)。** Mac App 只连接服务器管理，不再提供本地演示环境，也不需要安装模拟 CLI。

## 当前状态

2026-10-28，服务器运行不可变 release `0f15c85d616058f1df0b695b`。现有两位用户已实际启用“先解析域名、再拒绝私网”和计量 guard 的小幅时钟回拨容忍；原有凭据、订阅链接和端口保持。

- 管理复用既有 SSH；计量 API 仅监听回环。9443 提供公开注册门户与既有私密订阅；policy v2 和注册开关已启用。
- 单一 writer 独占账本；成员和受额度保护的管理员分别绑定各自 guard。计量保护仍为五秒，已记用量不会因恢复而清零。
- 两位现有用户目前均受额度约束；具体额度、余额、账户和服务状态以实时管理接口为准。
- 旧 443／8443 服务已由管理员退役；当前保护对象是已登记的用户和节点。项目证书的服务器本地 ACME 同步脚本记录在 [server/certsync/](server/certsync/)。
- 本轮整合保留已上线的恢复、管理员额度和手机验证码能力，合入一次性协调器的主机停顿／steal 检查及测试。成员公网访问闸门方案保留在原分支历史，当前采用已有 guard 绑定。

GitHub 合并与服务器发布分别记录。完整文件对照见[分支整合与服务器对照](docs/分支整合与服务器对照-2026-10-28.md)。

## 资料入口

| 路径 | 用途 |
| --- | --- |
| [服务器使用指南](docs/V3.1-服务器使用.md) | 连接管理 App、用户授权、导出订阅和流量口径 |
| [部署与恢复工具](deployment/README.md) | 新服务的发布、审批绑定、安装与项目范围恢复 |
| [邮件与删除用户](docs/V3.1-邮件与删除.md) | QQ SMTP 设置、邮箱验证、通知与安全删除 |
| [公开注册与人工放行](docs/公开注册与人工放行.md) | 先绑定邮箱、管理员启用、实际开通后发送订阅及部署边界 |
| [QQG API 调查](deployment/QQG-API-调查.md) | 官方确认的能力及尚缺的外部接口资料 |
| [并行部署合同](contracts/parallel-production.md) | 新旧服务边界、受限 Helper、计量和验收约束 |
| [客户端导入参考](docs/客户端导入.md) | Shadowrocket、Clash Verge Rev／Mihomo 导入参考；真实新配置以服务器导出为准 |
| [既有服务器维护参考](docs/服务器配置与维护.md) | 原服务的配置、证书与网络维护资料，不是新程序的重装步骤 |
| [原订阅服务参考](docs/订阅服务.md) | 原 8443 服务及共享网卡流量估算，与新个人载荷账本不同 |
| [backend/](backend/) 与 [deployment/](deployment/) | 服务器后台、计量、订阅及受限部署源码 |
| [macos/](macos/) | 服务器管理界面源码 |

`client/`、`server/`、`subscription/` 和配置生成脚本保留为维护与开发参考。历史本地使用、模拟邮件和第一阶段调查文档仅作审计记录，不再作为安装或使用入口。

## 配置与数据

本仓库提供脱敏源码与模板，**不能直接作为可用订阅导入**。真实服务器地址、SSH 私钥、证书私钥、节点凭据、REALITY 私钥和完整订阅令牌不得提交到公开仓库。

新服务器的配置与证书位于 `/etc/dazzle-vps`，账本位于 `/var/lib/dazzle-vps`，运行版本位于 `/opt/dazzle-vps`。这些生产资料不由本地演示数据替代，也不能通过重新生成示例配置覆盖。

两个协议共用同一服务器与出口 IP。它们不构成独立服务器备份，也不能保证所有 AI 账号、服务功能或晚高峰线路长期可用。TUIC 保持证书校验并关闭 0-RTT；“迅速”只是节点名称。

## 参考与来源

- [sing-box 官方项目](https://github.com/SagerNet/sing-box) 与 [官方配置文档](https://sing-box.sagernet.org/)
- [sing-box-yg 参考仓库](https://github.com/yonggekkk/sing-box-yg)：仅参考配置方式，未运行整套一键脚本。
- [Mihomo 官方文档](https://wiki.metacubex.one/)
- [Clash Verge Rev 官方项目](https://github.com/clash-verge-rev/clash-verge-rev)

上游协议来源和许可见 [third_party/NOTICE.md](third_party/NOTICE.md)。

## QQG 自动同步

QQG 整机余额自动同步与 App 显示已接入；每个用户仍使用独立本地代理载荷计量。单位、预算约束、发布与验证见 [上线记录](docs/QQG自动同步上线记录-2026-10-28.md)。凭据请保存在仓库外，由 `scripts/qqg_provider_configure.py` 引用；先不加 `--apply` 预览，再按需提交。
