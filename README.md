# Dazzle'VPS · MYVPS

个人 VPS 双协议配置与维护资料：**VLESS REALITY（常用）**、**TUIC v5（迅速）**，配套 Shadowrocket、Clash Verge Rev / Mihomo 分流配置和私密流量订阅服务。

本仓库为公开的脱敏模板，**不能直接作为节点订阅使用**。真实 SSH 私钥、证书私钥、节点 UUID / 密码、REALITY 密钥和订阅令牌仅保存在部署环境及本地私密文件中。

## 内容

| 路径 | 内容 |
| --- | --- |
| [客户端导入](docs/客户端导入.md) | Shadowrocket、Clash Verge Rev 与 Mihomo 客户端导入 |
| [服务器配置与维护](docs/服务器配置与维护.md) | 参数生成、服务、证书续期、防火墙及稳定性设置 |
| [订阅服务](docs/订阅服务.md) | 私密 HTTPS 订阅与共享剩余流量估算 |
| [client/](client/) | 保留原分流规则的脱敏示例 |
| [server/](server/) | sing-box 服务端示例、systemd、基础防护和证书部署钩子 |
| [scripts/](scripts/) | 本地生成配置及合并基本规则；不联网、不上传凭据 |
| [subscription/](subscription/) | Python 标准库实现的私密 HTTPS 订阅服务及测试 |

## 已采用的方案

- Ubuntu 24.04、官方 sing-box **1.14.4**；VLESS 使用 TCP 443，TUIC 使用 UDP 443。
- 节点名：`Dazzle'VPS-VLESS（常用）`、`Dazzle'VPS-TUIC5（迅速）`；默认常用，手动切换备用。
- 国内、局域网、Tailscale 直连；Shadowrocket 保留 616 条基本规则并新增 5 条优先直连规则。Mihomo 转换 615 条基本规则并新增 5 条直连规则。
- 两种协议共用同一服务器与出口 IP，不构成独立服务器备份，也不保证任意 AI 账号或功能长期可用。
- TUIC 保持证书校验、关闭 0-RTT；BBR 与“迅速”命名不代表所有网络下必然更快。
- 独立低权限服务、密钥登录、最小入站端口、异常恢复、日志限额、应急交换空间、安全更新不自动重启。
- 证书自动续期并热重载代理；私密订阅服务另用 TCP 8443，刷新后显示共享流量估算。

## 生成自己的配置

先阅读 [服务器配置与维护](docs/服务器配置与维护.md)，准备自己的服务器地址、随机节点凭据和 REALITY 密钥。公开示例中的占位符和示例凭据必须替换。

```sh
mkdir -p private
chmod 700 private
cp deployment.example.json private/deployment.json
# 编辑 private/deployment.json，填写自己的新凭据；不要提交此目录。
python3 scripts/render.py --input private/deployment.json --out generated
```

`generated/` 和 `private/` 已被 Git 忽略。生成器拒绝覆盖已有文件；输出含凭据，权限为 0600，目录为 0700。真实生成结果不能提交到仓库。

合并你自己的 Shadowrocket 基本规则：

```sh
python3 scripts/merge_base.py \
  --input private/deployment.json \
  --base private/default.conf \
  --out private/merged \
  --native-routing-only
```

合并结果也包含真实凭据，因此输出到被忽略的 `private/merged`。`--native-routing-only` 的规则文件不含 `[Proxy]`，Shadowrocket 必须先导入私密节点订阅。Mihomo 配置仍包含节点。

## 本地检查

```sh
python3 -m unittest discover -s subscription -p test_server.py -v
sh -n server/hooks/renew-certificate.sh
```

GitHub Actions 执行订阅服务测试、JSON 解析和证书钩子语法检查。模板本身不启动生产服务，测试通过不等于 AI 账号、晚高峰线路或商家余额已验证。

## 参考与来源

- [sing-box 官方项目](https://github.com/SagerNet/sing-box) 与 [官方配置文档](https://sing-box.sagernet.org/)
- [sing-box-yg 参考仓库](https://github.com/yonggekkk/sing-box-yg)：仅参考配置方式，没有运行其整套一键脚本。
- [Mihomo 官方文档](https://wiki.metacubex.one/)
- [Clash Verge Rev 官方项目](https://github.com/clash-verge-rev/clash-verge-rev)

本仓库不分发上述项目的二进制或第三方源码。
