# Dazzle'VPS 服务器管理端

原生 SwiftUI App，仅管理 VPS 上新程序的用户、用量和实例。没有演示环境、本地业务数据库、本地 Python 后台或备用检查模式；关闭 App 不影响服务器服务。

在“设置”填写“服务器地址”和“已有 SSH 私钥文件”，点击“连接服务器”。成功后核对“已固定的服务器身份”。已有 SSH 地址、密钥路径和服务器身份记录保持不变；后续启动只用一次只读快照恢复连接，未保存连接时显示空态。

通过现有 `/usr/bin/ssh` 调用固定 `/usr/local/bin/dazzle-vps-control rpc`，请求仅通过 JSON stdin。保留 BatchMode、严格主机指纹、UpdateHostKeys=no；只引用外部密钥，不复制密钥、不自动信任新指纹，没有任意命令、安装或防火墙入口。服务器 UUID 和根策略能力必须匹配后才允许操作。

前台连接后约每 8 秒刷新快照，不轮询商家 API；敏感操作、导出和预览期间暂停。写请求携带 revision；冲突只刷新，超时不自动重试。用户授权与实例状态分别展示，计量未知不会显示正常。旧 443 代理与 8443 订阅保持并行，只有根策略登记的新实例纳入管理。真实邮件尚未启用。

敏感修改与私密导出保留系统 LocalAuthentication。导出必须来自已固定的真实服务器和已配置的新端点，拒绝文档测试地址、旧代理端口；保存通过 NSSavePanel，文件权限 0600，正文默认隐藏，剪贴板未变化时 60 秒后清除。私密内容不写入操作日志。

开发者构建与验证：

```sh
bash macos/test-app.sh
bash macos/build-app.sh
```

产物为 `macos/dist/DazzleVPS.app`。App 运行时仅需 macOS，不需要本机 Python；构建脚本使用 Python 写入元数据和许可证，不打包任何后端代码。`third_party` 许可证随包。CLT 27 缺少 SwiftUI 新版宏插件，本机脚本选择已安装的 macOS 26.5 SDK，目标 macOS 14+；SwiftPM native 引擎执行 Swift Testing。

构建在系统临时目录签名后发布，失败恢复上一份构建。Documents 的 File Provider 可能随后附加 FinderInfo；分发 ZIP 应排除扩展属性，并将解压副本的签名验证作为最终检查。不要将 SSH 密钥、连接配置导出或二维码加入公开仓库。
