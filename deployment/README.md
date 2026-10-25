# 服务器部署、修复与回退

本轮已获得人类明确授权“批准并行部署，保留原代理”，新的服务器服务已并行安装。程序经数据库锁修复后切换到发布 `7b59b5cc8f22804c98211690`，目标Linux的六项锁回归检查通过。旧代理 TCP/UDP443、旧订阅 TCP8443 和 SSH继续保留；核查时旧进程PID9515/11189未变。用户是否已启用、worker是否正在提供代理，应以服务器最新状态为准，不能把已取得可信基线的stage状态当作已启用。

最终管理入口只面向真实服务器。Mac端只保存连接和界面偏好，不维护第二份用户/额度账本，不提供本地模拟、演示数据、模拟收件箱或离线代理配置。临时本地数据库和fake runner仅供开发回归测试，不能作为用户运行模式或上传到生产。

本目录保留首次安装与程序修复工具，**已安装主机不能重新运行首次安装器覆盖现有状态**。旧服务退役仍需要用户验收后的独立明确指令，本版本没有旧服务退役命令。

## 安装范围

| 项目 | 新增范围 |
| --- | --- |
| 公网代理 | 管理员 TCP+UDP24430；普通用户 TCP+UDP24431 |
| 个人订阅 | TCP9443，仅固定格式和私密令牌，无管理路由 |
| 原生计量 | 127.0.0.1:34430/34431，独立认证；不增加公网管理口 |
| 账户 | 新系统账户 `dazzle-agent`、`dazzle-proxy`，均 nologin、无 SSH 授权 |
| TLS组 | 新 `dazzle-vps`，只加入新服务账户，不加入旧 sing-box/qqg-sub 组 |
| 程序 | `/opt/dazzle-vps/releases/<release_id>`，root所有，独立venv；`current`由root选择 |
| 代理内核 | 只把已核SHA的原二进制复制到新 `/opt/dazzle-vps/core/sing-box`，root所有0755；不替换、不chmod旧文件 |
| 根策略和配置 | `/etc/dazzle-vps`，注册UUID、固定角色/端口、根注册表和独立证书对 |
| 私有账本 | `/var/lib/dazzle-vps`，agent所有0700；从空白production状态初始化 |
| 服务器内部控制 | `/run/dazzle-vps/helper.sock`，0660 root:dazzle-vps，并核验 Linux peer UID |

IPv4防火墙只新增五条带本项目唯一注释的规则。没有 `reset`、`reload`、修改默认策略、删除原规则或添加IPv6规则。旧22/80/443/8443、服务配置、证书续期hook、旧凭据和SSH策略均不在安装目标中。

## 准备和预览

`release.py`只从白名单收集 `backend/dazzle` 源文件、部署及修复模块、服务模板和指定的三份来源许可，再加入一份锁定SHA256的protobuf7.36.2运行库wheel。不会收集任何运行数据库、真实凭据、SSH材料、测试结果、截图或私密目录，不联网下载依赖。

wheel可以是纯Python `py3-none-any`，或目标Linux架构的manylinux版本。不能把Mac二进制模块放入Linux包。服务器只创建独立venv，离线、无依赖递归地安装这份wheel；不执行系统pip、apt升级、grpcio编译或第三方远程脚本。

在仓库根目录运行本地准备命令，路径由操作者明确提供：

```sh
python3 -m deployment.release --wheel PRIVATE_WHEEL --wheel-sha256 VERIFIED_SHA256 --output PRIVATE_RELEASE
python3 -m deployment.installer --preview --archive PRIVATE_RELEASE --server-endpoint APPROVED_ENDPOINT --baseline-file PRIVATE_BASELINE
```

默认预览不写文件、不创建账户、不调用远端或启动服务。没有baseline时可查看计划，但 `ready_for_approval` 为false。预览首次产生新的server/worker UUID；后续用 `--manifest` 复用保存的原始manifest，不能将测试用户或旧代理凭据自动视为新授权。

JSON预览外层包含 `manifest_sha256` 和 `manifest`。审批和安装使用内层manifest作为独立私密文件，不能误把整个预览外层传给 `--manifest`。

只读baseline格式如下；数值必须来自实际检查，而不是复制示例填充：

```json
{
  "version": 1,
  "core_sha256": "PINNED_CORE_SHA256",
  "legacy_config_sha256": "PINNED_LEGACY_CONFIG_SHA256",
  "services": {
    "sing-box.service": {"active": "active", "pid": 1, "nrestarts": 0},
    "qqg-sub.service": {"active": "active", "pid": 2, "nrestarts": 0}
  },
  "occupied_pilot_ports": [],
  "firewall_sha256": "SHA256_OF_UFW_STATUS_NUMBERED_STDOUT",
  "platform": {"system": "Linux", "machine": "x86_64", "python": "3.12"},
  "checked_at": "TIMEZONE_AWARE_UTC_TIME"
}
```

`--capture-baseline`仅在目标主机执行固定只读检查并打印结构化结果。baseline、endpoint、manifest和审批文件作为私密运维材料保存，不发布真实地址。

## 审批与实际安装

实际安装必须同时具备：归档原件、内层review manifest、单独明确审批文件，以及现场重新采集后仍一致的baseline。审批文件结构为：

```json
{
  "version": 1,
  "operation": "install",
  "manifest_sha256": "EXACT_CANONICAL_MANIFEST_SHA256",
  "approved": true,
  "approval_id": "NEW_CANONICAL_UUID"
}
```

这份文件是防止误操作和计划漂移的校验材料，**不能代替人的实际授权**。先审阅具体五条新规则、两个账户、TLS组、root helper和后台服务，再由获授权操作者显式执行：

```sh
python3 -m deployment.installer --apply --archive PRIVATE_RELEASE --manifest PRIVATE_MANIFEST --approval PRIVATE_APPROVAL
```

安装前要求项目目录、同名账户/组和同名unit尚未存在；不自动覆盖已有项目部署。中途失败保留可审查的root私有收据，不清空账本或自行删除账户重试。部分安装后的恢复或升级应先形成新计划。

安装过程不创建代理用户、不导入旧凭据、不启动新公开代理worker。只启动新helper socket、独立agent、新订阅和证书同步timer。后续需显式添加获批pilot用户，先进入无入站的API stage并取得可信基线，再启用对应认证worker。

## 数据库锁故障与最小程序修复

首次并行运行发现了已存在数据库的原始文件描述符操作问题：`Store.__init__`在SQLite已持有该数据库的情况下，额外执行 `os.open` 后立即 `os.close`。Linux的传统POSIX文件锁以进程为单位；同进程关闭指向该文件的其他描述符可能释放SQLite依赖的锁。后续连接错误地认为可以操作WAL/SHM，现场出现已删除但仍被agent持有的WAL/SHM与分叉观察状态。该问题不能靠重试控制命令或删除锁文件解决。

修复后的规则是：只有数据库确实不存在时才使用 `O_CREAT|O_EXCL|O_NOFOLLOW` 创建并关闭新文件；打开已有数据库直接交给SQLite处理，不再额外打开/关闭其原始文件描述符。创建时的并发、符号链接和权限检查保留。Linux六项专门回归已通过；这不替代业务连接与计量验收。

再次遇到锁、deleted WAL/SHM或不同进程看到不同用户状态时：

1. 暂停Mac轮询和新的控制RPC，保存现象及进程/文件身份信息。
2. 先保全生产主库、现存WAL/SHM，以及仍被新agent持有的已删除WAL/SHM；不得先删除、重建或覆盖原库。
3. 只停止新的agent、订阅和helper socket，并确认没有活动helper实例；旧443/8443服务不在停机对象中。
4. 在备份和一致性检查后，以经测试的新版本修复程序。数据恢复选择由操作者按证据决定，程序修复器不会自动选分支或退账。

`repair.py`是程序版本切换器。它不打开生产数据库、不迁移或重建账本，不修改root registry、policy、凭据、证书、core副本、unit、防火墙或账户，也不启动/停止服务。它绑定原先真实的安装授权记录，预览明确显示新旧源码摘要；操作者确认该预览SHA后，才可创建新独立release/venv、自检临时数据库并原子切换 `current`。不创建伪造的新“人类批准”记录。

```sh
python3 -m deployment.repair --archive PRIVATE_NEW_RELEASE
python3 -m deployment.repair --archive PRIVATE_NEW_RELEASE --apply --preview PRIVATE_INNER_REPAIR_PREVIEW --confirm-preview-sha256 EXACT_REPAIR_PREVIEW_SHA256
```

第一次命令只输出预览，第二次读取保存的**内层**preview。最小锁修复scope仅允许 `backend/dazzle/store.py`、新增 `deployment/repair.py` 和打包白名单 `deployment/release.py`；其他源码、helper或unit差异会标记为超范围并拒绝应用。

原release、原始授权与维修收据继续保留。切换后由操作者启动已经获批的新服务，再检查生产身份、用户、基线与旧进程。回退程序版本也必须确认旧版本不存在已知锁缺陷且兼容现有数据库；不能把“旧版本仍在磁盘上”当作可以直接退回的理由。

复发防护：同进程不得用额外的原始文件打开/关闭、文件哈希或手工复制操作触碰已被SQLite打开的生产数据库。正常备份使用SQLite backup等一致性机制；运行中不得手工删除 `-wal`、`-shm` 或所谓“锁文件”。发布前保留Linux外部进程锁回归，生产账本始终由服务器负责。

## 受限root helper

`helper.py`采用systemd `Accept=yes` socket activation，一连接一请求、一响应。只允许root或策略中的agent UID；请求最多1MiB，操作经root所有的文件锁串行处理。socket父目录0755可在重启后由systemd创建，目录不存秘密；socket0660与peerUID校验控制权限。Mac上的测试不会声称完成Linux `SO_PEERCRED` 验收。

请求严格为：

```text
{version:1, request_id:UUID, action, worker_id:UUID, generation:int, params:{...}}
```

允许 `status/provision/stage/activate/stop/revoke`。仅provision/stage/activate接受五项typed认证字段：`vless_uuid/tuic_uuid/tuic_password/short_id/api_secret`。其他动词不接受参数。不能传入命令、unit名、路径、证书路径、任意配置或端口。

root policy把UUID绑定角色、24430/24431公网端口和34430/34431回环API端口。策略、私钥、注册表和生成配置均由root控制；worker通过systemd `LoadCredential`取得自己的配置。helper只返回公钥、状态、代数、PID和固定端口，不返回REALITY私钥或API秘密。

每次改变状态恰好递增一个generation。相同generation只有完全相同请求可幂等重试；原PID变化则不能重复使用已完成的可信origin。先持久记录操作，再检查配置，再原子替换并操作固定unit。stage没有proxy inbounds。revoke先持久保存不可逆墓碑，再确认确切worker cgroup已停止；失败返回明确错误，不显示已应用。新启动被维护标记阻止，stop/revoke仍可用于收敛状态。

普通worker `BindsTo/After` agent，agent使用10秒watchdog；管理员worker不随agent停机。新worker无低端口能力，`Restart=no`，避免未经账本确认的自动重启。计量和helper I/O必须在SQLite事务之外，慢helper操作不应阻塞其他用户采样或watchdog心跳。

## 独立证书同步

`certsync.py`只读旧 `/etc/s-box/cert.pem` 和 `private.key`，验证证书有效期、IP SAN、剩余有效时间和公私钥匹配后，更新项目自己的 `tls/cert.pem` 与 `tls/key.pem`。不调用certbot、不修改旧hook、不重启旧或新代理。

本机官方1.14.4隔离实验发现：certificate_path和key_path共用同一combined PEM路径时，换私钥后可能无法重新加载；使用两个独立文件依次原子替换，代理保留旧有效pair直到新pair完整，并可保持PID/epoch。部署因此采用独立pair。首次安装在服务启动前准备好两份文件；验证失败不替换项目旧pair。两个文件的rename无法组成一个跨文件原子操作，遇到写入故障可能需要下次同步补齐；核心应继续使用内存中的旧有效pair，而不能把中间状态解释为重启成功。

新的HTTPS订阅服务需在新连接时安全切换经过校验的SSLContext，不能为换证重启代理实例而丢失计量epoch。具体TLS轮换实验不等于生产运行验收。

## 回退与验收

`--rollback --manifest ... --receipt ...`先输出回退计划。只有提供匹配该回退计划的新审批（operation为rollback）才实际执行。回退先持久设置root维护标记，防止排队中的旧启动请求稍后复活worker，再停止并禁用本项目unit，删除收据中确实新增的精确IPv4规则。

回退保留程序文件、账户、生产SQLite、已用字节、周期、永久撤销、邮件去重和当前TLS。它不清零配额，不退回旧凭据或旧证书，也不触及legacy服务。恢复旧程序版本或清理这些保留文件需要另行兼容性审查。

安装前后核对旧core/config SHA、旧进程PID及NRestarts。任一变化均停止“旧服务未受影响”的验收结论；需调查原因而不是忽略变化。新系统验收至少包括：新双协议连接、错误凭据拒绝、双向精确计量、禁用/撤销后关闭、agent故障普通用户停止/管理员保留、独立订阅轮换、证书换新连接、内存占用及旧443/8443继续可用。

本地回归使用临时策略和fake runner，不运行真实systemctl、UFW、账户管理或SSH命令。并行部署和Linux锁回归已实际执行；socket peer身份、双协议业务连接、真实计量、故障收敛、UFW精确回退和低资源并行负载等事项仍应分别记录现场证据，不能用测试数量代替尚未完成的验收。
