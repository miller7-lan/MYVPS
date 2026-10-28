# Phase B systemd 隔离演练

`phase_b_rehearsal.py` 在一次性、专用标记的 Ubuntu 24.04 systemd 容器中，依次建立真实 Phase A 成功现场，再演练真实的 `deployment.expansion` 和 `deployment.admin_budget`。不要在 VPS、共享开发容器或已有 dazzle 账号/文件的主机运行。

## 执行范围

使用真实 systemd、unit 模板、部署执行器、root helper、用户/组权限、进程身份、单写者锁及长期 TCP 连接。`rehearsal_dazzle/` 和 `rehearsal_core.py` 明确替代应用进程与 Native 计数来源；不会证明真实 sing-box、Shadowrocket、SMTP 或服务商计费兼容性。TLS 为容器内生成的自签名测试证书，不进入生产发布包。

默认六场景：

| 场景 | 预期 |
|---|---|
| success | Phase B接管成功，低权限9443门户200，未知Token经Unix Socket返回404 |
| fail-takeover | 恢复v1策略和固定前版写者，原成员Core/TCP/guard不变 |
| hang-takeover | 接管超时，在原五秒样本窗口内完成固定前版回退 |
| standby-never-ready | 撤回准备，原写者从未停止 |
| admin-success | 先启动guard、再绑定管理员；预算与共享池成功，观察超过60秒准备窗口 |
| admin-budget-rejected | 撤销新依赖后再停guard，保留Core和预算原状；观察旧准备期限后仍正常 |

每场核对Core PID/InvocationID/NRestarts、原成员长期TCP、guard进程、单写者锁、账本用量不倒退、配置摘要、真实注册关闭设置和策略的root:dazzle-vps权限。预存在同名组或状态文件时先拒绝，不清理这些资料。

## 运行

从只含 `backend/`、`deployment/`、`third_party/` 的临时源码副本构建，避免把本地私有文件送入Docker构建上下文。使用当前本机Docker context；不挂载宿主生产目录、不映射公网端口，容器网络设为none。

```bash
docker build -f deployment/tests/systemd_handoff/Dockerfile.phase_b -t dazzle-phase-b-rehearsal:UNIQUE_ID TEMP_SOURCE_DIRECTORY
docker run --detach --name dazzle-phase-b-UNIQUE_ID --label dazzle.phase-b-rehearsal.id=UNIQUE_ID \
  --privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock \
  --network none --memory 768m --pids-limit 512 dazzle-phase-b-rehearsal:UNIQUE_ID
docker exec dazzle-phase-b-UNIQUE_ID mount --make-rshared /
docker exec dazzle-phase-b-UNIQUE_ID /usr/bin/python3 deployment/tests/systemd_handoff/phase_b_rehearsal.py
```

`UNIQUE_ID` 和临时路径需替换。脚本可追加指定场景名；默认依次运行全部场景。预算的两场各含65秒观察，不能因等待较长便缩短保护或观察期限。

若生产模块在演练期间被其他agent更新，应在场景间复制冻结后的模块进入容器后再跑受影响场景，并分别记录受测文件SHA256；不能将旧结果冒充新源码通过。

`Dockerfile.phase_b`比第一阶段镜像多装`iproute2`与`openssl`，真实端口占用闸门和TLS监听健康检查需要这些程序。

## 清理与证据

保存stdout最后一行JSON、诊断日志与受测源码摘要。只删除本次唯一名称且标签匹配的容器和镜像，禁止Docker prune或删除其他agent的资源。实例内脚本会清理自己创建的测试服务/目录/账号；宿主容器与镜像仍由启动者确认标签后清理。

2026-10-26演练证据保存在本机 `/tmp/dazzle-phase-b-rehearsal/`；临时目录可能被系统清理，交付前应将脱敏结果和摘要复制至项目交付目录。
