import SwiftUI
import DazzleModels

struct CyclesPage: View {
    @Bindable var store: AppStore
    @State private var editing = false
    @State private var configuringBudget = false
    @State private var recording = false
    @State private var confirmingReset = false
    @State private var day = 24
    @State private var time = "16:19"
    @State private var timezone = "Asia/Shanghai"
    @State private var defaultQuota = "100"
    @State private var remaining = ""
    @State private var total = ""
    @State private var expectedReset = ""
    @State private var evidence = ""
    @State private var observationKind = "manual"
    @State private var externalCycleID = ""
    @State private var actualReset = ""
    @State private var verifiedUnits = false
    @State private var verifiedTotal = ""
    @State private var verifiedRemaining = ""
    var body: some View {
        let settings = store.value("settings"), cycle = store.value("quota_cycle"), provider = store.value("provider")
        VStack(alignment: .leading, spacing: 18) {
            Card {
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("每月 \(settings["day"].int ?? 24) 日 · \(settings["time"].string ?? "16:19")")
                            .font(.system(size: 26, weight: .semibold, design: .rounded)).foregroundStyle(VPSTheme.ink)
                        Text("管理员设定 · \(settings["timezone"].string ?? "Asia/Shanghai")").font(.caption).foregroundStyle(VPSTheme.muted)
                    }
                    Spacer()
                    Button(editing ? "收起" : "修改") { if !editing { load() }; editing.toggle() }.disabled(!store.canPerform("settings.update"))
                }
                ProgressView(value: cycleProgress(cycle)).tint(VPSTheme.accent)
                HStack { Text(shortDate(cycle["start_at"])); Spacer(); Text("下次刷新 " + shortDate(cycle["end_at"])) }.font(.caption).foregroundStyle(VPSTheme.muted)
                Text("普通用户 \(Display.bytes(settings["default_quota_bytes"].int)) / 周期").font(.callout)
                if editing {
                    Divider()
                    HStack {
                        Stepper("每月 \(day) 日", value: $day, in: 1...28).frame(maxWidth: 200)
                        TextField("HH:mm", text: $time).frame(width: 90)
                        TextField("时区", text: $timezone)
                    }
                    HStack(spacing: 18) {
                        LabeledContent("默认 GB") { TextField("100", text: $defaultQuota).frame(width: 80) }
                        Text("整数，至少50GB").font(.caption).foregroundStyle(VPSTheme.muted)
                    }
                    HStack {
                        Text("修改按下个周期生效，不会立即刷新。").font(.caption).foregroundStyle(VPSTheme.muted)
                        Spacer(); Button("保存") { saveSettings() }.buttonStyle(.borderedProminent).disabled(!store.canPerform("settings.update"))
                    }
                }
            }
            budgetCard
            Card {
                HStack {
                    Text("QQG.NET").font(.headline)
                    Text(providerSourceLabel(provider)).font(.caption)
                        .foregroundStyle(automaticProvider(provider) && store.value("provider_sync")["state"].string == "ok" && store.value("provider_freshness")["state"].string == "fresh" ? VPSTheme.accent : .orange)
                    Spacer(); Button(recording ? "收起" : "人工核对") { recording.toggle() }.disabled(!store.canPerform("provider.observe"))
                }
                HStack(alignment: .firstTextBaseline) {
                    VStack(alignment: .leading, spacing: 6) {
                        Text(provider["remaining_display"].text).font(.system(size: 28, weight: .semibold, design: .rounded))
                        Text((automaticProvider(provider) ? "QQG 最近读数 · 已用 \(provider["used_display"].text) · 总额 " : "页面剩余 · 总额 ") + provider["total_display"].text)
                            .font(.caption).foregroundStyle(VPSTheme.muted)
                        if automaticProvider(provider) {
                            Text("QQG 的 GB 为 GiB（1024³ 字节），与本地载荷的十进制 GB 分开统计。")
                                .font(.caption).foregroundStyle(VPSTheme.muted)
                        }
                    }
                    Spacer()
                    VStack(alignment: .trailing, spacing: 6) {
                        Text(provider["expected_reset_date"].text).font(.headline)
                        Text("预计归零 · 仅日期").font(.caption).foregroundStyle(VPSTheme.muted)
                    }
                }
                Text(provider["last_actual_reset_at"].string == nil ? "商家周期尚未核实，不触发个人额度刷新。" : "商家记录独立保存，不触发个人额度刷新。")
                    .font(.caption).foregroundStyle(VPSTheme.muted)
                DisclosureGroup("商家原始记录") {
                    VStack(spacing: 10) {
                        ValueRow(name: "实例 / 套餐", value: provider["instance_id"].text + " / " + provider["plan"].text)
                        ValueRow(name: "记录时间", value: Display.date(provider["observed_at"]))
                        ValueRow(name: "核实总量", value: Display.bytes(provider["total_bytes"].int))
                        ValueRow(name: "实际重置", value: Display.date(provider["last_actual_reset_at"]))
                        ValueRow(name: "商家时区", value: provider["timezone"].text)
                        if store.value("provider_sync")["configured"].bool == true {
                            let sync = store.value("provider_sync")
                            ValueRow(name: "上次同步", value: Display.date(sync["last_success_at"]))
                            ValueRow(name: "同步状态", value: providerSyncText(sync))
                            ValueRow(name: "QQG 计数 ÷ 本地载荷", value: sync["calibration"]["ratio"].double.map { String(format: "%.2f", $0) } ?? "数据不足")
                        }
                        if let note = provider["evidence"].string, !note.isEmpty { Text(note).font(.caption).foregroundStyle(VPSTheme.muted).frame(maxWidth: .infinity, alignment: .leading) }
                        Link("打开 QQG.NET", destination: URL(string: "https://www.qqg.net/")!).font(.caption).frame(maxWidth: .infinity, alignment: .leading)
                    }.padding(.top, 10)
                }.font(.callout)
                if recording { observationForm }
            }
            Card {
                DisclosureGroup("周期记录与检查") {
                    let cycles = store.value("cycles").array.filter { $0["status"].string == "closed" }
                    VStack(alignment: .leading, spacing: 12) {
                        if cycles.isEmpty { Text("尚无已结束周期").foregroundStyle(VPSTheme.muted) }
                        ForEach(Array(cycles.prefix(6).enumerated()), id: \.offset) { _, cycle in
                            HStack { Image(systemName: "checkmark.circle").foregroundStyle(VPSTheme.accent); Text(shortDate(cycle["start_at"]) + " — " + shortDate(cycle["end_at"])); Spacer(); Text("已归档").foregroundStyle(VPSTheme.muted) }
                        }
                    }.font(.caption).padding(.top, 10)
                }
            }
        }.onAppear { load() }
            .sheet(isPresented: $configuringBudget) { BudgetConfigurationSheet(store: store) }
            .confirmationDialog("确认商家已实际重置？", isPresented: $confirmingReset) {
                Button("记录已核实重置") { observe() }; Button("取消", role: .cancel) {}
            } message: { Text("仅保存商家证据，不刷新个人额度。") }
    }
    private var budgetCard: some View {
        Card {
            HStack {
                Text("分配预算").font(.headline)
                Spacer()
                Text(store.budget.configured ? (store.budget.providerRemainingVerified ? "本地预算 · QQG 核验" : "人工确认 · 本地账本") : "尚未配置").font(.caption).foregroundStyle(store.budget.configured ? VPSTheme.accent : .orange)
                Button(store.budget.configured ? "重新确认" : "确认预算") { configuringBudget = true }.disabled(!store.canPerform("budget.configure"))
            }
            if store.budget.configured {
                HStack(spacing: 20) {
                    VStack(alignment: .leading, spacing: 5) { Text("可分配").font(.caption).foregroundStyle(VPSTheme.muted); Text(Display.bytes(store.budget.available)).font(.title2.weight(.semibold)).monospacedDigit() }
                    Spacer()
                    VStack(alignment: .trailing, spacing: 6) {
                        Text("共享预留 " + Display.bytes(store.budget.raw["members_reserved_bytes"].int))
                        Text("安全余量 " + Display.bytes(store.budget.raw["safety_margin_bytes"].int))
                    }.font(.caption).foregroundStyle(VPSTheme.muted)
                }
                ValueRow(name: "套餐预算", value: Display.bytes(store.budget.raw["total_bytes"].int))
                ValueRow(name: "管理员可用余额", value: Display.bytes(store.budget.raw["admin_remaining_bytes"].int))
            }
            Text(store.budget.administratorPolicy).font(.callout)
            Text(store.budget.reason).font(.caption).foregroundStyle(VPSTheme.muted)
            Label(store.budget.providerRemainingVerified ? "QQG 余量已核实；管理员设定的额度刷新规则继续独立运行。" : "商家余量未核验；管理员设定的额度刷新规则继续独立运行。", systemImage: "info.circle")
                .font(.caption2).foregroundStyle(VPSTheme.muted)
        }
    }
    private var observationForm: some View {
        VStack(alignment: .leading, spacing: 12) {
            Divider()
            HStack { TextField("页面剩余", text: $remaining); TextField("页面总额", text: $total) }
            HStack {
                TextField("预计日期 YYYY-MM-DD", text: $expectedReset)
                Picker("记录", selection: $observationKind) {
                    Text("人工观察").tag("manual"); Text("续费").tag("renewal"); Text("赠送").tag("gift")
                    Text("升级").tag("upgrade"); Text("付费重置").tag("paid_reset"); Text("实际重置已确认").tag("reset_confirmed")
                }
            }
            if observationKind == "reset_confirmed" {
                TextField("已核实的商家周期标识", text: $externalCycleID)
                TextField("实际重置时间 ISO 8601，含时区", text: $actualReset)
            }
            Toggle("单位与字节换算已核实", isOn: $verifiedUnits).font(.caption)
            if verifiedUnits { HStack { TextField("总字节数", text: $verifiedTotal); TextField("剩余字节数", text: $verifiedRemaining) } }
            TextField("核对依据（必填）", text: $evidence, axis: .vertical).lineLimit(2...4)
            HStack {
                Text("保存需系统身份确认").font(.caption).foregroundStyle(VPSTheme.muted)
                Spacer(); Button("保存记录") { if observationKind == "reset_confirmed" { confirmingReset = true } else { observe() } }
                    .buttonStyle(.borderedProminent).disabled(!store.canPerform("provider.observe") || evidence.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
    }
    private func load() {
        let s = store.value("settings")
        day = Int(s["day"].int ?? 24); time = s["time"].string ?? "16:19"; timezone = s["timezone"].string ?? "Asia/Shanghai"
        defaultQuota = String(format: "%g", Double(s["default_quota_bytes"].int ?? 100_000_000_000) / 1e9)
    }
    private func saveSettings() {
        guard let quota = QuotaInput.bytes(defaultQuota, minimumGB: 50), TimeZone(identifier: timezone) != nil,
              time.range(of: #"\A(?:[01][0-9]|2[0-3]):[0-5][0-9]\z"#, options: .regularExpression) != nil else { store.error = "请核对额度、时区和时间。"; return }
        let p: [String: JSONValue] = ["day": .integer(Int64(day)), "time": .string(time), "timezone": .string(timezone), "default_quota_bytes": .integer(quota)]
        Task { await store.perform("settings.update", p) }
    }
    private func observe() {
        var p: [String: JSONValue] = ["instance_id": store.value("provider")["instance_id"], "evidence": .string(evidence), "kind": .string(observationKind)]
        if !remaining.isEmpty { p["remaining_display"] = .string(remaining) }; if !total.isEmpty { p["total_display"] = .string(total) }
        if !expectedReset.isEmpty { p["expected_reset_date"] = .string(expectedReset) }
        if observationKind == "reset_confirmed" {
            guard !externalCycleID.isEmpty, !actualReset.isEmpty else { store.error = "请填写商家周期标识和含时区的重置时间。"; return }
            p["external_cycle_id"] = .string(externalCycleID); p["last_actual_reset_at"] = .string(actualReset)
        }
        p["unit_verified"] = .bool(verifiedUnits)
        if verifiedUnits {
            for (key, text) in [("total_bytes", verifiedTotal), ("remaining_bytes", verifiedRemaining)] {
                if !text.isEmpty { guard let amount = Int64(text), amount >= 0 else { store.error = "字节数必须为非负整数。"; return }; p[key] = .integer(amount) }
            }
        }
        Task { await store.perform("provider.observe", p) }
    }
    private func shortDate(_ value: JSONValue) -> String {
        let full = Display.date(value); return full.count >= 10 ? String(full.prefix(10)) : full
    }
    private func automaticProvider(_ provider: JSONValue) -> Bool { provider["source"].string == "qqg_api" }
    private func providerSourceLabel(_ provider: JSONValue) -> String {
        let sync = store.value("provider_sync")
        if sync["configured"].bool == true {
            if sync["enabled"].bool != true { return "QQG 自动同步 · 已暂停" }
            if sync["state"].string == "error" { return "QQG 自动同步 · 中断" }
            if sync["state"].string == "waiting" { return "QQG 自动同步 · 等待首次读取" }
            if automaticProvider(provider) {
                return store.value("provider_freshness")["state"].string == "fresh"
                    ? "QQG 自动同步 · 已核实" : "QQG 自动同步 · 读数已过期"
            }
        }
        return provider["source"].string == "historical_manual_snapshot" ? "历史快照 · 未验证" : "人工记录 · 未自动同步"
    }
    private func providerSyncText(_ sync: JSONValue) -> String {
        switch sync["state"].string {
        case "ok": return "正常 · 每 \((sync["interval_seconds"].int ?? 600) / 60) 分钟"
        case "error": return "中断 · " + (sync["last_error"]["message"].string ?? "原因未知")
        case "disabled": return "已暂停"
        case "waiting": return "等待首次读取"
        default: return "未配置"
        }
    }
    private func cycleProgress(_ cycle: JSONValue) -> Double {
        func date(_ value: JSONValue) -> Date? {
            guard let raw = value.string else { return nil }
            let parser = ISO8601DateFormatter(); parser.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            if let result = parser.date(from: raw) { return result }; parser.formatOptions = [.withInternetDateTime]; return parser.date(from: raw)
        }
        guard let start = date(cycle["start_at"]), let end = date(cycle["end_at"]), end > start else { return 0 }
        return min(1, max(0, Date().timeIntervalSince(start) / end.timeIntervalSince(start)))
    }
}

struct RecoveryPage: View {
    @Bindable var store: AppStore
    @State private var target = "last_good"
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Card("恢复运行状态") {
                HStack(alignment: .top, spacing: 14) {
                    Image(systemName: "clock.arrow.circlepath").font(.system(size: 28, weight: .light)).foregroundStyle(VPSTheme.accent)
                    VStack(alignment: .leading, spacing: 6) { Text("账本与永久撤销保持不变").font(.headline); Text("仅预览新程序恢复范围；旧代理、用量与永久撤销保持不变。").font(.caption).foregroundStyle(VPSTheme.muted) }
                }
                HStack {
                    Picker("恢复到", selection: $target) { Text("上次稳定状态").tag("last_good"); Text("初始状态").tag("baseline") }.frame(maxWidth: 290)
                    Spacer(); Button("预览") { Task { await store.perform("rollback.preview", ["target": .string(target)]) } }.disabled(!store.canPerform("rollback.preview"))
                }
                Divider()
                HStack { Text("查看新程序范围，不包含撤下旧服务。").font(.caption).foregroundStyle(VPSTheme.muted); Spacer(); Button("查看上线计划") { Task { await store.perform("deploy.preview") } }.disabled(!store.canPerform("deploy.preview")) }
            }
            Card("最近操作") {
                if store.value("operations").array.isEmpty { Text("还没有操作记录").font(.callout).foregroundStyle(VPSTheme.muted) }
                ForEach(Array(store.value("operations").array.prefix(12).enumerated()), id: \.offset) { _, op in
                    HStack(alignment: .top, spacing: 13) {
                        Image(systemName: operationIcon(op["action"].text)).foregroundStyle(VPSTheme.accent).frame(width: 25, height: 25).background(VPSTheme.accent.opacity(0.08), in: Circle())
                        VStack(alignment: .leading, spacing: 6) {
                            HStack { Text(operationTitle(op["action"].text)).font(.callout.weight(.medium)); Spacer(); Text(Display.date(op["created_at"])).font(.caption).foregroundStyle(VPSTheme.muted) }
                            DisclosureGroup("详情") {
                                VStack(alignment: .leading, spacing: 5) { Text(op["action"].text).font(.system(.caption2, design: .monospaced)); Text(op["detail"].text).font(.caption) }.foregroundStyle(VPSTheme.muted).padding(.top, 5)
                            }.font(.caption).foregroundStyle(VPSTheme.muted)
                        }
                    }
                }
            }
        }
    }
    private func operationTitle(_ action: String) -> String {
        ["user.add": "添加用户", "user.enable": "启用用户", "user.disable": "停用请求", "user.revoke": "撤销请求", "user.update": "更新用户", "user.rotate": "更新私密凭据", "user.topup": "增加本期额度", "settings.update": "调整额度周期", "provider.observe": "核对商家信息"][action] ?? "服务器操作"
    }
    private func operationIcon(_ action: String) -> String {
        if action.hasPrefix("mail.") { return "envelope" }; if action.hasPrefix("user.") { return "person" }; if action.hasPrefix("rollback.") { return "clock.arrow.circlepath" }; if action.hasPrefix("provider.") { return "cloud" }; return "checkmark"
    }
}

struct ConnectionPage: View {
    @Bindable var store: AppStore
    private var providerConnectionStatus: String {
        let sync = store.value("provider_sync")
        guard sync["configured"].bool == true else { return "QQG 自动同步未配置" }
        guard sync["enabled"].bool == true else { return "QQG 自动同步已暂停" }
        switch sync["state"].string {
        case "ok": return store.value("provider_freshness")["state"].string == "fresh" ? "QQG 自动同步正常" : "QQG 读数已过期"
        case "error": return "QQG 自动同步中断"
        default: return "QQG 等待首次读取"
        }
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Card {
                HStack { Text("服务器连接").font(.headline); Spacer(); Label("受限管理", systemImage: "lock").font(.caption).foregroundStyle(VPSTheme.accent) }
                if store.fixedConnection != nil {
                    ValueRow(name: "固定服务器", value: store.sshHost)
                    ValueRow(name: "SSH 私钥文件", value: store.sshKeyPath)
                    Text("已固定连接配置，启动时自动连接。").font(.caption).foregroundStyle(VPSTheme.accent)
                } else {
                    TextField("服务器地址", text: $store.sshHost).disabled(store.connecting)
                    HStack {
                        TextField("已有 SSH 私钥文件", text: $store.sshKeyPath)
                        Button { store.chooseSSHKey() } label: { Image(systemName: "folder") }.help("选择已有私钥")
                    }.disabled(store.connecting)
                }
                HStack {
                    Text("复用已有 SSH，密钥只引用不复制。").font(.caption).foregroundStyle(VPSTheme.muted)
                    Spacer()
                    Button("连接服务器") { Task { await store.connectManagement() } }
                        .buttonStyle(.borderedProminent).disabled(store.connecting || store.sshHost.isEmpty || store.sshKeyPath.isEmpty)
                }
                if let context = store.serverContext { ValueRow(name: "已固定的服务器身份", value: context.serverID) }
                DisclosureGroup("连接要求与范围") {
                    VStack(spacing: 10) {
                        ValueRow(name: "身份", value: "已有 root 管理身份")
                        ValueRow(name: "服务器指纹", value: "严格验证，不自动信任新指纹")
                        ValueRow(name: "新程序入口", value: "固定 JSON 控制器，无任意命令")
                        Text("有口令的密钥需先在系统 SSH agent 解锁。应用不能安装程序、修改 SSH 或防火墙，也不提供旧代理退役入口。")
                            .font(.caption).foregroundStyle(VPSTheme.muted).frame(maxWidth: .infinity, alignment: .leading)
                    }.padding(.top, 10)
                }.font(.caption)
            }
            Card("数据与服务边界") {
                ValueRow(name: "服务器管理", value: store.serverContext == nil ? "未连接" : "按服务器能力管理新程序")
                ValueRow(name: "旧 443 / 8443", value: "并行保留，不参与新程序额度和撤销")
                ValueRow(name: "邮件 / 商家 API", value: (store.value("mail")["configured"].bool == true ? "邮件已配置" : "邮件待配置") + " / " + providerConnectionStatus)
                DisclosureGroup("隐私与存储") {
                    Text("真实快照仅保存在当前进程内；私密导出权限 0600，不进入操作日志。应用没有本地 HTTP 管理端口，连接后前台每约 8 秒只刷新快照。")
                        .font(.caption).foregroundStyle(VPSTheme.muted).padding(.top, 8)
                }.font(.caption)
            }
        }
    }
}

