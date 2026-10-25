import SwiftUI
import DazzleModels

struct StatusBadge: View {
    let user: ProxyUser
    private var active: Bool { ["active", "enabled", "running", "ready"].contains(user.raw["status"].string ?? "") }
    private var tint: Color {
        if user.revoked { return .red }
        if let state = user.raw["runtime_state"].string { return state == "running" && user.raw["runtime_verified_at"].string != nil ? VPSTheme.accent : .orange }
        return .orange
    }
    private var title: String {
        if let state = user.raw["runtime_state"].string { return state == "running" && user.raw["runtime_verified_at"].string == nil ? "运行待核实" : WorkerState.label(state) }
        return "状态未确认"
    }
    var body: some View {
        HStack(spacing: 5) {
            Circle().fill(tint).frame(width: 5, height: 5)
            Text(title).font(.system(size: 10, weight: .medium))
        }.padding(.horizontal, 8).padding(.vertical, 5)
            .foregroundStyle(tint).background(tint.opacity(0.08), in: Capsule())
    }
}

struct UsersPage: View {
    @Bindable var store: AppStore
    var initialSelection: String? = nil
    @State private var selected: String?
    @State private var search = ""
    @State private var addSheet = false
    @State private var editing: ProxyUser?
    @State private var showsExport = false
    @State private var showsTopup = false
    @State private var topup = "10"
    @State private var confirmAction: String?
    @State private var confirmUser: ProxyUser?
    @State private var confirmationRevision: Int64?

    private var filtered: [ProxyUser] {
        let query = search.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !query.isEmpty else { return store.users }
        return store.users.filter {
            $0.name.localizedStandardContains(query) || ($0.raw["email"].string?.localizedStandardContains(query) ?? false)
        }
    }
    private var user: ProxyUser? { filtered.first { $0.id == selected } ?? filtered.first }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack {
                Text("\(store.users.count) 位用户").font(.callout).foregroundStyle(VPSTheme.muted)
                Spacer()
                Button { addSheet = true } label: { Label("添加用户", systemImage: "plus") }
                    .buttonStyle(.borderedProminent).disabled(!store.canPerform("user.add"))
            }
            if store.users.isEmpty {
                Card { EmptyState(icon: "person.2", title: "添加第一位用户", detail: "每位用户一份凭据，可在多台设备使用。") }
            } else {
                HStack(alignment: .top, spacing: 18) {
                    userList.frame(width: 280)
                    if let user { detail(user) }
                    else { Card { EmptyState(icon: "magnifyingglass", title: "没有匹配的用户", detail: "试试名称或邮箱。") } }
                }
            }
        }
        .sheet(isPresented: $addSheet) { UserEditor(store: store, existing: nil) }
        .sheet(item: $editing) { UserEditor(store: store, existing: $0) }
        .onAppear { if let initialSelection { search = ""; selected = initialSelection } }
        .onChange(of: initialSelection) { _, value in if let value { search = ""; selected = value } }
        .onChange(of: selected) { _, _ in showsTopup = false; showsExport = false }
        .onChange(of: search) { _, _ in showsTopup = false; showsExport = false }
        .onChange(of: store.users.map(\.id)) { old, new in
            let previous = Set(old)
            if let initialSelection, new.contains(initialSelection), !previous.contains(initialSelection) {
                search = ""; selected = initialSelection
            } else if let added = new.first(where: { !previous.contains($0) }) { search = ""; selected = added }
        }
        .confirmationDialog(confirmationTitle, isPresented: Binding(get: { confirmAction != nil }, set: { if !$0 { confirmAction = nil } })) {
            Button(confirmAction == "user.revoke" ? "永久撤销" : "确认轮换", role: .destructive) {
                if let action = confirmAction, let target = confirmUser, !target.revoked, store.canPerform(action) {
                    Task { await store.perform(action, ["user_id": .string(target.id)], expectedRevision: confirmationRevision) }
                }
                confirmAction = nil
            }
            Button("取消", role: .cancel) { confirmAction = nil }
        } message: {
            Text(confirmAction == "user.revoke" ? "保留用量记录；恢复旧配置也不会重新授权。" : "旧凭据将失效，所有使用此用户的客户端都需要重新导入。")
        }
    }

    private var userList: some View {
        Card {
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass").foregroundStyle(VPSTheme.muted)
                TextField("搜索名称或邮箱", text: $search).textFieldStyle(.plain)
                if !search.isEmpty {
                    Button { search = "" } label: { Image(systemName: "xmark.circle.fill").foregroundStyle(VPSTheme.muted) }
                        .buttonStyle(.plain).help("清除搜索")
                }
            }.padding(10).background(VPSTheme.ink.opacity(0.035), in: RoundedRectangle(cornerRadius: 9))
            ScrollView {
                LazyVStack(spacing: 6) {
                    ForEach(filtered) { item in
                        Button { selected = item.id } label: {
                            HStack(spacing: 10) {
                                Image(systemName: item.role == "admin" ? "crown.fill" : "person.fill")
                                    .font(.system(size: 13)).foregroundStyle(VPSTheme.accent)
                                    .frame(width: 32, height: 34)
                                VStack(alignment: .leading, spacing: 5) {
                                    Text(item.name).font(.system(size: 12, weight: .semibold)).lineLimit(1)
                                    Text(item.role == "admin" ? "管理员 · 不限额" : "剩余 " + Display.bytes(item.remaining))
                                        .font(.system(size: 10)).foregroundStyle(VPSTheme.muted).lineLimit(1)
                                }
                                Spacer(minLength: 4)
                                if user?.id == item.id { Image(systemName: "chevron.right").font(.system(size: 10, weight: .semibold)).foregroundStyle(VPSTheme.accent) }
                            }.padding(.horizontal, 6).padding(.vertical, 9).contentShape(Rectangle())
                                .background(user?.id == item.id ? VPSTheme.accent.opacity(0.08) : .clear, in: RoundedRectangle(cornerRadius: 9))
                        }.buttonStyle(.plain).help(item.name)
                    }
                }
            }.frame(minHeight: 230, maxHeight: 460)
            if !search.isEmpty { Text("找到 \(filtered.count) 位用户").font(.caption2).foregroundStyle(VPSTheme.muted) }
        }
    }

    private func detail(_ user: ProxyUser) -> some View {
        let manualDisabled = user.raw["requested_authorization"].string == "disabled" || user.reasons.contains("manual_disabled")
        let protections = user.reasons.filter { $0 != "manual_disabled" && $0 != "revoked" }
        let canAct = store.canModify && !user.revoked
        return Card {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 6) {
                    Text(user.name).font(.system(size: 23, weight: .semibold)).foregroundStyle(VPSTheme.ink)
                    Text(user.role == "admin" ? "管理员" : "普通用户").font(.caption).foregroundStyle(VPSTheme.muted)
                }
                Spacer(); StatusBadge(user: user)
            }
            VStack(alignment: .leading, spacing: 12) {
                Text(user.role == "admin" ? "个人额度" : "本期剩余").font(.caption).foregroundStyle(VPSTheme.muted)
                Text(user.role == "admin" ? "不限额" : Display.bytes(user.remaining))
                    .font(.system(size: 32, weight: .semibold, design: .rounded)).monospacedDigit()
                if let limit = user.allowance { UsageTrack(used: user.used, limit: limit) }
                HStack {
                    Text("已用 " + Display.bytes(user.used))
                    Spacer()
                    Text(user.role == "admin" ? "商家实际剩余未验证" : "共 " + Display.bytes(user.allowance))
                }.font(.caption).foregroundStyle(VPSTheme.muted)
            }.padding(.vertical, 5)
            HStack(spacing: 10) {
                Button { showsExport = true } label: { Label("导出配置", systemImage: "square.and.arrow.up") }
                    .buttonStyle(.borderedProminent).disabled(!store.canPerform("user.export") || user.revoked)
                    .popover(isPresented: $showsExport, arrowEdge: .bottom) {
                        VStack(alignment: .leading, spacing: 12) {
                            Text("导出格式").font(.caption).foregroundStyle(VPSTheme.muted)
                            exportButton("Shadowrocket", format: "shadowrocket", user: user)
                            exportButton("Mihomo / Clash", format: "mihomo", user: user)
                            exportButton("节点链接", format: "uris", user: user)
                        }.padding(18).frame(width: 205).disabled(!store.canPerform("user.export") || user.revoked)
                    }
                    .help("系统身份确认后导出私密配置")
                if user.role != "admin" {
                    Button("加量") { topup = "10"; showsTopup = true }
                        .disabled(!store.canPerform("user.topup") || user.revoked).popover(isPresented: $showsTopup, arrowEdge: .bottom) { topupPopover(user) }
                }
                Button("编辑") { editing = user }.disabled(!store.canPerform("user.update") || user.revoked)
                Spacer(minLength: 8)
                Menu {
                    Button("轮换凭据…") { confirmUser = user; confirmationRevision = store.snapshot?.revision; confirmAction = "user.rotate" }.disabled(!store.canPerform("user.rotate"))
                    Divider()
                    Button("永久撤销…", role: .destructive) { confirmUser = user; confirmationRevision = store.snapshot?.revision; confirmAction = "user.revoke" }.disabled(!store.canPerform("user.revoke"))
                } label: { Image(systemName: "ellipsis").frame(width: 20, height: 20) }
                    .menuStyle(.borderlessButton).fixedSize().disabled(!canAct).help("更多操作")
            }
            Divider()
            if !protections.isEmpty {
                Label("保护暂停：" + protections.map(Display.reason).joined(separator: "、"), systemImage: "pause.circle")
                    .font(.caption).foregroundStyle(.orange)
            }
            HStack(spacing: 8) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(WorkerState.requested(user))
                        .font(.system(size: 12, weight: .medium))
                    if !user.revoked && !protections.isEmpty {
                        Text("计量与额度保护继续生效").font(.caption2).foregroundStyle(VPSTheme.muted)
                    }
                }
                Spacer()
                Button(manualDisabled ? "启用" : "停用") {
                    Task { await store.perform(manualDisabled ? "user.enable" : "user.disable", ["user_id": .string(user.id)]) }
                }.disabled(!store.canPerform(manualDisabled ? "user.enable" : "user.disable") || user.revoked).help(manualDisabled ? "恢复授权，不跳过计量及额度保护" : "关闭此用户的代理授权")
            }
            Group {
                ValueRow(name: "实例状态", value: user.raw["runtime_state"].string == "running" && user.raw["runtime_verified_at"].string == nil ? "运行待核实" : WorkerState.label(user.raw["runtime_state"].string))
                ValueRow(name: "计量状态", value: WorkerState.meterLabel(user.raw["meter_state"].string))
                ValueRow(name: "最近核实", value: Display.date(user.raw["runtime_verified_at"]))
                if let failure = user.raw["last_error"].string, !failure.isEmpty {
                    Text(failure).font(.caption2).foregroundStyle(.orange).lineLimit(3)
                }
            }
            Divider()
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 5) {
                    Text(user.raw["email"].string ?? "未设置通知邮箱").font(.caption).lineLimit(1)
                    if user.raw["email"].string != nil {
                        Label(user.raw["email_verified"].bool == true ? "已验证" : "待验证", systemImage: user.raw["email_verified"].bool == true ? "checkmark.seal" : "envelope.badge")
                            .font(.caption2).foregroundStyle(VPSTheme.muted)
                    }
                }
                Spacer()
                Text("凭据 v\(user.raw["credential_version"].int ?? 1)").font(.caption2).foregroundStyle(VPSTheme.muted)
            }
        }
    }

    private func topupPopover(_ user: ProxyUser) -> some View {
        VStack(alignment: .leading, spacing: 15) {
            Text("本期加量").font(.headline)
            Text(user.name).font(.caption).foregroundStyle(VPSTheme.muted).lineLimit(1)
            HStack { TextField("加量", text: $topup).textFieldStyle(.roundedBorder).accessibilityLabel("加量 GB"); Text("GB").foregroundStyle(VPSTheme.muted) }
            Text("仅当前周期生效").font(.caption2).foregroundStyle(VPSTheme.muted)
            HStack {
                Spacer()
                Button("确认加量") {
                    guard let bytes = decimalGB(topup), bytes > 0, store.canPerform("user.topup"), !user.revoked else { return }
                    showsTopup = false
                    Task { await store.perform("user.topup", ["user_id": .string(user.id), "bytes": .integer(bytes)]) }
                }.buttonStyle(.borderedProminent)
                    .disabled((decimalGB(topup) ?? 0) <= 0 || !store.canPerform("user.topup") || user.revoked)
            }
        }.padding(20).frame(width: 255)
    }

    private var confirmationTitle: String {
        let name = confirmUser?.name ?? "此用户"
        return confirmAction == "user.revoke" ? "永久撤销“\(name)”？" : "轮换“\(name)”的凭据？"
    }
    private func exportButton(_ name: String, format: String, user: ProxyUser) -> some View {
        Button(name) {
            guard store.canPerform("user.export"), !user.revoked else { return }
            showsExport = false
            Task { await store.perform("user.export", ["user_id": .string(user.id), "format": .string(format)]) }
        }
    }
}

func decimalGB(_ text: String) -> Int64? {
    guard let value = Double(text), value.isFinite, value >= 0, value <= Double(Int64.max / 1_000_000_000) else { return nil }
    return Int64(value * 1_000_000_000)
}

struct UserEditor: View {
    @Environment(\.dismiss) private var dismiss
    @Bindable var store: AppStore
    let existing: ProxyUser?
    @State private var name = ""
    @State private var role = "member"
    @State private var quota = "100"
    @State private var email = ""
    @State private var autoRestore = true
    @State private var threshold = 80
    @State private var advanced = false
    @State private var originalRevision: Int64?
    private var editorAction: String { existing == nil ? "user.add" : "user.update" }
    private var isAdmin: Bool { (existing?.role ?? role) == "admin" }
    private var unchangedVerifiedEmail: Bool {
        existing?.raw["email_verified"].bool == true && email.trimmingCharacters(in: .whitespacesAndNewlines) == existing?.raw["email"].string
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 22) {
            Text(existing == nil ? "添加用户" : "编辑用户").font(.system(size: 21, weight: .semibold))
            VStack(spacing: 16) {
                LabeledContent("名称") { TextField("用户名称", text: $name).textFieldStyle(.roundedBorder).accessibilityLabel("名称") }
                if existing == nil {
                    LabeledContent("角色") {
                        Picker("角色", selection: $role) { Text("普通用户").tag("member"); Text("管理员").tag("admin") }.labelsHidden()
                    }
                }
                if isAdmin { LabeledContent("个人额度", value: "不限额").foregroundStyle(VPSTheme.muted) }
                else {
                    LabeledContent("基础额度") {
                        HStack { TextField("额度", text: $quota).textFieldStyle(.roundedBorder).accessibilityLabel("基础额度 GB"); Text("GB / 周期").font(.caption).foregroundStyle(VPSTheme.muted) }
                    }.help("不含当前周期的临时加量")
                }
                if existing != nil {
                    LabeledContent("通知邮箱") { TextField("选填", text: $email).textFieldStyle(.roundedBorder).accessibilityLabel("通知邮箱") }
                    if unchangedVerifiedEmail {
                        HStack { Spacer(); Label("邮箱已验证", systemImage: "checkmark.seal").font(.caption2).foregroundStyle(VPSTheme.accent) }
                    } else if !email.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                        HStack { Spacer(); Text("保存后需验证邮箱").font(.caption2).foregroundStyle(VPSTheme.muted) }
                    }
                }
            }.font(.system(size: 13)).disabled(!store.canPerform(editorAction) || existing?.revoked == true)
            if existing != nil && !isAdmin {
                DisclosureGroup("进阶设置", isExpanded: $advanced) {
                    VStack(alignment: .leading, spacing: 13) {
                        Toggle("下周期自动恢复", isOn: $autoRestore)
                        Stepper("用量提醒 \(threshold)%", value: $threshold, in: 1...100)
                    }.font(.system(size: 12)).padding(.top, 13)
                }.font(.system(size: 12)).disabled(!store.canPerform(editorAction) || existing?.revoked == true)
            }
            HStack {
                if existing == nil { Text("创建后默认停用").font(.caption2).foregroundStyle(VPSTheme.muted) }
                Spacer()
                Button("取消") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("保存") { save() }.buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
                    .disabled(name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || !store.canPerform(editorAction) || existing?.revoked == true)
            }
        }.padding(26).frame(width: 455).onAppear {
            originalRevision = store.snapshot?.revision
            if let user = existing {
                name = user.name; quota = String(Double(user.quota ?? 100_000_000_000) / 1e9)
                email = user.raw["email"].string ?? ""; autoRestore = user.raw["auto_restore"].bool ?? true
                threshold = Int(user.raw["threshold_percent"].int ?? 80)
            } else { quota = String(Double(store.value("settings")["default_quota_bytes"].int ?? 100_000_000_000) / 1e9) }
        }
    }
    private func save() {
        guard store.canPerform(editorAction), existing?.revoked != true else { return }
        let bytes = decimalGB(quota)
        if !isAdmin, bytes == nil || bytes == 0 { store.error = "请输入大于 0 的有效额度数值。"; return }
        var params: [String: JSONValue]
        if let user = existing {
            do { params = try UserPayload.update(user: user, name: name, quotaBytes: bytes, email: email, autoRestore: autoRestore, thresholdPercent: threshold) }
            catch { store.error = error.localizedDescription; return }
        } else {
            params = ["name": .string(name.trimmingCharacters(in: .whitespacesAndNewlines)), "role": .string(role)]
            if role != "admin", let bytes { params["quota_bytes"] = .integer(bytes) }
        }
        let action = existing == nil ? "user.add" : "user.update"
        let revision = store.snapshot?.revision
        Task {
            await store.perform(action, params, expectedRevision: originalRevision)
            if store.error == nil, store.snapshot?.revision != revision { dismiss() }
        }
    }
}
