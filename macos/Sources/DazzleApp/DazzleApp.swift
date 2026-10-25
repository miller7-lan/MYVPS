import SwiftUI
import DazzleModels

@main struct DazzleVPSApp: App {
    @State private var store = AppStore()
    var body: some Scene {
        WindowGroup("Dazzle'VPS") {
            MainView(store: store).frame(minWidth: 960, minHeight: 650)
        }.defaultSize(width: 1120, height: 760)
        .commands {
            CommandGroup(replacing: .newItem) {}
            CommandGroup(after: .toolbar) { Button("刷新服务器") { Task { await store.refresh() } }.keyboardShortcut("r") }
        }
    }
}

enum Page: String, CaseIterable, Identifiable {
    case dashboard = "概览", users = "用户", mail = "通知", settings = "设置"
    var id: Self { self }
    var icon: String {
        switch self { case .dashboard: "chart.pie"; case .users: "person.2"; case .mail: "bell"; case .settings: "slider.horizontal.3" }
    }
}
enum SettingsSection: String, CaseIterable, Identifiable {
    case connection = "连接", cycles = "额度与周期", recovery = "恢复与记录"
    var id: Self { self }
}

struct MainView: View {
    @Bindable var store: AppStore
    @State private var page: Page = .dashboard
    @State private var settings: SettingsSection = .connection
    @State private var selectedUser: String?
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        HStack(spacing: 0) {
            sidebar
            Rectangle().fill(VPSTheme.line).frame(width: 1)
            VStack(spacing: 0) {
                header
                ScrollView {
                    VStack(alignment: .leading, spacing: 18) { serverContent }
                        .padding(24).frame(maxWidth: 1180, alignment: .leading).frame(maxWidth: .infinity)
                }
                footer
            }.background(VPSTheme.canvas)
        }.tint(VPSTheme.accent)
            .task {
                await store.restoreConnection()
                while !Task.isCancelled {
                    do { try await Task.sleep(for: .seconds(8)) } catch { break }
                    if scenePhase == .active { await store.pollManagement() }
                }
            }
            .onChange(of: store.sshHost) { _, _ in store.invalidateServerConnection() }
            .onChange(of: store.sshKeyPath) { _, _ in store.invalidateServerConnection() }
            .animation(reduceMotion ? nil : .easeInOut(duration: 0.18), value: page)
            .alert("操作未完成", isPresented: Binding(get: { store.error != nil }, set: { if !$0 { store.error = nil } })) {
                Button("知道了") { store.error = nil }
            } message: { Text(store.error ?? "") }
            .sheet(item: $store.artifact) { artifact in ExportView(store: store, artifact: artifact) }
            .sheet(isPresented: Binding(get: { store.preview != nil }, set: { if !$0 { store.preview = nil } })) {
                ReviewSheet(value: store.preview ?? .null) { store.preview = nil }
            }
    }
    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 28) {
            HStack(spacing: 9) {
                Image(systemName: "sparkle").foregroundStyle(VPSTheme.accent).font(.system(size: 18, weight: .semibold))
                Text("Dazzle'VPS").font(.system(size: 18, weight: .semibold, design: .rounded))
            }.padding(.horizontal, 10).padding(.top, 17)
            VStack(spacing: 5) {
                ForEach(Page.allCases) { item in NavigationItem(item: item, selected: page == item) { page = item } }
            }
            Spacer()
            HStack(spacing: 7) {
                Circle().fill(store.serverReachable ? VPSTheme.accent : .orange).frame(width: 6, height: 6)
                Text("服务器管理").font(.caption)
                Spacer(); Text("3.1").font(.caption2).foregroundStyle(.tertiary)
            }.foregroundStyle(.secondary).padding(10)
        }.padding(12).frame(width: 170).background(.ultraThinMaterial)
    }
    private var header: some View {
        HStack(spacing: 12) {
            Text(page.rawValue).font(.system(size: 22, weight: .semibold))
            Spacer()
            Label(store.serverReachable ? "已连接" : "未连接", systemImage: "lock.shield")
                .font(.system(size: 12, weight: .medium)).foregroundStyle(store.serverReachable ? VPSTheme.accent : .secondary)
            Button { Task { await store.refresh() } } label: { Image(systemName: "arrow.clockwise").frame(width: 22, height: 22) }
                .buttonStyle(.borderless).help("刷新服务器 ⌘R").disabled(store.busy)
        }.padding(.horizontal, 26).padding(.vertical, 18)
    }
    @ViewBuilder private var serverContent: some View {
        if store.serverContext == nil {
            if page == .settings { ConnectionPage(store: store) }
            else {
                Card {
                    EmptyState(icon: "server.rack", title: store.busy ? "正在连接服务器" : "连接服务器", detail: "读取服务器上的用户、用量与实例状态。")
                    Button("设置连接") { page = .settings; settings = .connection }.buttonStyle(.borderedProminent).disabled(store.busy).frame(maxWidth: .infinity)
                }
            }
        } else {
            ManagementStatusCard(store: store)
            switch page {
            case .dashboard:
                DashboardPage(store: store, onUsers: { selectedUser = nil; page = .users }, onUser: { id in selectedUser = id; page = .users }, onSettings: { settings = .cycles; page = .settings })
            case .users: UsersPage(store: store, initialSelection: selectedUser)
            case .mail: MailPage()
            case .settings:
                Picker("设置类别", selection: $settings) { ForEach(SettingsSection.allCases) { Text($0.rawValue).tag($0) } }
                    .pickerStyle(.segmented).frame(maxWidth: 390).padding(.bottom, 3)
                switch settings {
                case .connection: ConnectionPage(store: store)
                case .cycles: CyclesPage(store: store)
                case .recovery: RecoveryPage(store: store)
                }
            }
        }
    }
    private var footer: some View {
        HStack(spacing: 7) {
            if store.busy { ProgressView().controlSize(.mini); Text("处理中") }
            else if let notice = store.notice {
                Image(systemName: store.noticeIsWarning ? "exclamationmark.circle" : "checkmark.circle.fill").foregroundStyle(store.noticeIsWarning ? Color.orange : VPSTheme.accent)
                Text(notice).lineLimit(1).help(notice)
            } else { Text(store.serverContext == nil ? "服务器未连接" : "仅管理新程序 · 旧连接保留") }
            Spacer()
            if let date = store.lastUpdated { Text(date.formatted(date: .omitted, time: .shortened) + " 更新") }
        }.font(.system(size: 10)).foregroundStyle(.secondary).padding(.horizontal, 26).padding(.vertical, 10)
    }
}

private struct NavigationItem: View {
    let item: Page; let selected: Bool; let action: () -> Void
    @State private var hovered = false
    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) { Image(systemName: item.icon).font(.system(size: 16)).frame(width: 22); Text(item.rawValue).font(.system(size: 13, weight: selected ? .semibold : .regular)); Spacer() }
                .foregroundStyle(selected ? VPSTheme.accent : .primary.opacity(0.75))
                .padding(.horizontal, 12).padding(.vertical, 11)
                .background(selected ? VPSTheme.accent.opacity(0.09) : hovered ? Color.primary.opacity(0.035) : .clear, in: RoundedRectangle(cornerRadius: 11))
        }.buttonStyle(.plain).onHover { hovered = $0 }.accessibilityAddTraits(selected ? .isSelected : [])
    }
}

private struct ReviewSheet: View {
    let value: JSONValue; let close: () -> Void
    private let groups = [("changes_requiring_approval", "需要批准"), ("changes", "影响"), ("preserve", "保留"), ("preserves", "保留"), ("rollback", "恢复方式"), ("blockers", "待准备")]
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack { Text("变更预览").font(.title2.bold()); Spacer(); Button("完成", action: close).keyboardShortcut(.defaultAction) }
            Label("服务器预览 · 未执行变更", systemImage: "eye").font(.caption).foregroundStyle(VPSTheme.accent)
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    ForEach(groups, id: \.0) { key, title in
                        if !value[key].array.isEmpty {
                            VStack(alignment: .leading, spacing: 8) {
                                Text(title).font(.headline)
                                ForEach(Array(value[key].array.enumerated()), id: \.offset) { _, row in Label(human(row.text), systemImage: key == "blockers" ? "circle.dashed" : "checkmark").font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true) }
                            }
                        }
                    }
                    if !value["planned_ports"].array.isEmpty {
                        Text("待审批代理端口：" + value["planned_ports"].array.map { $0["port"].text }.joined(separator: "、")).font(.callout)
                    }
                    DisclosureGroup("技术详情") { Text(value.pretty).font(.system(size: 10, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading).padding(.top, 10) }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
        }.padding(26).frame(width: 610, height: 500)
    }
    private func human(_ text: String) -> String {
        let translations = [
            "legacy443": "现有 443 代理入口", "legacy8443": "现有 8443 订阅", "SSH": "SSH 管理设置", "ledger": "用量账本", "revocations": "永久撤销记录",
            "existing TCP/UDP443": "现有 443 代理入口", "SSH configuration, keys and port": "SSH 设置、密钥与端口", "global firewall": "系统防火墙", "other services": "其他网络服务",
            "Register dedicated low-privilege agent and restricted project worker helper": "注册本项目的低权限后台与受限助手",
            "Install project-only files and SQLite ledger under /opt and /var/lib/dazzle-vps": "安装项目文件与持久流量账本",
            "Enable loopback-only authenticated native API on NEW per-user workers": "为新用户实例启用仅本机可访问的计量接口",
            "Validate and separately approve each new public TCP/UDP proxy port and reachability": "逐个检查并批准新代理端口",
            "Install project systemd service/timers after local validation": "验证后安装本项目后台与定时任务",
            "Configure verified official provider adapter and securely provision credentials": "接入已核实的商家只读 API",
            "Configure real TLS SMTP and explicitly authorize test email": "配置加密邮件提交并批准测试投递",
            "No official QQG API scope/schema verified": "QQG API 权限与字段尚未核实", "No real SMTP configured": "真实邮件尚未配置", "Native API is not enabled or verified on production": "线上计量接口尚未启用", "New ports not approved": "新端口尚未批准",
            "Stop NEW project workers and agent only": "仅停止本项目新增的实例和后台", "Keep legacy443 untouched": "保留既有 443 入口",
            "Never roll back ledger counters, mail idempotency or completed cycles": "保留流量账本、通知去重与已处理周期",
            "Never overwrite current valid TLS certificate with an older backup": "保留当前有效证书"
        ]
        return translations[text] ?? text
    }
}
