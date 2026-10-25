import SwiftUI
import DazzleModels

struct RegistrationsPage: View {
    @Bindable var store: AppStore
    let openUser: (String) -> Void
    @State private var selected: String?
    @State private var search = ""
    @State private var pendingOnly = true
    @State private var review: RegistrationReview?
    private var overview: RegistrationOverview { store.registration }
    private var listedAccounts: [RegistrationAccount] {
        overview.accounts.filter { !pendingOnly || ["pending", "waiting_resources", "provisioning", "failed"].contains($0.status) }
    }
    private var accounts: [RegistrationAccount] {
        listedAccounts.filter { search.isEmpty || $0.email.localizedStandardContains(search) || $0.nickname.localizedStandardContains(search) }
    }
    private var account: RegistrationAccount? { accounts.first(where: { $0.id == selected }) ?? accounts.first }

    var body: some View {
        if !overview.supported {
            Card { EmptyState(icon: "person.badge.clock", title: "注册入口尚未部署", detail: "当前服务器未开放注册审核能力，现有用户和代理继续保留。") }
        } else {
            VStack(alignment: .leading, spacing: 18) {
                HStack(spacing: 14) {
                    MetricCard(title: "等待处理", value: String(overview.pendingCount), note: "已完成邮箱验证", icon: "person.badge.clock")
                    MetricCard(title: "空闲资源", value: "\(overview.available) / \(overview.total)", note: "已批准的普通用户槽位", icon: "square.stack.3d.up")
                    Card {
                        Toggle("接受新注册", isOn: Binding(get: { overview.enabled }, set: { value in
                            Task { await store.perform("settings.update", ["registration_enabled": .bool(value)]) }
                        })).toggleStyle(.switch).disabled(!store.canPerform("settings.update"))
                        Text("暂停后已有用户仍可登录和使用授权代理。")
                            .font(.caption2).foregroundStyle(VPSTheme.muted)
                        if let url = portalURL { Link("打开注册页", destination: url).font(.caption) }
                    }
                }
                HStack {
                    Picker("申请列表", selection: $pendingOnly) {
                        Text("待处理").tag(true); Text("全部申请").tag(false)
                    }.pickerStyle(.segmented).frame(width: 220)
                    Spacer()
                    Text("订阅在启用并检查通过后生效，同时发送开通邮件。")
                        .font(.caption).foregroundStyle(VPSTheme.muted)
                }
                if listedAccounts.isEmpty {
                    Card { EmptyState(icon: "checkmark.seal", title: pendingOnly ? "暂无待处理申请" : "暂无注册申请", detail: "公开申请先验证邮箱，再由你手动放行。") }
                } else {
                    HStack(alignment: .top, spacing: 18) {
                        accountList.frame(width: 275)
                        if let account { detail(account) }
                        else { Card { EmptyState(icon: "magnifyingglass", title: "没有匹配的申请", detail: "试试其他昵称或邮箱。") } }
                    }
                }
            }
            .sheet(item: $review) { value in RegistrationReviewSheet(store: store, review: value) }
            .onChange(of: pendingOnly) { _, _ in selected = nil }
        }
    }
    private var portalURL: URL? {
        guard let text = store.value("registration")["portal_url"].string,
              let url = URL(string: text), url.scheme == "https", url.port == 9443,
              url.user == nil, url.password == nil, url.query == nil, url.fragment == nil,
              url.path == "/portal/" else { return nil }
        return url
    }
    private var accountList: some View {
        Card {
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass").foregroundStyle(VPSTheme.muted)
                TextField("搜索昵称或邮箱", text: $search).textFieldStyle(.plain)
            }.padding(9).background(VPSTheme.ink.opacity(0.035), in: RoundedRectangle(cornerRadius: 9))
            LazyVStack(spacing: 7) {
                ForEach(accounts) { item in
                    Button { selected = item.id } label: {
                        HStack(alignment: .top, spacing: 10) {
                            Image(systemName: item.activationConfirmed(users: store.users) ? "person.crop.circle.badge.checkmark" : "person.crop.circle")
                                .font(.system(size: 22)).foregroundStyle(VPSTheme.accent)
                            VStack(alignment: .leading, spacing: 5) {
                                Text(item.nickname).font(.system(size: 12, weight: .medium))
                                Text(item.email).font(.caption2).foregroundStyle(VPSTheme.muted).lineLimit(1)
                                Text(item.label(users: store.users)).font(.caption2).foregroundStyle(item.activationConfirmed(users: store.users) ? VPSTheme.accent : .secondary)
                            }
                            Spacer(minLength: 0)
                        }.padding(10).frame(maxWidth: .infinity, alignment: .leading)
                            .background(account?.id == item.id ? VPSTheme.accent.opacity(0.08) : .clear, in: RoundedRectangle(cornerRadius: 10))
                    }.buttonStyle(.plain)
                }
            }
        }
    }
    private func detail(_ account: RegistrationAccount) -> some View {
        Card {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 7) {
                    Text(account.nickname).font(.title3.weight(.semibold))
                    Text(account.email).font(.callout).textSelection(.enabled)
                }
                Spacer()
                Text(account.label(users: store.users)).font(.caption.weight(.medium))
                    .foregroundStyle(account.activationConfirmed(users: store.users) ? VPSTheme.accent : .orange)
            }
            Divider()
            ValueRow(name: "注册时间", value: Display.date(account.raw["created_at"]))
            ValueRow(name: "周期额度", value: Display.bytes(account.raw["quota_bytes"].int ?? store.value("settings")["default_quota_bytes"].int ?? 100_000_000_000))
            ValueRow(name: "凭据权限", value: account.activationConfirmed(users: store.users) ? "代理已运行且计量可信" : "以服务器实际开通结果为准")
            if let error = account.raw["last_error"].string, !error.isEmpty {
                NoticeBox(icon: "exclamationmark.triangle", text: "开通未确认，请核对实例状态后处理。", tint: .orange)
            }
            if account.canApprove && overview.available == 0 {
                NoticeBox(icon: "hourglass", text: "已批准的资源池已用完。申请继续排队，扩容需要另行审批。", tint: .orange)
            } else if account.status == "provisioning" {
                NoticeBox(icon: "arrow.triangle.2.circlepath", text: "正在准备独立实例和可信计量。订阅暂不返回可用节点。")
            } else if account.canApprove {
                NoticeBox(icon: "lock", text: "邮箱已绑定，等待你启用。实际开通后，系统将邮件发送两条订阅链接。")
            }
            HStack {
                if let userID = account.proxyUserID {
                    Button("前往用户管理") { openUser(userID) }.buttonStyle(.borderedProminent)
                } else {
                    Button("启用") { review = RegistrationReview(account: account, approve: true, revision: store.snapshot?.revision) }
                        .buttonStyle(.borderedProminent)
                        .disabled(!account.canApprove || overview.available == 0 || !store.canPerform("registration.approve"))
                    Button("拒绝", role: .destructive) { review = RegistrationReview(account: account, approve: false, revision: store.snapshot?.revision) }
                        .disabled(!account.canReject || !store.canPerform("registration.reject"))
                }
                Spacer()
            }
            Text("停用、恢复、轮换及撤销在用户管理中完成，保留流量账本。")
                .font(.caption2).foregroundStyle(VPSTheme.muted)
        }
    }
}

private struct RegistrationReview: Identifiable {
    let id = UUID()
    let account: RegistrationAccount
    let approve: Bool
    let revision: Int64?
}

private struct RegistrationReviewSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Bindable var store: AppStore
    let review: RegistrationReview
    @State private var quota = "100"
    @State private var reason = ""
    @State private var validation: String?
    private var quotaBytes: Int64? { decimalGB(quota) }
    private var allocated: Int64 { TrafficOverview.sum(store.users.filter { !$0.revoked && $0.role != "admin" }.compactMap(\.allowance)) }
    private var hasUnlimitedMembers: Bool { store.users.contains { !$0.revoked && $0.role != "admin" && $0.quota == nil } }
    private var afterApproval: Int64 { TrafficOverview.sum([allocated, quotaBytes ?? 0]) }
    private var verifiedTotal: Int64? { store.snapshot.map(TrafficOverview.init(snapshot:))?.providerTotal }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack { Text(review.approve ? "启用申请" : "拒绝申请").font(.title2.weight(.semibold)); Spacer(); Button("取消") { dismiss() } }
            Text(review.account.email).font(.callout).textSelection(.enabled)
            if review.approve {
                HStack { TextField("周期额度", text: $quota).textFieldStyle(.roundedBorder).frame(width: 110); Text("GB / 现有额度周期").font(.caption).foregroundStyle(VPSTheme.muted) }
                ValueRow(name: "启用前已分配", value: Display.bytes(allocated))
                ValueRow(name: "启用后已分配", value: Display.bytes(afterApproval))
                if hasUnlimitedMembers {
                    NoticeBox(icon: "exclamationmark.triangle", text: "已有普通用户不限量，上述有限额度合计不包含他们的实际消耗。", tint: .orange)
                }
                if let total = verifiedTotal {
                    ValueRow(name: "已核实商家套餐", value: Display.bytes(total))
                    if afterApproval > total { NoticeBox(icon: "exclamationmark.triangle", text: "用户配置额度合计已超出商家套餐，尚未计入管理员预留与安全余量。", tint: .orange) }
                } else {
                    NoticeBox(icon: "exclamationmark.triangle", text: "商家实际额度尚未核实，不能确认总量保护。五位新用户各100GB即达到500GB，另有既有用户和管理员用量。", tint: .orange)
                }
                NoticeBox(icon: "eye", text: "本次使用一个已批准的空闲槽位，生成独立VLESS与TUIC凭据；实例运行且计量可信后，原订阅链接生效。不会新增防火墙规则。")
            } else {
                TextField("拒绝原因（选填，最多200字）", text: $reason).textFieldStyle(.roundedBorder)
                NoticeBox(icon: "lock", text: "该申请的订阅继续保持未启用。不会影响其他用户和原代理。", tint: .orange)
            }
            if let validation { Text(validation).font(.caption).foregroundStyle(.red) }
            HStack { Spacer(); Button(review.approve ? "确认并启用" : "确认拒绝", role: review.approve ? nil : .destructive) { submit() }.buttonStyle(.borderedProminent).disabled(store.busy) }
        }.padding(26).frame(width: 530)
            .onAppear { quota = String(format: "%g", Double(review.account.raw["quota_bytes"].int ?? store.value("settings")["default_quota_bytes"].int ?? 100_000_000_000) / 1e9) }
    }
    private func submit() {
        do {
            let parameters: [String: JSONValue]
            let action: String
            if review.approve {
                guard let quotaBytes else { throw ModelError.invalidResponse("请输入有效的周期额度。") }
                parameters = try store.registration.approveParameters(account: review.account, quotaBytes: quotaBytes)
                action = "registration.approve"
            } else {
                parameters = try store.registration.rejectParameters(account: review.account, reason: reason)
                action = "registration.reject"
            }
            dismiss()
            Task { await store.perform(action, parameters, expectedRevision: review.revision) }
        } catch { validation = error.localizedDescription }
    }
}
