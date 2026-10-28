import SwiftUI
import DazzleModels

struct RegistrationsPage: View {
    @Bindable var store: AppStore
    let openUser: (String) -> Void
    @State private var selected: String?
    @State private var search = ""
    @State private var pendingOnly = true
    @State private var review: RegistrationReview?
    @State private var bindingReview: RegistrationBindingReview?
    private var overview: RegistrationOverview { store.registration }
    private var listedAccounts: [RegistrationAccount] {
        overview.accounts.filter { !pendingOnly || $0.requiresReview }
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
                    MetricCard(title: "可接受新申请", value: String(overview.admissionRemaining), note: overview.admissionFull ? "人员已满，稍后再试" : "待审核申请已预留名额", icon: "square.stack.3d.up")
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
            .sheet(item: $bindingReview) { value in RegistrationBindingReviewSheet(store: store, review: value) }
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
            Text("已拒绝申请保留 72 小时，到期自动清理。")
                .font(.caption2).foregroundStyle(VPSTheme.muted)
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
            if account.needsBindingConfirmation {
                NoticeBox(icon: "person.crop.circle.badge.questionmark", text: account.bindingExplanation, tint: .orange)
                ForEach(Array(account.bindingCandidates.prefix(20))) { candidate in
                    HStack(alignment: .top) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(candidate.name).font(.callout.weight(.medium))
                            Text(candidate.email).font(.caption).textSelection(.enabled)
                            Text(candidate.explanation).font(.caption2).foregroundStyle(VPSTheme.muted)
                        }
                        Spacer()
                        Button("核对用户") { openUser(candidate.id) }
                    }.padding(10).background(VPSTheme.accent.opacity(0.04), in: RoundedRectangle(cornerRadius: 9))
                }
                if account.bindingCandidates.isEmpty {
                    Text("尚无可核对的匹配记录。请先在用户管理中核对邮箱并完成验证，再刷新此页。")
                        .font(.caption).foregroundStyle(VPSTheme.muted)
                }
            } else if account.canApprove && overview.available == 0 {
                NoticeBox(icon: "hourglass", text: "已批准的资源池已用完。申请继续排队，扩容需要另行审批。", tint: .orange)
            } else if account.status == "provisioning" {
                NoticeBox(icon: "arrow.triangle.2.circlepath", text: "正在准备独立实例和可信计量。订阅暂不返回可用节点。")
            } else if account.canApprove {
                NoticeBox(icon: "lock", text: "邮箱已绑定，等待你启用。实际开通后，系统将邮件发送两条订阅链接。")
            }
            if let deadline = account.raw["rejected_delete_at"].string {
                NoticeBox(icon: "clock", text: "已拒绝 · 将于 " + Display.date(.string(deadline)) + " 自动清理申请记录。")
            }
            if account.canApprove && !store.budget.canAllocate {
                NoticeBox(icon: "lock.shield", text: store.budget.reason, tint: .orange)
            }
            HStack {
                if let userID = account.proxyUserID {
                    Button("前往用户管理") { openUser(userID) }.buttonStyle(.borderedProminent)
                } else if account.needsBindingConfirmation {
                    Button("确认关联已有用户") {
                        guard let candidate = account.bindableCandidates.first, account.bindableCandidates.count == 1 else { return }
                        bindingReview = RegistrationBindingReview(account: account, candidate: candidate, revision: store.snapshot?.revision)
                    }.buttonStyle(.borderedProminent)
                        .disabled(account.bindableCandidates.count != 1 || !store.canPerform("registration.bind"))
                } else {
                    Button("启用") { review = RegistrationReview(account: account, approve: true, revision: store.snapshot?.revision) }
                        .buttonStyle(.borderedProminent)
                        .disabled(!account.canApprove || overview.available == 0 || !store.canPerform("registration.approve") || !store.budget.canAllocate)
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

private struct RegistrationBindingReview: Identifiable {
    let id = UUID()
    let account: RegistrationAccount
    let candidate: RegistrationBindingCandidate
    let revision: Int64?
}

private struct RegistrationBindingReviewSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Bindable var store: AppStore
    let review: RegistrationBindingReview
    @State private var confirmed = false
    @State private var validation: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack { Text("确认邮箱归属").font(.title2.weight(.semibold)); Spacer(); Button("取消") { dismiss() } }
            ValueRow(name: "门户登录邮箱", value: review.account.email)
            ValueRow(name: "已有代理用户", value: review.candidate.name)
            ValueRow(name: "已验证通知邮箱", value: review.candidate.email)
            NoticeBox(icon: "link", text: "关联后，使用此邮箱登录的人可以查看该用户的原订阅及节点配置。原有凭据、用量和额度保持，不会重复开户、启动实例或发送首次开通邮件。")
            Toggle("我已核对归属，确认关联此已有用户", isOn: $confirmed)
            Text("需系统身份确认。状态变化或出现重复邮箱时，服务器会拒绝绑定，请重新核对。")
                .font(.caption).foregroundStyle(VPSTheme.muted)
            if let validation { Text(validation).font(.caption).foregroundStyle(.red) }
            HStack { Spacer(); Button("确认关联") { submit() }.buttonStyle(.borderedProminent)
                    .disabled(!confirmed || !store.canPerform("registration.bind")) }
        }.padding(26).frame(width: 540)
    }
    private func submit() {
        do {
            let parameters = try store.registration.bindParameters(account: review.account, candidateID: review.candidate.id)
            dismiss()
            Task { await store.perform("registration.bind", parameters, expectedRevision: review.revision) }
        } catch { validation = error.localizedDescription }
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
    private var quotaBytes: Int64? { QuotaInput.bytes(quota, minimumGB: 50) }
    private var allocated: Int64 { TrafficOverview.sum(store.users.filter { !$0.revoked && !$0.sharesAdministratorBudget }.compactMap(\.allowance)) }
    private var hasUnlimitedMembers: Bool { store.users.contains { !$0.revoked && !$0.sharesAdministratorBudget && $0.quota == nil } }
    private var afterApproval: Int64 { TrafficOverview.sum([allocated, quotaBytes ?? 0]) }

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
                ValueRow(name: "人工确认套餐预算", value: Display.bytes(store.budget.raw["total_bytes"].int))
                ValueRow(name: "当前可分配预算", value: Display.bytes(store.budget.available))
                if quotaBytes.map({ !store.budget.permits($0) }) ?? true {
                    NoticeBox(icon: "lock.shield", text: quotaBytes == nil ? "普通用户周期额度需为至少50GB的整数。" : store.budget.rejectionReason(for: quotaBytes ?? 0), tint: .orange)
                }
                Text("分配同时保留安全余量；商家实时余量未核验。").font(.caption).foregroundStyle(VPSTheme.muted)
                NoticeBox(icon: "eye", text: "本次使用一个已批准的空闲槽位，生成独立VLESS与TUIC凭据；实例运行且计量可信后，原订阅链接生效。不会新增防火墙规则。")
            } else {
                TextField("拒绝原因（选填，最多200字）", text: $reason).textFieldStyle(.roundedBorder)
                NoticeBox(icon: "lock", text: "该申请的订阅继续保持未启用。不会影响其他用户和原代理。", tint: .orange)
            }
            if let validation { Text(validation).font(.caption).foregroundStyle(.red) }
            HStack { Spacer(); Button(review.approve ? "确认并启用" : "确认拒绝", role: review.approve ? nil : .destructive) { submit() }.buttonStyle(.borderedProminent).disabled(store.isSubmitting(review.approve ? "registration.approve" : "registration.reject", target: review.account.id) || (review.approve && (quotaBytes.map { !store.budget.permits($0) } ?? true))) }
        }.padding(26).frame(width: 530)
            .onAppear { quota = String(format: "%g", Double(review.account.raw["quota_bytes"].int ?? store.value("settings")["default_quota_bytes"].int ?? 100_000_000_000) / 1e9) }
    }
    private func submit() {
        do {
            let parameters: [String: JSONValue]
            let action: String
            if review.approve {
                guard let quotaBytes, store.budget.permits(quotaBytes) else { throw ModelError.invalidResponse("请输入至少50GB的整数额度，并确认可分配预算充足。") }
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
