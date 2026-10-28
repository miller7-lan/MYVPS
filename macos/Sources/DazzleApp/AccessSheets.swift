import SwiftUI
import DazzleModels

struct UserRecoverySheet: View {
    @Bindable var store: AppStore
    let value: JSONValue
    @State private var confirmedGap = false
    private var recovery: UserRecovery { UserRecovery(value) }
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack { Label(recovery.forceRestart ? "强制恢复连接" : "恢复正常使用", systemImage: "arrow.triangle.2.circlepath").font(.title2.weight(.semibold)); Spacer(); Button("关闭") { store.recoveryPreview = nil } }
            Text(recovery.label).font(.headline).foregroundStyle(recovery.state == "healthy" ? VPSTheme.accent : .primary)
            if !recovery.blockedReasons.isEmpty {
                NoticeBox(icon: "lock.shield", text: recovery.blockedReasons.map(Display.reason).joined(separator: "、"), tint: .orange)
            }
            if recovery.forceRestart {
                Text("这是你主动发起的强制恢复：即使检查正常，也会重建此用户的代理连接，现有会话可能短暂中断。原订阅、凭据和已记流量保留，完成后以实际运行与可信计量确认。")
            } else if recovery.state == "healthy" {
                Text("连接和计量已正常，无需重启。预览没有修改服务。")
            } else {
                Text("只处理此用户的异常连接与计量，不解除手动停用、额度、总池、撤销或到期限制。恢复成功以服务器运行与可信计量确认为准。")
            }
            if recovery.requiresGapConfirmation {
                NoticeBox(icon: "exclamationmark.triangle", text: "存在无法精确重建的计量间隙。确认表示接受这段未知用量的不确定性，既有用量与异常记录继续保留。", tint: .orange)
                recoveryGapDetails
                Toggle(recovery.forceRestart ? "我主动要求强制重建此用户连接，并接受上述计量间隙记录" : "我已了解未知用量风险，确认继续恢复", isOn: $confirmedGap)
            }
            Text("应用前需系统身份确认；预览过期或状态变化需要重新检查。")
                .font(.caption).foregroundStyle(VPSTheme.muted)
            HStack {
                Spacer()
                Button(recovery.forceRestart ? "确认强制恢复此用户" : "确认恢复正常使用") {
                    do {
                        guard let userID = value["user_id"].string else { return }
                        let parameters = try recovery.applyParameters(userID: userID, confirmedGap: confirmedGap)
                        let revision = value["expected_revision"].int
                        store.recoveryPreview = nil
                        Task { await store.perform("user.recovery.apply", parameters, expectedRevision: revision) }
                    } catch { store.error = error.localizedDescription }
                }.buttonStyle(.borderedProminent)
                    .disabled(!store.canPerform("user.recovery.apply") || !recovery.canApply || !recovery.blockedReasons.isEmpty || (recovery.requiresGapConfirmation && !confirmedGap))
            }
        }.font(.callout).padding(26).frame(width: 510)
    }
    @ViewBuilder private var recoveryGapDetails: some View {
        let summary = recovery.gapSummary
        if summary.available {
            VStack(alignment: .leading, spacing: 8) {
                ValueRow(name: "最近可信采样", value: summary.lastTrusted)
                ValueRow(name: "本次检查", value: summary.observed)
                Text("有 \(summary.unresolvedCount) 项待核对记录。" + (summary.mayRestartTarget ? "恢复可能只重启此用户实例，现有会话可能短暂断开。" : "处理仅限此用户。"))
                    .font(.caption).foregroundStyle(VPSTheme.muted)
                if summary.preservesRecordedUsage {
                    Label("保留已记用量，不把未知部分计作零", systemImage: "checkmark.shield").font(.caption)
                }
                if !summary.incidents.isEmpty {
                    DisclosureGroup("查看计量间隙与可核实差额") {
                        ScrollView {
                            VStack(alignment: .leading, spacing: 12) {
                                ForEach(summary.incidents) { incident in
                                    VStack(alignment: .leading, spacing: 4) {
                                        Text(incident.title).font(.caption.weight(.medium))
                                        Text("\(incident.from) → \(incident.to)").font(.caption2)
                                        Text("发现于 \(incident.detected)").font(.caption2).foregroundStyle(VPSTheme.muted)
                                        Text(incident.knownTraffic).font(.caption2)
                                        Text(incident.unknown ? "仍有无法核实的用量，不能认定为零。" : "存在可核实差额；完整性仍以服务器对账记录为准。")
                                            .font(.caption2).foregroundStyle(.orange)
                                    }.frame(maxWidth: .infinity, alignment: .leading)
                                }
                                if summary.omittedCount > 0 {
                                    Text("另有 \(summary.omittedCount) 条记录未展开，完整记录继续保留在服务器。")
                                        .font(.caption2).foregroundStyle(VPSTheme.muted)
                                }
                            }.padding(.top, 6)
                        }.frame(maxHeight: 180)
                    }.font(.caption)
                }
            }
        } else {
            Text("服务器未返回可核实的时间范围；未知用量没有被计作零。请先核对服务器计量记录。")
                .font(.caption).foregroundStyle(.orange)
        }
    }
}

struct BudgetConfigurationSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Bindable var store: AppStore
    @State private var total = ""
    @State private var safety = ""
    @State private var evidence = ""
    @State private var confirmed = false
    @State private var validation: String?
    @State private var revision: Int64?
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack { Text("确认套餐预算").font(.title2.weight(.semibold)); Spacer(); Button("取消") { dismiss() } }
            Text("根据 QQG 面板人工确认总额和安全余量。本地账本据此严格分配，商家实时余量继续显示未核验。")
                .font(.callout).foregroundStyle(VPSTheme.muted)
            LabeledContent("套餐总额") { HStack { TextField("整数", text: $total); Text("GB") } }
            LabeledContent("安全余量") { HStack { TextField("整数，可为0", text: $safety); Text("GB") } }
            TextField("核对依据，例如面板套餐信息与核对时间", text: $evidence, axis: .vertical).lineLimit(2...4)
            Toggle("我已核对并确认；管理员只使用共享预留外的余额", isOn: $confirmed)
            Text("这不是商家 API 验证，不会触发额度刷新。已有用量和预留不得清零。")
                .font(.caption).foregroundStyle(VPSTheme.muted)
            if let validation { Text(validation).font(.caption).foregroundStyle(.red) }
            HStack { Spacer(); Button("确认并保存") { save() }.buttonStyle(.borderedProminent).disabled(!confirmed || !store.canPerform("budget.configure")) }
        }.textFieldStyle(.roundedBorder).padding(26).frame(width: 540)
            .onAppear {
                revision = store.snapshot?.revision
                total = QuotaInput.text(store.budget.raw["total_bytes"].int)
                safety = QuotaInput.text(store.budget.raw["safety_margin_bytes"].int)
            }
    }
    private func save() {
        do {
            let params = try AllocationBudget.configure(total: total, safety: safety, evidence: evidence, confirmed: confirmed)
            dismiss(); Task { await store.perform("budget.configure", params, expectedRevision: revision) }
        } catch { validation = error.localizedDescription }
    }
}

struct TrialEditor: View {
    @Environment(\.dismiss) private var dismiss
    @Bindable var store: AppStore
    let existing: ProxyUser?
    @State private var name = ""
    @State private var days = 3
    @State private var quota = "5"
    @State private var validation: String?
    @State private var revision: Int64?
    private var action: String { existing == nil ? "trial.create" : "trial.update" }
    private var quotaBytes: Int64? { QuotaInput.bytes(quota) }
    private var extra: Int64 { max(0, (quotaBytes ?? 0) - (existing?.quota ?? 0)) }
    private var allowed: Bool { extra == 0 || store.budget.permits(extra) }
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack { Text(existing == nil ? "创建临时体验" : "调整临时体验").font(.title2.weight(.semibold)); Spacer(); Button("取消") { dismiss() } }
            if existing == nil { LabeledContent("名称") { TextField("体验用户", text: $name) } }
            Stepper("体验时长：\(days) 天", value: $days, in: 1...365)
            LabeledContent("累计额度") { HStack { TextField("5", text: $quota).frame(width: 100); Text("GB，至少1GB") } }
            Text("体验按到期时间和累计用量限制，不随每月额度周期清零。创建后直接在用户详情导出 Clash 或 Shadowrocket 配置。")
                .font(.caption).foregroundStyle(VPSTheme.muted)
            if !allowed { NoticeBox(icon: "lock.shield", text: store.budget.rejectionReason(for: extra), tint: .orange) }
            ValueRow(name: "当前可分配", value: Display.bytes(store.budget.available))
            if let validation { Text(validation).font(.caption).foregroundStyle(.red) }
            HStack { Spacer(); Button(existing == nil ? "创建体验" : "保存") { save() }.buttonStyle(.borderedProminent)
                .disabled(!store.canPerform(action) || !allowed || quotaBytes == nil || (existing == nil && name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)) }
        }.textFieldStyle(.roundedBorder).padding(26).frame(width: 500)
            .onAppear {
                revision = store.snapshot?.revision
                if let existing { name = existing.name; days = existing.trial.durationDays; quota = QuotaInput.text(existing.quota) }
            }
    }
    private func save() {
        do {
            guard allowed else { throw ModelError.invalidResponse(store.budget.rejectionReason(for: extra)) }
            let parameters = try TrialAccess.parameters(name: name, userID: existing?.id, days: days, quota: quota)
            let previousRevision = store.snapshot?.revision
            Task {
                await store.perform(action, parameters, expectedRevision: revision)
                if store.error == nil, store.snapshot?.revision != previousRevision { dismiss() }
            }
        } catch { validation = error.localizedDescription }
    }
}
