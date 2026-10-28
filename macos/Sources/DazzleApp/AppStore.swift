import SwiftUI
import AppKit
import LocalAuthentication
import DazzleModels
import DazzleTransport

/// One queued or submitting operation. Only its own action (and target) is locked.
struct PendingOperation: Identifiable, Equatable, Sendable {
    let id = UUID()
    let action: String
    let target: String?
    let fingerprint: Int
}

/// The last finished recovery stays visible until the administrator closes it.
struct RecoveryOutcome: Equatable {
    let userID: String
    let name: String
    let progress: RecoveryProgress
}

@MainActor @Observable final class AppStore {
    var serverSnapshot: Snapshot?
    var serverContext: ServerContext?
    /// Only the connection handshake: it disables the connection controls, nothing else.
    private(set) var connecting = false
    /// A read-only snapshot is in flight. The last data stays visible and every action stays usable.
    private(set) var refreshing = false
    /// Operations in submission order. Each locks only itself, never the window.
    private(set) var pendingOperations: [PendingOperation] = []
    var error: String?
    var notice: String?
    var noticeIsWarning = false
    var artifact: ExportArtifact?
    var preview: JSONValue?
    var recoveryPreview: JSONValue?
    /// The user whose recovery is being confirmed; read-only polling speeds up meanwhile.
    var recoveryNoticeUserID: String?
    private(set) var recoveryStartedAt: Date?
    private(set) var recoveryLastStep = 0
    var recoveryOutcome: RecoveryOutcome?
    var sensitiveInputActive = false
    let fixedConnection: FixedConnectionProfile?
    private var editableSSHHost: String
    private var editableSSHKeyPath: String
    var sshHost: String {
        get { fixedConnection?.host ?? editableSSHHost }
        set { if fixedConnection == nil { editableSSHHost = newValue } }
    }
    var sshKeyPath: String {
        get { fixedConnection?.identityFile ?? editableSSHKeyPath }
        set { if fixedConnection == nil { editableSSHKeyPath = newValue } }
    }
    var serverReachable = false
    var serverNeedsReview = false
    var serverRefreshError: String?
    private var serverUpdated: Date?
    private var managementConnection: SSHManagementRPC?
    // Snapshot ordering: a response is accepted only if it is not older than what is shown.
    private var snapshotSequence = 0
    private var acceptedSnapshotSequence = 0
    // Revisions produced by this App's own completed operations (old -> new).
    private var ownRevisionAdvances: [Int64: Int64] = [:]
    private var manualRefreshPending = false
    // FIFO submission lane: one operation talks to the server at a time, in click order.
    private var laneOccupied = false
    private var laneWaiters: [CheckedContinuation<Void, Never>] = []
    var snapshot: Snapshot? { serverSnapshot }
    var lastUpdated: Date? { serverUpdated }
    var users: [ProxyUser] { snapshot?.users ?? [] }
    var deletedUsers: [ProxyUser] { value("deleted_users").array.compactMap(ProxyUser.init) }
    var registration: RegistrationOverview { RegistrationOverview(value("registration")) }
    var budget: AllocationBudget { AllocationBudget(value("budget")) }
    var forcedRecoveryAvailable: Bool { value("capabilities")["forced_user_recovery"].bool == true }
    var canModify: Bool { serverSnapshot != nil && serverReachable && !serverNeedsReview && serverContext?.canModify == true }
    /// Seconds between read-only polls: 2 while a recovery is being confirmed (at most 2 minutes), else 8.
    var pollInterval: TimeInterval {
        if recoveryNoticeUserID != nil, let started = recoveryStartedAt, Date().timeIntervalSince(started) < 120 { return 2 }
        return 8
    }
    /// Footer activity: the submitting operation first, otherwise a non-blocking refresh.
    var activityText: String? {
        if let first = pendingOperations.first {
            let more = pendingOperations.count - 1
            return "正在提交：" + Self.operationTitle(first.action) + (more > 0 ? "（另有 \(more) 项排队）" : "")
        }
        return refreshing ? "更新中 · 显示上次数据" : nil
    }
    private let defaults: UserDefaults
    private let managementFactory: @Sendable (String, String) throws -> SSHManagementRPC
    private let identityCheck: (@MainActor () async -> Bool)?
    private let readsWithoutRevision: Set<String> = ["snapshot", "status", "doctor", "user.list", "user.resolve", "deploy.preview", "rollback.preview", "mail.status", "registration.list", "user.recovery.preview"]
    private let businessRejectionCodes: Set<String> = ["VALIDATION", "NOT_FOUND", "NOT_PROVISIONED", "APPROVAL_REQUIRED", "BUDGET_EXCEEDED", "PROVIDER_REMAINING_EXCEEDED", "BUDGET_NOT_CONFIGURED", "ADMIN_GUARD_REQUIRED", "QUOTA_BELOW_USED", "UNLIMITED_MEMBER", "LAST_ADMIN", "EXPIRED", "REVOKED", "RECOVERY_BLOCKED", "RECOVERY_CONFIRMATION_REQUIRED", "RECOVERY_PREVIEW_CHANGED", "RECOVERY_PREVIEW_EXPIRED", "CLEANUP_NOT_READY", "MAIL_NOT_CONFIGURED", "EMAIL_NOT_VERIFIED", "NOT_ACTIVE", "RATE_LIMITED"]

    init(defaults: UserDefaults = .standard,
         fixedConnection: FixedConnectionProfile? = .bundled,
         managementFactory: @escaping @Sendable (String, String) throws -> SSHManagementRPC = { try SSHManagementRPC(host: $0, identityFile: $1) },
         identityCheck: (@MainActor () async -> Bool)? = nil) {
        self.defaults = defaults; self.managementFactory = managementFactory; self.identityCheck = identityCheck
        self.fixedConnection = fixedConnection
        editableSSHHost = defaults.string(forKey: "sshHost") ?? ""
        editableSSHKeyPath = defaults.string(forKey: "sshKeyPath") ?? ""
    }
    /// Restores an existing connection with one read-only handshake; never creates authorization.
    func restoreConnection() async {
        guard managementConnection == nil, !sshHost.isEmpty, !sshKeyPath.isEmpty else { return }
        await connectManagement()
    }
    func value(_ key: String) -> JSONValue { snapshot?[key] ?? .null }
    /// Only a queued or submitting operation of the same action (and target) is locked.
    func canPerform(_ action: String, target: String? = nil) -> Bool { allowsAction(action) && !isSubmitting(action, target: target) }
    func isSubmitting(_ action: String, target: String? = nil) -> Bool {
        pendingOperations.contains { $0.action == action && (target == nil || $0.target == nil || $0.target == target) }
    }
    private func allowsAction(_ action: String) -> Bool {
        guard managementConnection != nil, serverSnapshot != nil, let serverContext, serverContext.allows(action) else { return false }
        if ServerContext.writeActions.contains(action) { return serverReachable && !serverNeedsReview }
        return action == "snapshot" || action == "status" || serverReachable
    }
    func refresh() async {
        guard managementConnection != nil else { await restoreConnection(); return }
        await refreshSnapshot(background: false)
        if serverReachable { serverNeedsReview = false }
    }
    /// Read-only refresh of the connected controller, never a provider poll or write retry.
    func pollManagement() async {
        guard managementConnection != nil, !sensitiveInputActive,
              artifact == nil, preview == nil, recoveryPreview == nil, error == nil else { return }
        await refreshSnapshot(background: true)
    }
    /// Foreground polling loop: the interval follows `pollInterval`, so a recovery is confirmed quickly.
    func runPolling() async {
        await pollManagement()
        var last = Date()
        while !Task.isCancelled {
            do { try await Task.sleep(for: .milliseconds(500)) } catch { break }
            if Date().timeIntervalSince(last) >= pollInterval {
                last = Date()
                await pollManagement()
            }
        }
    }
    func invalidateServerConnection() {
        serverContext = nil; serverSnapshot = nil; managementConnection = nil
        serverReachable = false; serverUpdated = nil; serverRefreshError = nil
        artifact = nil; preview = nil; recoveryPreview = nil
        recoveryNoticeUserID = nil; recoveryStartedAt = nil; recoveryOutcome = nil
        resetOrdering()
    }
    func connectManagement() async {
        guard !connecting else { return }
        connecting = true; defer { connecting = false }
        serverSnapshot = nil; serverContext = nil; serverReachable = false
        managementConnection = nil; serverRefreshError = nil
        resetOrdering()
        do {
            let connection = try managementFactory(sshHost.trimmingCharacters(in: .whitespacesAndNewlines), sshKeyPath)
            let host = connection.host, key = connection.identityFile
            let sequence = nextSnapshotSequence()
            let data = try await connection.call(RPCRequest(action: "snapshot", revision: nil))
            guard sshHost.trimmingCharacters(in: .whitespacesAndNewlines) == host, sshKeyPath == key else { return }
            let snapshot = try Snapshot(data)
            let pins = defaults.dictionary(forKey: "managementServerPins") as? [String: String] ?? [:]
            let context = try ServerContext(snapshot: snapshot, expectedServerID: pins[host.lowercased()])
            var updatedPins = pins; updatedPins[host.lowercased()] = context.serverID
            defaults.set(updatedPins, forKey: "managementServerPins")
            defaults.set(host, forKey: "sshHost"); defaults.set(key, forKey: "sshKeyPath")
            managementConnection = connection; serverContext = context; serverSnapshot = snapshot
            acceptedSnapshotSequence = sequence
            serverReachable = true; serverNeedsReview = false; serverUpdated = Date()
            noticeIsWarning = false; notice = "已连接新程序；现有代理继续保留"
        } catch { self.error = String(error.localizedDescription.prefix(600)) }
    }
    func perform(_ action: String, _ params: [String: JSONValue] = [:], background: Bool = false, expectedRevision: Int64? = nil) async {
        if action == "snapshot" || action == "status" { await refreshSnapshot(background: background); return }
        guard allowsAction(action) else { if !background { error = "服务器尚未连接或未开放此操作。" }; return }
        let operation = PendingOperation(action: action, target: Self.target(of: params), fingerprint: Self.fingerprint(action, params))
        // The same operation clicked again while queued or submitting is ignored, never sent twice.
        guard !pendingOperations.contains(where: { $0.fingerprint == operation.fingerprint }) else { return }
        pendingOperations.append(operation)
        defer { pendingOperations.removeAll { $0.id == operation.id } }
        let targetID = serverContext?.serverID
        let connection = managementConnection
        let capturedRevision = expectedRevision ?? snapshot?.revision
        if !background { noticeIsWarning = false }
        // Identity is confirmed at click time, before waiting behind earlier operations.
        if !readsWithoutRevision.contains(action), !(await confirmIdentity()) { return }
        await enterLane(); defer { leaveLane() }
        guard serverContext?.serverID == targetID, connectionMatches(connection), let connection else { return }
        guard allowsAction(action) else {
            if !background { error = "服务器连接待核对，本次操作没有提交。请刷新后重试。" }; return
        }
        var revision: Int64?
        if !readsWithoutRevision.contains(action) {
            // Checked just before sending: only this App's own completed operations may have
            // advanced the revision since the click. Anything else must be reviewed first.
            guard let latest = latestRevision(from: capturedRevision) else {
                if !background { error = "状态已被其他操作更新。请核对最新状态后重新提交；没有自动重试修改。" }
                return
            }
            revision = latest
        }
        let sequence = nextSnapshotSequence()
        do {
            let request = RPCRequest(action: action, revision: revision, params: params, serverID: targetID)
            let data = try await connection.call(request)
            guard connectionMatches(connection), serverContext?.serverID == targetID else { return }
            if action == "user.export" {
                let result = try ExportArtifact(data)
                try result.validateProduction(serverID: targetID ?? "")
                artifact = result
            } else if action == "user.recovery.preview" {
                let recovery = data["recovery"]
                guard recovery["user_id"].string == params["user_id"]?.string,
                      recovery["state"].string != nil else { throw ModelError.invalidResponse("恢复预览与用户不匹配，请重新检查。") }
                recoveryPreview = recovery
            } else if action.hasSuffix(".preview") { preview = data }
            else {
                let raw = data["snapshot"]["schema_version"].int != nil ? data["snapshot"] : data
                if raw["schema_version"].int != nil {
                    let accepted = try acceptSnapshot(raw, expectedServerID: targetID, sequence: sequence)
                    if accepted, let revision, let updated = serverSnapshot?.revision, updated > revision {
                        recordOwnAdvance(from: revision, to: updated)
                    }
                } else {
                    let follow = nextSnapshotSequence()
                    try acceptSnapshot(await connection.call(RPCRequest(action: "snapshot", revision: nil, serverID: targetID)),
                                       expectedServerID: targetID, sequence: follow)
                }
                if !background {
                    if action == "user.subscription_email" || (action.hasPrefix("mail.") && action != "mail.status") {
                        let result = action == "user.subscription_email" ? data["mail"] : data
                        let outcome = MailFeedback.message(action: action, result: result)
                        notice = outcome.text; noticeIsWarning = outcome.warning
                    } else {
                        notice = actionNotice(action, params: params)
                        if action == "user.recovery.apply", let userID = params["user_id"]?.string {
                            beginRecoveryTracking(userID)
                        }
                    }
                }
            }
        } catch {
            handleFailure(error, action: action, background: background, connection: connection, targetID: targetID)
        }
    }
    /// One snapshot read at a time; a later click joins the read already in flight.
    private func refreshSnapshot(background: Bool) async {
        guard allowsAction("snapshot"), let connection = managementConnection else {
            if !background { error = "服务器尚未连接或未开放此操作。" }; return
        }
        if refreshing { if !background { manualRefreshPending = true }; return }
        let targetID = serverContext?.serverID
        let wasTrackingRecovery = recoveryNoticeUserID != nil
        refreshing = true; defer { refreshing = false }
        let sequence = nextSnapshotSequence()
        do {
            let data = try await connection.call(RPCRequest(action: "snapshot", revision: nil, serverID: targetID))
            guard connectionMatches(connection), serverContext?.serverID == targetID else { return }
            try acceptSnapshot(data, expectedServerID: targetID, sequence: sequence)
            let manual = !background || manualRefreshPending
            manualRefreshPending = false
            if manual && !wasTrackingRecovery { notice = "状态已刷新"; noticeIsWarning = false }
        } catch {
            let manual = !background || manualRefreshPending
            manualRefreshPending = false
            handleFailure(error, action: "snapshot", background: !manual, connection: connection, targetID: targetID)
        }
    }
    private func handleFailure(_ error: Error, action: String, background: Bool, connection: SSHManagementRPC?, targetID: String?) {
        guard connectionMatches(connection) else { return }
        if let model = error as? ModelError, case .remote(let code, _) = model, code == "REVISION_CONFLICT" {
            Task { await self.refreshSnapshot(background: true) }
            self.error = "状态已更新，已重新获取快照。请核对最新状态，重新打开编辑或确认操作后提交；没有自动重试修改。"
        } else if let model = error as? ModelError, case .remote(let code, let message) = model,
                  businessRejectionCodes.contains(code) {
            // A validated RPC rejection confirms the controller answered.
            // It does not make an invalid allocation or expired preview a network outage.
            if !background { self.error = String(message.prefix(600)) }
        } else {
            serverReachable = false; serverRefreshError = "连接待核对，修改已禁用；显示上次快照"
            if ServerContext.writeActions.contains(action) {
                serverNeedsReview = true
            }
            if !background { self.error = action == "mail.configure" ? "邮件设置未确认保存成功。请刷新核对；授权码不会保留或回显。" : String(error.localizedDescription.prefix(600)) }
        }
    }
    private func connectionMatches(_ connection: SSHManagementRPC?) -> Bool {
        guard let connection, let current = managementConnection else { return false }
        return current.host == connection.host && current.identityFile == connection.identityFile &&
            sshHost.trimmingCharacters(in: .whitespacesAndNewlines) == connection.host && sshKeyPath == connection.identityFile
    }
    /// Returns false (and keeps the newer data) for a snapshot older than the one shown.
    @discardableResult
    private func acceptSnapshot(_ raw: JSONValue, expectedServerID: String?, sequence: Int) throws -> Bool {
        let value = try Snapshot(raw)
        let context = try ServerContext(snapshot: value, expectedServerID: expectedServerID)
        serverReachable = true; serverRefreshError = nil
        if let current = serverSnapshot {
            if value.revision < current.revision { return false }
            if value.revision == current.revision && sequence < acceptedSnapshotSequence { return false }
        }
        serverContext = context
        serverSnapshot = value; serverUpdated = Date(); acceptedSnapshotSequence = sequence
        updateRecoveryNotice()
        return true
    }
    private func nextSnapshotSequence() -> Int { snapshotSequence += 1; return snapshotSequence }
    private func resetOrdering() {
        acceptedSnapshotSequence = 0; ownRevisionAdvances = [:]; manualRefreshPending = false
    }
    private func recordOwnAdvance(from old: Int64, to new: Int64) {
        ownRevisionAdvances[old] = new
        if ownRevisionAdvances.count > 64, let oldest = ownRevisionAdvances.keys.min() { ownRevisionAdvances[oldest] = nil }
    }
    /// The revision to send: the captured one, moved forward only through this App's own results.
    private func latestRevision(from captured: Int64?) -> Int64? {
        guard var revision = captured, let current = snapshot?.revision else { return nil }
        var steps = 0
        while revision != current, let next = ownRevisionAdvances[revision], steps < 64 { revision = next; steps += 1 }
        return revision == current ? current : nil
    }
    private func enterLane() async {
        if laneOccupied { await withCheckedContinuation { laneWaiters.append($0) } }
        else { laneOccupied = true }
    }
    private func leaveLane() {
        if laneWaiters.isEmpty { laneOccupied = false } else { laneWaiters.removeFirst().resume() }
    }
    private static func target(of params: [String: JSONValue]) -> String? {
        params["user_id"]?.string ?? params["account_id"]?.string
    }
    private static func fingerprint(_ action: String, _ params: [String: JSONValue]) -> Int {
        var hasher = Hasher(); hasher.combine(action)
        let encoder = JSONEncoder(); encoder.outputFormatting = .sortedKeys
        hasher.combine((try? encoder.encode(params)) ?? Data())
        return hasher.finalize()
    }
    private func beginRecoveryTracking(_ userID: String) {
        recoveryNoticeUserID = userID; recoveryStartedAt = Date(); recoveryLastStep = 0; recoveryOutcome = nil
        updateRecoveryNotice()
    }
    private func updateRecoveryNotice() {
        guard let userID = recoveryNoticeUserID, let user = users.first(where: { $0.id == userID }) else { return }
        notice = user.connectionRecoveryLabel
        noticeIsWarning = ["failed", "blocked"].contains(user.recovery.state)
        let progress = RecoveryProgress(recovery: user.recovery, lastStep: recoveryLastStep)
        recoveryLastStep = progress.step
        if !["checking", "recovering", "starting"].contains(user.recovery.state) {
            if recoveryStartedAt != nil { recoveryOutcome = RecoveryOutcome(userID: userID, name: user.name, progress: progress) }
            recoveryNoticeUserID = nil; recoveryStartedAt = nil
        }
    }
    /// Live progress of the recovery being confirmed, or the last finished one.
    var recoveryDisplay: (name: String, progress: RecoveryProgress, startedAt: Date?)? {
        if let userID = recoveryNoticeUserID, recoveryStartedAt != nil, let user = users.first(where: { $0.id == userID }) {
            return (user.name, RecoveryProgress(recovery: user.recovery, lastStep: recoveryLastStep), recoveryStartedAt)
        }
        if let outcome = recoveryOutcome { return (outcome.name, outcome.progress, nil) }
        return nil
    }
    static func operationTitle(_ action: String) -> String {
        switch action {
        case "user.add": "添加用户"
        case "user.update": "保存用户设置"
        case "user.topup": "增加额度"
        case "user.enable": "启用用户"
        case "user.disable": "停用用户"
        case "user.rotate": "轮换凭据"
        case "user.revoke": "撤销用户"
        case "user.delete": "删除用户"
        case "user.export": "导出配置"
        case "user.subscription_email": "重发订阅邮件"
        case "user.cleanup.confirm": "确认清理"
        case "user.recovery.preview": "检查连接"
        case "user.recovery.apply": "恢复连接"
        case "registration.approve": "启用申请"
        case "registration.reject": "拒绝申请"
        case "registration.bind": "关联邮箱"
        case "budget.configure": "确认预算"
        case "trial.create": "创建体验"
        case "trial.update": "调整体验"
        case "settings.update": "保存设置"
        case "provider.observe": "保存商家记录"
        case "mail.configure": "保存邮件设置"
        case "mail.test": "发送测试邮件"
        case "mail.verify.send": "发送验证码"
        case "mail.verify.confirm": "验证邮箱"
        case "mail.preferences": "保存通知设置"
        case "deploy.preview", "rollback.preview": "生成预览"
        default: "操作"
        }
    }
    private func actionNotice(_ action: String, params: [String: JSONValue]) -> String {
        switch action {
        case "registration.approve": "启用请求已提交，正在等待实例和计量确认"
        case "registration.reject": "申请已拒绝，订阅保持未启用"
        case "registration.bind": "邮箱归属已关联，原订阅、凭据和用量保持；实际连接状态以服务器确认为准"
        case "user.add": "用户已添加"
        case "user.update": "用户设置已保存"
        case "user.topup": "本周期额度已增加"
        case "user.disable": "停用请求已提交，等待服务确认"
        case "user.enable": "授权设置已更新，实例状态以服务确认为准"
        case "user.rotate": "新凭据已生成，请重新导出"
        case "user.revoke": "撤销请求已提交，等待服务确认"
        case "user.delete": "删除已归档；实例停止状态等待服务确认"
        case "user.cleanup.confirm": "未知尾部用量确认已记录，资源释放以服务器确认为准"
        case "user.recovery.apply": users.first(where: { $0.id == params["user_id"]?.string })?.recovery.label ?? "恢复请求已提交，等待运行和可信计量确认"
        case "budget.configure": "人工预算已确认；商家实时余量仍未核验"
        case "trial.create": "体验用户已创建，连接以实例运行及计量确认为准"
        case "trial.update": "体验设置已保存；累计用量继续保留"
        case "provider.observe": "商家核对记录已保存"
        case "settings.update": params.keys.contains(where: { ["day", "time", "timezone"].contains($0) }) ? "刷新规则已保存，下个边界生效" : "设置已保存"
        default: "已完成"
        }
    }
    func chooseSSHKey() {
        guard fixedConnection == nil else { return }
        let panel = NSOpenPanel(); panel.canChooseDirectories = false; panel.canChooseFiles = true; panel.allowsMultipleSelection = false
        panel.title = "选择已有的 SSH 私钥"; panel.message = "只引用外部文件，不复制、不修改，也不会自动信任未知服务器。"
        if panel.runModal() == .OK, let url = panel.url { sshKeyPath = url.path }
    }
    private func confirmIdentity() async -> Bool {
        if let identityCheck { return await identityCheck() }
        return await authenticate()
    }
    private func authenticate() async -> Bool {
        let context = LAContext(); context.localizedCancelTitle = "取消"
        var failure: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &failure) else {
            error = "系统身份确认不可用。请先设置 Mac 登录密码或 Touch ID，再执行此敏感操作。"; return false
        }
        do { return try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "确认管理 Dazzle'VPS 的敏感设置或私密凭据") }
        catch { noticeIsWarning = true; notice = "已取消操作"; return false }
    }
    func saveArtifact(_ artifact: ExportArtifact) {
        let panel = NSSavePanel(); panel.nameFieldStringValue = artifact.filename; panel.canCreateDirectories = true
        panel.title = "保存私密配置"; panel.message = "文件仅当前用户可读写（0600）。请勿提交到公开仓库。"
        if panel.runModal() == .OK, let destination = panel.url {
            do { try SecureExport.write(Data(artifact.content.utf8), to: destination); notice = "已保存私密配置。" }
            catch { self.error = error.localizedDescription }
        }
    }
    func copyPrivate(_ text: String) {
        let board = NSPasteboard.general; board.clearContents(); board.setString(text, forType: .string)
        let count = board.changeCount; notice = "已复制；若剪贴板未变化，60 秒后自动清除。"
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(60))
            if board.changeCount == count { board.clearContents() }
        }
    }
}
