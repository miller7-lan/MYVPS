import SwiftUI
import AppKit
import LocalAuthentication
import DazzleModels
import DazzleTransport

@MainActor @Observable final class AppStore {
    var serverSnapshot: Snapshot?
    var serverContext: ServerContext?
    var busy = false
    var error: String?
    var notice: String?
    var noticeIsWarning = false
    var artifact: ExportArtifact?
    var preview: JSONValue?
    var sensitiveInputActive = false
    var sshHost: String
    var sshKeyPath: String
    var serverReachable = false
    var serverNeedsReview = false
    var serverRefreshError: String?
    private var serverUpdated: Date?
    private var managementConnection: SSHManagementRPC?
    var snapshot: Snapshot? { serverSnapshot }
    var lastUpdated: Date? { serverUpdated }
    var users: [ProxyUser] { snapshot?.users ?? [] }
    var deletedUsers: [ProxyUser] { value("deleted_users").array.compactMap(ProxyUser.init) }
    var canModify: Bool { !busy && serverSnapshot != nil && serverReachable && !serverNeedsReview && serverContext?.canModify == true }
    private let defaults: UserDefaults
    private let managementFactory: @Sendable (String, String) throws -> SSHManagementRPC
    private let readsWithoutRevision: Set<String> = ["snapshot", "status", "doctor", "user.list", "user.resolve", "deploy.preview", "rollback.preview", "mail.status"]

    init(defaults: UserDefaults = .standard,
         managementFactory: @escaping @Sendable (String, String) throws -> SSHManagementRPC = { try SSHManagementRPC(host: $0, identityFile: $1) }) {
        self.defaults = defaults; self.managementFactory = managementFactory
        sshHost = defaults.string(forKey: "sshHost") ?? ""
        sshKeyPath = defaults.string(forKey: "sshKeyPath") ?? ""
    }
    /// Restores an existing connection with one read-only handshake; never creates authorization.
    func restoreConnection() async {
        guard managementConnection == nil, !sshHost.isEmpty, !sshKeyPath.isEmpty else { return }
        await connectManagement()
    }
    func value(_ key: String) -> JSONValue { snapshot?[key] ?? .null }
    func canPerform(_ action: String) -> Bool { !busy && allowsAction(action) }
    private func allowsAction(_ action: String) -> Bool {
        guard managementConnection != nil, serverSnapshot != nil, let serverContext, serverContext.allows(action) else { return false }
        if ServerContext.writeActions.contains(action) { return serverReachable && !serverNeedsReview }
        return action == "snapshot" || action == "status" || serverReachable
    }
    func refresh() async {
        guard !busy else { return }
        guard managementConnection != nil else { await restoreConnection(); return }
        await perform("snapshot")
        if serverReachable { serverNeedsReview = false }
    }
    /// Read-only refresh of the connected controller, never a provider poll or write retry.
    func pollManagement() async {
        guard managementConnection != nil, !busy, !sensitiveInputActive,
              artifact == nil, preview == nil, error == nil else { return }
        await perform("snapshot", background: true)
    }
    func invalidateServerConnection() {
        serverContext = nil; serverSnapshot = nil; managementConnection = nil
        serverReachable = false; serverUpdated = nil; serverRefreshError = nil
        artifact = nil; preview = nil
    }
    func connectManagement() async {
        guard !busy else { return }
        busy = true; defer { busy = false }
        serverSnapshot = nil; serverContext = nil; serverReachable = false
        managementConnection = nil; serverRefreshError = nil
        do {
            let connection = try managementFactory(sshHost.trimmingCharacters(in: .whitespacesAndNewlines), sshKeyPath)
            let host = connection.host, key = connection.identityFile
            let data = try await connection.call(RPCRequest(action: "snapshot", revision: nil))
            guard sshHost.trimmingCharacters(in: .whitespacesAndNewlines) == host, sshKeyPath == key else { return }
            let snapshot = try Snapshot(data)
            let pins = defaults.dictionary(forKey: "managementServerPins") as? [String: String] ?? [:]
            let context = try ServerContext(snapshot: snapshot, expectedServerID: pins[host.lowercased()])
            var updatedPins = pins; updatedPins[host.lowercased()] = context.serverID
            defaults.set(updatedPins, forKey: "managementServerPins")
            defaults.set(host, forKey: "sshHost"); defaults.set(key, forKey: "sshKeyPath")
            managementConnection = connection; serverContext = context; serverSnapshot = snapshot
            serverReachable = true; serverNeedsReview = false; serverUpdated = Date()
            noticeIsWarning = false; notice = "已连接新程序；现有代理继续保留"
        } catch { self.error = String(error.localizedDescription.prefix(600)) }
    }
    func perform(_ action: String, _ params: [String: JSONValue] = [:], background: Bool = false, expectedRevision: Int64? = nil) async {
        guard !busy else { return }
        guard allowsAction(action) else { if !background { error = "服务器尚未连接或未开放此操作。" }; return }
        let targetID = serverContext?.serverID
        let connection = managementConnection
        busy = true; if !background { noticeIsWarning = false }; defer { busy = false }
        if !readsWithoutRevision.contains(action), !(await authenticate()) { return }
        guard serverContext?.serverID == targetID, connectionMatches(connection) else { return }
        do {
            guard let connection else { throw TransportError.unavailable("服务器尚未连接。") }
            let request = RPCRequest(action: action, revision: readsWithoutRevision.contains(action) ? nil : (expectedRevision ?? snapshot?.revision),
                                     params: params, serverID: targetID)
            let data = try await connection.call(request)
            guard connectionMatches(connection), serverContext?.serverID == targetID else { return }
            if action == "user.export" {
                let result = try ExportArtifact(data)
                try result.validateProduction(serverID: targetID ?? "")
                artifact = result
            } else if action.hasSuffix(".preview") { preview = data }
            else {
                let raw = data["snapshot"]["schema_version"].int != nil ? data["snapshot"] : data
                if raw["schema_version"].int != nil { try acceptSnapshot(raw, expectedServerID: targetID) }
                else { try acceptSnapshot(await connection.call(RPCRequest(action: "snapshot", revision: nil, serverID: targetID)), expectedServerID: targetID) }
                if action != "snapshot" && action != "status" && !background {
                    if action.hasPrefix("mail."), action != "mail.status" {
                        let outcome = MailFeedback.message(action: action, result: data)
                        notice = outcome.text; noticeIsWarning = outcome.warning
                    } else { notice = actionNotice(action, params: params) }
                }
            }
        } catch {
            guard connectionMatches(connection) else { return }
            if let model = error as? ModelError, case .remote(let code, _) = model, code == "REVISION_CONFLICT" {
                do {
                    if let connection { try acceptSnapshot(await connection.call(RPCRequest(action: "snapshot", revision: nil, serverID: targetID)), expectedServerID: targetID) }
                } catch { serverReachable = false }
                self.error = "状态已更新，已重新获取快照。请核对最新状态，重新打开编辑或确认操作后提交；没有自动重试修改。"
            } else {
                serverReachable = false; serverRefreshError = "连接待核对，修改已禁用；显示上次快照"
                if ServerContext.writeActions.contains(action) {
                    if let model = error as? ModelError, case .remote = model { /* explicit domain failure */ }
                    else { serverNeedsReview = true }
                }
                if !background { self.error = action == "mail.configure" ? "邮件设置未确认保存成功。请刷新核对；授权码不会保留或回显。" : String(error.localizedDescription.prefix(600)) }
            }
        }
    }
    private func connectionMatches(_ connection: SSHManagementRPC?) -> Bool {
        guard let connection, let current = managementConnection else { return false }
        return current.host == connection.host && current.identityFile == connection.identityFile &&
            sshHost.trimmingCharacters(in: .whitespacesAndNewlines) == connection.host && sshKeyPath == connection.identityFile
    }
    private func acceptSnapshot(_ raw: JSONValue, expectedServerID: String?) throws {
        let value = try Snapshot(raw)
        serverContext = try ServerContext(snapshot: value, expectedServerID: expectedServerID)
        serverSnapshot = value; serverUpdated = Date(); serverReachable = true; serverRefreshError = nil
    }
    private func actionNotice(_ action: String, params: [String: JSONValue]) -> String {
        switch action {
        case "user.add": "用户已添加"
        case "user.update": "用户设置已保存"
        case "user.topup": "本周期额度已增加"
        case "user.disable": "停用请求已提交，等待服务确认"
        case "user.enable": "授权设置已更新，实例状态以服务确认为准"
        case "user.rotate": "新凭据已生成，请重新导出"
        case "user.revoke": "撤销请求已提交，等待服务确认"
        case "user.delete": "删除已归档；实例停止状态等待服务确认"
        case "provider.observe": "商家核对记录已保存"
        case "settings.update": params.keys.contains(where: { ["day", "time", "timezone"].contains($0) }) ? "刷新规则已保存，下个边界生效" : "设置已保存"
        default: "已完成"
        }
    }
    func chooseSSHKey() {
        let panel = NSOpenPanel(); panel.canChooseDirectories = false; panel.canChooseFiles = true; panel.allowsMultipleSelection = false
        panel.title = "选择已有的 SSH 私钥"; panel.message = "只引用外部文件，不复制、不修改，也不会自动信任未知服务器。"
        if panel.runModal() == .OK, let url = panel.url { sshKeyPath = url.path }
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
