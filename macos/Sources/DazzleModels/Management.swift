import Foundation

/// A server advertises a subset of this application's fixed project-only protocol.
/// A capability never grants shell, installation, legacy retirement or simulation APIs.
public struct ServerContext: Sendable, Equatable {
    public static let readActions: Set<String> = ["doctor", "status", "snapshot", "user.list", "user.resolve", "user.export", "deploy.preview", "rollback.preview", "mail.status"]
    public static let writeActions: Set<String> = ["user.add", "user.enable", "user.disable", "user.revoke", "user.rotate", "user.update", "user.topup", "settings.update", "provider.observe", "meter.reconcile", "user.delete", "mail.configure", "mail.verify.send", "mail.verify.confirm", "mail.test", "mail.preferences"]
    public let serverID: String
    public let allowedActions: Set<String>
    public let productionMutations: Bool

    public init(snapshot: Snapshot, expectedServerID: String? = nil) throws {
        let capabilities = snapshot["capabilities"]
        guard snapshot["mode"].string == "production", let identifier = snapshot["server_id"].string,
              UUID(uuidString: identifier) != nil,
              capabilities["controller"].string == "root_policy",
              capabilities["legacy_retirement"].bool == false,
              snapshot["legacy"]["managed"].bool == false,
              snapshot["legacy"]["retirement_supported"].bool == false,
              capabilities["allowed_actions"].array.allSatisfy({ $0.string != nil }) else {
            throw ModelError.invalidResponse("服务器没有返回受限的新程序管理能力；修改功能保持关闭。")
        }
        guard expectedServerID == nil || expectedServerID == identifier else {
            throw ModelError.invalidResponse("服务器身份与已固定的身份不符；连接已拒绝，请先通过现有管理流程核实。")
        }
        let actions = Set(capabilities["allowed_actions"].array.compactMap(\.string))
        guard actions.contains("snapshot") else { throw ModelError.invalidResponse("服务器未开放快照能力。") }
        serverID = identifier
        productionMutations = capabilities["production_mutations"].bool == true
        allowedActions = actions.intersection(Self.readActions.union(Self.writeActions))
    }
    public func allows(_ action: String) -> Bool {
        allowedActions.contains(action) && (Self.readActions.contains(action) || productionMutations)
    }
    public var canModify: Bool { productionMutations && !allowedActions.intersection(Self.writeActions).isEmpty }
}

public enum WorkerState {
    public static func meterLabel(_ value: String?) -> String {
        switch value {
        case "trusted": "计量正常"
        case "reconciliation_required": "需人工核对"
        case "failure": "计量异常"
        case nil, "unknown", "uninitialized": "尚未建立可信计量"
        default: "计量状态未确认"
        }
    }
    public static func label(_ value: String?) -> String {
        switch value {
        case "unprovisioned": "待配置"
        case "provisioned": "已配置 · 代理未开启"
        case "staged": "就绪 · 代理未开启"
        case "starting": "正在启动"
        case "running": "运行中"
        case "stop_pending": "正在停止"
        case "stop_failed": "停止失败"
        case "stopped": "已停止"
        case "revoked": "已撤销"
        default: "状态未确认"
        }
    }
    public static func requested(_ user: ProxyUser) -> String {
        switch user.raw["requested_authorization"].string {
        case "enabled": "授权已开启"
        case "disabled": "授权已关闭"
        case "revoked": "授权已撤销"
        default: user.revoked ? "授权已撤销" : user.reasons.contains("manual_disabled") ? "授权已关闭" : "授权已开启"
        }
    }
}
