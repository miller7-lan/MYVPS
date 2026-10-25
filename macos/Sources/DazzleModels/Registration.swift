import Foundation

public struct RegistrationAccount: Identifiable, Sendable, Equatable {
    public let raw: JSONValue
    public let id: String
    public init?(_ raw: JSONValue) {
        guard let id = raw["id"].string, !id.isEmpty, let email = raw["email"].string, !email.isEmpty,
              raw["email_verified"].bool != false else { return nil }
        self.id = id; self.raw = raw
    }
    public var email: String { raw["email"].string ?? "" }
    public var nickname: String {
        guard let name = raw["nickname"].string, !name.isEmpty else { return "共享用户" }; return name
    }
    public var status: String { raw["status"].string ?? "unknown" }
    public var proxyUserID: String? { raw["proxy_user_id"].string }
    public var canApprove: Bool { proxyUserID == nil && ["pending", "waiting_resources", "rejected", "failed"].contains(status) }
    public var canReject: Bool { proxyUserID == nil && ["pending", "waiting_resources", "failed"].contains(status) }
    public func activationConfirmed(users: [ProxyUser]) -> Bool {
        guard status == "active", let user = users.first(where: { $0.id == proxyUserID }) else { return false }
        return user.raw["runtime_state"].string == "running" && user.raw["runtime_verified_at"].string != nil &&
            user.raw["meter_state"].string == "trusted" && user.reasons.isEmpty && !user.revoked
    }
    public func label(users: [ProxyUser]) -> String {
        switch status {
        case "pending": "待审核"
        case "waiting_resources": "等待资源"
        case "provisioning": "正在开通"
        case "active": activationConfirmed(users: users) ? "已启用" : "运行待核实"
        case "rejected": "已拒绝"
        case "disabled": "已停用"
        case "revoked": "已撤销"
        case "failed": "开通失败"
        default: "状态待核对"
        }
    }
}

public struct RegistrationOverview: Sendable {
    public let supported: Bool
    public let enabled: Bool
    public let accounts: [RegistrationAccount]
    public let pendingCount: Int
    public let available: Int
    public let total: Int
    public init(_ raw: JSONValue) {
        supported = raw["enabled"].bool != nil
        enabled = supported && raw["enabled"].bool == true
        accounts = raw["accounts"].array.compactMap(RegistrationAccount.init)
        pendingCount = max(0, Int(raw["pending_count"].int ?? 0))
        available = max(0, Int(raw["pool"]["available"].int ?? 0))
        total = max(0, Int(raw["pool"]["total"].int ?? 0))
    }
    public func approveParameters(account: RegistrationAccount, quotaBytes: Int64) throws -> [String: JSONValue] {
        guard supported, account.canApprove, quotaBytes > 0 else { throw ModelError.invalidResponse("请核对申请状态和周期额度。") }
        guard available > 0 else { throw ModelError.invalidResponse("没有空闲的已批准槽位；申请继续排队，请先审批资源扩容。") }
        return ["account_id": .string(account.id), "quota_bytes": .integer(quotaBytes)]
    }
    public func rejectParameters(account: RegistrationAccount, reason: String) throws -> [String: JSONValue] {
        guard supported, account.canReject else { throw ModelError.invalidResponse("当前申请不能拒绝，请刷新核对。") }
        let reason = reason.trimmingCharacters(in: .whitespacesAndNewlines)
        guard reason.count <= 200 else { throw ModelError.invalidResponse("拒绝原因最多200字。") }
        var result: [String: JSONValue] = ["account_id": .string(account.id)]
        if !reason.isEmpty { result["reason"] = .string(reason) }
        return result
    }
}
