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
    public var needsBindingConfirmation: Bool { status == "needs_confirmation" && proxyUserID == nil }
    public var requiresReview: Bool { ["pending", "waiting_resources", "provisioning", "failed", "needs_confirmation"].contains(status) }
    public var bindingCandidates: [RegistrationBindingCandidate] { raw["binding_candidates"].array.compactMap(RegistrationBindingCandidate.init) }
    public var bindableCandidates: [RegistrationBindingCandidate] {
        bindingCandidates.filter { $0.canBind && $0.email.caseInsensitiveCompare(email) == .orderedSame }
    }
    public var bindingExplanation: String {
        switch raw["binding_issue"].string {
        case "email_conflict": "此邮箱对应多个记录，请先在用户管理中核对归属。未形成唯一匹配前不能绑定。"
        case "email_not_verified": "已有用户的通知邮箱尚未验证。请先在用户管理中完成验证，再刷新核对。"
        case "previous_authorization_revoked": "此前授权已撤销，不能通过邮箱登录恢复旧凭据。请核对是否需要重新授权。"
        case "already_linked": "此用户已被其他门户账户绑定，请先核对账户归属。"
        case "authorization_unavailable": "已有授权尚不完整或已清理，请先检查用户与实例状态。"
        default: "请核对已有用户与已验证邮箱；只有服务器确认的唯一匹配才能关联。"
        }
    }
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
        case "needs_confirmation": "待确认邮箱归属"
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

public struct RegistrationBindingCandidate: Identifiable, Sendable, Equatable {
    public let raw: JSONValue
    public let id: String
    public init?(_ raw: JSONValue) {
        guard let id = raw["user_id"].string, !id.isEmpty,
              let email = raw["email"].string, !email.isEmpty else { return nil }
        self.id = id; self.raw = raw
    }
    public var name: String { raw["name"].string ?? "已有用户" }
    public var email: String { raw["email"].string ?? "" }
    public var verified: Bool { raw["email_verified"].bool == true }
    public var canBind: Bool { verified && raw["can_bind"].bool == true }
    public var explanation: String {
        if canBind { return "已验证邮箱 · 服务器确认唯一匹配" }
        return switch raw["reason"].string {
        case "email_conflict": "邮箱存在重复记录，须先核对"
        case "already_linked": "已关联其他门户账户"
        case "previous_authorization_revoked", "revoked", "deleted": "原授权已撤销，不能恢复"
        case "authorization_unavailable": "授权尚不可用"
        default: verified ? "当前不能绑定，请核对服务器状态" : "通知邮箱尚未验证"
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
    public let reservedApplications: Int
    public var admissionRemaining: Int { max(0, available - reservedApplications) }
    public var admissionFull: Bool { rawFull ?? (admissionRemaining == 0) }
    private let rawFull: Bool?
    public init(_ raw: JSONValue) {
        supported = raw["enabled"].bool != nil
        enabled = supported && raw["enabled"].bool == true
        accounts = raw["accounts"].array.compactMap(RegistrationAccount.init)
        pendingCount = max(0, Int(raw["pending_count"].int ?? 0))
        available = max(0, Int(raw["pool"]["available"].int ?? 0))
        total = max(0, Int(raw["pool"]["total"].int ?? 0))
        reservedApplications = max(0, Int(raw["capacity"]["waiting"].int ?? Int64(accounts.filter { $0.proxyUserID == nil && ["pending", "waiting_resources"].contains($0.status) }.count)))
        rawFull = raw["capacity"]["full"].bool
    }
    public func approveParameters(account: RegistrationAccount, quotaBytes: Int64) throws -> [String: JSONValue] {
        guard supported, account.canApprove, QuotaInput.valid(quotaBytes, minimumGB: 50) else { throw ModelError.invalidResponse("请核对申请状态，周期额度需为至少 50 GB 的整数。") }
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
    public func bindParameters(account: RegistrationAccount, candidateID: String) throws -> [String: JSONValue] {
        guard supported, account.needsBindingConfirmation,
              account.bindableCandidates.count == 1,
              account.bindableCandidates.first?.id == candidateID else {
            throw ModelError.invalidResponse("邮箱归属尚未形成唯一、已验证的匹配，请先核对已有用户并刷新。")
        }
        return ["account_id": .string(account.id), "user_id": .string(candidateID)]
    }
}
