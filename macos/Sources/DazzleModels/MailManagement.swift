import Foundation

public struct MailStatus: Sendable {
    public let raw: JSONValue
    public init(_ raw: JSONValue) { self.raw = raw }
    public var configured: Bool { raw["configured"].bool == true && raw["secret_configured"].bool == true }
    public var secretConfigured: Bool { raw["secret_configured"].bool == true }
    public var enabled: Bool { raw["preferences"]["enabled"].bool ?? false }
    public var adminEmail: String { raw["admin_email"].string ?? "" }
    public var adminVerified: Bool { raw["admin_email_verified"].bool == true }
    public func canRequestVerification(address: String) -> Bool {
        configured && enabled && Self.validEmail(address)
    }
    public func canTest(address: String, verified: Bool) -> Bool { canRequestVerification(address: address) && verified }
    public static func validEmail(_ address: String) -> Bool {
        address.range(of: #"\A[^\s@]+@[^\s@]+\.[^\s@]+\z"#, options: .regularExpression) != nil
    }
    public static func historyLabel(_ status: String?) -> String {
        switch status {
        case "sent", "smtp_accepted": "SMTP 已接受 · 送达待确认"
        case "queued": "等待提交"
        case "sending": "正在提交 SMTP"
        case "retry": "等待重试"
        case "dead", "failed": "提交失败"
        case "cancelled": "已取消"
        default: "状态待确认"
        }
    }
}

public struct SMTPDraft: Sendable {
    public var host: String
    public var port: String
    public var security: String
    public var username: String
    public var sender: String
    public var adminEmail: String
    public init(host: String, port: String, security: String, username: String, sender: String, adminEmail: String) {
        self.host = host; self.port = port; self.security = security; self.username = username; self.sender = sender; self.adminEmail = adminEmail
    }
    public func parameters(secret: String) throws -> [String: JSONValue] {
        let host = host.trimmingCharacters(in: .whitespacesAndNewlines)
        let username = username.trimmingCharacters(in: .whitespacesAndNewlines)
        let sender = sender.trimmingCharacters(in: .whitespacesAndNewlines)
        let adminEmail = adminEmail.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !host.isEmpty, !host.contains(where: { $0.isWhitespace }), let port = Int64(port), (1...65535).contains(port),
              ["ssl", "starttls"].contains(security), !username.isEmpty,
              MailStatus.validEmail(sender), MailStatus.validEmail(adminEmail) else {
            throw ModelError.invalidResponse("请填写有效的 SMTP 主机、端口、账号、发件地址和管理员邮箱。")
        }
        var params: [String: JSONValue] = ["host": .string(host), "port": .integer(port), "security": .string(security),
             "username": .string(username), "sender": .string(sender), "admin_email": .string(adminEmail)]
        if !secret.isEmpty { params["secret"] = .string(secret) }
        return params
    }
}

public enum MailFeedback {
    public static func message(action: String, result: JSONValue) -> (text: String, warning: Bool) {
        if action == "mail.configure" {
            return result["configured"].bool == true ? ("邮件设置已保存", false) : ("设置已保存，请补充邮箱授权码", true)
        }
        if action == "mail.verify.confirm" {
            if result["verified"].bool == true { return ("邮箱已验证", false) }
        } else if ["mail.verify.send", "mail.test"].contains(action), result["queued"].bool == true {
            return (action == "mail.test" ? "测试邮件已排队，等待 SMTP 提交" : "验证邮件已排队，请稍后查收", false)
        } else if action == "mail.preferences" { return ("邮件提醒偏好已保存", false) }
        let reasons = ["smtp_secret_required": "请先填写邮箱授权码", "not_configured": "请先完成发件设置", "smtp_not_configured": "请先完成发件设置",
            "invalid_code": "验证码不正确", "expired": "验证码已过期，请重新发送", "attempt_limit": "验证次数已用尽，请重新发送",
            "verification_missing": "请先获取验证码", "email_unverified": "请先验证收件邮箱", "recipient_unavailable": "请先绑定收件邮箱",
            "notifications_disabled": "请先开启邮件提醒", "cooldown": "发送过于频繁，请稍后重试", "duplicate": "已有相同邮件等待处理"]
        return (reasons[result["reason"].string ?? ""] ?? "操作未完成，请核对邮件设置与验证状态", true)
    }
}

public enum UserDeletionPolicy {
    public static func stopConfirmed(_ user: ProxyUser) -> Bool {
        ["revoked", "stopped"].contains(user.raw["runtime_state"].string ?? "")
    }
    public static func isProtectedAdministrator(_ user: ProxyUser, currentUsers: [ProxyUser]) -> Bool {
        user.role == "admin" && !currentUsers.contains { $0.id != user.id && $0.role == "admin" && !$0.revoked }
    }
}
