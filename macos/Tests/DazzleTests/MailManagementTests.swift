import Foundation
import Testing
import DazzleModels
@testable import DazzleTransport
@testable import DazzleApp

@Test func smtpDraftKeepsSecretsWriteOnlyAndOmissionPreservesExistingCredential() throws {
    let draft = SMTPDraft(host: "smtp.qq.com", port: "465", security: "ssl", username: "sender@example.test", sender: "sender@example.test", adminEmail: "admin@example.test")
    let retained = try draft.parameters(secret: "")
    #expect(retained["secret"] == nil)
    let explicit = try draft.parameters(secret: "fixture-authorization-code")
    #expect(explicit["secret"] == .string("fixture-authorization-code"))
    #expect(retained["host"] == .string("smtp.qq.com"))
    #expect(retained["port"] == .integer(465))
    let invalid = SMTPDraft(host: "smtp.qq.com", port: "465", security: "none", username: "sender@example.test", sender: "sender@example.test", adminEmail: "admin@example.test")
    #expect(throws: ModelError.self) { try invalid.parameters(secret: "") }
}

@Test func verificationAndTestMailRequireConfiguredSecretAndExplicitVerification() {
    let missing = MailStatus(.object(["configured": .bool(true), "secret_configured": .bool(false), "preferences": .object(["enabled": .bool(true)])]))
    #expect(!missing.canRequestVerification(address: "admin@example.test"))
    let ready = MailStatus(.object(["configured": .bool(true), "secret_configured": .bool(true), "preferences": .object(["enabled": .bool(true)])]))
    #expect(ready.canRequestVerification(address: "admin@example.test"))
    #expect(!ready.canTest(address: "admin@example.test", verified: false))
    #expect(ready.canTest(address: "admin@example.test", verified: true))
    #expect(!ready.canTest(address: "", verified: true))
    #expect(!MailStatus(.null).canTest(address: "admin@example.test", verified: true))
}

@Test func queuedMailIsNeverReportedAsDeliveredAndNegativeRepliesRemainWarnings() {
    let queued = MailFeedback.message(action: "mail.test", result: .object(["queued": .bool(true)]))
    #expect(!queued.warning)
    #expect(queued.text.contains("已排队"))
    #expect(!queued.text.contains("已送达"))
    let failed = MailFeedback.message(action: "mail.verify.send", result: .object(["queued": .bool(false), "reason": .string("smtp_secret_required")]))
    #expect(failed.warning)
    #expect(failed.text.contains("授权码"))
    let rejected = MailFeedback.message(action: "mail.verify.confirm", result: .object(["verified": .bool(false), "reason": .string("invalid_code")]))
    #expect(rejected.warning)
    #expect(MailStatus.historyLabel("sent").contains("送达待确认"))
    #expect(!MailStatus.historyLabel("queued").contains("送达"))
}

@Test func subscriptionMailNeedsAnActiveTrustedUserAndVerifiedBoundEmail() throws {
    var value: [String: JSONValue] = ["id": .string("member"), "email": .string("member@example.test"),
        "email_verified": .bool(true), "runtime_state": .string("running"),
        "runtime_verified_at": .string("2026-10-27T00:00:00Z"), "meter_state": .string("trusted")]
    func user() throws -> ProxyUser { try #require(ProxyUser(.object(value))) }
    #expect(try user().canReceiveSubscriptionEmail)
    for (key, bad) in [("email_verified", JSONValue.bool(false)), ("email", .string("")),
                       ("runtime_state", .string("staged")), ("runtime_verified_at", .null),
                       ("meter_state", .string("reconciliation_required")),
                       ("subscription_email_available", .bool(false)),
                       ("disabled_reasons", .array([.string("manual_disabled")]))] {
        let original = value[key]
        value[key] = bad
        #expect(try !user().canReceiveSubscriptionEmail)
        value[key] = original
    }
    let queued = MailFeedback.message(action: "user.subscription_email", result: .object(["queued": .bool(true)]))
    #expect(!queued.warning && queued.text.contains("已排队"))
    #expect(!queued.text.contains("已送达"))
    let refused = MailFeedback.message(action: "user.subscription_email", result: .object(["queued": .bool(false), "reason": .string("cooldown")]))
    #expect(refused.warning && refused.text.contains("频繁"))
    #expect(ServerContext.writeActions.contains("user.subscription_email"))
    let request = RPCRequest(action: "user.subscription_email", revision: 7, params: ["user_id": .string("member")])
    #expect(request.expected_revision == 7 && request.params.object.count == 1)
}

@Test func archiveDeletionProtectsTheLastAdministratorAndPreservesSeparateHistory() throws {
    let admin = try #require(ProxyUser(.object(["id": .string("admin"), "role": .string("admin"), "status": .string("ready")])))
    let member = try #require(ProxyUser(.object(["id": .string("member"), "role": .string("member"), "status": .string("ready")])))
    #expect(UserDeletionPolicy.isProtectedAdministrator(admin, currentUsers: [admin, member]))
    #expect(!UserDeletionPolicy.isProtectedAdministrator(member, currentUsers: [admin, member]))
    let other = try #require(ProxyUser(.object(["id": .string("other"), "role": .string("admin"), "status": .string("ready")])))
    #expect(!UserDeletionPolicy.isProtectedAdministrator(admin, currentUsers: [admin, other]))
    let raw = JSONValue.object(["schema_version": .integer(1), "revision": .integer(9), "mode": .string("production"),
        "users": .array([admin.raw]), "deleted_users": .array([member.raw])])
    let snapshot = try Snapshot(raw)
    #expect(snapshot.users.map(\.id) == ["admin"])
    #expect(snapshot["deleted_users"].array.first?["id"].string == "member")
    let pending = try #require(ProxyUser(.object(["id": .string("pending"), "runtime_state": .string("stop_pending")])))
    let failed = try #require(ProxyUser(.object(["id": .string("failed"), "runtime_state": .string("stop_failed")])))
    let stopped = try #require(ProxyUser(.object(["id": .string("stopped"), "runtime_state": .string("revoked"), "worker": .object(["process_id": .null, "last_error": .null, "verified_at": .string("2026-10-25T16:19:00+08:00")])])))
    #expect(!UserDeletionPolicy.stopConfirmed(pending))
    #expect(!UserDeletionPolicy.stopConfirmed(failed))
    #expect(UserDeletionPolicy.stopConfirmed(stopped))
}

@Test func smtpSecretUsesOnlyRPCStandardInputAndNeverSSHArguments() async throws {
    let key = FileManager.default.temporaryDirectory.appendingPathComponent("mail-key-" + UUID().uuidString)
    try Data("fixture-not-a-real-key".utf8).write(to: key); defer { try? FileManager.default.removeItem(at: key) }
    let connection = try SSHManagementRPC(host: "192.0.2.20", identityFile: key.path) { arguments, input in
        #expect(!arguments.joined(separator: " ").contains("fixture-authorization-code"))
        let request = try JSONDecoder().decode(RPCRequest.self, from: input)
        #expect(request.action == "mail.configure")
        #expect(request.params["secret"].string == "fixture-authorization-code")
        return try JSONEncoder().encode(JSONValue.object(["ok": .bool(true), "request_id": .string(request.request_id), "data": .object(["configured": .bool(true)])]))
    }
    _ = try await connection.call(RPCRequest(action: "mail.configure", revision: 7, params: ["secret": .string("fixture-authorization-code")], serverID: "840737d0-365c-4da4-a706-3b3ee86be1da"))
}
