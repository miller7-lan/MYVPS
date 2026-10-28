import Foundation
import Testing
import DazzleModels
@testable import DazzleTransport
@testable import DazzleApp

private func bindingAccount(_ candidates: [JSONValue], status: String = "needs_confirmation") throws -> RegistrationAccount {
    try #require(RegistrationAccount(.object(["id": .string("binding-account"), "email": .string("friend@example.test"),
        "email_verified": .bool(true), "status": .string(status), "binding_issue": .string("email_conflict"),
        "binding_candidates": .array(candidates)])))
}

private func bindingCandidate(_ id: String = "existing-user", verified: Bool = true, allowed: Bool = true,
                              email: String = "friend@example.test") -> JSONValue {
    .object(["user_id": .string(id), "name": .string("Existing friend"), "email": .string(email),
        "email_verified": .bool(verified), "can_bind": .bool(allowed), "reason": .string(verified ? "" : "email_not_verified")])
}

@Test func existingEmailConfirmationRemainsVisibleAndCannotCreateDuplicateAuthorization() throws {
    let pending = try bindingAccount([bindingCandidate()])
    #expect(pending.requiresReview)
    #expect(pending.label(users: []) == "待确认邮箱归属")
    #expect(!pending.canApprove && !pending.canReject)
    let overview = RegistrationOverview(.object(["enabled": .bool(true)]))
    let params = try overview.bindParameters(account: pending, candidateID: "existing-user")
    #expect(params == ["account_id": .string("binding-account"), "user_id": .string("existing-user")])
    #expect(params["quota_bytes"] == nil && params["token"] == nil)
    #expect(throws: ModelError.self) { try overview.approveParameters(account: pending, quotaBytes: 100_000_000_000) }
    let request = RPCRequest(action: "registration.bind", revision: 21, params: params)
    #expect(request.expected_revision == 21)
    #expect(ServerContext.writeActions.contains(request.action))
}

@Test func bindingReviewRejectsUnverifiedConflictingForeignAndUnapprovedCandidates() throws {
    let overview = RegistrationOverview(.object(["enabled": .bool(true)]))
    for candidates in [[], [bindingCandidate(verified: false)], [bindingCandidate(allowed: false)],
                       [bindingCandidate(email: "someone-else@example.test")],
                       [bindingCandidate(), bindingCandidate("second-user")]] as [[JSONValue]] {
        let account = try bindingAccount(candidates)
        #expect(throws: ModelError.self) { try overview.bindParameters(account: account, candidateID: "existing-user") }
    }
    let account = try bindingAccount([bindingCandidate()])
    #expect(throws: ModelError.self) { try overview.bindParameters(account: account, candidateID: "unknown-user") }
    #expect(throws: ModelError.self) { try overview.bindParameters(account: bindingAccount([bindingCandidate()], status: "pending"), candidateID: "existing-user") }
}

@Test func recoveryGapReviewShowsUnknownBoundsWithoutInventingUsageOrExposingInternalKind() {
    let entry: JSONValue = .object(["kind": .string("future_internal_incident"), "from_at": .null,
        "to_at": .string("2026-10-26T08:00:05Z"), "detected_at": .string("2026-10-26T08:00:06Z"),
        "delta_unknown": .bool(true), "known_upload_bytes": .integer(1024), "known_download_bytes": .null])
    let summary = RecoveryGapSummary(.object(["last_trusted_at": .null, "observed_at": .string("2026-10-26T08:00:06Z"),
        "unresolved_count": .integer(23), "incidents": .array(Array(repeating: entry, count: 21)),
        "omitted_count": .integer(2), "may_restart_target": .bool(true), "preserves_recorded_usage": .bool(true)]))
    #expect(summary.available && summary.preservesRecordedUsage && summary.mayRestartTarget)
    #expect(summary.lastTrusted == "可信起点尚未确认")
    #expect(summary.incidents.count == 20 && summary.omittedCount == 3)
    #expect(summary.incidents[0].from == "起点未确认")
    #expect(summary.incidents[0].unknown)
    #expect(!summary.incidents[0].title.contains("future_internal"))
    #expect(summary.incidents[0].knownTraffic.contains("未确认"))
    #expect(!summary.incidents[0].to.contains("未确认"))
    #expect(!RecoveryGapSummary(.null).available)
    #expect(RecoveryGapSummary.time(.string("invalid-date")) == "未确认")
}

private actor RejectionController {
    let code: String
    init(code: String) { self.code = code }
    func reply(_ input: Data) throws -> Data {
        let request = try JSONDecoder().decode(RPCRequest.self, from: input)
        if request.action != "snapshot" {
            return try JSONEncoder().encode(JSONValue.object(["ok": .bool(false), "request_id": .string(request.request_id),
                "error": .object(["code": .string(code), "message": .string("操作未生效，请核对后重试。")])]))
        }
        let snapshot: JSONValue = .object(["schema_version": .integer(1), "mode": .string("production"), "revision": .integer(17),
            "server_id": .string("840737d0-365c-4da4-a706-3b3ee86be1da"), "users": .array([]),
            "legacy": .object(["managed": .bool(false), "retirement_supported": .bool(false)]),
            "capabilities": .object(["controller": .string("root_policy"), "legacy_retirement": .bool(false),
                "production_mutations": .bool(true), "allowed_actions": .array(["snapshot", "user.recovery.preview", "registration.bind"].map(JSONValue.string))])])
        return try JSONEncoder().encode(JSONValue.object(["ok": .bool(true), "request_id": .string(request.request_id), "data": snapshot]))
    }
}

@Test @MainActor func manualSnapshotRefreshCannotLeaveAnOldRecoveryProgressNotice() async throws {
    let key = FileManager.default.temporaryDirectory.appendingPathComponent("recovery-refresh-" + UUID().uuidString)
    try Data("local-test-only".utf8).write(to: key)
    defer { try? FileManager.default.removeItem(at: key) }
    let suite = "dazzle-recovery-refresh-" + UUID().uuidString
    let defaults = try #require(UserDefaults(suiteName: suite))
    defer { defaults.removePersistentDomain(forName: suite) }
    let controller = RejectionController(code: "VALIDATION")
    let store = AppStore(defaults: defaults, managementFactory: { host, key in
        try SSHManagementRPC(host: host, identityFile: key, execute: { _, input in try await controller.reply(input) })
    })
    store.sshHost = "192.0.2.20"; store.sshKeyPath = key.path
    await store.connectManagement()
    store.notice = "正在恢复连接"
    await store.refresh()
    #expect(store.serverReachable)
    #expect(store.notice == "状态已刷新")
}

private actor RecoveryProgressController {
    var state = "recovering"
    func finish() { state = "succeeded" }
    func reply(_ input: Data) throws -> Data {
        let request = try JSONDecoder().decode(RPCRequest.self, from: input)
        #expect(request.action == "snapshot")
        let raw: JSONValue = .object(["schema_version": .integer(1), "mode": .string("production"), "revision": .integer(18),
            "server_id": .string("840737d0-365c-4da4-a706-3b3ee86be1da"),
            "users": .array([.object(["id": .string("recovering-user"), "meter_state": .string("trusted"),
                "recovery": .object(["state": .string(state)])])]),
            "legacy": .object(["managed": .bool(false), "retirement_supported": .bool(false)]),
            "capabilities": .object(["controller": .string("root_policy"), "legacy_retirement": .bool(false),
                "forced_user_recovery": .bool(true), "production_mutations": .bool(true),
                "allowed_actions": .array([.string("snapshot")])])])
        return try JSONEncoder().encode(JSONValue.object(["ok": .bool(true), "request_id": .string(request.request_id), "data": raw]))
    }
}

@Test @MainActor func backgroundSnapshotCompletesTheTargetedRecoveryNoticeWithoutAWrite() async throws {
    let key = FileManager.default.temporaryDirectory.appendingPathComponent("recovery-progress-" + UUID().uuidString)
    try Data("local-test-only".utf8).write(to: key)
    defer { try? FileManager.default.removeItem(at: key) }
    let suite = "dazzle-recovery-progress-" + UUID().uuidString
    let defaults = try #require(UserDefaults(suiteName: suite))
    defer { defaults.removePersistentDomain(forName: suite) }
    let controller = RecoveryProgressController()
    let store = AppStore(defaults: defaults, managementFactory: { host, key in
        try SSHManagementRPC(host: host, identityFile: key, execute: { _, input in try await controller.reply(input) })
    })
    store.sshHost = "192.0.2.20"; store.sshKeyPath = key.path
    await store.connectManagement()
    #expect(store.forcedRecoveryAvailable)
    store.recoveryNoticeUserID = "recovering-user"; store.notice = "正在恢复连接"
    await controller.finish()
    await store.pollManagement()
    #expect(store.notice == "恢复成功 · 计量可信")
    #expect(store.recoveryNoticeUserID == nil)
    #expect(store.serverReachable)
}

@Test @MainActor func explicitBusinessRefusalsKeepConnectionButIdentityFailuresStillDisableWrites() async throws {
    let key = FileManager.default.temporaryDirectory.appendingPathComponent("interaction-key-" + UUID().uuidString)
    try Data("local-test-only".utf8).write(to: key); defer { try? FileManager.default.removeItem(at: key) }
    for code in ["BUDGET_EXCEEDED", "PROVIDER_REMAINING_EXCEEDED", "ADMIN_GUARD_REQUIRED", "RECOVERY_PREVIEW_EXPIRED", "VALIDATION", "MAIL_NOT_CONFIGURED", "EMAIL_NOT_VERIFIED", "NOT_ACTIVE", "RATE_LIMITED", "SERVER_ID_MISMATCH", "INTERNAL"] {
        let suite = "dazzle-interaction-" + UUID().uuidString
        let defaults = try #require(UserDefaults(suiteName: suite)); defer { defaults.removePersistentDomain(forName: suite) }
        let controller = RejectionController(code: code)
        let store = AppStore(defaults: defaults, managementFactory: { host, key in
            try SSHManagementRPC(host: host, identityFile: key, execute: { _, input in try await controller.reply(input) })
        })
        store.sshHost = "192.0.2.20"; store.sshKeyPath = key.path
        await store.connectManagement()
        #expect(store.canPerform("registration.bind"))
        await store.perform("user.recovery.preview", ["user_id": .string("fixture")])
        let businessFailure = !["SERVER_ID_MISMATCH", "INTERNAL"].contains(code)
        #expect(store.serverReachable == businessFailure)
        #expect(store.canPerform("registration.bind") == businessFailure)
        #expect(store.serverSnapshot?.revision == 17)
        #expect(store.error?.contains("操作未生效") == true)
        #expect((store.serverRefreshError == nil) == businessFailure)
    }
}
