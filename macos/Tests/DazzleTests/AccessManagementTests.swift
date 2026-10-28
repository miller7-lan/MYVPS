import Foundation
import Testing
import DazzleModels
@testable import DazzleTransport
@testable import DazzleApp

@Test func allocationInputsRequireWholeGBWithSeparateMemberAndTrialMinimums() {
    #expect(QuotaInput.bytes("50", minimumGB: 50) == 50_000_000_000)
    #expect(QuotaInput.bytes("49", minimumGB: 50) == nil)
    #expect(QuotaInput.bytes("50.0", minimumGB: 50) == nil)
    #expect(QuotaInput.bytes("5e1", minimumGB: 50) == nil)
    #expect(QuotaInput.bytes("-50", minimumGB: 50) == nil)
    #expect(QuotaInput.bytes("５０", minimumGB: 50) == nil)
    #expect(QuotaInput.bytes(String(Int64.max)) == nil)
    #expect(QuotaInput.bytes("1") == 1_000_000_000)
    #expect(QuotaInput.bytes("0") == nil)
    #expect(QuotaInput.bytes("0", minimumGB: 0) == 0)
}

@Test func administratorBudgetRemainsDistinctFromProviderVerification() throws {
    let absent = AllocationBudget(.null)
    #expect(!absent.configured && !absent.canAllocate && !absent.permits(1))
    #expect(absent.administratorPolicy == "当前策略：不限额，预算保护尚未启用")
    let confirmed = AllocationBudget(.object(["source": .string("administrator_budget"), "configured": .bool(true), "verified": .bool(false), "can_allocate": .bool(true), "available_bytes": .integer(50_000_000_000)]))
    #expect(confirmed.canAllocate)
    #expect(confirmed.permits(50_000_000_000))
    #expect(!confirmed.permits(50_000_000_001))
    #expect(!confirmed.permits(-1))
    #expect(confirmed.raw["verified"].bool == false)
    let unknown = AllocationBudget(.object(["configured": .bool(true), "can_allocate": .bool(true)]))
    #expect(!unknown.permits(1))
}

@Test func budgetConfirmationRequiresEvidenceExplicitConsentAndValidMargin() throws {
    let params = try AllocationBudget.configure(total: "500", safety: "20", evidence: "Panel reviewed locally", confirmed: true)
    #expect(params["total_bytes"] == .integer(500_000_000_000))
    #expect(params["safety_margin_bytes"] == .integer(20_000_000_000))
    #expect(params["confirmed"] == .bool(true))
    #expect(params["verified"] == nil)
    #expect(throws: ModelError.self) { try AllocationBudget.configure(total: "500", safety: "500", evidence: "review", confirmed: true) }
    #expect(throws: ModelError.self) { try AllocationBudget.configure(total: "500", safety: "0", evidence: " ", confirmed: true) }
    #expect(throws: ModelError.self) { try AllocationBudget.configure(total: "500", safety: "0", evidence: "review", confirmed: false) }
}

@Test func ordinaryProfileEditsCanOmitQuotaWhileNewQuotaRequiresFiftyGB() throws {
    let member = try #require(ProxyUser(.object(["id": .string("member"), "quota_bytes": .integer(20_000_000_000)])))
    let profile = try UserPayload.update(user: member, name: "Renamed", quotaBytes: nil, email: "friend@example.test", autoRestore: true, thresholdPercent: 80)
    #expect(profile["quota_bytes"] == nil)
    #expect(profile["email"] == .string("friend@example.test"))
    #expect(throws: ModelError.self) { try UserPayload.update(user: member, name: "Member", quotaBytes: 49_000_000_000, email: "", autoRestore: true, thresholdPercent: 80) }
    #expect(throws: ModelError.self) { try UserPayload.update(user: member, name: "Member", quotaBytes: 50_500_000_000, email: "", autoRestore: true, thresholdPercent: 80) }
}

@Test func trialsHaveOwnTypeDurationAndLifetimeQuotaRatherThanMonthlyReset() throws {
    let trial = try #require(ProxyUser(.object(["id": .string("trial"), "type": .string("trial"), "trial": .object(["duration_days": .integer(3), "started_at": .string("2026-10-25T16:19:00+08:00"), "expires_at": .string("2026-10-28T16:19:00+08:00"), "status": .string("active")]) ])))
    #expect(trial.isTrial)
    #expect(trial.trial.durationDays == 3)
    #expect(trial.trial.status == "active")
    let defaults = try TrialAccess.parameters(name: " Test ", days: 3, quota: "5")
    #expect(defaults == ["name": .string("Test"), "duration_days": .integer(3), "quota_bytes": .integer(5_000_000_000)])
    let update = try TrialAccess.parameters(name: nil, userID: trial.id, days: 7, quota: "1")
    #expect(update["user_id"] == .string(trial.id))
    #expect(update["name"] == nil)
    #expect(throws: ModelError.self) { try TrialAccess.parameters(name: "Test", days: 0, quota: "5") }
    #expect(throws: ModelError.self) { try TrialAccess.parameters(name: "Test", days: 3, quota: "0.5") }
}

private func recoveryFixture(requiresGap: Bool = true, blocked: [String] = [], state: String = "idle") -> JSONValue {
    .object(["user_id": .string("user-fixture"), "state": .string(state), "can_apply": .bool(blocked.isEmpty), "blocked_reasons": .array(blocked.map(JSONValue.string)), "requires_unknown_gap_confirmation": .bool(requiresGap), "preview_token": .string("local-fixture-preview"), "expected_revision": .integer(17)])
}

@Test func recoveryIsBoundToPreviewUserRevisionAndExplicitUnknownGapConfirmation() throws {
    let recovery = UserRecovery(recoveryFixture())
    #expect(throws: ModelError.self) { try recovery.applyParameters(userID: "user-fixture", confirmedGap: false) }
    #expect(throws: ModelError.self) { try recovery.applyParameters(userID: "other-user", confirmedGap: true) }
    let parameters = try recovery.applyParameters(userID: "user-fixture", confirmedGap: true)
    #expect(parameters["preview_token"] == .string("local-fixture-preview"))
    #expect(parameters["confirm_unknown_gap"] == .bool(true))
    let request = RPCRequest(action: "user.recovery.apply", revision: recovery.raw["expected_revision"].int, params: parameters)
    #expect(request.expected_revision == 17)
    for reason in ["manual_disabled", "quota_exceeded", "pool_protection", "revoked", "deleted", "expired"] {
        #expect(throws: ModelError.self) { try UserRecovery(recoveryFixture(blocked: [reason])).applyParameters(userID: "user-fixture", confirmedGap: true) }
    }
    var missing = recoveryFixture().object; missing.removeValue(forKey: "preview_token")
    #expect(throws: ModelError.self) { try UserRecovery(.object(missing)).applyParameters(userID: "user-fixture", confirmedGap: true) }
}

@Test func recoveryLabelsDoNotTreatQueuedWorkAsSuccess() {
    #expect(UserRecovery(recoveryFixture(state: "checking")).label == "正在检查连接")
    #expect(UserRecovery(recoveryFixture(state: "recovering")).label == "正在恢复连接")
    #expect(UserRecovery(recoveryFixture(state: "starting")).label == "等待启动与计量确认")
    #expect(UserRecovery(recoveryFixture(state: "failed")).label == "恢复未成功")
    #expect(UserRecovery(recoveryFixture(state: "healthy")).label == "连接与计量正常")
}

@Test func explicitForcedRecoveryRetainsTheReviewedModeInApplyParameters() throws {
    var raw = recoveryFixture(state: "healthy").object
    raw["force_restart"] = .bool(true)
    let recovery = UserRecovery(.object(raw))
    #expect(throws: ModelError.self) { try recovery.applyParameters(userID: "user-fixture", confirmedGap: false) }
    let params = try recovery.applyParameters(userID: "user-fixture", confirmedGap: true)
    #expect(params["force_restart"] == .bool(true))
    #expect(recovery.label == "可主动强制重建连接")
    #expect(try UserRecovery(recoveryFixture()).applyParameters(userID: "user-fixture", confirmedGap: true)["force_restart"] == nil)
}

@Test func aNewMeterFaultKeepsRecoveryAvailableAfterAnEarlierSuccessfulRecovery() throws {
    let healthy: JSONValue = .object(["id": .string("member"), "meter_state": .string("trusted"),
        "recovery": .object(["state": .string("succeeded")]), "used_upload": .integer(123),
        "used_download": .integer(456), "quota_bytes": .integer(100_000_000_000)])
    let original = try #require(ProxyUser(healthy))
    #expect(!original.needsConnectionRecovery)
    var fault = healthy.object
    fault["meter_state"] = .string("reconciliation_required")
    fault["disabled_reasons"] = .array([.string("metering_failure")])
    let affected = try #require(ProxyUser(.object(fault)))
    #expect(affected.needsConnectionRecovery)
    #expect(affected.connectionRecoveryLabel == "计量异常，需要重新检查连接")
    #expect(affected.used == original.used && affected.allowance == original.allowance)
    fault["disabled_reasons"] = .array([.string("metering_failure"), .string("revoked")])
    #expect(try #require(ProxyUser(.object(fault))).needsConnectionRecovery == false)
}

@Test func newManagementActionsRequireServerAdvertisedCapabilities() throws {
    let newActions = ["user.recovery.preview", "user.recovery.apply", "budget.configure", "trial.create", "trial.update", "user.cleanup.confirm", "registration.bind", "user.subscription_email"]
    var raw: [String: JSONValue] = ["schema_version": .integer(1), "mode": .string("production"), "revision": .integer(4), "server_id": .string("840737d0-365c-4da4-a706-3b3ee86be1da"), "legacy": .object(["managed": .bool(false), "retirement_supported": .bool(false)])]
    func context(_ actions: [String], mutations: Bool) throws -> ServerContext {
        raw["capabilities"] = .object(["controller": .string("root_policy"), "legacy_retirement": .bool(false), "production_mutations": .bool(mutations), "allowed_actions": .array(actions.map(JSONValue.string))])
        return try ServerContext(snapshot: Snapshot(.object(raw)))
    }
    let old = try context(["snapshot"], mutations: true)
    #expect(newActions.allSatisfy { !old.allows($0) })
    let current = try context(["snapshot"] + newActions, mutations: true)
    #expect(newActions.allSatisfy { current.allows($0) })
    let readOnly = try context(["snapshot"] + newActions, mutations: false)
    #expect(readOnly.allows("user.recovery.preview"))
    #expect(!readOnly.allows("user.recovery.apply"))
    #expect(!readOnly.allows("registration.bind"))
    #expect(!readOnly.allows("user.subscription_email"))
}

@Test func deletionNeedsObservedStopAndSeparateCleanupProofBeforeClaimingReleased() throws {
    var raw: [String: JSONValue] = ["id": .string("deleted-fixture"), "status": .string("revoked"), "runtime_state": .string("revoked"), "cleanup": .object(["state": .string("waiting_reconciliation"), "requires_unknown_gap_confirmation": .bool(true)])]
    func user() throws -> ProxyUser { try #require(ProxyUser(.object(raw))) }
    #expect(!UserDeletionPolicy.stopConfirmed(try user()))
    raw["worker"] = .object(["process_id": .integer(123), "last_error": .null, "verified_at": .string("2026-10-25T16:19:00+08:00")])
    #expect(!UserDeletionPolicy.stopConfirmed(try user()))
    raw["worker"] = .object(["process_id": .null, "last_error": .null, "verified_at": .string("2026-10-25T16:19:00+08:00")])
    #expect(UserDeletionPolicy.stopConfirmed(try user()))
    #expect(!UserDeletionPolicy.cleanupConfirmed(try user()))
    #expect(UserDeletionPolicy.canConfirmUnknownTail(try user()))
    raw["cleanup"] = .object(["state": .string("released"), "requires_unknown_gap_confirmation": .bool(false)])
    #expect(UserDeletionPolicy.cleanupConfirmed(try user()))
    #expect(!UserDeletionPolicy.canConfirmUnknownTail(try user()))
    raw["worker"] = .object(["process_id": .null, "last_error": .string("STOP_FAILED"), "verified_at": .string("2026-10-25T16:19:00+08:00")])
    #expect(!UserDeletionPolicy.cleanupConfirmed(try user()))
}

private actor RecoveryPreviewController {
    var requests: [RPCRequest] = []
    func count() -> Int { requests.count }
    func last() -> RPCRequest? { requests.last }
    func reply(_ input: Data) throws -> Data {
        let request = try JSONDecoder().decode(RPCRequest.self, from: input); requests.append(request)
        let snapshot: JSONValue = .object(["schema_version": .integer(1), "mode": .string("production"), "revision": .integer(17), "server_id": .string("840737d0-365c-4da4-a706-3b3ee86be1da"), "users": .array([]), "legacy": .object(["managed": .bool(false), "retirement_supported": .bool(false)]), "capabilities": .object(["controller": .string("root_policy"), "legacy_retirement": .bool(false), "production_mutations": .bool(true), "allowed_actions": .array(["snapshot", "user.recovery.preview", "user.recovery.apply"].map(JSONValue.string))])])
        let data = request.action == "user.recovery.preview" ? JSONValue.object(["recovery": recoveryFixture()]) : snapshot
        return try JSONEncoder().encode(JSONValue.object(["ok": .bool(true), "request_id": .string(request.request_id), "data": data]))
    }
}

@Test @MainActor func recoveryPreviewUsesReadOnlyRequestAndPrivateDedicatedReviewInsteadOfGenericJSON() async throws {
    let key = FileManager.default.temporaryDirectory.appendingPathComponent("recovery-key-" + UUID().uuidString)
    try Data("local-fixture-only".utf8).write(to: key); defer { try? FileManager.default.removeItem(at: key) }
    let suite = "dazzle-recovery-" + UUID().uuidString
    let defaults = try #require(UserDefaults(suiteName: suite)); defer { defaults.removePersistentDomain(forName: suite) }
    let controller = RecoveryPreviewController()
    let store = AppStore(defaults: defaults, managementFactory: { host, key in
        try SSHManagementRPC(host: host, identityFile: key, execute: { _, input in try await controller.reply(input) })
    })
    store.sshHost = "192.0.2.20"; store.sshKeyPath = key.path
    await store.connectManagement()
    await store.perform("user.recovery.preview", ["user_id": .string("user-fixture")])
    #expect(store.error == nil)
    #expect(store.preview == nil)
    #expect(store.recoveryPreview?["expected_revision"].int == 17)
    #expect(store.snapshot?.revision == 17)
    #expect(await controller.last()?.action == "user.recovery.preview")
    #expect(await controller.last()?.expected_revision == nil)
    #expect(await controller.last()?.server_id == store.serverContext?.serverID)
    let count = await controller.count()
    await store.pollManagement()
    #expect(await controller.count() == count)
    store.invalidateServerConnection()
    #expect(store.recoveryPreview == nil)
}
