import Foundation
import Testing
import DazzleModels

private func application(_ status: String = "pending", bound: String? = nil, verified: Bool = true) throws -> RegistrationAccount {
    var raw: [String: JSONValue] = ["id": .string("application-fixture"), "email": .string("friend@example.test"),
        "nickname": .string("Friend"), "status": .string(status), "email_verified": .bool(verified), "quota_bytes": .integer(100_000_000_000)]
    if let bound { raw["proxy_user_id"] = .string(bound) }
    return try #require(RegistrationAccount(.object(raw)))
}
private func registrationOverview(slots: Int64 = 5, accounts: [RegistrationAccount] = []) -> RegistrationOverview {
    RegistrationOverview(.object(["enabled": .bool(true), "pending_count": .integer(1),
        "accounts": .array(accounts.map(\.raw)), "pool": .object(["available": .integer(slots), "total": .integer(6)])]))
}

@Test func absentRegistrationCapabilityDoesNotInventAReadyPortal() {
    let overview = RegistrationOverview(.null)
    #expect(!overview.supported)
    #expect(!overview.enabled)
    #expect(overview.accounts.isEmpty)
    #expect(overview.available == 0)
}

@Test func pendingRegistrationApprovalBindsOnlyItsOwnAccountAndQuota() throws {
    let account = try application()
    let overview = registrationOverview(accounts: [account])
    #expect(overview.available == 5 && overview.total == 6)
    let params = try overview.approveParameters(account: account, quotaBytes: 75_000_000_000)
    #expect(params == ["account_id": .string(account.id), "quota_bytes": .integer(75_000_000_000)])
    #expect(params["role"] == nil && params["port"] == nil && params["token"] == nil)
    #expect(throws: ModelError.self) { try overview.approveParameters(account: account, quotaBytes: 0) }
}

@Test func exhaustedPoolDoesNotPretendAnApplicationCanBeActivated() throws {
    let account = try application("waiting_resources")
    #expect(account.label(users: []) == "等待资源")
    #expect(throws: ModelError.self) { try registrationOverview(slots: 0).approveParameters(account: account, quotaBytes: 100) }
    let bound = try application("failed", bound: "already-created-worker")
    #expect(!bound.canApprove)
    #expect(throws: ModelError.self) { try registrationOverview().approveParameters(account: bound, quotaBytes: 100) }
}

@Test func claimedActivationNeedsTheMatchingRunningTrustedWorker() throws {
    let account = try application("active", bound: "worker-fixture")
    #expect(account.label(users: []) == "运行待核实")
    var raw: [String: JSONValue] = ["id": .string("worker-fixture"), "runtime_state": .string("running"),
        "runtime_verified_at": .string("2026-10-25T08:00:00Z"), "meter_state": .string("trusted"), "disabled_reasons": .array([])]
    let running = try #require(ProxyUser(.object(raw)))
    #expect(account.activationConfirmed(users: [running]))
    #expect(account.label(users: [running]) == "已启用")
    raw["disabled_reasons"] = .array([.string("manual_disabled")])
    #expect(!account.activationConfirmed(users: [try #require(ProxyUser(.object(raw)))]))
    raw["disabled_reasons"] = .array([]); raw["meter_state"] = .string("failure")
    #expect(!account.activationConfirmed(users: [try #require(ProxyUser(.object(raw)))]))
    #expect(try application("provisioning", bound: "worker-fixture").label(users: [running]) == "正在开通")
}

@Test func revokedUnknownAndUnverifiedApplicationsCannotGrantAuthorization() throws {
    for state in ["revoked", "disabled", "active", "unknown", "new-future-state"] {
        #expect(try !application(state).canApprove)
    }
    #expect(RegistrationAccount(.object(["id": .string("fixture"), "email": .string("unverified@example.test"), "email_verified": .bool(false)])) == nil)
    #expect(try application("unknown").label(users: []) == "状态待核对")
}

@Test func registrationRejectionKeepsAdministrativeInputsBounded() throws {
    let account = try application()
    let overview = registrationOverview(accounts: [account])
    #expect(try overview.rejectParameters(account: account, reason: "  ") == ["account_id": .string(account.id)])
    #expect(try overview.rejectParameters(account: account, reason: " reason ")["reason"] == .string("reason"))
    #expect(throws: ModelError.self) { try overview.rejectParameters(account: account, reason: String(repeating: "x", count: 201)) }
    #expect(throws: ModelError.self) { try overview.rejectParameters(account: application("active", bound: "worker"), reason: "") }
}

@Test func registrationCapabilitiesRemainWithinTheFixedSSHProtocol() throws {
    let raw: JSONValue = .object(["schema_version": .integer(1), "revision": .integer(1), "mode": .string("production"),
        "server_id": .string("840737d0-365c-4da4-a706-3b3ee86be1da"),
        "legacy": .object(["managed": .bool(false), "retirement_supported": .bool(false)]),
        "capabilities": .object(["controller": .string("root_policy"), "production_mutations": .bool(true),
            "legacy_retirement": .bool(false), "allowed_actions": .array(["snapshot", "registration.list", "registration.approve", "registration.reject", "root.exec"].map(JSONValue.string))])])
    let context = try ServerContext(snapshot: Snapshot(raw))
    #expect(context.allows("registration.list"))
    #expect(context.allows("registration.approve"))
    #expect(context.allows("registration.reject"))
    #expect(!context.allows("root.exec"))
    #expect(ServerContext.readActions.contains("registration.list"))
    #expect(ServerContext.writeActions.contains("registration.approve"))
}
