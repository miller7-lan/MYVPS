import Foundation
import Testing
import DazzleModels

@Test func sharingAdministratorBudgetDoesNotGrantAdministratorRoleOrDoubleCountAllocations() throws {
    let pool = try #require(ProxyUser(.object(["id": .string("pool-fixture"), "role": .string("member"), "quota_pool": .string("administrator"), "quota_bytes": .integer(490_000_000_000)])))
    #expect(pool.sharesAdministratorBudget)
    #expect(pool.role == "member")
    let snapshot = try Snapshot(.object(["schema_version": .integer(1), "revision": .integer(1), "mode": .string("production"), "users": .array([
        pool.raw,
        .object(["id": .string("fixed-fixture"), "role": .string("member"), "quota_bytes": .integer(100_000_000_000)])
    ])]))
    #expect(TrafficOverview(snapshot: snapshot).allocated == 100_000_000_000)
    #expect(throws: ModelError.self) {
        try UserPayload.update(user: pool, name: "Pool member", quotaBytes: 100_000_000_000, email: "", autoRestore: true, thresholdPercent: 80)
    }
    let profile = try UserPayload.update(user: pool, name: "Pool member", quotaBytes: nil, email: "", autoRestore: true, thresholdPercent: 80)
    #expect(profile["quota_bytes"] == nil)
    #expect(profile["quota_pool"] == nil)
}

@Test func registrationReservationsBlockNewApplicationsButStillPermitTheirApproval() throws {
    let account: JSONValue = .object(["id": .string("pending-fixture"), "email": .string("fixture@example.test"), "email_verified": .bool(true), "status": .string("pending")])
    let overview = RegistrationOverview(.object(["enabled": .bool(true), "accounts": .array([account]), "pool": .object(["available": .integer(3), "total": .integer(3)]), "capacity": .object(["waiting": .integer(3), "full": .bool(true)])]))
    #expect(overview.admissionRemaining == 0)
    #expect(overview.admissionFull)
    let application = try #require(RegistrationAccount(account))
    let approval = try overview.approveParameters(account: application, quotaBytes: 100_000_000_000)
    #expect(approval["account_id"] == .string(application.id))
}
