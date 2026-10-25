import Foundation
import Testing
import DazzleModels

private enum VisualFixture {
    static func user(_ id: String, role: String = "member", quota: Int64 = 100,
                     topup: Int64 = 0, upload: Int64 = 0, download: Int64 = 0,
                     unlimited: Bool = false, revoked: Bool = false) -> JSONValue {
        .object([
            "id": .string(id), "name": .string(id), "role": .string(role),
            "quota_bytes": .integer(quota), "topup_bytes": .integer(topup),
            "used_upload": .integer(upload), "used_download": .integer(download),
            "unlimited": .bool(unlimited),
            "status": .string(revoked ? "revoked" : "running"),
            "disabled_reasons": .array(revoked ? [.string("revoked")] : []),
        ])
    }

    static func snapshot(users: [JSONValue] = [], provider: [String: JSONValue] = [:],
                         freshness: JSONValue = .null) throws -> Snapshot {
        try Snapshot(.object([
            "schema_version": .integer(1), "revision": .integer(1), "mode": .string("simulation"),
            "users": .array(users), "provider": .object(provider),
            "provider_freshness": freshness,
        ]))
    }
}

@Test func historicalDisplayStringsNeverBecomeProviderCapacity() throws {
    let history: [String: JSONValue] = [
        "total_display": .string("500GB"), "remaining_display": .string("493.36GB"),
        "total_bytes": .null, "remaining_bytes": .null, "unit_verified": .bool(false),
        "source": .string("historical_manual_snapshot"),
    ]
    let overview = TrafficOverview(snapshot: try VisualFixture.snapshot(provider: history))
    #expect(overview.providerTotal == nil)
    #expect(overview.providerRemaining == nil)
    #expect(!overview.providerVerified)
    #expect(!overview.hasTraffic)
}

@Test func providerCapacityRequiresVerifiedFreshAndValidByteAmounts() throws {
    let provider: [String: JSONValue] = [
        "unit_verified": .bool(true), "total_bytes": .integer(500_000_000_000),
        "remaining_bytes": .integer(493_360_000_000),
    ]
    let fresh = JSONValue.object(["state": .string("fresh")])
    let valid = TrafficOverview(snapshot: try VisualFixture.snapshot(provider: provider, freshness: fresh))
    #expect(valid.providerTotal == 500_000_000_000)
    #expect(valid.providerRemaining == 493_360_000_000)
    #expect(valid.providerVerified)

    for freshness in [JSONValue.null, .object(["state": .string("stale")])] {
        let stale = TrafficOverview(snapshot: try VisualFixture.snapshot(provider: provider, freshness: freshness))
        #expect(stale.providerRemaining == nil)
        #expect(stale.providerTotal == nil)
        #expect(!stale.providerVerified)
    }
    let invalidOverrides: [[String: JSONValue]] = [
        ["unit_verified": .bool(false)], ["unit_verified": .null],
        ["total_bytes": .null], ["total_bytes": .integer(0)], ["total_bytes": .integer(-1)],
        ["remaining_bytes": .null], ["remaining_bytes": .integer(-1)],
        ["remaining_bytes": .integer(500_000_000_001)],
    ]
    for overrides in invalidOverrides {
        let invalid = provider.merging(overrides) { _, new in new }
        let overview = TrafficOverview(snapshot: try VisualFixture.snapshot(provider: invalid, freshness: fresh))
        #expect(overview.providerRemaining == nil)
        #expect(overview.providerTotal == nil)
        #expect(!overview.providerVerified)
    }
    let exhausted = provider.merging(["remaining_bytes": JSONValue.integer(0)]) { _, new in new }
    #expect(TrafficOverview(snapshot: try VisualFixture.snapshot(provider: exhausted, freshness: fresh)).providerRemaining == 0)
}

@Test func finiteMemberAllocationIsSeparateFromAllUserPayload() throws {
    let users = [
        VisualFixture.user("finite", topup: 20, upload: 10, download: 20),
        // Even a legacy numeric quota on an administrator must not enter the finite pool.
        VisualFixture.user("administrator", role: "admin", quota: 900, upload: 30, download: 40, unlimited: true),
        VisualFixture.user("unlimited-member", quota: 800, upload: 50, download: 60, unlimited: true),
        VisualFixture.user("revoked", quota: 700, upload: 70, download: 80, revoked: true),
    ]
    let snapshot = try VisualFixture.snapshot(users: users)
    let overview = TrafficOverview(snapshot: snapshot)
    #expect(overview.allocated == 120)
    #expect(overview.users.count == 3)
    #expect(!overview.users.contains { $0.id == "revoked" })
    #expect(overview.upload == 160)
    #expect(overview.download == 200)
    #expect(overview.total == 360)
    #expect(try #require(snapshot.users.first { $0.id == "administrator" }).allowance == nil)
    #expect(try #require(snapshot.users.first { $0.id == "unlimited-member" }).allowance == nil)
}

@Test func emptyAndZeroDataDoNotInventCapacityDenominators() throws {
    let overview = TrafficOverview(snapshot: try VisualFixture.snapshot())
    #expect(overview.users.isEmpty)
    #expect(overview.total == 0)
    #expect(overview.allocated == 0)
    #expect(!overview.hasTraffic)
    #expect(overview.uploadFraction == 0)
    #expect(overview.providerRemaining == nil)
    #expect(ChartValues.fraction(used: 0, limit: nil) == nil)
    #expect(ChartValues.fraction(used: 0, limit: 0) == nil)
    #expect(ChartValues.fraction(used: 12, limit: -1) == nil)
    // A known, positive allowance with zero usage is a genuine zero percent.
    #expect(ChartValues.fraction(used: 0, limit: 100) == 0)
}

@Test func overQuotaClampsTheChartWithoutChangingRecordedUsage() throws {
    let snapshot = try VisualFixture.snapshot(users: [
        VisualFixture.user("over-quota", quota: 100, upload: 90, download: 60),
    ])
    let user = try #require(snapshot.users.first)
    #expect(user.used == 150)
    #expect(user.allowance == 100)
    #expect(user.remaining == 0)
    #expect(ChartValues.fraction(used: user.used, limit: user.allowance) == 1)
    #expect(ChartValues.fraction(used: -20, limit: 100) == 0)
    #expect(TrafficOverview(snapshot: snapshot).total == 150)
}

@Test func aggregateOverflowSaturatesWithoutTrappingOrGoingNegative() throws {
    #expect(TrafficOverview.sum([Int64.max, 1]) == Int64.max)
    #expect(TrafficOverview.sum([Int64.max - 1, 2]) == Int64.max)
    #expect(TrafficOverview.sum([-100, 20]) == 20)
    #expect(TrafficOverview.sum([]) == 0)
    let overview = TrafficOverview(snapshot: try VisualFixture.snapshot(users: [
        VisualFixture.user("large-a", quota: Int64.max, upload: Int64.max),
        VisualFixture.user("large-b", quota: Int64.max, upload: Int64.max),
    ]))
    #expect(overview.upload == Int64.max)
    #expect(overview.allocated == Int64.max)
    #expect(overview.total == Int64.max)
    #expect(overview.hasTraffic)
    #expect(overview.uploadFraction.isFinite)
}

@Test func cycleProgressRequiresValidDatesAndClampsClockMovement() throws {
    let start = JSONValue.string("2026-11-24T08:19:00.000000Z")
    let end = JSONValue.string("2026-12-24T08:19:00Z")
    let beginning = try #require(ChartValues.date(start))
    let ending = try #require(ChartValues.date(end))
    let middle = beginning.addingTimeInterval(ending.timeIntervalSince(beginning) / 2)
    #expect(ChartValues.progress(start: start, end: end, now: middle) == 0.5)
    #expect(ChartValues.progress(start: start, end: end, now: beginning.addingTimeInterval(-60)) == 0)
    #expect(ChartValues.progress(start: start, end: end, now: ending.addingTimeInterval(60)) == 1)
    #expect(ChartValues.progress(start: .null, end: end, now: middle) == nil)
    #expect(ChartValues.progress(start: start, end: .null, now: middle) == nil)
    #expect(ChartValues.progress(start: .string("invalid-date"), end: end, now: middle) == nil)
    #expect(ChartValues.progress(start: end, end: start, now: middle) == nil)
    #expect(ChartValues.progress(start: start, end: start, now: middle) == nil)
}
