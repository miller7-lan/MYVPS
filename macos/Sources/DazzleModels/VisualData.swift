import Foundation

/// A chart-ready projection; provider billing bytes never share a denominator
/// with proxy payload or administrator allowance.
public struct TrafficOverview: Sendable {
    public let users: [ProxyUser]
    public let upload: Int64
    public let download: Int64
    public let allocated: Int64
    public let availableUsers: Int
    public let providerTotal: Int64?
    public let providerRemaining: Int64?
    public var total: Int64 { Self.sum([upload, download]) }
    public var uploadFraction: Double { total > 0 ? Double(upload) / Double(total) : 0 }
    public var hasTraffic: Bool { total > 0 }
    public var providerVerified: Bool { providerTotal != nil && providerRemaining != nil }

    public init(snapshot: Snapshot) {
        users = snapshot.users.filter { !$0.revoked }
        upload = Self.sum(snapshot.users.map { $0.raw["used_upload"].int ?? 0 })
        download = Self.sum(snapshot.users.map { $0.raw["used_download"].int ?? 0 })
        allocated = Self.sum(users.filter { !$0.sharesAdministratorBudget }.compactMap(\.allowance))
        availableUsers = users.filter { $0.reasons.isEmpty && ["ready", "running", "active", "enabled"].contains($0.raw["status"].string ?? "") }.count
        let p = snapshot["provider"]
        if p["unit_verified"].bool == true, snapshot["provider_freshness"]["state"].string == "fresh",
           let total = p["total_bytes"].int, let remaining = p["remaining_bytes"].int,
           total > 0, remaining >= 0, remaining <= total {
            providerTotal = total; providerRemaining = remaining
        } else { providerTotal = nil; providerRemaining = nil }
    }
    public static func sum(_ values: [Int64]) -> Int64 {
        values.reduce(0) { partial, value in
            let result = partial.addingReportingOverflow(max(0, value))
            return result.overflow ? Int64.max : result.partialValue
        }
    }
}

public enum ChartValues {
    public static func fraction(used: Int64, limit: Int64?) -> Double? {
        guard let limit, limit > 0 else { return nil }
        return min(1, max(0, Double(used) / Double(limit)))
    }
    public static func date(_ value: JSONValue) -> Date? {
        guard let text = value.string else { return nil }
        let parser = ISO8601DateFormatter(); parser.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = parser.date(from: text) { return date }
        parser.formatOptions = [.withInternetDateTime]
        return parser.date(from: text)
    }
    public static func progress(start: JSONValue, end: JSONValue, now: Date = Date()) -> Double? {
        guard let start = date(start), let end = date(end), end > start else { return nil }
        return min(1, max(0, now.timeIntervalSince(start) / end.timeIntervalSince(start)))
    }
}
