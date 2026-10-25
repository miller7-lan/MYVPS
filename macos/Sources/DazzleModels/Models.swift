import Foundation

public enum JSONValue: Codable, Sendable, Equatable {
    case object([String: JSONValue]), array([JSONValue]), string(String), integer(Int64), number(Double), bool(Bool), null

    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null }
        else if let v = try? c.decode(Bool.self) { self = .bool(v) }
        else if let v = try? c.decode(Int64.self) { self = .integer(v) }
        else if let v = try? c.decode(Double.self) { self = .number(v) }
        else if let v = try? c.decode(String.self) { self = .string(v) }
        else if let v = try? c.decode([String: JSONValue].self) { self = .object(v) }
        else { self = .array(try c.decode([JSONValue].self)) }
    }
    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .object(let v): try c.encode(v)
        case .array(let v): try c.encode(v)
        case .string(let v): try c.encode(v)
        case .integer(let v): try c.encode(v)
        case .number(let v): try c.encode(v)
        case .bool(let v): try c.encode(v)
        case .null: try c.encodeNil()
        }
    }
    public subscript(_ key: String) -> JSONValue {
        if case .object(let o) = self { return o[key] ?? .null }; return .null
    }
    public var object: [String: JSONValue] { if case .object(let o) = self { return o }; return [:] }
    public var array: [JSONValue] { if case .array(let a) = self { return a }; return [] }
    public var string: String? { if case .string(let s) = self { return s }; return nil }
    public var int: Int64? { if case .integer(let n) = self { return n }; return nil }
    public var double: Double? { if case .number(let n) = self { return n }; return int.map(Double.init) }
    public var bool: Bool? { if case .bool(let b) = self { return b }; return nil }
    public var text: String { string ?? int.map(String.init) ?? (bool.map { $0 ? "是" : "否" }) ?? "未确认" }
    public var pretty: String {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        return (try? String(data: encoder.encode(self), encoding: .utf8)) ?? "{}"
    }
}

public struct RPCRequest: Codable, Sendable {
    public let api_version: Int
    public let request_id: String
    public let action: String
    public let expected_revision: Int64?
    public let server_id: String?
    public let params: JSONValue
    public init(action: String, revision: Int64?, params: [String: JSONValue] = [:], serverID: String? = nil, id: String = UUID().uuidString) {
        api_version = 1; request_id = id; self.action = action; expected_revision = revision; self.params = .object(params); server_id = serverID
    }
}

public struct RPCError: Codable, Sendable { public let code: String; public let message: String }
public struct RPCResponse: Decodable, Sendable {
    public let ok: Bool
    public let request_id: String
    public let revision: Int64?
    public let data: JSONValue?
    public let error: RPCError?
    public func checked(for request: RPCRequest) throws -> JSONValue {
        guard request_id == request.request_id else { throw ModelError.invalidResponse("响应与请求不匹配") }
        guard ok else { throw ModelError.remote(error?.code ?? "INTERNAL", error?.message ?? "操作未完成") }
        return data ?? .object([:])
    }
}
public enum ModelError: Error, LocalizedError, Sendable {
    case invalidResponse(String), remote(String, String)
    public var errorDescription: String? {
        switch self { case .invalidResponse(let s): return s; case .remote(let code, let s): return "\(s)（\(code)）" }
    }
}

public struct Snapshot: Sendable {
    public let raw: JSONValue
    public init(_ raw: JSONValue) throws {
        guard raw["schema_version"].int == 1, raw["revision"].int != nil,
              raw["mode"].string != nil else { throw ModelError.invalidResponse("后端快照格式不兼容") }
        self.raw = raw
    }
    public var revision: Int64 { raw["revision"].int ?? 0 }
    public var users: [ProxyUser] { raw["users"].array.compactMap(ProxyUser.init) }
    public subscript(_ key: String) -> JSONValue { raw[key] }
}

public struct ProxyUser: Identifiable, Sendable, Hashable {
    public let raw: JSONValue
    public let id: String
    public init?(_ raw: JSONValue) {
        guard let id = raw["id"].string else { return nil }; self.raw = raw; self.id = id
    }
    public var name: String { raw["name"].string ?? id }
    public var role: String { raw["role"].string ?? "member" }
    public var used: Int64 { (raw["used_upload"].int ?? 0) + (raw["used_download"].int ?? 0) }
    public var quota: Int64? { raw["unlimited"].bool == true ? nil : raw["quota_bytes"].int }
    public var allowance: Int64? { quota.map { $0 + (raw["topup_bytes"].int ?? 0) } }
    public var remaining: Int64? { allowance.map { max(0, $0 - used) } }
    public var revoked: Bool { raw["status"].string == "revoked" || raw["disabled_reasons"].array.contains(.string("revoked")) }
    public var reasons: [String] { raw["disabled_reasons"].array.compactMap(\.string) }
    public static func == (lhs: Self, rhs: Self) -> Bool { lhs.id == rhs.id && lhs.raw == rhs.raw }
    public func hash(into hasher: inout Hasher) { hasher.combine(id) }
}

public enum UserPayload {
    public static func update(user: ProxyUser, name: String, quotaBytes: Int64?, email: String,
                              autoRestore: Bool, thresholdPercent: Int) throws -> [String: JSONValue] {
        var p: [String: JSONValue] = ["user_id": .string(user.id), "name": .string(name.trimmingCharacters(in: .whitespacesAndNewlines)),
                                     "auto_restore": .bool(autoRestore), "threshold_percent": .integer(Int64(thresholdPercent))]
        let address = email.trimmingCharacters(in: .whitespacesAndNewlines)
        p["email"] = address.isEmpty ? .null : .string(address)
        if user.role != "admin" {
            guard let quotaBytes, quotaBytes > 0 else { throw ModelError.invalidResponse("普通用户的基础额度必须大于 0。") }
            p["quota_bytes"] = .integer(quotaBytes)
        }
        return p
    }
}

public struct ExportArtifact: Sendable, Identifiable {
    public let id = UUID()
    public let filename: String
    public let content: String
    public let nodesURL: String?
    public let configURL: String?
    public let subscriptionURL: String?
    public let nodes: [String]
    public let deployed: Bool
    public let environment: String?
    public let serverID: String?
    public let runtimeState: String?
    public init(_ data: JSONValue) throws {
        guard data["sensitive"].bool == true, let filename = data["filename"].string,
              let content = data["content"].string, !filename.isEmpty, !content.isEmpty else {
            throw ModelError.invalidResponse("后端没有返回有效的私密导出文件")
        }
        // Server chooses a basename; an export never chooses a local directory.
        self.filename = URL(fileURLWithPath: filename).lastPathComponent
        self.content = content; nodesURL = data["nodes_url"].string
        configURL = data["config_url"].string; subscriptionURL = data["subscription_url"].string
        nodes = data["nodes"].array.compactMap(\.string); deployed = data["deployed"].bool ?? false
        environment = data["environment"].string; serverID = data["server_id"].string
        runtimeState = data["runtime_state"].string
    }
    public func validateProduction(serverID expected: String) throws {
        guard environment == "production", serverID == expected, deployed, !nodes.isEmpty else {
            throw ModelError.invalidResponse("导出配置缺少匹配的真实服务器来源或尚未完成配置；没有显示私密内容。")
        }
        for node in nodes {
            guard let parts = URLComponents(string: node), ["vless", "tuic"].contains(parts.scheme ?? ""),
                  let host = parts.host, !Self.isDocumentationHost(host), let port = parts.port,
                  (1...65535).contains(port), port != 443 else {
                throw ModelError.invalidResponse("真实配置包含模拟地址或旧代理入口，导出已拒绝。")
            }
        }
        for link in [nodesURL, configURL, subscriptionURL].compactMap({ $0 }) {
            guard let parts = URLComponents(string: link), parts.scheme == "https", let host = parts.host,
                  !Self.isDocumentationHost(host), parts.port == 9443 else {
                throw ModelError.invalidResponse("真实订阅地址不符合并行部署范围。")
            }
        }
    }
    private static func isDocumentationHost(_ host: String) -> Bool {
        host.hasPrefix("192.0.2.") || host.hasPrefix("198.51.100.") || host.hasPrefix("203.0.113.") || host == "localhost" || host == "127.0.0.1" || host == "::1"
    }
}

public enum Display {
    public static func bytes(_ value: Int64?) -> String {
        guard let value else { return "未确认" }
        if value == 0 { return "0 GB" }
        return String(format: "%.2f GB", Double(value) / 1_000_000_000)
    }
    public static func date(_ value: JSONValue) -> String {
        guard let raw = value.string else { return "未确认" }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let fractionalDate = formatter.date(from: raw)
        formatter.formatOptions = [.withInternetDateTime]
        guard let date = fractionalDate ?? formatter.date(from: raw) else { return raw }
        let output = DateFormatter(); output.locale = Locale(identifier: "zh_CN"); output.dateFormat = "yyyy/MM/dd HH:mm"
        return output.string(from: date)
    }
    public static func reason(_ text: String) -> String {
        ["manual_disabled": "手动停用", "quota_exceeded": "额度用尽", "quota": "额度用尽", "revoked": "已撤销",
         "metering_failure": "计量异常", "pool_protection": "总池保护", "pool_exhausted": "总池保护", "pool": "总池保护" ][text] ?? text
    }
}
