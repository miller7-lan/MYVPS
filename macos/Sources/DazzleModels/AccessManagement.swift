import Foundation

public enum QuotaInput {
    public static let gigabyte: Int64 = 1_000_000_000
    /// Decimal GB are deliberate, and allocations use whole GB to match the server contract.
    public static func bytes(_ text: String, minimumGB: Int64 = 1) -> Int64? {
        let value = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty, value.allSatisfy({ $0.isASCII && $0.isNumber }),
              let gb = Int64(value), gb >= minimumGB, gb <= Int64.max / gigabyte else { return nil }
        return gb * gigabyte
    }
    public static func valid(_ bytes: Int64, minimumGB: Int64 = 1) -> Bool {
        bytes >= minimumGB * gigabyte && bytes % gigabyte == 0
    }
    public static func text(_ bytes: Int64?) -> String {
        guard let bytes else { return "" }; return String(bytes / gigabyte)
    }
}

public struct AllocationBudget: Sendable {
    public let raw: JSONValue
    public init(_ raw: JSONValue) { self.raw = raw }
    public var configured: Bool { raw["configured"].bool == true }
    public var canAllocate: Bool { configured && raw["can_allocate"].bool == true }
    public var providerRemainingVerified: Bool { raw["provider_remaining_verified"].bool == true }
    public var available: Int64? { raw["available_bytes"].int }
    public var administratorPolicy: String {
        configured ? "管理员使用共享预留外余额" : "当前策略：不限额，预算保护尚未启用"
    }
    public var reason: String {
        guard configured else { return "请先在“额度与周期”确认套餐预算和安全余量，再新增、加量或审批。" }
        if canAllocate {
            return providerRemainingVerified
                ? "依据本地预算与 QQG 最近有效余量（取较小值）分配。"
                : "依据人工确认预算与本地账本分配；商家实时余量仍未核验。"
        }
        if raw["limited_by"].string == "provider" { return "QQG 实际剩余不足，暂不能新增或加量。" }
        return ["insufficient_budget": "可分配预算不足", "budget_exhausted": "可分配预算已用尽", "reconciliation_required": "预算账本需要核对"][raw["reason"].string ?? ""] ?? "当前预算不可分配，请在“额度与周期”核对。"
    }
    public func permits(_ bytes: Int64) -> Bool {
        guard canAllocate, let available, bytes >= 0 else { return false }; return bytes <= available
    }
    public func rejectionReason(for bytes: Int64) -> String {
        if canAllocate, let available, bytes > available { return "本次分配超过当前可分配预算（\(Display.bytes(available))）。请减少额度或核对预算。" }
        return reason
    }
    public static func configure(total: String, safety: String, evidence: String, confirmed: Bool) throws -> [String: JSONValue] {
        let note = evidence.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let totalBytes = QuotaInput.bytes(total), let safetyBytes = QuotaInput.bytes(safety, minimumGB: 0),
              safetyBytes < totalBytes, confirmed, !note.isEmpty, note.count <= 500 else {
            throw ModelError.invalidResponse("请填写整数 GB 套餐预算、低于总额的安全余量和核对依据，并明确确认。")
        }
        return ["total_bytes": .integer(totalBytes), "safety_margin_bytes": .integer(safetyBytes), "confirmed": .bool(true), "evidence": .string(note)]
    }
}

public struct UserRecovery: Sendable {
    public let raw: JSONValue
    public init(_ raw: JSONValue) { self.raw = raw }
    public var state: String { raw["state"].string ?? "idle" }
    public var canApply: Bool { raw["can_apply"].bool == true }
    public var forceRestart: Bool { raw["force_restart"].bool == true }
    public var requiresGapConfirmation: Bool { raw["requires_unknown_gap_confirmation"].bool == true }
    public var gapSummary: RecoveryGapSummary { RecoveryGapSummary(raw["gap_summary"]) }
    public var blockedReasons: [String] { raw["blocked_reasons"].array.compactMap(\.string) }
    public var errorCode: String? { raw["error_code"].string }
    public var label: String {
        switch state {
        case "healthy": forceRestart ? "可主动强制重建连接" : "连接与计量正常"
        case "checking": "正在检查连接"
        case "recovering": "正在恢复连接"
        case "starting": "等待启动与计量确认"
        case "succeeded": "恢复成功 · 计量可信"
        case "failed": "恢复未成功"
        case "blocked": "需先处理保护限制"
        default: "检查异常并恢复连接"
        }
    }
    public func applyParameters(userID: String, confirmedGap: Bool) throws -> [String: JSONValue] {
        guard raw["user_id"].string == userID, canApply, blockedReasons.isEmpty,
              let token = raw["preview_token"].string, !token.isEmpty,
              raw["expected_revision"].int != nil,
              !requiresGapConfirmation || confirmedGap else {
            throw ModelError.invalidResponse("恢复预览无效或尚未确认计量间隙，请重新检查。")
        }
        var parameters: [String: JSONValue] = ["user_id": .string(userID), "preview_token": .string(token), "confirm_unknown_gap": .bool(confirmedGap)]
        if forceRestart { parameters["force_restart"] = .bool(true) }
        return parameters
    }
}

/// The four visible steps of one targeted recovery, mapped from the server state machine
/// (checking → recovering → starting → succeeded). Steps never move backwards on screen.
public struct RecoveryProgress: Sendable, Equatable {
    public static let steps = ["停止旧连接", "重建", "核对计量", "恢复成功"]
    public enum Outcome: Sendable, Equatable { case running, succeeded, failed(String) }
    /// Index of the step in progress; 3 once recovery succeeded.
    public let step: Int
    public let outcome: Outcome
    public init(recovery: UserRecovery, lastStep: Int = 0) {
        let floor = min(max(lastStep, 0), 2)
        switch recovery.state {
        case "checking": step = floor; outcome = .running
        case "recovering": step = max(floor, 1); outcome = .running
        case "starting": step = max(floor, 2); outcome = .running
        case "succeeded", "healthy": step = 3; outcome = .succeeded
        default:
            step = floor
            outcome = .failed(Self.failure(state: recovery.state, code: recovery.errorCode))
        }
    }
    public var finished: Bool { outcome != .running }
    public static func failure(state: String, code: String?) -> String {
        switch code {
        case "RECOVERY_TIMEOUT": return "60 秒内未确认完成，已停止等待；原用量和订阅保留"
        case "RECOVERY_RUNTIME_FAILED": return "实例重建未成功；请检查实例状态后重试"
        case "RECOVERY_USER_CHANGED": return "期间凭据已变化，本次恢复已停止"
        case "RECOVERY_BLOCKED": return "被停用、额度、到期等保护限制阻止"
        default: return state == "blocked" ? "被停用、额度、到期等保护限制阻止" : "恢复未成功，请重新检查连接"
        }
    }
}

public struct RecoveryGapSummary: Sendable {
    public let raw: JSONValue
    public init(_ raw: JSONValue) { self.raw = raw }
    public var available: Bool { !raw.object.isEmpty }
    public var unresolvedCount: Int { max(0, Int(raw["unresolved_count"].int ?? 0)) }
    public var incidents: [RecoveryGapIncident] {
        Array(raw["incidents"].array.prefix(20)).enumerated().map { RecoveryGapIncident(raw: $0.element, index: $0.offset) }
    }
    public var omittedCount: Int {
        max(0, Int(raw["omitted_count"].int ?? 0)) + max(0, raw["incidents"].array.count - 20)
    }
    public var mayRestartTarget: Bool { raw["may_restart_target"].bool == true }
    public var preservesRecordedUsage: Bool { raw["preserves_recorded_usage"].bool == true }
    public var lastTrusted: String { Self.time(raw["last_trusted_at"], missing: "可信起点尚未确认") }
    public var observed: String { Self.time(raw["observed_at"], missing: "本次检查时间尚未确认") }
    public static func time(_ raw: JSONValue, missing: String = "未确认") -> String {
        guard let value = ChartValues.date(raw) else { return missing }
        let format = DateFormatter(); format.locale = Locale(identifier: "zh_CN")
        format.dateFormat = "yyyy/MM/dd HH:mm:ss zzz"
        return format.string(from: value)
    }
}

public struct RecoveryGapIncident: Identifiable, Sendable {
    public let raw: JSONValue
    public let index: Int
    public var id: Int { index }
    public var title: String {
        switch raw["kind"].string {
        case "sample_gap", "stale_sample": "采样出现间隙"
        case "worker_epoch_changed", "counter_regression": "计量计数发生变化"
        case "initial_nonzero_baseline": "初始计量需要核对"
        case "meter_unavailable", "collection_failed": "计量暂时不可用"
        default: "计量记录需要核对"
        }
    }
    public var from: String { RecoveryGapSummary.time(raw["from_at"], missing: "起点未确认") }
    public var to: String { RecoveryGapSummary.time(raw["to_at"], missing: "结束时间未确认") }
    public var detected: String { RecoveryGapSummary.time(raw["detected_at"]) }
    public var unknown: Bool { raw["delta_unknown"].bool != false }
    public var knownTraffic: String {
        func amount(_ value: JSONValue) -> String {
            guard let bytes = value.int, bytes >= 0 else { return "未确认" }
            return ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
        }
        return "可核实上传差额 \(amount(raw["known_upload_bytes"])) · 下载差额 \(amount(raw["known_download_bytes"]))"
    }
}

public struct TrialAccess: Sendable {
    public let raw: JSONValue
    public init(_ raw: JSONValue) { self.raw = raw }
    public var durationDays: Int { Int(raw["duration_days"].int ?? 3) }
    public var status: String { raw["status"].string ?? "unknown" }
    public static func parameters(name: String?, userID: String? = nil, days: Int, quota: String) throws -> [String: JSONValue] {
        guard (1...365).contains(days), let bytes = QuotaInput.bytes(quota) else {
            throw ModelError.invalidResponse("体验额度需为至少 1 GB 的整数，时长为 1–365 天。")
        }
        var params: [String: JSONValue] = ["duration_days": .integer(Int64(days)), "quota_bytes": .integer(bytes)]
        if let userID { params["user_id"] = .string(userID) }
        else {
            let name = (name ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            guard !name.isEmpty else { throw ModelError.invalidResponse("请填写体验用户名称。") }
            params["name"] = .string(name)
        }
        return params
    }
}

extension ProxyUser {
    public var isTrial: Bool { raw["type"].string == "trial" || raw["kind"].string == "trial" || !raw["trial"].object.isEmpty }
    public var trial: TrialAccess { TrialAccess(raw["trial"]) }
    public var recovery: UserRecovery { UserRecovery(raw["recovery"]) }
    /// Current faults take precedence over an earlier successful recovery record.
    public var needsConnectionRecovery: Bool {
        guard !revoked, raw["deleted_at"].string == nil else { return false }
        if hasMeteringFault { return true }
        return !["healthy", "succeeded"].contains(recovery.state)
    }
    public var connectionRecoveryLabel: String {
        hasMeteringFault && ["healthy", "succeeded"].contains(recovery.state)
            ? "计量异常，需要重新检查连接" : recovery.label
    }
    private var hasMeteringFault: Bool {
        reasons.contains("metering_failure") || ["failure", "reconciliation_required"].contains(raw["meter_state"].string ?? "")
    }
}
