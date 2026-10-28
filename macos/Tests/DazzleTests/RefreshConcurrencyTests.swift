import Foundation
import Testing
import DazzleModels
@testable import DazzleTransport
@testable import DazzleApp

private let pacedServerID = "5b1e0c55-7d0f-4c86-9a5b-2f0c4f1f9e21"

/// Fake controller: a snapshot reports the revision at the moment the server read it,
/// and each accepted write advances the revision by one, like the production RPC.
private actor PacedController {
    private(set) var revision: Int64 = 7
    private(set) var received: [RPCRequest] = []
    private var recoveryState = "failed"
    private var holdSnapshots = false, holdWrites = false
    private var heldSnapshots: [CheckedContinuation<Void, Never>] = []
    private var heldWrites: [CheckedContinuation<Void, Never>] = []

    func hold(snapshots: Bool = false, writes: Bool = false) { holdSnapshots = snapshots; holdWrites = writes }
    func releaseSnapshots() { holdSnapshots = false; let waiting = heldSnapshots; heldSnapshots = []; waiting.forEach { $0.resume() } }
    func releaseWrites() { holdWrites = false; let waiting = heldWrites; heldWrites = []; waiting.forEach { $0.resume() } }
    func externalChange() { revision += 1 }
    func setRecovery(_ state: String) { recoveryState = state }
    func writes() -> [RPCRequest] { received.filter { ServerContext.writeActions.contains($0.action) } }
    func count() -> Int { received.count }

    private func snapshot(_ revision: Int64) -> JSONValue {
        let user = { (id: String, state: String) -> JSONValue in
            .object(["id": .string(id), "name": .string(id == "u1" ? "Member one" : "Member two"),
                     "meter_state": .string("trusted"), "recovery": .object(["state": .string(state)])])
        }
        return .object(["schema_version": .integer(1), "mode": .string("production"), "revision": .integer(revision),
            "server_id": .string(pacedServerID), "users": .array([user("u1", recoveryState), user("u2", "healthy")]),
            "legacy": .object(["managed": .bool(false), "retirement_supported": .bool(false)]),
            "capabilities": .object(["controller": .string("root_policy"), "legacy_retirement": .bool(false),
                "production_mutations": .bool(true),
                "allowed_actions": .array(["snapshot", "user.update", "user.topup", "user.rotate", "user.recovery.apply"].map(JSONValue.string))])])
    }
    private func encode(_ request: RPCRequest, ok: Bool, data: JSONValue? = nil, code: String? = nil) throws -> Data {
        var value: [String: JSONValue] = ["ok": .bool(ok), "request_id": .string(request.request_id), "revision": .integer(revision)]
        if let data { value["data"] = data }
        if let code { value["error"] = .object(["code": .string(code), "message": .string("Refresh before applying this change")]) }
        return try JSONEncoder().encode(JSONValue.object(value))
    }
    func reply(_ input: Data) async throws -> Data {
        let request = try JSONDecoder().decode(RPCRequest.self, from: input)
        received.append(request)
        if request.action == "snapshot" {
            let observed = revision
            if holdSnapshots { await withCheckedContinuation { heldSnapshots.append($0) } }
            return try encode(request, ok: true, data: snapshot(observed))
        }
        if holdWrites { await withCheckedContinuation { heldWrites.append($0) } }
        guard request.expected_revision == revision else { return try encode(request, ok: false, code: "REVISION_CONFLICT") }
        if request.action == "user.recovery.apply" { recoveryState = "checking" }
        revision += 1
        return try encode(request, ok: true, data: .object(["snapshot": snapshot(revision)]))
    }
}

@MainActor private final class PacedHarness {
    let controller: PacedController
    let key: URL
    let suite: String
    let store: AppStore
    init() throws {
        let controller = PacedController(), suite = "dazzle-paced-" + UUID().uuidString
        let key = FileManager.default.temporaryDirectory.appendingPathComponent("paced-key-" + UUID().uuidString)
        try Data("local-test-only".utf8).write(to: key)
        let defaults = try #require(UserDefaults(suiteName: suite))
        self.controller = controller; self.key = key; self.suite = suite
        store = AppStore(defaults: defaults, managementFactory: { host, key in
            try SSHManagementRPC(host: host, identityFile: key, execute: { _, input in try await controller.reply(input) })
        }, identityCheck: { true })
        store.sshHost = "192.0.2.30"; store.sshKeyPath = key.path
    }
    func close() {
        try? FileManager.default.removeItem(at: key)
        UserDefaults(suiteName: suite)?.removePersistentDomain(forName: suite)
    }
}

@MainActor private func eventually(_ condition: @MainActor () async -> Bool) async -> Bool {
    for _ in 0..<400 {
        if await condition() { return true }
        try? await Task.sleep(for: .milliseconds(5))
    }
    return false
}

@Test @MainActor func backgroundRefreshKeepsActionsUsableAndCannotOverwriteANewerResult() async throws {
    let harness = try PacedHarness(); defer { harness.close() }
    let store = harness.store, controller = harness.controller
    await store.connectManagement()
    #expect(store.serverSnapshot?.revision == 7)
    await controller.hold(snapshots: true)
    let poll = Task { await store.pollManagement() }
    #expect(await eventually { await controller.count() == 2 })
    // The refresh is in flight: nothing is locked and the last data stays visible.
    #expect(store.refreshing)
    #expect(store.canModify)
    #expect(store.canPerform("user.update", target: "u1"))
    #expect(store.activityText?.contains("更新中") == true)
    await store.perform("user.update", ["user_id": .string("u1"), "name": .string("Renamed")])
    #expect(store.serverSnapshot?.revision == 8)
    await controller.releaseSnapshots()
    await poll.value
    // The refresh read revision 7 before the write; it must not replace the newer result.
    #expect(store.serverSnapshot?.revision == 8)
    #expect(!store.refreshing)
    #expect(store.error == nil)
}

@Test @MainActor func operationsRunInClickOrderLockOnlyThemselvesAndIgnoreRepeatedClicks() async throws {
    let harness = try PacedHarness(); defer { harness.close() }
    let store = harness.store, controller = harness.controller
    await store.connectManagement()
    await controller.hold(writes: true)
    let first = Task { await store.perform("user.update", ["user_id": .string("u1"), "name": .string("A")]) }
    #expect(await eventually { await controller.writes().count == 1 })
    #expect(store.isSubmitting("user.update", target: "u1"))
    #expect(!store.canPerform("user.update", target: "u1"))
    #expect(store.canPerform("user.update", target: "u2"))
    #expect(store.canPerform("user.topup", target: "u1"))
    #expect(store.canModify)
    // A repeated click on the identical operation returns at once and is never sent.
    await store.perform("user.update", ["user_id": .string("u1"), "name": .string("A")])
    let second = Task { await store.perform("user.topup", ["user_id": .string("u2"), "bytes": .integer(10_000_000_000)]) }
    #expect(await eventually { store.pendingOperations.count == 2 })
    #expect(await controller.writes().count == 1)
    #expect(store.activityText?.contains("另有 1 项排队") == true)
    await controller.releaseWrites()
    await first.value; await second.value
    let writes = await controller.writes()
    #expect(writes.map(\.action) == ["user.update", "user.topup"])
    // The queued operation was checked against the revision the first one produced.
    #expect(writes.map(\.expected_revision) == [7, 8])
    #expect(store.serverSnapshot?.revision == 9)
    #expect(store.pendingOperations.isEmpty)
    #expect(store.error == nil)
}

@Test @MainActor func queuedOperationIsNotSentWhenSomeoneElseChangedTheState() async throws {
    let harness = try PacedHarness(); defer { harness.close() }
    let store = harness.store, controller = harness.controller
    await store.connectManagement()
    await controller.externalChange()
    await store.pollManagement()
    #expect(store.serverSnapshot?.revision == 8)
    // A confirmation opened at revision 7 cannot silently apply to someone else's newer state.
    await store.perform("user.rotate", ["user_id": .string("u1")], expectedRevision: 7)
    #expect(await controller.writes().isEmpty)
    #expect(store.error?.contains("其他操作") == true)
    #expect(store.pendingOperations.isEmpty)
}

@Test func recoveryProgressFollowsTheServerStepsWithoutGoingBackwards() {
    func progress(_ state: String, _ last: Int = 0, code: String? = nil) -> RecoveryProgress {
        var raw: [String: JSONValue] = ["state": .string(state)]
        if let code { raw["error_code"] = .string(code) }
        return RecoveryProgress(recovery: UserRecovery(.object(raw)), lastStep: last)
    }
    #expect(RecoveryProgress.steps == ["停止旧连接", "重建", "核对计量", "恢复成功"])
    #expect(progress("checking") == RecoveryProgress(recovery: UserRecovery(.object(["state": .string("checking")]))))
    #expect(progress("checking").step == 0 && progress("checking").outcome == .running)
    #expect(progress("recovering").step == 1)
    #expect(progress("starting").step == 2)
    #expect(progress("succeeded").step == 3 && progress("succeeded").outcome == .succeeded)
    #expect(progress("checking", 2).step == 2)
    let timeout = progress("failed", 2, code: "RECOVERY_TIMEOUT")
    #expect(timeout.step == 2 && timeout.finished)
    #expect(timeout.outcome == .failed("60 秒内未确认完成，已停止等待；原用量和订阅保留"))
    #expect(progress("blocked", 1).outcome == .failed("被停用、额度、到期等保护限制阻止"))
}

@Test @MainActor func recoveryIsConfirmedQuicklyAndItsResultStaysVisible() async throws {
    let harness = try PacedHarness(); defer { harness.close() }
    let store = harness.store, controller = harness.controller
    await store.connectManagement()
    #expect(store.pollInterval == 8)
    await store.perform("user.recovery.apply", ["user_id": .string("u1"), "preview_token": .string("preview"),
                                               "confirm_unknown_gap": .bool(false)], expectedRevision: 7)
    #expect(store.recoveryNoticeUserID == "u1")
    #expect(store.pollInterval == 2)
    #expect(store.recoveryDisplay?.progress.step == 0)
    #expect(store.recoveryDisplay?.name == "Member one")
    await controller.setRecovery("starting")
    await store.pollManagement()
    #expect(store.recoveryDisplay?.progress.step == 2)
    // Other users stay selectable and editable while the recovery is being confirmed.
    #expect(store.canPerform("user.update", target: "u2"))
    await controller.setRecovery("succeeded")
    await store.pollManagement()
    #expect(store.recoveryNoticeUserID == nil)
    #expect(store.pollInterval == 8)
    #expect(store.recoveryOutcome?.progress.outcome == .succeeded)
    #expect(store.recoveryDisplay?.progress.step == 3)
    #expect(store.notice == "恢复成功 · 计量可信")
    store.recoveryOutcome = nil
    #expect(store.recoveryDisplay == nil)
}
