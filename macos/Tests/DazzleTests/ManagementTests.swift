import Foundation
import Testing
import DazzleModels
@testable import DazzleTransport
@testable import DazzleApp

private let fixtureServerID = "840737d0-365c-4da4-a706-3b3ee86be1da"
private func managedFixture(actions: [String] = ["snapshot", "user.export", "user.add"], mutations: Bool = true) -> JSONValue {
    .object(["schema_version": .integer(1), "revision": .integer(7), "mode": .string("production"),
             "server_id": .string(fixtureServerID), "users": .array([]),
             "capabilities": .object(["controller": .string("root_policy"), "allowed_actions": .array(actions.map(JSONValue.string)),
                                        "production_mutations": .bool(mutations), "legacy_retirement": .bool(false)]),
             "legacy": .object(["managed": .bool(false), "retirement_supported": .bool(false)])])
}

@Test func productionHandshakeRequiresIdentityNamespaceAndLimitedCapabilities() throws {
    let value = try Snapshot(managedFixture(actions: ["snapshot", "user.add", "demo.initialize", "legacy.stop", "mail.test"]))
    let context = try ServerContext(snapshot: value, expectedServerID: fixtureServerID)
    #expect(context.allows("user.add"))
    #expect(!context.allows("legacy.stop"))
    #expect(!context.allows("demo.initialize"))
    #expect(context.allows("mail.test"))
    #expect(throws: ModelError.self) { try ServerContext(snapshot: value, expectedServerID: UUID().uuidString) }
    var raw = value.raw.object
    raw["mode"] = .string("simulation")
    #expect(throws: ModelError.self) { try ServerContext(snapshot: Snapshot(.object(raw))) }
    raw = value.raw.object
    raw["legacy"] = .object(["managed": .bool(true), "retirement_supported": .bool(false)])
    #expect(throws: ModelError.self) { try ServerContext(snapshot: Snapshot(.object(raw))) }
    let readOnly = try ServerContext(snapshot: Snapshot(managedFixture(mutations: false)))
    #expect(readOnly.allows("snapshot"))
    #expect(!readOnly.allows("user.add"))
    #expect(!readOnly.canModify)
}

@Test @MainActor func serverWorkspaceStartsEmptyAndRequiresAuthenticatedConnection() throws {
    let store = AppStore()
    #expect(store.snapshot == nil)
    #expect(store.users.isEmpty)
    #expect(!store.canModify)
    #expect(!store.canPerform("user.add"))
    store.serverSnapshot = try Snapshot(managedFixture())
    store.serverContext = try ServerContext(snapshot: #require(store.serverSnapshot))
    #expect(store.snapshot?.revision == 7)
    #expect(!store.canPerform("user.add"))
    store.invalidateServerConnection()
    #expect(store.snapshot == nil)
    #expect(store.users.isEmpty)
}

private func temporaryIdentity() throws -> URL {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("ssh-fixture-" + UUID().uuidString)
    try Data("fixture-not-a-real-key".utf8).write(to: url)
    return url
}

@Test func managementTransportUsesFixedCommandAndJSONStdin() async throws {
    let key = try temporaryIdentity(); defer { try? FileManager.default.removeItem(at: key) }
    let connection = try SSHManagementRPC(host: "192.0.2.20", identityFile: key.path) { arguments, input in
        #expect(arguments.last == "/usr/local/bin/dazzle-vps-control rpc")
        #expect(arguments.contains("StrictHostKeyChecking=yes"))
        #expect(arguments.contains("UpdateHostKeys=no"))
        #expect(arguments.contains("BatchMode=yes"))
        #expect(!arguments.joined(separator: " ").contains("sent-only-over-stdin"))
        let request = try JSONDecoder().decode(RPCRequest.self, from: input)
        #expect(request.server_id == fixtureServerID)
        #expect(request.expected_revision == 7)
        #expect(request.params["name"].string == "sent-only-over-stdin")
        return try JSONEncoder().encode(JSONValue.object(["ok": .bool(true), "request_id": .string(request.request_id), "data": .object(["accepted": .bool(true)])]))
    }
    let result = try await connection.call(RPCRequest(action: "user.add", revision: 7, params: ["name": .string("sent-only-over-stdin")], serverID: fixtureServerID))
    #expect(result["accepted"].bool == true)
}

@Test func managementTransportRejectsSimulationAndMismatchedResponses() async throws {
    let key = try temporaryIdentity(); defer { try? FileManager.default.removeItem(at: key) }
    let connection = try SSHManagementRPC(host: "192.0.2.20", identityFile: key.path) { _, _ in
        Data(#"{"ok":true,"request_id":"wrong","data":{}}"#.utf8)
    }
    do { _ = try await connection.call(RPCRequest(action: "demo.initialize", revision: 7)); Issue.record("Simulation action was accepted") }
    catch { #expect(error is TransportError) }
    do { _ = try await connection.call(RPCRequest(action: "snapshot", revision: nil)); Issue.record("Mismatched reply was accepted") }
    catch { #expect(error is ModelError) }
    #expect(throws: TransportError.self) { try SSHManagementRPC(host: "host;command", identityFile: key.path) }
}

@Test func productionExportRequiresMatchingServerAndRealNewEndpoints() throws {
    var raw: [String: JSONValue] = ["filename": .string("Dazzle.conf"), "content": .string("private fixture"), "sensitive": .bool(true),
        "environment": .string("production"), "server_id": .string(fixtureServerID), "deployed": .bool(true),
        "runtime_state": .string("staged"),
        "nodes": .array([.string("vless://fixture@8.8.8.8:24430?security=reality#fixture")]),
        "nodes_url": .string("https://8.8.8.8:9443/fixture/nodes.txt")]
    try ExportArtifact(.object(raw)).validateProduction(serverID: fixtureServerID)
    #expect(throws: ModelError.self) { try ExportArtifact(.object(raw)).validateProduction(serverID: UUID().uuidString) }
    raw["nodes"] = .array([.string("vless://fixture@192.0.2.10:24430?security=reality#fixture")])
    #expect(throws: ModelError.self) { try ExportArtifact(.object(raw)).validateProduction(serverID: fixtureServerID) }
    raw["nodes"] = .array([.string("vless://fixture@8.8.8.8:443#legacy")])
    #expect(throws: ModelError.self) { try ExportArtifact(.object(raw)).validateProduction(serverID: fixtureServerID) }
    raw["nodes"] = .array([.string("vless://fixture@8.8.8.8:24430?security=reality#fixture")])
    raw["nodes_url"] = .string("https://8.8.8.8:8443/fixture/nodes.txt")
    #expect(throws: ModelError.self) { try ExportArtifact(.object(raw)).validateProduction(serverID: fixtureServerID) }
    raw["deployed"] = .bool(false)
    #expect(throws: ModelError.self) { try ExportArtifact(.object(raw)).validateProduction(serverID: fixtureServerID) }
}

@Test func workerRuntimeLabelsPreservePendingAndFailureStates() {
    #expect(WorkerState.label("stop_pending") == "正在停止")
    #expect(WorkerState.label("stop_failed") == "停止失败")
    #expect(WorkerState.label("unprovisioned") != WorkerState.label("running"))
    #expect(WorkerState.label(nil) == "状态未确认")
    #expect(WorkerState.meterLabel("unknown") == "尚未建立可信计量")
    #expect(WorkerState.meterLabel("reconciliation_required") == "需人工核对")
}

private actor FixtureController {
    private var snapshot = managedFixture(actions: ["snapshot", "user.export", "user.add", "demo.initialize", "mail.test", "legacy.stop"])
    private var received: [RPCRequest] = []
    private var disconnected = false
    func disconnect() { disconnected = true }
    func changeServerID() { var value = snapshot.object; value["server_id"] = .string(UUID().uuidString); snapshot = .object(value) }
    func requests() -> [RPCRequest] { received }
    func reply(_ arguments: [String], _ input: Data) throws -> Data {
        #expect(arguments.last == SSHManagementRPC.remoteCommand)
        let request = try JSONDecoder().decode(RPCRequest.self, from: input)
        received.append(request)
        if disconnected { throw TransportError.timeout }
        return try JSONEncoder().encode(JSONValue.object(["ok": .bool(true), "request_id": .string(request.request_id), "data": snapshot]))
    }
}

@Test @MainActor func managementHandshakePinsServerAndPollsOnlyTheIndependentSnapshot() async throws {
    let key = try temporaryIdentity(); defer { try? FileManager.default.removeItem(at: key) }
    let suite = "dazzle-tests-" + UUID().uuidString
    let defaults = try #require(UserDefaults(suiteName: suite)); defer { defaults.removePersistentDomain(forName: suite) }
    let fixture = FixtureController()
    let store = AppStore(defaults: defaults, managementFactory: { host, key in
        try SSHManagementRPC(host: host, identityFile: key, execute: { try await fixture.reply($0, $1) })
    })
    store.sshHost = "192.0.2.20"; store.sshKeyPath = key.path
    #expect(await fixture.requests().isEmpty)
    await store.connectManagement()
    #expect(store.error == nil)
    #expect(store.serverContext?.serverID == fixtureServerID)
    #expect(store.serverSnapshot?.revision == 7)
    #expect(store.canPerform("user.add"))
    #expect(!store.canPerform("demo.initialize"))
    #expect(store.canPerform("mail.test"))
    #expect(!store.canPerform("legacy.stop"))
    let pins = try #require(defaults.dictionary(forKey: "managementServerPins") as? [String: String])
    #expect(pins["192.0.2.20"] == fixtureServerID)
    await store.pollManagement()
    let requests = await fixture.requests()
    #expect(requests.count == 2)
    #expect(requests.allSatisfy { $0.action == "snapshot" && $0.expected_revision == nil })
    #expect(requests[0].server_id == nil)
    #expect(requests[1].server_id == fixtureServerID)
    store.invalidateServerConnection()
    #expect(store.snapshot == nil)
    await store.pollManagement()
    #expect(await fixture.requests().count == 2)
    await fixture.changeServerID()
    await store.connectManagement()
    #expect(store.error != nil)
    #expect(store.serverSnapshot == nil)
    #expect(store.serverContext == nil)
    #expect(!store.canModify)
    #expect((defaults.dictionary(forKey: "managementServerPins") as? [String: String])?["192.0.2.20"] == fixtureServerID)
}

@Test func actualProductionSnapshotMatchesMacHandshakeWithoutDeploying() async throws {
    let repo = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    let candidates = ["/opt/homebrew/bin/python3", "/usr/local/bin/python3", "/usr/bin/python3"]
    let python = try #require(candidates.first(where: FileManager.default.isExecutableFile(atPath:)))
    let code = #"""
import json,sys,tempfile
sys.path.insert(0,sys.argv[1])
from dazzle.production_state import ProductionStore,CORE_SHA256
from dazzle.production import handle_request
policy={"version":1,"server_id":"840737d0-365c-4da4-a706-3b3ee86be1da","server_endpoint":"8.8.8.8","core_sha256":CORE_SHA256,"agent_uid":1001,"workers":{"56c6efc3-7ff5-40c9-ae66-c7095deca290":{"role":"admin","public_port":24430,"api_port":34430}}}
with tempfile.TemporaryDirectory(prefix="dazzle-mac-contract-") as folder:
    store=ProductionStore(folder,policy=policy,initialize=True)
    reply=handle_request(store,{"api_version":1,"request_id":"mac-fixture","action":"snapshot","expected_revision":None,"params":{}})
    store.close()
    print(json.dumps(reply))
"""#
    let bytes = try await ProcessRunner.run(executable: URL(fileURLWithPath: python), arguments: ["-I", "-c", code, repo.appendingPathComponent("backend").path])
    let response = try JSONDecoder().decode(RPCResponse.self, from: bytes)
    let value = try response.checked(for: RPCRequest(action: "snapshot", revision: nil, id: "mac-fixture"))
    let snapshot = try Snapshot(value)
    let context = try ServerContext(snapshot: snapshot)
    #expect(context.serverID == fixtureServerID)
    #expect(context.allows("user.update"))
    #expect(!context.allows("mail.process"))
    #expect(!context.allows("mail.simulated_inbox"))
    #expect(snapshot.users.isEmpty)
    #expect(snapshot["legacy"]["managed"].bool == false)
    #expect(snapshot["mail"]["transport"].string == "not_enabled")
}

@Test @MainActor func startupWithoutSavedConnectionDoesNotRunAnyProcess() async throws {
    let suite = "dazzle-empty-start-" + UUID().uuidString
    let defaults = try #require(UserDefaults(suiteName: suite)); defer { defaults.removePersistentDomain(forName: suite) }
    let store = AppStore(defaults: defaults, managementFactory: { _, _ in
        Issue.record("An empty startup must not launch SSH")
        throw TransportError.unavailable("unexpected test call")
    })
    await store.restoreConnection()
    #expect(store.snapshot == nil)
    #expect(store.serverContext == nil)
    #expect(store.error == nil)
    #expect(!store.canModify)
}

@Test @MainActor func startupRestoresSavedSSHIdentityWithReadOnlyHandshake() async throws {
    let key = try temporaryIdentity(); defer { try? FileManager.default.removeItem(at: key) }
    let suite = "dazzle-saved-start-" + UUID().uuidString
    let defaults = try #require(UserDefaults(suiteName: suite)); defer { defaults.removePersistentDomain(forName: suite) }
    defaults.set("192.0.2.20", forKey: "sshHost")
    defaults.set(key.path, forKey: "sshKeyPath")
    defaults.set(["192.0.2.20": fixtureServerID], forKey: "managementServerPins")
    let fixture = FixtureController()
    let store = AppStore(defaults: defaults, managementFactory: { host, key in
        try SSHManagementRPC(host: host, identityFile: key, execute: { try await fixture.reply($0, $1) })
    })
    await store.restoreConnection()
    #expect(store.serverReachable)
    #expect(store.serverContext?.serverID == fixtureServerID)
    let requests = await fixture.requests()
    #expect(requests.count == 1)
    #expect(requests[0].action == "snapshot")
    #expect(requests[0].expected_revision == nil)
    #expect(defaults.string(forKey: "sshKeyPath") == key.path)
    store.sensitiveInputActive = true
    await store.pollManagement()
    #expect(await fixture.requests().count == 1)
    store.sensitiveInputActive = false
    await store.restoreConnection()
    #expect(await fixture.requests().count == 1)
}

@Test @MainActor func disconnectedControllerKeepsOldSnapshotAndBlocksAllWrites() async throws {
    let key = try temporaryIdentity(); defer { try? FileManager.default.removeItem(at: key) }
    let suite = "dazzle-disconnect-" + UUID().uuidString
    let defaults = try #require(UserDefaults(suiteName: suite)); defer { defaults.removePersistentDomain(forName: suite) }
    let fixture = FixtureController()
    let store = AppStore(defaults: defaults, managementFactory: { host, key in
        try SSHManagementRPC(host: host, identityFile: key, execute: { try await fixture.reply($0, $1) })
    })
    store.sshHost = "192.0.2.20"; store.sshKeyPath = key.path
    await store.connectManagement()
    #expect(store.canPerform("user.add"))
    await fixture.disconnect()
    await store.pollManagement()
    #expect(!store.serverReachable)
    #expect(store.snapshot?.revision == 7)
    #expect(!store.canModify)
    #expect(!store.canPerform("user.add"))
    #expect(!store.canPerform("user.export"))
    #expect(store.serverRefreshError?.contains("修改已禁用") == true)
    let before = await fixture.requests().count
    await store.perform("user.add", ["name": .string("must not send")])
    #expect(await fixture.requests().count == before)
}

@Test func twentyKilobyteLiveMailSnapshotDecodesWithoutWaitingForCredentials() throws {
    var raw = managedFixture().object
    raw["mail"] = .object(["configured": .bool(false), "settings_configured": .bool(true), "secret_configured": .bool(false),
        "credential_required": .bool(true), "admin_email": .string("admin@example.test"), "admin_email_verified": .bool(false),
        "transport": .string("smtp"), "configuration": .object(["host": .string("smtp.qq.com"), "port": .integer(465), "security": .string("ssl"), "username": .string("sender@example.test"), "sender": .string("sender@example.test")]),
        "queue": .array([]), "history": .array([]), "preferences": .object(["enabled": .bool(true)])])
    raw["operations"] = .array((0..<100).map { .object(["id": .string("fixture-\($0)"), "action": .string("status"), "detail": .string(String(repeating: "fixture", count: 30))]) })
    let request = RPCRequest(action: "snapshot", revision: nil, id: "large-mail-fixture")
    let encoded = try JSONEncoder().encode(JSONValue.object(["ok": .bool(true), "request_id": .string(request.request_id), "revision": .integer(7), "data": .object(raw)]))
    #expect(encoded.count > 20_480)
    let began = Date()
    let response = try JSONDecoder().decode(RPCResponse.self, from: encoded)
    let snapshot = try Snapshot(response.checked(for: request))
    _ = try ServerContext(snapshot: snapshot)
    let status = MailStatus(snapshot["mail"])
    #expect(!status.configured)
    #expect(!status.secretConfigured)
    #expect(!status.canRequestVerification(address: status.adminEmail))
    #expect(status.raw["credential_required"].bool == true)
    #expect(Date().timeIntervalSince(began) < 1)
}
