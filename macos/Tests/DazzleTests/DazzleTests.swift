import Foundation
import Testing
import DazzleModels
@testable import DazzleTransport

@Test func contractRetainsNullAndExtraFields() throws {
    let raw = Data(#"{"schema_version":1,"mode":"simulation","revision":9223372036854775,"users":[],"provider":{"total_bytes":null,"observed_at":null},"future":{"flag":true}}"#.utf8)
    let decoded = try JSONDecoder().decode(JSONValue.self, from: raw)
    let snapshot = try Snapshot(decoded)
    #expect(snapshot.revision == 9223372036854775)
    #expect(snapshot["provider"]["observed_at"] == .null)
    #expect(snapshot["provider"]["total_bytes"].int == nil)
    #expect(try JSONDecoder().decode(JSONValue.self, from: JSONEncoder().encode(decoded)) == decoded)
}

@Test func mismatchedAndFailedRepliesAreRejected() throws {
    let request = RPCRequest(action: "snapshot", revision: nil, id: "expected")
    let wrong = try JSONDecoder().decode(RPCResponse.self, from: Data(#"{"ok":true,"request_id":"different","data":{}}"#.utf8))
    #expect(throws: ModelError.self) { try wrong.checked(for: request) }
    let denied = try JSONDecoder().decode(RPCResponse.self, from: Data(#"{"ok":false,"request_id":"expected","error":{"code":"READ_ONLY","message":"read only"}}"#.utf8))
    #expect(throws: ModelError.self) { try denied.checked(for: request) }
}

@Test func sensitiveExportRequiresExplicitMarkerAndSafeBasename() throws {
    #expect(throws: ModelError.self) { try ExportArtifact(.object(["filename": .string("config.yaml"), "content": .string("private")])) }
    let value = try ExportArtifact(.object(["filename": .string("../../private.yaml"), "content": .string("fixture-only"), "sensitive": .bool(true)]))
    #expect(value.filename == "private.yaml")
    #expect(value.nodesURL == nil)
}

@Test func userEditingHandlesAbsentEmailAndAdministratorQuota() throws {
    let member = try #require(ProxyUser(.object(["id": .string("member-fixture"), "role": .string("member")])))
    let body = try UserPayload.update(user: member, name: "Renamed", quotaBytes: 120_000_000_000, email: "  ", autoRestore: true, thresholdPercent: 80)
    #expect(body["email"] == .null)
    #expect(body["quota_bytes"] == .integer(120_000_000_000))
    let admin = try #require(ProxyUser(.object(["id": .string("admin-fixture"), "role": .string("admin")])))
    let unlimited = try UserPayload.update(user: admin, name: "Admin", quotaBytes: nil, email: "admin@example.test", autoRestore: true, thresholdPercent: 80)
    #expect(unlimited["quota_bytes"] == nil)
    #expect(unlimited["email"] == .string("admin@example.test"))
}

@Test func remainingTrafficIncludesTopupsAndClampsExhaustedQuota() throws {
    var raw: [String: JSONValue] = ["id": .string("remaining-fixture"), "role": .string("member"),
        "quota_bytes": .integer(100), "topup_bytes": .integer(20),
        "used_upload": .integer(30), "used_download": .integer(40)]
    #expect(try #require(ProxyUser(.object(raw))).remaining == 50)
    raw["used_download"] = .integer(140)
    #expect(try #require(ProxyUser(.object(raw))).remaining == 0)
    raw["role"] = .string("admin")
    raw["unlimited"] = .bool(true)
    #expect(try #require(ProxyUser(.object(raw))).remaining == nil)
}

@Test func exportIsPrivateAndDoesNotFollowSymlinks() throws {
    let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: folder) }
    let file = folder.appendingPathComponent("private.txt")
    try SecureExport.write(Data("fixture-value".utf8), to: file)
    #expect(try String(contentsOf: file, encoding: .utf8) == "fixture-value")
    #expect((try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? NSNumber)?.intValue == 0o600)
    let link = folder.appendingPathComponent("link")
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: file)
    #expect(throws: TransportError.self) { try SecureExport.write(Data("replaced".utf8), to: link) }
    #expect(try String(contentsOf: file, encoding: .utf8) == "fixture-value")
}

@Test func processCapturesOutputAndDoesNotDiscloseStderr() async throws {
    let output = try await ProcessRunner.run(executable: URL(fileURLWithPath: "/usr/bin/printf"), arguments: ["%s", "fixture-output"])
    #expect(String(data: output, encoding: .utf8) == "fixture-output")
    do {
        _ = try await ProcessRunner.run(executable: URL(fileURLWithPath: "/bin/sh"), arguments: ["-c", "printf 'fixture-secret' >&2; exit 9"])
        Issue.record("failing child unexpectedly succeeded")
    } catch { #expect(!error.localizedDescription.contains("fixture-secret")) }
}

@Test func timeoutTerminatesChild() async throws {
    let start = Date()
    do {
        _ = try await ProcessRunner.run(executable: URL(fileURLWithPath: "/bin/sleep"), arguments: ["5"], timeout: 0.05)
        Issue.record("timeout was not enforced")
    } catch { #expect(error is TransportError); #expect(Date().timeIntervalSince(start) < 3) }
}

@Test func sshRejectsOptionInjectionBeforeStartingProcess() {
    #expect(throws: TransportError.self) { try SSHManagementRPC(host: "-oProxyCommand=malicious", identityFile: "/not-used") }
    #expect(throws: TransportError.self) { try SSHManagementRPC(host: "example.com;whoami", identityFile: "/not-used") }
}


@Test func processDrainsTwentyKilobyteStdoutWithoutPipeStall() async throws {
    let expected = String(repeating: "x", count: 20_480)
    let began = Date()
    let data = try await ProcessRunner.run(executable: URL(fileURLWithPath: "/usr/bin/printf"),
                                           arguments: ["%s", expected], timeout: 3)
    #expect(data.count == 20_480)
    #expect(String(data: data, encoding: .utf8) == expected)
    #expect(Date().timeIntervalSince(began) < 3)
}

@Test func processDrainsStdoutAndStderrTogetherWithoutDisclosingStderr() async throws {
    let data = try await ProcessRunner.run(executable: URL(fileURLWithPath: "/bin/sh"),
        arguments: ["-c", "i=0; while [ $i -lt 2048 ]; do printf 'abcdefghij'; printf 'stderrfixture' >&2; i=$((i+1)); done"], timeout: 3)
    #expect(data.count == 20_480)
    #expect(!String(decoding: data, as: UTF8.self).contains("stderrfixture"))
}

@Test func processSendsInputThenClosesStdinBeforeReceivingLargeReply() async throws {
    let expected = Data(String(repeating: "rpc-fixture", count: 2048).utf8)
    let actual = try await ProcessRunner.run(executable: URL(fileURLWithPath: "/bin/cat"), arguments: [], input: expected, timeout: 3)
    #expect(actual == expected)
}
