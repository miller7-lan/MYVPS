import Foundation
import Testing
import DazzleModels
@testable import DazzleTransport

@Test func connectionReuseUsesAPrivatePerKeySocketAndFallsBackWhenUnsafe() throws {
    let base = URL(fileURLWithPath: "/tmp/dz-" + String(UUID().uuidString.prefix(8)))
    defer { try? FileManager.default.removeItem(at: base) }
    let key = FileManager.default.temporaryDirectory.appendingPathComponent("mux-key-" + UUID().uuidString)
    let otherKey = FileManager.default.temporaryDirectory.appendingPathComponent("mux-key-" + UUID().uuidString)
    try Data("local-test-only".utf8).write(to: key); try Data("local-test-only".utf8).write(to: otherKey)
    defer { try? FileManager.default.removeItem(at: key); try? FileManager.default.removeItem(at: otherKey) }
    let directory = base.appendingPathComponent("ssh")
    let connection = try SSHManagementRPC(host: "192.0.2.40", identityFile: key.path, controlDirectory: directory, execute: { _, _ in Data() })
    let path = try #require(connection.controlPath)
    let name = String(path.dropFirst(directory.standardizedFileURL.path.count + 1))
    #expect(path.hasPrefix(directory.standardizedFileURL.path + "/") && !path.contains("%"))
    #expect(name.count == 16 && name.allSatisfy(\.isHexDigit))
    // OpenSSH binds "<path>.<16 characters>" first; that must still fit a 104-byte socket path.
    #expect(path.utf8.count + 17 <= 103)
    // The real per-user default directory leaves room for that temporary name as well.
    let realDirectory = try #require(SSHMultiplexing.defaultDirectory())
    #expect(realDirectory.standardizedFileURL.path.utf8.count + 1 + 16 + 17 <= 103)
    var info = stat()
    #expect(lstat(directory.path, &info) == 0 && info.st_mode & 0o777 == 0o700)
    let arguments = connection.arguments
    #expect(arguments.contains("ControlMaster=auto") && arguments.contains("ControlPersist=60") && arguments.contains("ControlPath=" + path))
    #expect(arguments.contains("StrictHostKeyChecking=yes") && arguments.contains("BatchMode=yes"))
    #expect(arguments.last == SSHManagementRPC.remoteCommand)
    // Another key never reuses a connection authenticated with this one.
    let other = try SSHManagementRPC(host: "192.0.2.40", identityFile: otherKey.path, controlDirectory: directory, execute: { _, _ in Data() })
    #expect(other.controlPath != nil && other.controlPath != path)
    // Another server never reuses it either.
    let otherHost = try SSHManagementRPC(host: "192.0.2.41", identityFile: key.path, controlDirectory: directory, execute: { _, _ in Data() })
    #expect(otherHost.controlPath != nil && otherHost.controlPath != path)
    // A symlinked or overlong socket directory disables reuse instead of weakening it.
    let link = base.appendingPathComponent("link")
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: directory)
    #expect(SSHMultiplexing.controlPath(in: link, identityFile: key.path, host: "192.0.2.40") == nil)
    #expect(SSHMultiplexing.controlPath(in: base.appendingPathComponent(String(repeating: "x", count: 60)), identityFile: key.path, host: "192.0.2.40") == nil)
    // Without a directory (the test seam default) every request keeps its own handshake.
    let plain = try SSHManagementRPC(host: "192.0.2.40", identityFile: key.path, execute: { _, _ in Data() })
    #expect(plain.controlPath == nil && !plain.arguments.contains("ControlMaster=auto"))
}
