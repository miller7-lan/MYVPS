import Foundation
import CryptoKit
import Darwin
import DazzleModels

public struct SSHManagementRPC: Sendable {
    public let host: String
    public let identityFile: String
    public static let remoteCommand = "/usr/local/bin/dazzle-vps-control rpc"
    private let execute: @Sendable ([String], Data) async throws -> Data
    /// OpenSSH control socket that lets one authenticated connection serve later requests.
    let controlPath: String?

    public init(host: String, identityFile: String) throws {
        try self.init(host: host, identityFile: identityFile, controlDirectory: SSHMultiplexing.defaultDirectory(), execute: { arguments, input in
            try await ProcessRunner.run(executable: URL(fileURLWithPath: "/usr/bin/ssh"), arguments: arguments,
                                        input: input, timeout: 25, acceptedExitCodes: [0, 1])
        })
    }
    // Internal executor seam is used only by transport tests; the App always uses /usr/bin/ssh.
    init(host: String, identityFile: String, controlDirectory: URL? = nil,
         execute: @escaping @Sendable ([String], Data) async throws -> Data) throws {
        guard host.range(of: #"\A[A-Za-z0-9][A-Za-z0-9.:-]{0,252}\z"#, options: .regularExpression) != nil else {
            throw TransportError.invalidInput("请输入有效的服务器 IP 或主机名。")
        }
        guard identityFile.hasPrefix("/"), FileManager.default.isReadableFile(atPath: identityFile),
              (try? URL(fileURLWithPath: identityFile).resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true else {
            throw TransportError.invalidInput("请选择已有的 SSH 私钥文件；应用不会复制或修改该密钥。")
        }
        self.host = host; self.identityFile = identityFile; self.execute = execute
        controlPath = controlDirectory.flatMap { SSHMultiplexing.controlPath(in: $0, identityFile: identityFile, host: host) }
    }
    var arguments: [String] {
        var result = ["-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no", "-o", "IdentitiesOnly=yes",
                      "-o", "ConnectTimeout=8", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=1"]
        if let controlPath {
            // Reuse one verified connection; it closes itself after 60 idle seconds.
            result += ["-o", "ControlMaster=auto", "-o", "ControlPersist=60", "-o", "ControlPath=" + controlPath]
        }
        return result + ["-i", identityFile, "root@" + host, Self.remoteCommand]
    }
    public func call(_ request: RPCRequest) async throws -> JSONValue {
        // Even an incorrectly advertised server capability cannot expose simulation/system APIs.
        guard ServerContext.readActions.union(ServerContext.writeActions).contains(request.action) else {
            throw TransportError.invalidInput("服务器管理不支持此操作。")
        }
        var input = try JSONEncoder().encode(request); input.append(10)
        guard input.count <= 1_048_576 else { throw TransportError.tooLarge }
        let output = try await execute(arguments, input)
        guard output.count <= 2_097_152 else { throw TransportError.tooLarge }
        let response: RPCResponse
        do { response = try JSONDecoder().decode(RPCResponse.self, from: output) }
        catch { throw ModelError.invalidResponse("服务器返回了无法解析的响应；原始输出已隐藏。") }
        return try response.checked(for: request)
    }
}

/// Private OpenSSH connection reuse. Any doubt about the socket directory disables it,
/// so every request still works exactly as before with a fresh, fully verified handshake.
enum SSHMultiplexing {
    static func defaultDirectory() -> URL? {
        FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first?
            .appendingPathComponent("DazzleVPS/ssh", isDirectory: true)
    }
    /// The socket name is derived from key, host, user and port, so choosing another key or
    /// server never reuses a connection that was authenticated for the previous one.
    static func controlPath(in directory: URL, identityFile: String, host: String) -> String? {
        let path = directory.standardizedFileURL.path
        let name = SHA256.hash(data: Data((identityFile + "\n" + host + "\nroot\n22").utf8))
            .prefix(8).map { String(format: "%02x", $0) }.joined()
        // OpenSSH first binds "<path>.<16 random characters>", and a Unix socket path holds
        // at most 103 bytes on macOS. A path that does not fit would silently disable reuse.
        guard path.hasPrefix("/"), path.utf8.count + 1 + name.count + 17 <= 103 else { return nil }
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
        } catch { return nil }
        var info = stat()
        guard lstat(path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR, info.st_uid == getuid() else { return nil }
        if info.st_mode & 0o077 != 0 {
            guard chmod(path, 0o700) == 0 else { return nil }
        }
        return path + "/" + name
    }
}
