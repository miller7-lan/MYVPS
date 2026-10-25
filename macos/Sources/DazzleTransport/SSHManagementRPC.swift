import Foundation
import DazzleModels

public struct SSHManagementRPC: Sendable {
    public let host: String
    public let identityFile: String
    public static let remoteCommand = "/usr/local/bin/dazzle-vps-control rpc"
    private let execute: @Sendable ([String], Data) async throws -> Data

    public init(host: String, identityFile: String) throws {
        try self.init(host: host, identityFile: identityFile, execute: { arguments, input in
            try await ProcessRunner.run(executable: URL(fileURLWithPath: "/usr/bin/ssh"), arguments: arguments,
                                        input: input, timeout: 25, acceptedExitCodes: [0, 1])
        })
    }
    // Internal executor seam is used only by transport tests; the App always uses /usr/bin/ssh.
    init(host: String, identityFile: String, execute: @escaping @Sendable ([String], Data) async throws -> Data) throws {
        guard host.range(of: #"\A[A-Za-z0-9][A-Za-z0-9.:-]{0,252}\z"#, options: .regularExpression) != nil else {
            throw TransportError.invalidInput("请输入有效的服务器 IP 或主机名。")
        }
        guard identityFile.hasPrefix("/"), FileManager.default.isReadableFile(atPath: identityFile),
              (try? URL(fileURLWithPath: identityFile).resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true else {
            throw TransportError.invalidInput("请选择已有的 SSH 私钥文件；应用不会复制或修改该密钥。")
        }
        self.host = host; self.identityFile = identityFile; self.execute = execute
    }
    public func call(_ request: RPCRequest) async throws -> JSONValue {
        // Even an incorrectly advertised server capability cannot expose simulation/system APIs.
        guard ServerContext.readActions.union(ServerContext.writeActions).contains(request.action) else {
            throw TransportError.invalidInput("服务器管理不支持此操作。")
        }
        let arguments = ["-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no", "-o", "IdentitiesOnly=yes",
                         "-o", "ConnectTimeout=8", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=1",
                         "-i", identityFile, "root@" + host, Self.remoteCommand]
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
