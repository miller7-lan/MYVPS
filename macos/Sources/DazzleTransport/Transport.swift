import Foundation
import Darwin
import DazzleModels

public enum TransportError: Error, LocalizedError, Sendable {
    case timeout, failed(Int32), unavailable(String), tooLarge, invalidInput(String)
    public var errorDescription: String? {
        switch self {
        case .timeout: return "请求超时；未自动重试修改操作，请刷新后核对结果。"
        case .failed(let code): return "后台进程未成功完成（退出码 \(code)）。请检查后端安装或 SSH 连接；敏感输出已隐藏。"
        case .unavailable(let message), .invalidInput(let message): return message
        case .tooLarge: return "后台响应超过安全限制。"
        }
    }
}

private final class Capture: @unchecked Sendable {
    let lock = NSLock()
    var value = Data()
    var overflow = false
    func append(_ bytes: Data) {
        lock.lock(); defer { lock.unlock() }
        if value.count + bytes.count <= 2_097_152 { value.append(bytes) } else { overflow = true }
    }
}

public enum ProcessRunner {
    public static func run(executable: URL, arguments: [String], input: Data = Data(),
                           timeout: TimeInterval = 15, environment: [String: String]? = nil,
                           acceptedExitCodes: Set<Int32> = [0]) async throws -> Data {
        try await Task.detached(priority: .userInitiated) {
            try runBlocking(executable: executable, arguments: arguments, input: input, timeout: timeout, environment: environment, acceptedExitCodes: acceptedExitCodes)
        }.value
    }
    private static func runBlocking(executable: URL, arguments: [String], input: Data,
                                    timeout: TimeInterval, environment: [String: String]?, acceptedExitCodes: Set<Int32>) throws -> Data {
            guard input.count <= 1_048_576 else { throw TransportError.tooLarge }
            let process = Process(), output = Pipe(), errors = Pipe(), incoming = Pipe()
            process.executableURL = executable; process.arguments = arguments
            process.standardInput = incoming; process.standardOutput = output; process.standardError = errors
            process.environment = environment
            let stdout = Capture(), discardedErrors = Capture(), readers = DispatchGroup()
            let terminated = DispatchSemaphore(value: 0)
            process.terminationHandler = { _ in terminated.signal() }
            try process.run()
            for (pipe, capture) in [(output, stdout), (errors, discardedErrors)] {
                readers.enter()
                DispatchQueue.global(qos: .utility).async {
                    while true {
                        let data = pipe.fileHandleForReading.availableData
                        if data.isEmpty { break }
                        capture.append(data)
                    }
                    readers.leave()
                }
            }
            do { try incoming.fileHandleForWriting.write(contentsOf: input); try incoming.fileHandleForWriting.close() }
            catch { process.terminate(); throw TransportError.unavailable("无法向后台发送请求。") }
            if terminated.wait(timeout: .now() + timeout) == .timedOut {
                process.terminate()
                if terminated.wait(timeout: .now() + 1) == .timedOut { kill(process.processIdentifier, SIGKILL) }
                _ = readers.wait(timeout: .now() + 2)
                throw TransportError.timeout
            }
            _ = readers.wait(timeout: .now() + 2)
            guard acceptedExitCodes.contains(process.terminationStatus) else { throw TransportError.failed(process.terminationStatus) }
            guard !stdout.overflow else { throw TransportError.tooLarge }
            return stdout.value
    }
}

public enum SecureExport {
    public static func write(_ data: Data, to destination: URL) throws {
        guard destination.isFileURL else { throw TransportError.invalidInput("导出目标必须为本地文件。") }
        if let values = try? destination.resourceValues(forKeys: [.isSymbolicLinkKey, .isDirectoryKey]),
           values.isSymbolicLink == true || values.isDirectory == true {
            throw TransportError.invalidInput("不能覆盖目录或符号链接。")
        }
        let temporary = destination.deletingLastPathComponent().appendingPathComponent(".dazzle-export-" + UUID().uuidString)
        let fd = Darwin.open(temporary.path, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, S_IRUSR | S_IWUSR)
        guard fd >= 0 else { throw TransportError.unavailable("无法创建私密导出文件。") }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        defer { try? handle.close(); try? FileManager.default.removeItem(at: temporary) }
        try handle.write(contentsOf: data); try handle.synchronize(); try handle.close()
        guard Darwin.rename(temporary.path, destination.path) == 0 else { throw TransportError.unavailable("无法保存私密文件。") }
    }
}
