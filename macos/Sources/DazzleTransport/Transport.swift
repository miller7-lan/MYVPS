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

// Blocking pipe work runs on a dedicated OS thread, never on Swift's cooperative
// executor or a dispatch reader queue that can be starved by waiting tasks.
private final class ProcessCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false
    func cancel() { lock.lock(); cancelled = true; lock.unlock() }
    var isCancelled: Bool { lock.lock(); defer { lock.unlock() }; return cancelled }
}

public enum ProcessRunner {
    public static func run(executable: URL, arguments: [String], input: Data = Data(),
                           timeout: TimeInterval = 15, environment: [String: String]? = nil,
                           acceptedExitCodes: Set<Int32> = [0]) async throws -> Data {
        let cancellation = ProcessCancellation()
        return try await withTaskCancellationHandler {
            let result: Data = try await withCheckedThrowingContinuation { continuation in
                Thread.detachNewThread {
                    do {
                        continuation.resume(returning: try runBlocking(executable: executable, arguments: arguments,
                            input: input, timeout: timeout, environment: environment,
                            acceptedExitCodes: acceptedExitCodes, cancellation: cancellation))
                    } catch { continuation.resume(throwing: error) }
                }
            }
            try Task.checkCancellation()
            return result
        } onCancel: { cancellation.cancel() }
    }

    private static func runBlocking(executable: URL, arguments: [String], input: Data,
                                    timeout: TimeInterval, environment: [String: String]?,
                                    acceptedExitCodes: Set<Int32>, cancellation: ProcessCancellation) throws -> Data {
        guard input.count <= 1_048_576 else { throw TransportError.tooLarge }
        guard timeout.isFinite, timeout > 0 else { throw TransportError.timeout }
        if cancellation.isCancelled { throw CancellationError() }
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        let process = Process(), output = Pipe(), errors = Pipe(), incoming = Pipe()
        process.executableURL = executable; process.arguments = arguments
        process.standardInput = incoming; process.standardOutput = output; process.standardError = errors
        process.environment = environment
        do { try process.run() }
        catch { throw TransportError.unavailable("无法启动后台进程。") }
        defer {
            // Closing our handles also bounds cleanup if a descendant inherited a pipe.
            try? incoming.fileHandleForWriting.close()
            try? output.fileHandleForReading.close()
            try? errors.fileHandleForReading.close()
            if process.isRunning {
                process.terminate()
                let grace = ProcessInfo.processInfo.systemUptime + 0.25
                while process.isRunning && ProcessInfo.processInfo.systemUptime < grace { usleep(5_000) }
                if process.isRunning { _ = Darwin.kill(process.processIdentifier, SIGKILL) }
            }
            process.waitUntilExit()
        }
        let outFD = output.fileHandleForReading.fileDescriptor
        let errFD = errors.fileHandleForReading.fileDescriptor
        let inFD = incoming.fileHandleForWriting.fileDescriptor
        for fd in [outFD, errFD, inFD] {
            let flags = fcntl(fd, F_GETFL)
            guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else {
                throw TransportError.unavailable("无法建立后台通信管道。")
            }
        }
        // Do not change the application's global SIGPIPE handling.
        guard fcntl(inFD, F_SETNOSIGPIPE, 1) == 0 else {
            throw TransportError.unavailable("无法建立后台通信管道。")
        }
        var stdout = Data(), outOpen = true, errOpen = true, inputOpen = true
        var offset = 0, sendFailed = false
        var buffer = [UInt8](repeating: 0, count: 16_384)
        func closeInput() { if inputOpen { try? incoming.fileHandleForWriting.close(); inputOpen = false } }
        if input.isEmpty { closeInput() }
        while true {
            if cancellation.isCancelled { throw CancellationError() }
            let remaining = deadline - ProcessInfo.processInfo.systemUptime
            guard remaining > 0 else { throw TransportError.timeout }
            if !process.isRunning {
                closeInput()
                if !outOpen && !errOpen { break }
            }
            var descriptors = [pollfd]()
            if outOpen { descriptors.append(pollfd(fd: outFD, events: Int16(POLLIN), revents: 0)) }
            if errOpen { descriptors.append(pollfd(fd: errFD, events: Int16(POLLIN), revents: 0)) }
            if inputOpen { descriptors.append(pollfd(fd: inFD, events: Int16(POLLOUT), revents: 0)) }
            let waited = descriptors.withUnsafeMutableBufferPointer { ptr in
                Darwin.poll(ptr.baseAddress, nfds_t(ptr.count), Int32(min(20, max(1, remaining * 1000))))
            }
            if waited < 0 { if errno == EINTR { continue }; throw TransportError.unavailable("后台通信读取失败。") }
            for descriptor in descriptors where descriptor.revents != 0 {
                if descriptor.fd == inFD {
                    if descriptor.revents & Int16(POLLERR | POLLHUP | POLLNVAL) != 0 {
                        sendFailed = offset < input.count; closeInput(); continue
                    }
                    let count = input.withUnsafeBytes { bytes in
                        Darwin.write(inFD, bytes.baseAddress!.advanced(by: offset), min(16_384, input.count - offset))
                    }
                    if count > 0 { offset += count; if offset == input.count { closeInput() } }
                    else if count < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR {
                        sendFailed = true; closeInput()
                    }
                } else {
                    // Drain both streams while writing stdin; neither stream can fill
                    // a pipe and prevent the process from reading its request.
                    for _ in 0..<16 {
                        let count = buffer.withUnsafeMutableBytes { Darwin.read(descriptor.fd, $0.baseAddress!, $0.count) }
                        if count > 0 {
                            if descriptor.fd == outFD {
                                guard stdout.count + count <= 2_097_152 else { throw TransportError.tooLarge }
                                stdout.append(contentsOf: buffer.prefix(count))
                            }
                        } else if count == 0 {
                            if descriptor.fd == outFD { outOpen = false } else { errOpen = false }
                            break
                        } else if errno == EINTR { continue }
                        else if errno == EAGAIN || errno == EWOULDBLOCK { break }
                        else { throw TransportError.unavailable("后台通信读取失败。") }
                    }
                }
            }
        }
        process.waitUntilExit()
        guard acceptedExitCodes.contains(process.terminationStatus) else { throw TransportError.failed(process.terminationStatus) }
        guard !sendFailed && offset == input.count else { throw TransportError.unavailable("无法完整发送后台请求。") }
        return stdout
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
