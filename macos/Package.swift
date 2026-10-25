// swift-tools-version: 6.0
import PackageDescription
import Foundation

// Only selected standalone CLT needs explicit Testing framework search paths.
// Full Xcode resolves its own matching Testing library and macro plugin normally.
let developer: String = {
    if let override = ProcessInfo.processInfo.environment["DEVELOPER_DIR"], !override.isEmpty {
        return URL(fileURLWithPath: override).standardizedFileURL.path
    }
    let process = Process(), output = Pipe()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/xcode-select")
    process.arguments = ["-p"]; process.standardOutput = output; process.standardError = FileHandle.nullDevice
    do {
        try process.run()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        if process.terminationStatus == 0, let path = String(data: data, encoding: .utf8) {
            return URL(fileURLWithPath: path.trimmingCharacters(in: .whitespacesAndNewlines)).standardizedFileURL.path
        }
    } catch {}
    return ""
}()
let usesCLT = developer.hasSuffix("/CommandLineTools")
let testingFrameworks = developer + "/Library/Developer/Frameworks"
let testingSwiftSettings: [SwiftSetting] = usesCLT ? [.unsafeFlags(["-F", testingFrameworks])] : []
let testingLinkerSettings: [LinkerSetting] = usesCLT ? [.unsafeFlags(["-F", testingFrameworks, "-framework", "Testing", "-Xlinker", "-rpath", "-Xlinker", testingFrameworks])] : []

let package = Package(
    name: "DazzleVPS",
    platforms: [.macOS(.v14)],
    products: [.executable(name: "DazzleVPS", targets: ["DazzleApp"])],
    targets: [
        .target(name: "DazzleModels"),
        .target(name: "DazzleTransport", dependencies: ["DazzleModels"]),
        .executableTarget(name: "DazzleApp", dependencies: ["DazzleModels", "DazzleTransport"]),
        .testTarget(name: "DazzleTests", dependencies: ["DazzleModels", "DazzleTransport", "DazzleApp"],
            swiftSettings: testingSwiftSettings,
            linkerSettings: testingLinkerSettings)
    ]
)
