// swift-tools-version: 6.0
import PackageDescription
import Foundation

// CLT ships Swift Testing as a developer framework. The native SwiftPM engine
// needs its location explicitly; full Xcode uses the corresponding developer dir.
let developer = ProcessInfo.processInfo.environment["DEVELOPER_DIR"] ?? "/Library/Developer/CommandLineTools"
let testingFrameworks = developer + "/Library/Developer/Frameworks"

let package = Package(
    name: "DazzleVPS",
    platforms: [.macOS(.v14)],
    products: [.executable(name: "DazzleVPS", targets: ["DazzleApp"])],
    targets: [
        .target(name: "DazzleModels"),
        .target(name: "DazzleTransport", dependencies: ["DazzleModels"]),
        .executableTarget(name: "DazzleApp", dependencies: ["DazzleModels", "DazzleTransport"]),
        .testTarget(name: "DazzleTests", dependencies: ["DazzleModels", "DazzleTransport", "DazzleApp"],
            swiftSettings: [.unsafeFlags(["-F", testingFrameworks])],
            linkerSettings: [.unsafeFlags(["-F", testingFrameworks, "-framework", "Testing", "-Xlinker", "-rpath", "-Xlinker", testingFrameworks])])
    ]
)
