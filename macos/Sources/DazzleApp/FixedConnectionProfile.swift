import Foundation

/// Local build metadata contains an endpoint and an external key path, never key bytes.
struct FixedConnectionProfile: Equatable, Sendable {
    let host: String
    let identityFile: String

    init?(configuration: [String: String]?) {
        guard let configuration else { return nil }
        let host = (configuration["Host"] ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let identity = (configuration["IdentityFile"] ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        guard !host.isEmpty, identity.hasPrefix("/") else { return nil }
        self.host = host
        self.identityFile = identity
    }

    static var bundled: Self? {
        Self(configuration: Bundle.main.object(forInfoDictionaryKey: "DazzleFixedConnection") as? [String: String])
    }
}
