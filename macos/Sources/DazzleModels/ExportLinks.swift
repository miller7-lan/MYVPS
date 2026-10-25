import Foundation

public enum ExportClient: Sendable { case mihomo, shadowrocket, nodes }
public enum ExportSelection: String, Sendable, CaseIterable { case subscription, rules, vless, tuic }

extension ExportArtifact {
    public var client: ExportClient {
        let name = filename.lowercased()
        if name.hasSuffix(".yaml") || name.hasSuffix(".yml") { return .mihomo }
        if name.hasSuffix(".conf") { return .shadowrocket }
        return .nodes
    }
    public var defaultSelection: ExportSelection { client == .nodes ? .vless : .subscription }
    public var selections: [ExportSelection] {
        switch client {
        case .mihomo: [.subscription, .vless, .tuic]
        case .shadowrocket: [.subscription, .rules, .vless, .tuic]
        case .nodes: [.vless, .tuic] + (address(for: .subscription) == nil ? [] : [.subscription])
        }
    }
    public func label(for selection: ExportSelection) -> String {
        switch selection {
        case .vless: "VLESS · 常用"
        case .tuic: "TUIC5 · 迅速"
        case .rules: "Shadowrocket 规则"
        case .subscription:
            switch client { case .mihomo: "Clash 订阅"; case .shadowrocket: "Shadowrocket 订阅"; case .nodes: "节点订阅" }
        }
    }
    public var clientTitle: String {
        switch client { case .mihomo: "Clash / Mihomo 配置"; case .shadowrocket: "Shadowrocket 配置"; case .nodes: "节点链接" }
    }
    public func address(for selection: ExportSelection) -> String? {
        switch selection {
        case .vless: return nodes.first { $0.hasPrefix("vless://") }
        case .tuic: return nodes.first { $0.hasPrefix("tuic://") }
        case .rules: return client == .shadowrocket ? Self.formatLink(configURL, filename: "config.conf") : nil
        case .subscription:
            if client == .mihomo {
                // A Clash profile must contain full YAML configuration. Never substitute base64 node URIs.
                return Self.formatLink(subscriptionURL, filename: "config.yaml")
            }
            return Self.formatLink(subscriptionURL, filename: "nodes.txt") ?? Self.formatLink(nodesURL, filename: "nodes.txt")
        }
    }
    static func formatLink(_ link: String?, filename: String) -> String? {
        guard let link, let parts = URLComponents(string: link), parts.scheme == "https",
              parts.host != nil, parts.port == 9443, parts.user == nil, parts.password == nil,
              parts.fragment == nil, parts.path.split(separator: "/").last.map(String.init) == filename else { return nil }
        return link
    }
}
