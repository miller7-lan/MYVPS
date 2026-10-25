import Foundation
import Testing
import DazzleModels

private let exportServerID = "840737d0-365c-4da4-a706-3b3ee86be1da"
private let linkBase = "https://8.8.8.8:9443/fixture-token/"
private func exportFixture(filename: String, subscription: String? = nil, nodesURL: String? = linkBase + "nodes.txt", configURL: String? = linkBase + "config.conf", nodes: [String]? = nil) throws -> ExportArtifact {
    var data: [String: JSONValue] = ["filename": .string(filename), "content": .string("private fixture"), "sensitive": .bool(true),
        "environment": .string("production"), "server_id": .string(exportServerID), "deployed": .bool(true),
        "nodes": .array((nodes ?? ["vless://fixture@8.8.8.8:24430?security=reality#VLESS", "tuic://fixture:fixture@8.8.8.8:24430?insecure=0#TUIC"]).map(JSONValue.string))]
    if let subscription { data["subscription_url"] = .string(subscription) }
    if let nodesURL { data["nodes_url"] = .string(nodesURL) }
    if let configURL { data["config_url"] = .string(configURL) }
    return try ExportArtifact(.object(data))
}

@Test func mihomoExportDefaultsToClashYAMLAndHidesShadowrocketRules() throws {
    let value = try exportFixture(filename: "Dazzle-VPS.yaml", subscription: linkBase + "config.yaml")
    try value.validateProduction(serverID: exportServerID)
    #expect(value.client == .mihomo)
    #expect(value.defaultSelection == .subscription)
    #expect(value.address(for: .subscription) == linkBase + "config.yaml")
    #expect(value.address(for: .subscription) != value.nodesURL)
    #expect(!value.selections.contains(.rules))
    #expect(value.address(for: .rules) == nil)
    #expect(value.label(for: .subscription) == "Clash 订阅")
}

@Test func missingOrWrongMihomoSubscriptionNeverFallsBackToNodeURIList() throws {
    let missing = try exportFixture(filename: "Dazzle-VPS.yaml")
    #expect(missing.nodesURL != nil)
    #expect(missing.defaultSelection == .subscription)
    #expect(missing.address(for: .subscription) == nil)
    let wrong = try exportFixture(filename: "Dazzle-VPS.yaml", subscription: linkBase + "nodes.txt")
    #expect(wrong.address(for: .subscription) == nil)
    #expect(throws: ModelError.self) { try wrong.validateProduction(serverID: exportServerID) }
}

@Test func shadowrocketExportKeepsDistinctNodeSubscriptionAndConfigurationRules() throws {
    let value = try exportFixture(filename: "Dazzle-VPS.conf", subscription: linkBase + "nodes.txt")
    try value.validateProduction(serverID: exportServerID)
    #expect(value.client == .shadowrocket)
    #expect(value.defaultSelection == .subscription)
    #expect(value.address(for: .subscription) == linkBase + "nodes.txt")
    #expect(value.address(for: .rules) == linkBase + "config.conf")
    #expect(value.selections.contains(.rules))
    #expect(value.label(for: .subscription) == "Shadowrocket 订阅")
    #expect(value.label(for: .rules) == "Shadowrocket 规则")
    let fallback = try exportFixture(filename: "Dazzle-VPS.conf")
    #expect(fallback.address(for: .subscription) == linkBase + "nodes.txt")
}

@Test func nodeURIExportDefaultsToVLESSAndDoesNotOfferShadowrocketRules() throws {
    let value = try exportFixture(filename: "Dazzle-VPS.txt", subscription: linkBase + "nodes.txt")
    try value.validateProduction(serverID: exportServerID)
    #expect(value.client == .nodes)
    #expect(value.defaultSelection == .vless)
    #expect(value.address(for: .vless)?.hasPrefix("vless://") == true)
    #expect(value.address(for: .tuic)?.hasPrefix("tuic://") == true)
    #expect(value.address(for: .subscription) == linkBase + "nodes.txt")
    #expect(value.address(for: .rules) == nil)
    #expect(!value.selections.contains(.rules))
}

@Test func exportRejectsCrossFormatPathsPlainHTTPAndDisabledCertificateVerification() throws {
    for url in [linkBase + "config.conf", linkBase + "nodes.txt", "http://8.8.8.8:9443/fixture-token/config.yaml", "https://8.8.8.8:8443/fixture-token/config.yaml"] {
        let value = try exportFixture(filename: "Dazzle-VPS.yaml", subscription: url)
        #expect(value.address(for: .subscription) == nil)
        #expect(throws: ModelError.self) { try value.validateProduction(serverID: exportServerID) }
    }
    let mismatch = try exportFixture(filename: "Dazzle-VPS.conf", subscription: linkBase + "config.yaml")
    #expect(throws: ModelError.self) { try mismatch.validateProduction(serverID: exportServerID) }
    for node in ["tuic://fixture:fixture@8.8.8.8:24430?insecure=1", "tuic://fixture:fixture@8.8.8.8:24430?insecure=1&insecure=0", "vless://fixture@8.8.8.8:24430?security=none", "vless://fixture@8.8.8.8:24430?security=reality&allowInsecure=true"] {
        let value = try exportFixture(filename: "Dazzle-VPS.txt", subscription: linkBase + "nodes.txt", nodes: [node])
        #expect(throws: ModelError.self) { try value.validateProduction(serverID: exportServerID) }
    }
}
