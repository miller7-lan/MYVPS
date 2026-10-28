import Foundation
import Testing
@testable import DazzleApp

@Test @MainActor func fixedConnectionOverridesSavedPreferencesAndRemainsFixed() throws {
    let name = "fixed-connection-" + UUID().uuidString
    let defaults = try #require(UserDefaults(suiteName: name))
    defer { defaults.removePersistentDomain(forName: name) }
    defaults.set("old.example.invalid", forKey: "sshHost")
    defaults.set("/old/key", forKey: "sshKeyPath")
    let profile = try #require(FixedConnectionProfile(configuration: ["Host":"fixed.example.invalid", "IdentityFile":"/external/key"]))
    let store = AppStore(defaults: defaults, fixedConnection: profile)
    #expect(store.sshHost == "fixed.example.invalid")
    #expect(store.sshKeyPath == "/external/key")
    store.sshHost = "different.example.invalid"
    store.sshKeyPath = "/different/key"
    #expect(store.sshHost == profile.host)
    #expect(store.sshKeyPath == profile.identityFile)
}

@Test @MainActor func ordinaryBuildRetainsEditableConnectionPreferences() throws {
    let name = "editable-connection-" + UUID().uuidString
    let defaults = try #require(UserDefaults(suiteName: name))
    defer { defaults.removePersistentDomain(forName: name) }
    defaults.set("saved.example.invalid", forKey: "sshHost")
    defaults.set("/saved/key", forKey: "sshKeyPath")
    let store = AppStore(defaults: defaults, fixedConnection: nil)
    #expect(store.sshHost == "saved.example.invalid")
    store.sshHost = "new.example.invalid"
    #expect(store.sshHost == "new.example.invalid")
}

@Test func fixedConnectionValidatesBuildMetadata() {
    #expect(FixedConnectionProfile(configuration: nil) == nil)
    #expect(FixedConnectionProfile(configuration: ["Host":" ", "IdentityFile":"/key"]) == nil)
    #expect(FixedConnectionProfile(configuration: ["Host":"host.example.invalid", "IdentityFile":"relative-key"]) == nil)
    let profile = FixedConnectionProfile(configuration: ["Host":" host.example.invalid\n", "IdentityFile":" /external/key "])
    #expect(profile?.host == "host.example.invalid")
    #expect(profile?.identityFile == "/external/key")
}
