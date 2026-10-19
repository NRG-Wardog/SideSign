// Runs only against generated, byte-bound production source and inert ZIP data.
import Foundation

struct TestFailure: Error, CustomStringConvertible {
    let description: String
}
func check(_ condition: @autoclosure () -> Bool, _ message: String) throws {
    if !condition() { throw TestFailure(description: message) }
}

@main
enum LibraryIntegrityTests {
    static func assertPair(_ directory: URL, generation: String) throws {
        for name in Constants.Anisette.Libraries.requiredNames {
            let bytes = try Data(contentsOf: directory.appendingPathComponent(name))
            try check(bytes == Data("INERT SYNTHETIC \(generation) \(name)\n".utf8), "pair bytes: \(name)")
        }
    }

    static func assertNoTemporaryZIP() throws {
        let files = try Foundation.FileManager.default.contentsOfDirectory(
            atPath: Observations.shared.temporaryRoot.path)
        try check(files.isEmpty, "temporary ZIP not cleaned up")
    }

    static func matching(root: URL, digest: String?, label: String) async throws {
        let manager = DownloadFixture(root: root.appendingPathComponent(label))
        Observations.shared.reset()
        try await manager.downloadAndCacheLibs(from: ODAInfo(base64Payload: FixtureData.newBase64, sha256: digest))
        try assertPair(manager.remoteLibsDir, generation: "NEW")
        try check(!manager.fixtureIsCaching, "success reset")
        try check(manager.fixtureProvider != nil, "success installs provider boundary")
        try check(Observations.shared.extractionCalls == 1, "matching must extract")
        try check(Observations.shared.temporaryDirectoryReads == 1, "matching must stage ZIP")
        try check(Observations.shared.providerCalls == 1, "matching provider count")
        try check(Observations.shared.validationCalls == 1, "matching validation count")
        try check(Observations.shared.networkCalls == 0, "matching inline payload must not network")
        try assertNoTemporaryZIP()
        print("PASS: \(label)")
    }

    static func mismatching(root: URL, previousPair: Bool, malformedArchive: Bool = false,
                            malformedExpected: Bool = false) async throws {
        let label = "mismatch-\(previousPair ? "existing" : "empty")-\(malformedArchive ? "malformed" : "valid")-\(malformedExpected ? "bad-metadata" : "hex-metadata")"
        let manager = DownloadFixture(root: root.appendingPathComponent(label))
        if previousPair {
            try await manager.downloadAndCacheLibs(from: ODAInfo(base64Payload: FixtureData.oldBase64, sha256: FixtureData.oldSHA))
            try assertPair(manager.remoteLibsDir, generation: "OLD")
        }
        let previousProvider = manager.fixtureProvider
        let payload = malformedArchive ? FixtureData.invalidBase64 : FixtureData.newBase64
        let actual = malformedArchive ? FixtureData.invalidSHA : FixtureData.newSHA
        // Intentionally mixed-case: the thrown value must preserve metadata bytes.
        let expected = malformedExpected ? "not a SHA-256 digest" : "AbCd" + String(repeating: "0", count: 60)
        Observations.shared.reset()
        do {
            try await manager.downloadAndCacheLibs(from: ODAInfo(base64Payload: payload, sha256: expected))
            throw TestFailure(description: "mismatch unexpectedly succeeded")
        } catch AnisetteError.sha256Mismatch(let thrownExpected, let thrownActual) {
            try check(thrownExpected == expected, "expected digest was altered")
            try check(thrownActual == actual, "actual archive digest is wrong")
        }
        try check(!manager.fixtureIsCaching, "mismatch reset")
        try check(manager.fixtureProvider === previousProvider, "previous provider changed")
        try check(Observations.shared.directoryCreates == 2, "pre-verification directory creation remains")
        try check(Observations.shared.temporaryDirectoryReads == 0, "mismatch reached ZIP staging")
        try check(Observations.shared.extractionCalls == 0, "mismatch reached genuine extraction")
        try check(Observations.shared.providerCalls == 0, "mismatch constructed provider")
        try check(Observations.shared.validationCalls == 0, "mismatch reached post-extraction validation")
        try check(Observations.shared.networkCalls == 0, "mismatch inline payload used network")
        if previousPair {
            try assertPair(manager.remoteLibsDir, generation: "OLD")
        } else {
            let names = try Foundation.FileManager.default.contentsOfDirectory(atPath: manager.remoteLibsDir.path)
            try check(names.isEmpty, "mismatch wrote assets into empty cache")
        }
        try assertNoTemporaryZIP()
        // A real second invocation exercises the reset, rather than just reading it.
        Observations.shared.reset()
        try await manager.downloadAndCacheLibs(from: ODAInfo(base64Payload: FixtureData.newBase64, sha256: FixtureData.newSHA))
        try assertPair(manager.remoteLibsDir, generation: "NEW")
        try check(!manager.fixtureIsCaching && Observations.shared.providerCalls == 1, "retry after mismatch failed")
        try assertNoTemporaryZIP()
        print("PASS: \(label) and retry")
    }

    static func main() async throws {
        let root = Foundation.FileManager.default.temporaryDirectory
            .appendingPathComponent("sidesign-integrity-synthetic-" + UUID().uuidString)
        try Foundation.FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? Foundation.FileManager.default.removeItem(at: root) }
        Observations.shared.temporaryRoot = root.appendingPathComponent("temporary-zips")
        try Foundation.FileManager.default.createDirectory(at: Observations.shared.temporaryRoot, withIntermediateDirectories: true)
        try await matching(root: root, digest: FixtureData.newSHA, label: "matching-lowercase")
        try await matching(root: root, digest: FixtureData.newSHA.uppercased(), label: "matching-uppercase")
        try await matching(root: root, digest: nil, label: "absent-hash-compatibility")
        try await matching(root: root, digest: "", label: "empty-hash-compatibility")
        try await mismatching(root: root, previousPair: false)
        try await mismatching(root: root, previousPair: true)
        try await mismatching(root: root, previousPair: false, malformedArchive: true)
        try await mismatching(root: root, previousPair: true, malformedExpected: true)
        print("PASS: 8 genuine-source synthetic cases; no native provider or network")
    }
}
