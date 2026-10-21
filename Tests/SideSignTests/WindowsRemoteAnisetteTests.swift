import XCTest
@testable import SideSign

private func fakeWindowsData() -> AnisetteData {
    AnisetteData(machineID: "fake-mid", oneTimePassword: "fake-otp", localUserID: "fake-lu",
                 routingInfo: "17106176", deviceID: "00010203-0405-0607-0809-0A0B0C0D0E0F",
                 serialNumber: "fake-serial", clientInfo: "<Windows;fake>", userAgent: "fake-agent",
                 clientTime: "2026-01-01T00:00:00Z", locale: "en_US", timeZone: "UTC")
}

private actor WindowsCalls {
    private var values: [String?] = []
    func record(_ sim: String?) -> AnisetteData { values.append(sim); return fakeWindowsData() }
    func count() -> Int { values.count }
}

@MainActor
final class WindowsRemoteAnisetteTests: XCTestCase {
    func testExactAllowedOriginsOnly() {
        XCTAssertNotNil(WindowsAnisetteEndpoint(rawValue: "https://ani.jkcoxson.com"))
        XCTAssertNotNil(WindowsAnisetteEndpoint(rawValue: "https://ani2.stikstore.app"))
        for value in ["http://ani.jkcoxson.com", "https://ani.jkcoxson.com/", "https://ani.jkcoxson.com.evil.invalid",
                      "https://user@ani.jkcoxson.com", "https://ani.jkcoxson.com?redirect=1"] {
            XCTAssertNil(WindowsAnisetteEndpoint(rawValue: value))
        }
    }

    func testProvisioningDestinationMatchesRoleExactly() {
        let roles = [
            "Lookup": "https://gsa.apple.com/grandslam/GsService2/lookup",
            "fetchSpim": "https://gsa.apple.com/grandslam/MidService/startMachineProvisioning",
            "fetchPtmTk": "https://gsa.apple.com/grandslam/MidService/finishMachineProvisioning"
        ]
        for (role, destination) in roles {
            XCTAssertTrue(WindowsRemoteAnisetteClient.permitsAppleProvisioningURL(URL(string: destination)!, step: role))
            for bad in [destination + "?x=1", destination + "#x", destination + "/", destination.replacingOccurrences(of: "https:", with: "http:"),
                        destination.replacingOccurrences(of: "gsa.apple.com", with: "gsa.apple.com.evil.invalid"),
                        destination.replacingOccurrences(of: "gsa.apple.com", with: "user@gsa.apple.com"),
                        destination.replacingOccurrences(of: "gsa.apple.com", with: "gsa.apple.com:443")] {
                XCTAssertFalse(WindowsRemoteAnisetteClient.permitsAppleProvisioningURL(URL(string: bad)!, step: role))
            }
            XCTAssertFalse(WindowsRemoteAnisetteClient.permitsAppleProvisioningURL(URL(string: destination)!, step: "unknown"))
            for (otherRole, otherURL) in roles where otherRole != role {
                XCTAssertFalse(WindowsRemoteAnisetteClient.permitsAppleProvisioningURL(URL(string: otherURL)!, step: role))
            }
        }
    }

    func testWireIdentityAndOpaqueBlobRoundTrip() throws {
        let profile = WindowsAnisetteProfile(endpoint: .jkcoxson, clientInfo: "<Windows;fake>", userAgent: "fake-agent")
        let fixture: [String: Any] = ["profile": ["endpoint": profile.endpoint.rawValue, "clientInfo": profile.clientInfo, "userAgent": profile.userAgent],
                                     "identity": "AAECAwQFBgcICQoLDA0ODw==", "adiPB": "ZmFrZS1ibG9i=="]
        let state = try JSONDecoder().decode(WindowsAnisetteState.self, from: JSONSerialization.data(withJSONObject: fixture))
        try state.validated(for: profile)
        XCTAssertEqual(state.identifier, "AAECAwQFBgcICQoLDA0ODw==")
        XCTAssertEqual(state.localUserID, "BE45CB2605BF36BEBDE684841A28F0FD43C69850A3DCE5FEDBA69928EE3A8991")
        XCTAssertEqual(state.deviceID.uuidString, "00010203-0405-0607-0809-0A0B0C0D0E0F")
        XCTAssertEqual(try JSONDecoder().decode(WindowsAnisetteState.self, from: JSONEncoder().encode(state)), state)
        XCTAssertEqual(state.adiPB, "ZmFrZS1ibG9i==")
        let normal = try state.headerRequestBody(adiPB: "ZmFrZS1ibG9i==", sim: nil)
        XCTAssertEqual(normal, ["identifier": "AAECAwQFBgcICQoLDA0ODw==", "adi_pb": "ZmFrZS1ibG9i=="])
        let resync = try state.headerRequestBody(adiPB: "ZmFrZS1ibG9i==", sim: "fake-sim")
        XCTAssertEqual(Set(resync.keys), Set(["identifier", "adi_pb", "sim", "device_id", "md_lu"]))
        XCTAssertEqual(resync["identifier"], normal["identifier"])
        XCTAssertEqual(resync["adi_pb"], normal["adi_pb"])
        XCTAssertEqual(resync["device_id"], state.deviceID.uuidString)
        XCTAssertEqual(resync["md_lu"], state.localUserID)
        XCTAssertThrowsError(try state.headerRequestBody(adiPB: "", sim: nil))
        XCTAssertThrowsError(try state.headerRequestBody(adiPB: "fake-blob", sim: ""))
        let other = WindowsAnisetteProfile(endpoint: .stikstore, clientInfo: profile.clientInfo, userAgent: profile.userAgent)
        XCTAssertThrowsError(try state.validated(for: other))
        XCTAssertNotEqual(profile.storageKey, other.storageKey)
        XCTAssertNotEqual(profile.storageKey, WindowsAnisetteProfile(endpoint: .jkcoxson, clientInfo: "<Windows;other>", userAgent: profile.userAgent).storageKey)
    }

    func testSingleResyncAndRevocationWithNoNetwork() async throws {
        let calls = WindowsCalls()
        let context = WindowsAnisetteAuthenticationContext { sim in await calls.record(sim) }
        _ = try await context.fetch()
        _ = try await context.resynchronize(sim: "fake-sim")
        do { _ = try await context.resynchronize(sim: "another-fake-sim"); XCTFail("Repeated resync was allowed") }
        catch WindowsAnisetteError.resyncUnavailable { }
        context.invalidate()
        do { _ = try await context.fetch(); XCTFail("Revoked attempt was allowed") }
        catch WindowsAnisetteError.consentRequired { }
        let count = await calls.count()
        XCTAssertEqual(count, 2)
        XCTAssertNil(WindowsAnisetteAuthentication.current)
    }

    func testEmptySIMDoesNotCallProvider() async throws {
        let calls = WindowsCalls()
        let context = WindowsAnisetteAuthenticationContext { sim in await calls.record(sim) }
        defer { context.invalidate() }
        do { _ = try await context.resynchronize(sim: ""); XCTFail("Empty SIM was allowed") }
        catch WindowsAnisetteError.resyncUnavailable { }
        let count = await calls.count()
        XCTAssertEqual(count, 0)
    }
}
