// Offline parity boundary only. No Keychain/Security/account or lease execution.
// This suite supplies an empty installation store, so separate uncommitted
// manual attempts are fresh. The remote-identity-reuse suite executes the real
// protected store, account generation, registry and request leases.
struct LCEmbeddedAuthenticationSnapshot: Equatable, Sendable {
    let appleIDEmailAddress: String?
    let appleIDPassword: String?
    let appleIDAdsid: String?
    let appleIDXcodeToken: String?
    var hasTokenCredentials: Bool { false }
}
final class Keychain: @unchecked Sendable {
    static let shared = Keychain()
    func authenticationSnapshot() throws -> LCEmbeddedAuthenticationSnapshot? { nil }
    func remoteIdentityRecord() throws -> V3RemoteIdentityRecord? { nil }
    func remoteIdentityRouteBytes() throws -> Data? { nil }
    func remoteIdentityRouteMarker() throws -> V3RemoteRouteMarker? { nil }
    func commitRemoteIdentity(_ record: V3RemoteIdentityRecord, replacing old: V3RemoteIdentityRecord?,
                              credentials: LCEmbeddedAuthenticationSnapshot, expectedRoute: Data) throws {
        throw FixtureFailure.unscripted
    }
    func resetRemoteIdentity() throws { throw FixtureFailure.unscripted }
}
final class AuthManager: @unchecked Sendable {
    static let shared = AuthManager()
    let v3IdentityStamp = "synthetic-empty-store"
    let v3IdentityIsStable = true
    func v3BeginIdentityTransition() { preconditionFailure("Unexpected account transition in parity fixture") }
    func v3CompleteIdentityTransition() { preconditionFailure("Unexpected account transition in parity fixture") }
}
enum V3RemoteRequestLeases {
    static func registerManual(_ context: ILoaderRemoteAuthenticationContext, id: String) {}
    static func removeManual(_ id: String) {}
    static func invalidateManualAttempts() { preconditionFailure("Unexpected global revocation in parity fixture") }
}
