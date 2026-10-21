// Inert substitutes. No external provider, native or network execution.
enum DeveloperPortalError: Error { case invalidAnisetteData(cause: String) }
enum AnisetteError: Error { case modeNotConfigured, noServersConfigured, allServersFailed }
enum FixtureError: Error { case rejected }
func debugLog(_ value: String) {}
protocol FakeProvider: Sendable {}
struct RemoteAnisetteDataProvider: FakeProvider {}
struct UnicornAnisetteDataProvider: FakeProvider {}
struct NativeAnisetteDataProvider: FakeProvider {}
struct UnknownAnisetteDataProvider: FakeProvider {}
enum ProvisioningStorage { case memory(existingBlob: Data?) }
final class FixtureState: @unchecked Sendable {
    private let lock = NSLock()
    private var requests: [AnisetteRequestHeaders?] = []
    var failCalls: Set<Int> = []
    var cancelCalls: Set<Int> = []
    var setupFails = false
    var adapterOverride: String? = nil
    var outputOverride: String? = nil
    var blobOutput: Data? = nil
    var calls: Int { lock.withLock { requests.count } }
    var captured: [AnisetteRequestHeaders?] { lock.withLock { requests } }
    func capture(_ headers: AnisetteRequestHeaders?) throws {
        let disposition = lock.withLock { () -> Int in
            requests.append(headers)
            if cancelCalls.contains(requests.count) { return 2 }
            return failCalls.contains(requests.count) ? 1 : 0
        }
        if disposition == 2 { throw CancellationError() }
        if disposition == 1 { throw FixtureError.rejected }
    }
}
struct AnisetteClient {
    let provider: any FakeProvider
    let clientInfo: String
    let state: FixtureState
    func getAnisetteData(identifier: UUID, storage: ProvisioningStorage,
                         headers: AnisetteRequestHeaders?) async throws -> ([String: String], Data?) {
        try state.capture(headers)
        var output = Fixture.data().toRequestHeaders().applyingOverrides(headers)
        output.clientInfo = state.outputOverride ?? headers?.clientInfo ?? clientInfo
        return (AnisetteHeadersDTO.toDictionary(from: output), state.blobOutput)
    }
}
// Collector stand-in only. Actual epoch/history behavior has a separate suite.
final class AuthenticationDiagnosticTrace: @unchecked Sendable {
    @TaskLocal static var current: AuthenticationDiagnosticTrace?
    struct ProviderObservationToken: Sendable { fileprivate let owner: ObjectIdentifier; fileprivate let epoch: Int }
    private let lock = NSLock()
    private var epoch = 0
    private var observation: AuthenticationProviderObservation?
    func beginProviderObservation(_ value: AuthenticationProviderObservation) -> ProviderObservationToken {
        lock.withLock {
            epoch += 1; observation = value
            return ProviderObservationToken(owner: ObjectIdentifier(self), epoch: epoch)
        }
    }
    func setProviderObservation(_ value: AuthenticationProviderObservation, token: ProviderObservationToken) {
        lock.withLock {
            guard token.owner == ObjectIdentifier(self), token.epoch == epoch else { return }
            observation = value
        }
    }
    var providerObservation: AuthenticationProviderObservation? { lock.withLock { observation } }
}
