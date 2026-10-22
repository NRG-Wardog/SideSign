// Opt-in RemoteV3 adaptation of isideload 0.5.0 (fc7a81a6).
// This identity lives only for the approved attempt. No native ADI or persistent store is used.
import Foundation
import Crypto
import AnisetteKit

public enum ILoaderRemoteEndpoint: String, Sendable, CaseIterable {
    case macJkcoxson = "https://mac-ani.jkcoxson.com"
    public var url: URL { URL(string: rawValue)! }
}

public enum ILoaderRemoteError: LocalizedError, Sendable {
    case consentRequired, invalidProvider, providerProfileMismatch, invalidState, stateChanged, invalidResponse, resyncUnavailable
    case httpStatus(Int)
    public var reasonCode: String {
        switch self {
        case .consentRequired: return "consentRequired"
        case .invalidProvider: return "invalidProvider"
        case .providerProfileMismatch: return "providerProfileMismatch"
        case .invalidState: return "invalidState"
        case .stateChanged: return "stateChanged"
        case .invalidResponse: return "invalidResponse"
        case .resyncUnavailable: return "resyncUnavailable"
        case .httpStatus: return "httpStatus"
        }
    }
    public var httpStatusCode: Int? { if case .httpStatus(let code) = self { return code }; return nil }
    public var errorDescription: String? {
        switch self {
        case .consentRequired: return "This remote sign-in attempt is no longer active."
        case .invalidProvider: return "The selected provider returned invalid client metadata."
        case .providerProfileMismatch: return "The selected provider does not advertise the required Mac profile."
        case .invalidState: return "The temporary remote identity is invalid. Existing anisette data was not changed."
        case .stateChanged: return "The temporary remote identity changed during this attempt. Start a new attempt."
        case .invalidResponse: return "The remote sign-in service returned an invalid response."
        case .resyncUnavailable: return "Anisette resynchronization could not be completed for this attempt."
        case .httpStatus(let code): return "The remote sign-in request returned HTTP \(code)."
        }
    }
}

public enum ILoaderRemoteAuthentication {
    @TaskLocal public static var current: ILoaderRemoteAuthenticationContext?
}

/// One operation owns this revocable context; it never silently chooses another provider.
public final class ILoaderRemoteAuthenticationContext: @unchecked Sendable {
    public let endpoint: ILoaderRemoteEndpoint
    public let session: URLSession
    private let fetcher: @Sendable (String?) async throws -> AnisetteData
    private let canceller: @Sendable () -> Void
    private let now: @Sendable () -> Date
    private let lock = NSLock()
    private var invalidated = false
    private var didResynchronize = false
    private var fetching = false
    private var cached: (data: AnisetteData, time: Date)?
    public init(endpoint: ILoaderRemoteEndpoint = .macJkcoxson,
                canceller: @escaping @Sendable () -> Void = {},
                now: @escaping @Sendable () -> Date = { Date() },
                fetcher: @escaping @Sendable (String?) async throws -> AnisetteData) {
        self.endpoint = endpoint; self.canceller = canceller; self.fetcher = fetcher; self.now = now
        self.session = ILoaderRemoteTransport.makeSession()
    }
    deinit { session.invalidateAndCancel() }
    public func invalidate() {
        let cancel = lock.withLock { () -> Bool in
            guard !invalidated else { return false }
            invalidated = true; cached = nil; return true
        }
        if cancel { session.invalidateAndCancel(); canceller() }
    }
    public func fetch() async throws -> AnisetteData { try await acquire(sim: nil) }
    public func resynchronize(sim: String) async throws -> AnisetteData {
        guard !sim.isEmpty, sim.utf8.count <= 1_048_576 else { throw ILoaderRemoteError.resyncUnavailable }
        return try await acquire(sim: sim)
    }
    private func acquire(sim: String?) async throws -> AnisetteData {
        try Task.checkCancellation()
        let cache: (data: AnisetteData, age: TimeInterval)? = try lock.withLock {
            guard !invalidated else { throw ILoaderRemoteError.consentRequired }
            guard !fetching else { throw ILoaderRemoteError.stateChanged }
            if sim != nil {
                guard !didResynchronize else { throw ILoaderRemoteError.resyncUnavailable }
                didResynchronize = true
            } else if let cached {
                let age = now().timeIntervalSince(cached.time)
                // isideload uses elapsed.as_secs() > 60, so 60.x is still fresh. A clock reversal is not.
                if age >= 0 && age < 61 { return (cached.data, age) }
            }
            fetching = true
            return nil
        }
        if let cache {
            var data = cache.data
            data.markDiagnosticCacheHit(age: cache.age, requestedClientInfo: data.clientInfo)
            let context = data.diagnosticHeaderProvenance.context
            let observation = AuthenticationProviderObservation(mode: .remote, stage: .cacheHit,
                requestedClientInfoSource: .provider, requestedClientInfoFamily: .classify(data.clientInfo),
                adapter: .remote, librarySelection: .remote, libraryValidation: .notObserved,
                requestedBlobInput: context.generationBlobInput)
            _ = AuthenticationDiagnosticTrace.current?.beginProviderObservation(observation)
            try Task.checkCancellation()
            try lock.withLock { guard !invalidated else { throw ILoaderRemoteError.consentRequired } }
            return data
        }
        defer { lock.withLock { fetching = false } }
        let result = try await fetcher(sim)
        try Task.checkCancellation()
        try lock.withLock {
            guard !invalidated else { throw ILoaderRemoteError.consentRequired }
            cached = (result, now())
        }
        return result
    }
}

private final class ILoaderRemoteTransport: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    private static let delegate = ILoaderRemoteTransport()
    static func makeSession() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.urlCache = nil; config.httpCookieStorage = nil; config.httpShouldSetCookies = false
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.timeoutIntervalForRequest = 30; config.timeoutIntervalForResource = 60
        return URLSession(configuration: config, delegate: delegate, delegateQueue: nil)
    }
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
                    completionHandler: @escaping @Sendable (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

public struct ILoaderRemoteProfile: Sendable, Equatable {
    public let endpoint: ILoaderRemoteEndpoint
    public let clientInfo: String
    public let userAgent: String
}

public struct ILoaderRemoteState: Sendable, Equatable {
    public let profile: ILoaderRemoteProfile
    public let identity: Data
    /// Canonical base64 wire representation, not a local native ADI blob.
    public var adiPB: String?
    public init(profile: ILoaderRemoteProfile) {
        self.profile = profile
        self.identity = Data((0..<16).map { _ in UInt8.random(in: .min ... .max) })
        self.adiPB = nil
    }
    // Owned synthetic fixture initializer; production identity still comes from secure platform RNG.
    init(profile: ILoaderRemoteProfile, identity: Data, adiPB: String?) {
        self.profile = profile; self.identity = identity; self.adiPB = adiPB
    }
    public func validated(for profile: ILoaderRemoteProfile) throws {
        guard self.profile == profile, identity.count == 16 else { throw ILoaderRemoteError.invalidState }
        if let adiPB { _ = try Self.validatedBlob(adiPB) }
    }
    static func validatedBlob(_ value: String) throws -> String {
        guard !value.isEmpty, value.utf8.count <= 8_388_608,
              let decoded = Data(base64Encoded: value), !decoded.isEmpty else { throw ILoaderRemoteError.invalidState }
        return decoded.base64EncodedString()
    }
    public var identifier: String { identity.base64EncodedString() }
    public var localUserID: String { SHA256.hash(data: identity).map { String(format: "%02x", $0) }.joined() }
    public var deviceID: String {
        guard identity.count == 16 else { return "" }
        var bytes: uuid_t = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        _ = withUnsafeMutableBytes(of: &bytes) { identity.copyBytes(to: $0) }
        return UUID(uuid: bytes).uuidString.lowercased()
    }
    func headerRequestBody(sim: String?) throws -> [String: String] {
        try validated(for: profile)
        guard let adiPB else { throw ILoaderRemoteError.invalidState }
        var body = ["identifier": identifier, "adi_pb": try Self.validatedBlob(adiPB)]
        if let sim {
            guard !sim.isEmpty, sim.utf8.count <= 1_048_576 else { throw ILoaderRemoteError.resyncUnavailable }
            body["sim"] = sim; body["device_id"] = deviceID; body["md_lu"] = localUserID
        }
        return body
    }
}

/// Direct scoped RemoteV3 implementation. No AnisetteKit/native provisioner is constructed.
public actor ILoaderRemoteAnisetteClient {
    public let endpoint: ILoaderRemoteEndpoint
    private nonisolated let session = ILoaderRemoteTransport.makeSession()
    private nonisolated let acquisitionTimeoutNanoseconds: UInt64
    public init(endpoint: ILoaderRemoteEndpoint = .macJkcoxson, acquisitionTimeoutNanoseconds: UInt64 = 60_000_000_000) {
        self.endpoint = endpoint
        self.acquisitionTimeoutNanoseconds = min(acquisitionTimeoutNanoseconds, 60_000_000_000)
    }
    deinit { session.invalidateAndCancel() }
    public nonisolated func invalidate() { session.invalidateAndCancel() }

    public func fetchProfile() async throws -> ILoaderRemoteProfile {
        try Task.checkCancellation()
        _ = AuthenticationDiagnosticTrace.current?.beginProviderObservation(.selectedBranch(onDevice: false))
        let data = try await requestData(URLRequest(url: endpoint.url.appendingPathComponent("v3/client_info")))
        return try Self.decodeProfile(data, endpoint: endpoint)
    }
    nonisolated static func decodeProfile(_ data: Data, endpoint: ILoaderRemoteEndpoint) throws -> ILoaderRemoteProfile {
        struct Response: Decodable { let client_info: String; let user_agent: String }
        guard data.count <= 1_048_576, let value = try? JSONDecoder().decode(Response.self, from: data),
              ILoaderAuthenticationPolicy.validHeader(value.client_info),
              ILoaderAuthenticationPolicy.validHeader(value.user_agent) else { throw ILoaderRemoteError.invalidProvider }
        let lower = value.client_info.lowercased()
        guard (lower.contains("<mac os x;") || lower.contains("<macos;")),
              lower.contains("com.apple.akd/"), !lower.contains("<windows;") else {
            throw ILoaderRemoteError.providerProfileMismatch
        }
        return ILoaderRemoteProfile(endpoint: endpoint, clientInfo: value.client_info, userAgent: value.user_agent)
    }
    public func fetch(state: ILoaderRemoteState, sim: String? = nil) async throws -> (AnisetteData, ILoaderRemoteState) {
        let deadline = ILoaderRemoteDeadline()
        do {
            let result = try await withTaskCancellationHandler {
                try await withThrowingTaskGroup(of: (AnisetteData, ILoaderRemoteState).self) { group in
                    group.addTask { try await self.fetchValue(state: state, sim: sim) }
                    group.addTask {
                        try await Task.sleep(nanoseconds: self.acquisitionTimeoutNanoseconds)
                        deadline.expire()
                        // Cancellation explicitly reaches both HTTP and an upgraded WebSocket.
                        self.invalidate()
                        throw URLError(.timedOut)
                    }
                    defer { group.cancelAll() }
                    guard let result = try await group.next() else { throw ILoaderRemoteError.invalidResponse }
                    return result
                }
            } onCancel: { self.invalidate() }
            try Task.checkCancellation()
            guard !deadline.expired else { throw URLError(.timedOut) }
            return result
        } catch {
            if deadline.expired && !Task.isCancelled { throw URLError(.timedOut) }
            throw error
        }
    }
    private func fetchValue(state: ILoaderRemoteState, sim: String?) async throws -> (AnisetteData, ILoaderRemoteState) {
        try Task.checkCancellation()
        guard state.profile.endpoint == endpoint else { throw ILoaderRemoteError.invalidState }
        try state.validated(for: state.profile)
        guard sim == nil || state.adiPB != nil else { throw ILoaderRemoteError.resyncUnavailable }
        // Official RemoteV3 reads client_info for each acquisition. Fail closed on a changed profile.
        let profile = try await fetchProfile()
        guard profile == state.profile else { throw ILoaderRemoteError.stateChanged }
        let observation = AuthenticationProviderObservation(mode: .remote,
            requestedClientInfoSource: .provider, requestedClientInfoFamily: .classify(profile.clientInfo),
            requestedBlobInput: state.adiPB == nil ? .absent : .present)
        let trace = AuthenticationDiagnosticTrace.current
        let token = trace?.beginProviderObservation(observation)
        if let token { trace?.setProviderObservation(observation.observing(.clientReady,
            adapter: .remote, library: .remote, validation: .notObserved), token: token) }
        var updated = state
        if updated.adiPB == nil {
            updated.adiPB = try await withILoaderDiagnosticStage(.provisioning) { try await provision(state: state) }
        } else { LoginDiagnosticTrace.current?.skip(.provisioning, reason: .cached) }
        var request = URLRequest(url: endpoint.url.appendingPathComponent("v3/get_headers"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: updated.headerRequestBody(sim: sim))
        let response = try Self.decodeHeaders(try await requestData(request))
        var data = AnisetteData(machineID: response.mid, oneTimePassword: response.otp,
            localUserID: state.localUserID, routingInfo: response.routing, deviceID: state.deviceID,
            serialNumber: "0", clientInfo: profile.clientInfo, userAgent: profile.userAgent,
            clientTime: ISO8601DateFormatter().string(from: Date()), locale: "en_US", timeZone: "UTC")
        data.recordDiagnosticHeaderProvenance(source: .provider, provider: .remote,
            context: AuthenticationAnisetteContext(cache: .generated,
                requestedClientInfoFamily: .classify(profile.clientInfo),
                generationBlobInput: state.adiPB == nil ? .absent : .present,
                generationBlobOutput: state.adiPB == nil ? .generated : .notGenerated,
                adapter: .remote, librarySelection: .remote, libraryValidation: .notObserved,
                clientInfoPreservation: .matched, historicalBlobAssociation: .notRecorded))
        if let token { trace?.setProviderObservation(observation.observing(.dataReady,
            adapter: .remote, library: .remote, validation: .notObserved), token: token) }
        try Task.checkCancellation()
        return (data, updated)
    }
    nonisolated static func decodeHeaders(_ data: Data) throws -> (mid: String, otp: String, routing: String) {
        guard data.count <= 1_048_576,
              let value = try? JSONSerialization.jsonObject(with: data) as? [String: String],
              value["result"] == "Headers",
              let mid = value["X-Apple-I-MD-M"], ILoaderAuthenticationPolicy.validHeader(mid),
              let otp = value["X-Apple-I-MD"], ILoaderAuthenticationPolicy.validHeader(otp),
              let routing = value["X-Apple-I-MD-RINFO"], UInt64(routing) != nil else {
            // Deliberately do not erase/reprovision state on provider -45061 or retry -80045.
            throw ILoaderRemoteError.invalidResponse
        }
        return (mid, otp, routing)
    }
    private func provision(state: ILoaderRemoteState) async throws -> String {
        let lookup = try Self.makeAppleRequest(role: "lookup", profile: state.profile, state: nil)
        let lookupData = try await withILoaderDiagnosticStage(.appleLookup) { try await requestData(lookup) }
        try Self.validateLookup(lookupData)
        var components = URLComponents(url: endpoint.url.appendingPathComponent("v3/provisioning_session"), resolvingAgainstBaseURL: false)!
        components.scheme = "wss"
        let socket = session.webSocketTask(with: components.url!)
        socket.maximumMessageSize = 8_388_608
        socket.resume()
        defer { socket.cancel(with: .normalClosure, reason: nil) }
        return try await withTaskCancellationHandler {
            let first = try await Self.receive(socket)
            guard first["result"] == "GiveIdentifier" else { throw ILoaderRemoteError.invalidResponse }
            try await Self.send(["identifier": state.identifier], to: socket)
            let start = try await Self.receive(socket)
            guard start["result"] == "GiveStartProvisioningData" else { throw ILoaderRemoteError.invalidResponse }
            let startRequest = try Self.makeAppleRequest(role: "start", profile: state.profile, state: state)
            let startData = try await withILoaderDiagnosticStage(.appleSPIM) { try await requestData(startRequest) }
            let spim = try Self.plistResponse(startData)["spim"] as? String
            guard let spim, !spim.isEmpty else { throw ILoaderRemoteError.invalidResponse }
            try await Self.send(["spim": spim], to: socket)
            let finish = try await Self.receive(socket)
            guard finish["result"] == "GiveEndProvisioningData", let cpim = finish["cpim"], !cpim.isEmpty else { throw ILoaderRemoteError.invalidResponse }
            let finishRequest = try Self.makeAppleRequest(role: "finish", profile: state.profile, state: state, cpim: cpim)
            let finishData = try await withILoaderDiagnosticStage(.appleFinish) { try await requestData(finishRequest) }
            let completed = try Self.plistResponse(finishData)
            guard let ptm = completed["ptm"] as? String, !ptm.isEmpty,
                  let tk = completed["tk"] as? String, !tk.isEmpty else { throw ILoaderRemoteError.invalidResponse }
            try await Self.send(["ptm": ptm, "tk": tk], to: socket)
            let result = try await Self.receive(socket)
            guard result["result"] == "ProvisioningSuccess", let adiPB = result["adi_pb"] else { throw ILoaderRemoteError.invalidResponse }
            return try ILoaderRemoteState.validatedBlob(adiPB)
        } onCancel: { socket.cancel(with: .goingAway, reason: nil) }
    }
    nonisolated static func makeAppleRequest(role: String, profile: ILoaderRemoteProfile,
                                             state: ILoaderRemoteState?, cpim: String? = nil) throws -> URLRequest {
        let urls = ILoaderAuthenticationPolicy.provisioningURLs
        guard let value = urls[role], let url = URL(string: value) else { throw ILoaderRemoteError.invalidResponse }
        var request = URLRequest(url: url)
        request.httpMethod = role == "lookup" ? "GET" : "POST"
        var headers = ILoaderAuthenticationPolicy.baseHeaders(clientInfo: profile.clientInfo, userAgent: profile.userAgent)
        if role == "lookup" { headers["X-Mme-Client-Info"] = ILoaderAuthenticationPolicy.lookupClientInfo }
        else {
            guard let state else { throw ILoaderRemoteError.invalidState }
            try state.validated(for: profile)
            headers["X-Apple-I-MD-LU"] = state.localUserID
            headers["X-Mme-Device-Id"] = state.deviceID
            var payload: [String: Any] = [:]
            if role == "finish" {
                guard let cpim, !cpim.isEmpty else { throw ILoaderRemoteError.invalidResponse }
                payload["cpim"] = cpim
            }
            request.httpBody = try PropertyListSerialization.data(fromPropertyList: ["Header": [:], "Request": payload], format: .xml, options: 0)
        }
        for (key, value) in headers { request.setValue(value, forHTTPHeaderField: key) }
        return request
    }
    nonisolated static func validateLookup(_ data: Data) throws {
        guard let root = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let urls = root["urls"] as? [String: Any],
              urls["midStartProvisioning"] as? String == ILoaderAuthenticationPolicy.provisioningURLs["start"],
              urls["midFinishProvisioning"] as? String == ILoaderAuthenticationPolicy.provisioningURLs["finish"] else {
            throw ILoaderRemoteError.invalidResponse
        }
        // Fixed approved GSA/2FA URLs only, rather than trusting arbitrary lookup destinations.
        guard urls["gsService"] as? String == Constants.URLs.grandSlamAuth.absoluteString,
              urls["trustedDeviceSecondaryAuth"] as? String == Constants.URLs.trustedDevice.absoluteString,
              urls["validateCode"] as? String == Constants.URLs.grandSlamValidate.absoluteString else {
            throw ILoaderRemoteError.invalidResponse
        }
    }
    nonisolated static func plistResponse(_ data: Data) throws -> [String: Any] {
        guard let root = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let response = root["Response"] as? [String: Any] else { throw ILoaderRemoteError.invalidResponse }
        return response
    }
    private func requestData(_ request: URLRequest) async throws -> Data {
        try Task.checkCancellation()
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw ILoaderRemoteError.httpStatus((response as? HTTPURLResponse)?.statusCode ?? -1)
        }
        guard data.count <= 1_048_576 else { throw ILoaderRemoteError.invalidResponse }
        return data
    }
    private nonisolated static func send(_ dictionary: [String: String], to socket: URLSessionWebSocketTask) async throws {
        try Task.checkCancellation()
        let data = try JSONSerialization.data(withJSONObject: dictionary)
        try await socket.send(.string(String(decoding: data, as: UTF8.self)))
    }
    private nonisolated static func receive(_ socket: URLSessionWebSocketTask) async throws -> [String: String] {
        try Task.checkCancellation()
        let deadline = ILoaderRemoteDeadline()
        let message: URLSessionWebSocketTask.Message
        do {
            message = try await withThrowingTaskGroup(of: URLSessionWebSocketTask.Message.self) { group in
                group.addTask { try await socket.receive() }
                group.addTask {
                    try await Task.sleep(nanoseconds: 30_000_000_000)
                    deadline.expire()
                    socket.cancel(with: .goingAway, reason: nil)
                    throw URLError(.timedOut)
                }
                defer { group.cancelAll() }
                guard let result = try await group.next() else { throw ILoaderRemoteError.invalidResponse }
                return result
            }
        } catch {
            if deadline.expired && !Task.isCancelled { throw URLError(.timedOut) }
            throw error
        }
        try Task.checkCancellation()
        guard !deadline.expired else { throw URLError(.timedOut) }
        guard case .string(let text) = message, let data = text.data(using: .utf8),
              let value = try? JSONSerialization.jsonObject(with: data) as? [String: String] else { throw ILoaderRemoteError.invalidResponse }
        return value
    }
}

private func withILoaderDiagnosticStage<T>(_ stage: LoginDiagnosticStage, isolation: isolated (any Actor)? = #isolation, operation: () async throws -> T) async rethrows -> T {
    let span = LoginDiagnosticTrace.current?.begin(stage)
    do {
        let result = try await operation()
        span?.finish(.succeeded)
        return result
    } catch {
        span?.finish(.failed, reason: error is CancellationError ? .cancelled : .unavailable, error: error)
        throw error
    }
}

private final class ILoaderRemoteDeadline: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false
    var expired: Bool { lock.withLock { value } }
    func expire() { lock.withLock { value = true } }
}
