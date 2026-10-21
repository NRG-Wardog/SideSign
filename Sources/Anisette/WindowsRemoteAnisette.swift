// Experimental, explicitly approved remote-only adaptation of AltStore PR #1835.
// No native Windows ADI is loaded or executed on this device.
import Foundation
import Crypto
import AnisetteKit

public enum WindowsAnisetteEndpoint: String, Sendable, Codable, CaseIterable {
    case jkcoxson = "https://ani.jkcoxson.com"
    case stikstore = "https://ani2.stikstore.app"
    public var url: URL { URL(string: rawValue)! }
}

public enum WindowsAnisetteError: LocalizedError, Sendable {
    case consentRequired, invalidProvider, invalidState, stateChanged, invalidResponse, resyncUnavailable
    case httpStatus(Int)
    public var reasonCode: String {
        switch self {
        case .consentRequired: return "consentRequired"
        case .invalidProvider: return "invalidProvider"
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
        case .consentRequired: return "Confirm this experimental remote sign-in attempt on your device first."
        case .invalidProvider: return "The selected provider did not advertise a Windows anisette identity."
        case .invalidState: return "The separate experimental provider identity is invalid. Existing anisette data was not changed."
        case .stateChanged: return "The experimental provider state changed during this attempt. Please start a new attempt."
        case .invalidResponse: return "The experimental provider returned an invalid response."
        case .resyncUnavailable: return "Apple's anisette resynchronization could not be completed."
        case .httpStatus(let code): return "The experimental anisette request returned HTTP \(code)."
        }
    }
}

public enum WindowsAnisetteAuthentication {
    @TaskLocal public static var current: WindowsAnisetteAuthenticationContext?
}

/// Ephemeral authority for one explicitly approved operation. Never persisted.
public final class WindowsAnisetteAuthenticationContext: @unchecked Sendable {
    public let endpoint: WindowsAnisetteEndpoint?
    public let session: URLSession
    private let fetcher: @Sendable (String?) async throws -> AnisetteData
    private let lock = NSLock()
    private let canceller: @Sendable () -> Void
    private var invalidated = false
    private var didResynchronize = false
    public init(endpoint: WindowsAnisetteEndpoint? = nil, canceller: @escaping @Sendable () -> Void = {}, fetcher: @escaping @Sendable (String?) async throws -> AnisetteData) {
        self.endpoint = endpoint
        self.fetcher = fetcher
        self.canceller = canceller
        self.session = WindowsAnisetteTransport.makeSession()
    }
    deinit { session.invalidateAndCancel() }
    public func invalidate() {
        let shouldCancel = lock.withLock {
            guard !invalidated else { return false }
            invalidated = true
            return true
        }
        if shouldCancel { session.invalidateAndCancel(); canceller() }
    }
    private func requireActive() throws {
        guard lock.withLock({ !invalidated }) else { throw WindowsAnisetteError.consentRequired }
        try Task.checkCancellation()
    }
    public func fetch() async throws -> AnisetteData {
        try requireActive()
        let data = try await fetcher(nil)
        try requireActive()
        return data
    }
    public func resynchronize(sim: String) async throws -> AnisetteData {
        guard !sim.isEmpty, sim.utf8.count <= 1_048_576 else { throw WindowsAnisetteError.resyncUnavailable }
        let allowed = lock.withLock {
            guard !invalidated, !didResynchronize else { return false }
            didResynchronize = true
            return true
        }
        guard allowed else { throw WindowsAnisetteError.resyncUnavailable }
        try requireActive()
        let data = try await fetcher(sim)
        try requireActive()
        return data
    }
}

private final class WindowsAnisetteTransport: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    private static let delegate = WindowsAnisetteTransport()
    static func makeSession() -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.timeoutIntervalForRequest = 30
        configuration.timeoutIntervalForResource = 60
        return URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
    }
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
                    completionHandler: @escaping @Sendable (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

public struct WindowsAnisetteProfile: Sendable, Equatable, Codable {
    public let endpoint: WindowsAnisetteEndpoint
    public let clientInfo: String
    public let userAgent: String
    public var storageKey: String {
        let scope = Data((endpoint.rawValue + "\n" + clientInfo + "\n" + userAgent).utf8)
        return "windowsAnisettePR1835_" + SHA256.hash(data: scope).map { String(format: "%02x", $0) }.joined()
    }
}

/// Atomic provider-specific record. The opaque adi_pb wire string is not a native ADI blob.
public struct WindowsAnisetteState: Codable, Equatable, Sendable {
    public let profile: WindowsAnisetteProfile
    public let identity: Data
    public var adiPB: String?
    public init(profile: WindowsAnisetteProfile) {
        self.profile = profile
        self.identity = Data((0..<16).map { _ in UInt8.random(in: .min ... .max) })
        self.adiPB = nil
    }
    public func validated(for profile: WindowsAnisetteProfile) throws {
        guard self.profile == profile, identity.count == 16,
              adiPB.map({ !$0.isEmpty && $0.utf8.count <= 8_388_608 }) ?? true else {
            throw WindowsAnisetteError.invalidState
        }
    }
    func headerRequestBody(adiPB: String, sim: String?) throws -> [String: String] {
        try validated(for: profile)
        guard !adiPB.isEmpty else { throw WindowsAnisetteError.invalidState }
        var body = ["identifier": identifier, "adi_pb": adiPB]
        if let sim {
            guard !sim.isEmpty else { throw WindowsAnisetteError.resyncUnavailable }
            body["sim"] = sim; body["device_id"] = deviceID.uuidString; body["md_lu"] = localUserID
        }
        return body
    }

    public var identifier: String { identity.base64EncodedString() }
    public var localUserID: String { SHA256.hash(data: identity).map { String(format: "%02X", $0) }.joined() }
    public var deviceID: UUID {
        // Only called after validated; avoid alignment-dependent UUID loads.
        var bytes: uuid_t = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        _ = withUnsafeMutableBytes(of: &bytes) { identity.copyBytes(to: $0) }
        return UUID(uuid: bytes)
    }
}

/// Uses the existing AnisetteKit provisioning seam, but never its local providers.
public actor WindowsRemoteAnisetteClient {
    public let endpoint: WindowsAnisetteEndpoint
    private nonisolated let session = WindowsAnisetteTransport.makeSession()
    public init(endpoint: WindowsAnisetteEndpoint) { self.endpoint = endpoint }
    deinit { session.invalidateAndCancel() }
    public nonisolated func invalidate() { session.invalidateAndCancel() }

    public func fetchProfile() async throws -> WindowsAnisetteProfile {
        try Task.checkCancellation()
        let request = URLRequest(url: endpoint.url.appendingPathComponent("v3/client_info"))
        let data = try await requestData(request)
        struct Response: Decodable { let client_info: String; let user_agent: String }
        let response: Response
        do { response = try JSONDecoder().decode(Response.self, from: data) }
        catch { throw WindowsAnisetteError.invalidProvider }
        guard response.client_info.contains("<Windows;"),
              !response.user_agent.isEmpty,
              response.client_info.utf8.count <= 4096, response.user_agent.utf8.count <= 4096,
              !response.client_info.contains("\r"), !response.client_info.contains("\n"),
              !response.user_agent.contains("\r"), !response.user_agent.contains("\n") else {
            throw WindowsAnisetteError.invalidProvider
        }
        return WindowsAnisetteProfile(endpoint: endpoint, clientInfo: response.client_info, userAgent: response.user_agent)
    }

    public func fetch(state: WindowsAnisetteState, sim: String? = nil) async throws -> (AnisetteData, WindowsAnisetteState) {
        try Task.checkCancellation()
        guard state.profile.endpoint == endpoint else { throw WindowsAnisetteError.invalidState }
        try state.validated(for: state.profile)
        guard sim == nil || state.adiPB != nil else { throw WindowsAnisetteError.resyncUnavailable }
        let provider = WindowsV3AnisetteProvider(endpoint: endpoint, session: session, state: state, sim: sim)
        // Isolated temporary routing-info files only; existing local provisioning is never read.
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("windows-anisette-" + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let headers = AnisetteRequestHeaders().with {
            $0.clientInfo = state.profile.clientInfo
            $0.userAgent = state.profile.userAgent
            $0.deviceID = state.deviceID.uuidString
            $0.localUserID = state.localUserID
            $0.serialNumber = "C02LKHBBFD57"
            $0.locale = Locale.current.identifier
            $0.timeZone = AnisetteKit.safeTimeZoneAbbreviation(for: .current)
        }
        let client = try AnisetteClient(provisioningDir: directory,
            clientInfo: state.profile.clientInfo, userAgent: state.profile.userAgent,
            provider: provider, requestSession: session,
            provisioningURLValidator: Self.permitsAppleProvisioningURL,
            provisioningHeaderPolicy: .windowsV3)
        let (rawHeaders, freshBlob) = try await withTaskCancellationHandler {
            try await client.getAnisetteData(identifier: state.deviceID,
                storage: .memory(existingBlob: state.adiPB.map { Data($0.utf8) }), headers: headers)
        } onCancel: {
            provider.cancel()
        }
        var result = try AnisetteDataManager.validateAndCreateAnisetteData(from: rawHeaders)
        guard let routingInfo = provider.routingInfo else { throw WindowsAnisetteError.invalidResponse }
        result.routingInfo = routingInfo
        var updated = state
        if let freshBlob {
            guard let text = String(data: freshBlob, encoding: .utf8), !text.isEmpty else { throw WindowsAnisetteError.invalidResponse }
            updated.adiPB = text
        }
        try Task.checkCancellation()
        return (result, updated)
    }

    // Fail closed if Apple's lookup bag moves. These exact destinations have source evidence;
    // do not authorize arbitrary apple.com subdomains or redirects.
    public nonisolated static func permitsAppleProvisioningURL(_ url: URL, step: String) -> Bool {
        let destinations = [
            "Lookup": "https://gsa.apple.com/grandslam/GsService2/lookup",
            "fetchSpim": "https://gsa.apple.com/grandslam/MidService/startMachineProvisioning",
            "fetchPtmTk": "https://gsa.apple.com/grandslam/MidService/finishMachineProvisioning"
        ]
        return destinations[step] == url.absoluteString
    }

    private func requestData(_ request: URLRequest) async throws -> Data {
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw WindowsAnisetteError.httpStatus((response as? HTTPURLResponse)?.statusCode ?? -1)
        }
        guard data.count <= 1_048_576 else { throw WindowsAnisetteError.invalidResponse }
        return data
    }
}

private final class WindowsV3AnisetteProvider: AnisetteDataProvider, @unchecked Sendable {
    var requiresLocalLibraries: Bool { false }
    let endpoint: WindowsAnisetteEndpoint
    let session: URLSession
    let state: WindowsAnisetteState
    let sim: String?
    private let lock = NSLock()
    private var socket: URLSessionWebSocketTask?
    private var lastRoutingInfo: String?
    var routingInfo: String? { lock.withLock { lastRoutingInfo } }
    init(endpoint: WindowsAnisetteEndpoint, session: URLSession, state: WindowsAnisetteState, sim: String?) {
        self.endpoint = endpoint; self.session = session; self.state = state; self.sim = sim
    }
    deinit { socket?.cancel(with: .normalClosure, reason: nil) }
    func cancel() {
        let task = lock.withLock { let current = socket; socket = nil; return current }
        task?.cancel(with: .goingAway, reason: nil)
    }

    func getAnisetteHeaders(libDir: String, provisioningDir: String, identifier: [UInt8], adiPb: [UInt8]) async throws -> AnisetteDataResponse {
        guard Data(identifier) == state.identity,
              let blob = String(bytes: adiPb, encoding: .utf8), !blob.isEmpty else { throw WindowsAnisetteError.invalidState }
        let body = try state.headerRequestBody(adiPB: blob, sim: sim)
        var request = URLRequest(url: endpoint.url.appendingPathComponent("v3/get_headers"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw WindowsAnisetteError.httpStatus((response as? HTTPURLResponse)?.statusCode ?? -1)
        }
        guard data.count <= 1_048_576,
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: String],
              json["result"] != "GetHeadersError",
              let mid = json["X-Apple-I-MD-M"], !mid.isEmpty,
              let otp = json["X-Apple-I-MD"], !otp.isEmpty,
              let rinfo = json["X-Apple-I-MD-RINFO"], UInt64(rinfo) != nil else {
            throw WindowsAnisetteError.invalidResponse
        }
        lock.withLock { lastRoutingInfo = rinfo }
        return AnisetteDataResponse(oneTimePassword: otp, machineID: mid)
    }

    func startProvision(libDir: String, provisioningDir: String, identifier: [UInt8], spim: [UInt8]) async throws -> (cpim: Data, session: UInt32) {
        guard Data(identifier) == state.identity, sim == nil else { throw WindowsAnisetteError.invalidState }
        var components = URLComponents(url: endpoint.url.appendingPathComponent("v3/provisioning_session"), resolvingAgainstBaseURL: false)!
        components.scheme = "wss"
        let task = session.webSocketTask(with: components.url!)
        task.maximumMessageSize = 8_388_608
        lock.withLock { socket = task }
        task.resume()
        do {
            // Reject repeated/out-of-order prompts rather than loop or reveal arbitrary data.
            let first = try await receive(task)
            guard first["result"] == "GiveIdentifier" else { throw WindowsAnisetteError.invalidResponse }
            try await send(["identifier": state.identifier], to: task)
            let start = try await receive(task)
            guard start["result"] == "GiveStartProvisioningData" else { throw WindowsAnisetteError.invalidResponse }
            try await send(["spim": Data(spim).base64EncodedString()], to: task)
            let end = try await receive(task)
            guard end["result"] == "GiveEndProvisioningData", let cpimString = end["cpim"],
                  let cpim = Data(base64Encoded: cpimString), !cpim.isEmpty else { throw WindowsAnisetteError.invalidResponse }
            return (cpim, 1)
        } catch {
            task.cancel(with: .normalClosure, reason: nil)
            lock.withLock { socket = nil }
            throw error
        }
    }

    func endProvision(libDir: String, provisioningDir: String, identifier: [UInt8], session sessionID: UInt32, ptm: [UInt8], tk: [UInt8]) async throws -> Data {
        guard sessionID == 1, Data(identifier) == state.identity,
              let task = lock.withLock({ socket }) else {
            throw WindowsAnisetteError.invalidState
        }
        defer {
            task.cancel(with: .normalClosure, reason: nil)
            lock.withLock { if socket === task { socket = nil } }
        }
        try await send(["ptm": Data(ptm).base64EncodedString(), "tk": Data(tk).base64EncodedString()], to: task)
        let response = try await receive(task)
        guard response["result"] == "ProvisioningSuccess", let blob = response["adi_pb"], !blob.isEmpty else {
            throw WindowsAnisetteError.invalidResponse
        }
        return Data(blob.utf8)
    }

    private func send(_ dictionary: [String: String], to task: URLSessionWebSocketTask) async throws {
        try Task.checkCancellation()
        let data = try JSONSerialization.data(withJSONObject: dictionary)
        try await task.send(.string(String(decoding: data, as: UTF8.self)))
    }
    private func receive(_ task: URLSessionWebSocketTask) async throws -> [String: String] {
        try Task.checkCancellation()
        let message = try await task.receive()
        guard case .string(let text) = message, let data = text.data(using: .utf8),
              let dictionary = try? JSONSerialization.jsonObject(with: data) as? [String: String] else {
            throw WindowsAnisetteError.invalidResponse
        }
        return dictionary
    }
}
