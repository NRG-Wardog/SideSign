// Explicit, opt-in v3 reserve. Historical .remote/.localODA/.remoteODA are unchanged.
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Crypto
import AnisetteKit

public enum RemoteReserveError: Error, LocalizedError, Sendable, Equatable {
    case invalidOrigin, invalidInput, invalidDescriptor, descriptorChanged
    case invalidResponse, responseTooLarge, unexpectedStep, redirectRefused, timedOut
    case httpStatus(Int)

    public var errorDescription: String? {
        switch self {
        case .invalidOrigin: return "The reserve server must be a plain HTTPS origin."
        case .invalidInput: return "The reserve identity or provisioning data is invalid."
        case .invalidDescriptor: return "The reserve server did not provide a valid v3 client descriptor."
        case .descriptorChanged: return "The reserve server's client descriptor changed. Choose another reserve server or return to on-device Anisette."
        case .invalidResponse: return "The reserve server returned an invalid v3 response."
        case .responseTooLarge: return "The reserve response exceeded its size limit."
        case .unexpectedStep: return "The reserve provisioning sequence was rejected."
        case .redirectRefused: return "A reserve request attempted a redirect."
        case .timedOut: return "The reserve request timed out."
        case .httpStatus(let status): return "The reserve request failed with HTTP status \(status)."
        }
    }
}

/// Persist this alongside the reserve origin, generation, UUID and blob. A changed
/// descriptor is rejected before sending identity material, even at the same host.
public struct RemoteReserveDescriptor: Codable, Hashable, Sendable {
    public let origin: String
    public let protocolVersion: Int
    public let clientInfo: String
    public let userAgent: String
}

struct RemoteReserveOrigin: Sendable {
    let url: URL
    init(_ input: URL) throws {
        guard var c = URLComponents(url: input, resolvingAgainstBaseURL: false),
              c.scheme?.lowercased() == "https", let host = c.host, !host.isEmpty,
              host.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || [45, 46, 58, 91, 93].contains($0) }), !host.hasSuffix("."),
              c.user == nil, c.password == nil, c.query == nil, c.fragment == nil,
              c.percentEncodedPath.isEmpty || c.percentEncodedPath == "/",
              c.port == nil || (1...65535).contains(c.port!) else {
            throw RemoteReserveError.invalidOrigin
        }
        c.scheme = "https"
        c.host = host.lowercased()
        if c.port == 443 { c.port = nil }
        c.path = ""
        guard let url = c.url else { throw RemoteReserveError.invalidOrigin }
        self.url = url
    }
    func endpoint(_ path: String) -> URL { url.appendingPathComponent("v3").appendingPathComponent(path) }
    var webSocketURL: URL {
        var c = URLComponents(url: endpoint("provisioning_session"), resolvingAgainstBaseURL: false)!
        c.scheme = "wss"
        return c.url!
    }
}

public extension AnisetteDataManager {
    static func normalizedRemoteReserveOrigin(_ server: URL) throws -> URL {
        try RemoteReserveOrigin(server).url
    }

    /// Calling this API is the explicit reserve opt-in. It never changes activeMode,
    /// falls back, rotates servers, re-provisions an existing blob, or uses a cache.
    /// Caller owns consent and atomic generation/descriptor-bound persistence.
    func fetchRemoteReserveAnisetteData(
        server: URL, identifier: UUID, existingAdiBlob: Data?, profileGeneration: UUID,
        expectedDescriptor: RemoteReserveDescriptor? = nil
    ) async throws -> (data: AnisetteData, newAdiBlob: Data?, descriptor: RemoteReserveDescriptor) {
        try await fetchRemoteReserveAnisetteData(server: server, identifier: identifier,
            existingAdiBlob: existingAdiBlob, profileGeneration: profileGeneration,
            expectedDescriptor: expectedDescriptor, transport: RemoteReserveNetworkTransport())
    }
}

extension AnisetteDataManager {
    // Internal test seam: no mock can be selected by a production setting.
    func fetchRemoteReserveAnisetteData(
        server: URL, identifier: UUID, existingAdiBlob: Data?, profileGeneration: UUID,
        expectedDescriptor: RemoteReserveDescriptor?, transport: any RemoteReserveTransport
    ) async throws -> (data: AnisetteData, newAdiBlob: Data?, descriptor: RemoteReserveDescriptor) {
        try Task.checkCancellation()
        if let blob = existingAdiBlob {
            guard !blob.isEmpty, blob.count <= RemoteReserveValidation.maximumBlobBytes,
                  expectedDescriptor != nil else { throw RemoteReserveError.invalidInput }
        }
        let origin = try RemoteReserveOrigin(server)
        let descriptorSpan = LoginDiagnosticTrace.current?.begin(.remoteDescriptor)
        let descriptor: RemoteReserveDescriptor
        do {
            let bytes = try await transport.data(for: RemoteReserveValidation.request(origin.endpoint("client_info")),
                maximumBytes: 16_384)
            let object = try RemoteReserveValidation.json(bytes.data, maximumBytes: 16_384)
            guard let clientInfo = object["client_info"], let userAgent = object["user_agent"],
                  RemoteReserveValidation.header(clientInfo, maximum: 1024),
                  clientInfo.hasPrefix("<"), clientInfo.hasSuffix(">"),
                  RemoteReserveValidation.header(userAgent, maximum: 512) else {
                throw RemoteReserveError.invalidDescriptor
            }
            descriptor = RemoteReserveDescriptor(origin: origin.url.absoluteString,
                protocolVersion: 3, clientInfo: clientInfo, userAgent: userAgent)
            if let expectedDescriptor, expectedDescriptor != descriptor {
                throw RemoteReserveError.descriptorChanged
            }
            try Task.checkCancellation()
            descriptorSpan?.finish(.succeeded)
        } catch {
            descriptorSpan?.finish(.failed, reason: error is CancellationError ? .cancelled : .rejected, error: error)
            throw error
        }
        let identifierBytes = withUnsafeBytes(of: identifier.uuid) { Data($0) }
        let provider = RemoteReserveV3Provider(origin: origin, identifier: identifierBytes, transport: transport)
        defer { provider.cancelProvisioning(session: 1) }
        var headers = AnisetteRequestHeaders()
        headers.clientInfo = descriptor.clientInfo
        headers.userAgent = descriptor.userAgent
        headers.localUserID = SHA256.hash(data: identifierBytes).map { String(format: "%02x", $0) }.joined()
        headers.deviceID = identifier.uuidString.uppercased()
        headers.serialNumber = "0"
        headers.locale = "en_US"
        headers.timeZone = "UTC"
        // No caller-provided/local custom headers are accepted. A generation-specific
        // placeholder is never accessed: .ephemeral returns before filesystem work.
        let client = try AnisetteClient(
            provisioningDir: URL(fileURLWithPath: "/remote-reserve-unused/\(profileGeneration.uuidString)"),
            clientInfo: descriptor.clientInfo, userAgent: descriptor.userAgent,
            provider: provider, requestTransport: { request in
                try RemoteReserveValidation.validateAppleRequest(request)
                let result = try await transport.data(for: request, maximumBytes: RemoteReserveValidation.maximumResponseBytes)
                return (result.data, result.response)
            })
        let result = try await client.getAnisetteData(identifier: identifier,
            storage: .ephemeral(existingBlob: existingAdiBlob), headers: headers)
        try Task.checkCancellation()
        let data = try Self.validateAndCreateAnisetteData(from: result.headers)
        return (data, result.newBlob, descriptor)
    }
}

// Reviewed protocol reference (format only; its insecure TLS/retry behavior is NOT used):
// https://github.com/SideStore/apple-private-apis/blob/master/omnisette/src/remote_anisette_v3.rs
// identifier is base64 of the 16 UUID bytes, not the historical provider's hex text.
final class RemoteReserveV3Provider: AnisetteDataProvider, @unchecked Sendable {
    var requiresLocalLibraries: Bool { false }
    private let origin: RemoteReserveOrigin
    private let identifier: Data
    private let transport: any RemoteReserveTransport
    private let lock = NSLock()
    private var socket: (any RemoteReserveWebSocket)?

    init(origin: RemoteReserveOrigin, identifier: Data, transport: any RemoteReserveTransport) {
        self.origin = origin; self.identifier = identifier; self.transport = transport
    }
    private func validate(_ bytes: [UInt8]) throws {
        try Task.checkCancellation()
        guard identifier.count == 16, Data(bytes) == identifier else { throw RemoteReserveError.invalidInput }
    }
    func cancelProvisioning(session: UInt32) {
        let owned = lock.withLock { let value = socket; socket = nil; return value }
        owned?.cancel()
    }
    func getAnisetteHeaders(libDir: String, provisioningDir: String, identifier: [UInt8], adiPb: [UInt8]) async throws -> AnisetteDataResponse {
        try validate(identifier)
        guard !adiPb.isEmpty, adiPb.count <= RemoteReserveValidation.maximumBlobBytes else { throw RemoteReserveError.invalidInput }
        let request = try RemoteReserveValidation.jsonRequest(origin.endpoint("get_headers"), [
            "identifier": self.identifier.base64EncodedString(), "adi_pb": Data(adiPb).base64EncodedString()])
        let bytes = try await transport.data(for: request, maximumBytes: 65_536)
        let object = try RemoteReserveValidation.json(bytes.data, maximumBytes: 65_536)
        guard object["result"] == "Headers",
              let otp = object[AnisetteConstants.Headers.oneTimePassword],
              let mid = object[AnisetteConstants.Headers.machineID],
              let routing = object[AnisetteConstants.Headers.routingInfo],
              RemoteReserveValidation.header(otp, maximum: 16_384),
              RemoteReserveValidation.header(mid, maximum: 16_384),
              !routing.isEmpty, routing.count <= 20, routing.utf8.allSatisfy({ (48...57).contains($0) }),
              UInt64(routing) != nil else { throw RemoteReserveError.invalidResponse }
        try Task.checkCancellation()
        return AnisetteDataResponse(oneTimePassword: otp, machineID: mid, routingInfo: routing)
    }
    func startProvision(libDir: String, provisioningDir: String, identifier: [UInt8], spim: [UInt8]) async throws -> (cpim: Data, session: UInt32) {
        try validate(identifier)
        guard !spim.isEmpty, spim.count <= RemoteReserveValidation.maximumBlobBytes else { throw RemoteReserveError.invalidInput }
        let connection = try transport.openWebSocket(at: origin.webSocketURL)
        let stored = lock.withLock { () -> Bool in
            guard socket == nil else { return false }
            socket = connection
            return true
        }
        guard stored else { connection.cancel(); throw RemoteReserveError.unexpectedStep }
        do {
            // Finite state machine: each request appears exactly once, in order.
            _ = try await receive("GiveIdentifier", from: connection)
            try await connection.send(RemoteReserveValidation.encode(["identifier": self.identifier.base64EncodedString()]))
            _ = try await receive("GiveStartProvisioningData", from: connection)
            try await connection.send(RemoteReserveValidation.encode(["spim": Data(spim).base64EncodedString()]))
            let end = try await receive("GiveEndProvisioningData", from: connection)
            let cpim = try RemoteReserveValidation.blob(end["cpim"])
            try Task.checkCancellation()
            return (cpim, 1)
        } catch {
            cancelProvisioning(session: 1)
            throw error
        }
    }
    func endProvision(libDir: String, provisioningDir: String, identifier: [UInt8], session: UInt32, ptm: [UInt8], tk: [UInt8]) async throws -> Data {
        try validate(identifier)
        guard session == 1, !ptm.isEmpty, !tk.isEmpty,
              ptm.count <= RemoteReserveValidation.maximumBlobBytes, tk.count <= RemoteReserveValidation.maximumBlobBytes,
              let connection = lock.withLock({ let value = socket; socket = nil; return value }) else {
            throw RemoteReserveError.invalidInput
        }
        defer { connection.cancel() }
        try await connection.send(RemoteReserveValidation.encode(["ptm": Data(ptm).base64EncodedString(), "tk": Data(tk).base64EncodedString()]))
        let response = try await receive("ProvisioningSuccess", from: connection)
        let blob = try RemoteReserveValidation.blob(response["adi_pb"])
        try Task.checkCancellation()
        return blob
    }
    private func receive(_ expected: String, from connection: any RemoteReserveWebSocket) async throws -> [String: String] {
        try Task.checkCancellation()
        let message = try await connection.receive()
        let object = try RemoteReserveValidation.json(message, maximumBytes: RemoteReserveValidation.maximumResponseBytes)
        guard object["result"] == expected else { throw RemoteReserveError.unexpectedStep }
        return object
    }
}

enum RemoteReserveValidation {
    static let maximumBlobBytes = 1_048_576
    static let maximumResponseBytes = 3_000_000
    static func header(_ value: String, maximum: Int) -> Bool {
        !value.isEmpty && value.utf8.count <= maximum && value.utf8.allSatisfy { (32...126).contains($0) }
            && !value.trimmingCharacters(in: .whitespaces).isEmpty
    }
    static func blob(_ value: String?) throws -> Data {
        guard let value, value.utf8.count <= ((maximumBlobBytes + 2) / 3) * 4,
              let bytes = Data(base64Encoded: value), !bytes.isEmpty, bytes.count <= maximumBlobBytes,
              bytes.base64EncodedString() == value else { throw RemoteReserveError.invalidResponse }
        return bytes
    }
    static func json(_ data: Data, maximumBytes: Int) throws -> [String: String] {
        guard !data.isEmpty, data.count <= maximumBytes else { throw RemoteReserveError.responseTooLarge }
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: String],
              object.count <= 16 else { throw RemoteReserveError.invalidResponse }
        return object
    }
    static func encode(_ object: [String: String]) throws -> Data { try JSONSerialization.data(withJSONObject: object) }
    static func request(_ url: URL) -> URLRequest {
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 30)
        request.httpMethod = "GET"
        request.httpShouldHandleCookies = false
        return request
    }
    static func jsonRequest(_ url: URL, _ object: [String: String]) throws -> URLRequest {
        var request = request(url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try encode(object)
        return request
    }
    static func validateAppleRequest(_ request: URLRequest) throws {
        // The authenticated Apple lookup may return URLs, but may not widen this
        // explicit origin policy. Validation happens BEFORE request transmission.
        guard let url = request.url, let c = URLComponents(url: url, resolvingAgainstBaseURL: false),
              c.scheme == "https", c.host?.lowercased() == "gsa.apple.com",
              c.port == nil || c.port == 443, c.user == nil, c.password == nil,
              c.query == nil, c.fragment == nil, c.path.hasPrefix("/grandslam/") else {
            throw RemoteReserveError.invalidOrigin
        }
        guard (request.httpBody?.count ?? 0) <= maximumResponseBytes else { throw RemoteReserveError.invalidInput }
        guard request.allHTTPHeaderFields?.allSatisfy({ header($0.key, maximum: 128) && header($0.value, maximum: 16_384) }) ?? true else {
            throw RemoteReserveError.invalidInput
        }
    }
}
