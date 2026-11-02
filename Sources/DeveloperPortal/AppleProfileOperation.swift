import Foundation

/// Finite failures only. Never contains response bodies, account identifiers or profiles.
public enum AppleProfileEvidenceError: String, Error, Sendable {
    case unavailable, invalidResponse, responseTooLarge, identityMismatch, ambiguousProfile, recordNotFound
    case cancelled, expiredOperation, ownershipChanged
}

/// Exact bytes returned by this operation's private Apple-origin transport.
/// This is not a general signer endorsement, CMS verification or a persistable credential.
public final class AppleProfileEvidence: Sendable {
    public enum Role: Sendable { case existing, candidate }
    public let profile: ProvisioningProfile
    public var cmsData: Data { profile.data }
    public var uuid: UUID { profile.uuid }
    public let role: Role
    fileprivate let operationID: UUID
    fileprivate init(profile: ProvisioningProfile, role: Role, operationID: UUID) {
        self.profile = profile; self.role = role; self.operationID = operationID
    }
}

public extension DeveloperPortal {
    func makePreservationProfileOperation(team: Team, session: Session, bundleIdentifier: String,
        validateOwnership: @escaping @Sendable () throws -> Void) throws -> AppleProfileOperation {
        try AppleProfileOperation(team: team, session: session, bundleIdentifier: bundleIdentifier, headers: customHeaders,
                                  validateOwnership: validateOwnership)
    }
}

/// One short-lived refresh operation. No URLSession, URL, trust root or raw response injection.
public final class AppleProfileOperation: @unchecked Sendable {
    private let id = UUID()
    private let team: Team
    private let session: Session
    private let bundleIdentifier: String
    private var activeTransport: AppleProfileTransport?
    private let headers: SideSignHeaders
    private let validateOwnership: @Sendable () throws -> Void
    private let deadline = ProcessInfo.processInfo.systemUptime + 180
    private let lock = NSLock()
    private var invalidated = false
    private var busy = false
    fileprivate init(team: Team, session: Session, bundleIdentifier: String, headers: SideSignHeaders,
                     validateOwnership: @escaping @Sendable () throws -> Void) throws {
        guard !bundleIdentifier.isEmpty, bundleIdentifier.utf8.count <= 512, bundleIdentifier.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 || $0 == 46 }), !team.identifier.isEmpty, !session.dsid.isEmpty, !session.authToken.isEmpty else {
            throw AppleProfileEvidenceError.identityMismatch
        }
        self.team = team; self.session = session; self.headers = headers; self.bundleIdentifier = bundleIdentifier
        self.validateOwnership = validateOwnership
        try check()
    }
    public func invalidate() {
        let transport = lock.withLock { invalidated = true; return activeTransport }
        transport?.cancel()
    }
    deinit { activeTransport?.cancel() }
    private func check() throws {
        guard !Task.isCancelled else { throw AppleProfileEvidenceError.cancelled }
        guard lock.withLock({ !invalidated }), ProcessInfo.processInfo.systemUptime < deadline,
              session.isValid else { throw AppleProfileEvidenceError.expiredOperation }
        do { try validateOwnership() } catch { throw AppleProfileEvidenceError.ownershipChanged }
        guard !Task.isCancelled, lock.withLock({ !invalidated }),
              ProcessInfo.processInfo.systemUptime < deadline else { throw AppleProfileEvidenceError.cancelled }
    }
    private func begin() throws {
        try check()
        try lock.withLock {
            guard !busy else { throw AppleProfileEvidenceError.unavailable }
            busy = true
        }
    }
    public func authorize(_ evidence: AppleProfileEvidence, exactCMS: Data) throws {
        try check()
        guard evidence.operationID == id, evidence.profile.bundleIdentifier == bundleIdentifier, !exactCMS.isEmpty,
              evidence.profile.data == exactCMS else { throw AppleProfileEvidenceError.identityMismatch }
    }
    /// Read-only: list existing profiles, then download precisely one listed portal ID.
    /// Never calls the team-profile generation endpoint, including on failure.
    public func corroborateExisting(installedCMS: Data, uuid: UUID,
                                    bundleIdentifier: String) async throws -> AppleProfileEvidence {
        try begin(); defer { lock.withLock { busy = false } }
        guard bundleIdentifier == self.bundleIdentifier else { throw AppleProfileEvidenceError.identityMismatch }
        guard !installedCMS.isEmpty, installedCMS.count <= 1024 * 1024 else { throw AppleProfileEvidenceError.responseTooLarge }
        let listed: ListedProfileResponse = try await request(.list, parameters: ["includeTeamProfiles": true])
        try check()
        guard let profiles = listed.provisioningProfiles, profiles.count <= 512 else { throw AppleProfileEvidenceError.invalidResponse }
        let matches = profiles.filter { $0.uuid == uuid }
        guard !matches.isEmpty else { throw AppleProfileEvidenceError.recordNotFound }
        guard matches.count == 1, let match = matches.first else { throw AppleProfileEvidenceError.ambiguousProfile }
        guard let portalID = match.identifier, Self.validID(portalID), match.bundleIdentifier == bundleIdentifier,
              profiles.filter({ $0.identifier == portalID }).count == 1 else { throw AppleProfileEvidenceError.identityMismatch }
        let response: ProfileResponse = try await request(.existing, parameters: ["provisioningProfileId": portalID])
        try check()
        let profile = try Self.parseProfile(response, expectedID: portalID, expectedUUID: uuid,
                                            bundleIdentifier: bundleIdentifier, teamID: team.identifier)
        guard profile.data == installedCMS else { throw AppleProfileEvidenceError.identityMismatch }
        try check()
        return AppleProfileEvidence(profile: profile, role: .existing, operationID: id)
    }
    /// Explicit owner-authorized normal refresh only. This endpoint may generate a profile.
    /// Its new evidence covers only its own returned CMS; existing evidence is never reused.
    public func generateCandidate(for appID: AppID, deviceType: DeviceType = .iPhone) async throws -> AppleProfileEvidence {
        try begin(); defer { lock.withLock { busy = false } }
        guard Self.validID(appID.identifier), appID.bundleIdentifier == bundleIdentifier else {
            throw AppleProfileEvidenceError.identityMismatch
        }
        var parameters: [String: any Sendable] = ["appIdId": appID.identifier]
        if deviceType.contains(.appleTV) { parameters["subPlatform"] = "tvOS" }
        else if deviceType.contains(.mac) { parameters["subPlatform"] = "macOS" }
        else if deviceType.contains(.visionPro) { parameters["subPlatform"] = "visionOS" }
        let response: ProfileResponse = try await request(.candidate, parameters: parameters)
        try check()
        let profile = try Self.parseProfile(response, expectedID: nil, expectedUUID: nil,
                                            bundleIdentifier: appID.bundleIdentifier, teamID: team.identifier)
        try check()
        return AppleProfileEvidence(profile: profile, role: .candidate, operationID: id)
    }
    private static func validID(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 256 && value.utf8.allSatisfy { (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 }
    }
    // Internal pure parser is testable but cannot mint an evidence capability.
    static func parseProfile(_ response: ProfileResponse, expectedID: String?, expectedUUID: UUID?,
                             bundleIdentifier: String, teamID: String) throws -> ProvisioningProfile {
        guard response.resultCode == 0, let details = response.provisioningProfile,
              !details.encodedProfile.isEmpty, details.encodedProfile.count <= 1024 * 1024 else {
            throw AppleProfileEvidenceError.invalidResponse
        }
        // Envelope metadata is optional in the existing provider schema. Its
        // absence cannot replace mandatory embedded identity/byte checks below.
        if let identifier = details.provisioningProfileId {
            guard validID(identifier), expectedID == nil || expectedID == identifier else {
                throw AppleProfileEvidenceError.identityMismatch
            }
        }
        let envelopeUUID: UUID?
        if let text = details.uuid {
            guard let parsed = UUID(uuidString: text) else { throw AppleProfileEvidenceError.invalidResponse }
            envelopeUUID = parsed
        } else { envelopeUUID = nil }
        do {
            let profile = try details.toProvisioningProfile()
            guard (envelopeUUID == nil || profile.uuid == envelopeUUID),
                  (expectedUUID == nil || profile.uuid == expectedUUID),
                  profile.bundleIdentifier == bundleIdentifier,
                  profile.teamIdentifier == teamID else { throw AppleProfileEvidenceError.identityMismatch }
            let dictionary = try profile.propertyList()
            guard let teams = dictionary["TeamIdentifier"] as? [String], teams == [teamID] else {
                throw AppleProfileEvidenceError.identityMismatch
            }
            return profile
        } catch let error as AppleProfileEvidenceError { throw error }
        catch { throw AppleProfileEvidenceError.invalidResponse }
    }
    private enum Endpoint: String {
        case list = "listProvisioningProfiles.action"
        case existing = "downloadProvisioningProfile.action"
        case candidate = "downloadTeamProvisioningProfile.action"
    }
    private func request<T: Decodable>(_ endpoint: Endpoint, parameters: [String: any Sendable]) async throws -> T {
        try check()
        var components = URLComponents(string: "https://developerservices2.apple.com/services/QH65B2/ios/" + endpoint.rawValue)!
        components.queryItems = [URLQueryItem(name: "clientId", value: Constants.DeveloperServices.clientID)]
        let url = components.url!
        var fields: [String: any Sendable] = ["clientId": Constants.DeveloperServices.clientID,
            "protocolVersion": "QH65B2", "requestId": UUID().uuidString.uppercased(), "teamId": team.identifier]
        parameters.forEach { fields[$0] = $1 }
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 30)
        request.httpMethod = "POST"
        do { request.httpBody = try PropertyListSerialization.data(fromPropertyList: fields, format: .xml, options: 0) }
        catch { throw AppleProfileEvidenceError.invalidResponse }
        let a = session.anisetteData
        let values = ["Content-Type": "text/x-xml-plist", "Accept": "text/x-xml-plist", "Accept-Language": "en-us",
            "Cache-Control": "no-store", "Pragma": "no-cache",
            "User-Agent": headers.developerServices.userAgent, "X-Apple-App-Info": headers.grandSlam.authApp,
            "X-Xcode-Version": session.xcodeVersion, "X-Apple-I-Identity-Id": session.dsid,
            "X-Apple-GS-Token": session.authToken, "X-Apple-I-MD-M": a.machineID, "X-Apple-I-MD": a.oneTimePassword,
            "X-Apple-I-MD-LU": a.localUserID, "X-Apple-I-MD-RINFO": a.routingInfo, "X-Mme-Device-Id": a.deviceID,
            "X-MMe-Client-Info": a.clientInfo, "X-Apple-I-Client-Time": a.clientTime,
            "X-Apple-Locale": a.locale, "X-Apple-I-Locale": a.locale, "X-Apple-I-TimeZone": a.timeZone]
        values.forEach { request.setValue($1, forHTTPHeaderField: $0) }
        let transport = AppleProfileTransport(url: url)
        lock.withLock { activeTransport = transport }
        defer { lock.withLock { activeTransport = nil } }
        try check()
        let data: Data
        do {
            data = try await withTaskCancellationHandler(operation: {
                try await withCheckedThrowingContinuation { transport.start(request, continuation: $0) }
            }, onCancel: { transport.cancel() })
        } catch {
            try check()
            throw (error as? AppleProfileEvidenceError) ?? .unavailable
        }
        try check()
        do {
            let status = try PropertyListDecoder().decode(DeveloperPortalStatusResponse.self, from: data)
            guard status.resultCode == 0, status.errors?.isEmpty != false else { throw AppleProfileEvidenceError.unavailable }
            return try PropertyListDecoder().decode(T.self, from: data)
        } catch let error as AppleProfileEvidenceError { throw error }
        catch { throw AppleProfileEvidenceError.invalidResponse }
    }
}

#if SIDESIGN_PROFILE_TRANSPORT_TESTING
// Native fixture compilation only; never part of a production SideSign build.
enum AppleProfileTransportTesting {
    nonisolated(unsafe) static var protocolClasses: [AnyClass] = []
}
#endif

/// Private production transport; no caller-provided sessions, protocols, redirects or trust delegates.
private final class AppleProfileTransport: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private let url: URL
    private let limit = 4 * 1024 * 1024
    private let lock = NSLock()
    private var buffer = Data()
    private var continuation: CheckedContinuation<Data, Error>?
    private var connection: URLSession?
    private var task: URLSessionDataTask?
    private var completed = false
    private var acceptedResponse = false
    init(url: URL) { self.url = url }
    func start(_ request: URLRequest, continuation: CheckedContinuation<Data, Error>) {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.urlCache = nil; configuration.httpCookieStorage = nil; configuration.urlCredentialStorage = nil
        configuration.httpShouldSetCookies = false; configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.protocolClasses = []
        #if SIDESIGN_PROFILE_TRANSPORT_TESTING
        configuration.protocolClasses = AppleProfileTransportTesting.protocolClasses
        #endif
        configuration.timeoutIntervalForRequest = 30; configuration.timeoutIntervalForResource = 45
        let queue = OperationQueue(); queue.maxConcurrentOperationCount = 1
        let connection = URLSession(configuration: configuration, delegate: self, delegateQueue: queue)
        let task = connection.dataTask(with: request)
        let accepted = lock.withLock { () -> Bool in
            guard !completed else { return false }
            self.continuation = continuation; self.connection = connection; self.task = task; return true
        }
        if accepted { task.resume() }
        else { connection.invalidateAndCancel(); continuation.resume(throwing: AppleProfileEvidenceError.cancelled) }
    }
    func cancel() { finish(.failure(AppleProfileEvidenceError.cancelled)) }
    private func finish(_ result: Result<Data, Error>) {
        let saved = lock.withLock { () -> (CheckedContinuation<Data, Error>?, URLSession?) in
            guard !completed else { return (nil, nil) }
            completed = true
            let saved = (continuation, connection)
            continuation = nil; connection = nil; task = nil; buffer.removeAll(keepingCapacity: false)
            return saved
        }
        saved.1?.invalidateAndCancel(); saved.0?.resume(with: result)
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping @Sendable (URLRequest?) -> Void) {
        completionHandler(nil); finish(.failure(AppleProfileEvidenceError.invalidResponse))
    }
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        // Platform TLS validation including the system/user trust store; not Apple-pinned attestation.
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust &&
           challenge.protectionSpace.host == "developerservices2.apple.com" &&
           challenge.protectionSpace.protocol == "https" && challenge.protectionSpace.port == 443 {
            completionHandler(.performDefaultHandling, nil)
        } else { completionHandler(.cancelAuthenticationChallenge, nil) }
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                    completionHandler: @escaping @Sendable (URLSession.ResponseDisposition) -> Void) {
        guard let response = response as? HTTPURLResponse, response.statusCode == 200,
              response.url == url, response.expectedContentLength >= -1, response.expectedContentLength <= Int64(limit) else {
            completionHandler(.cancel); finish(.failure(AppleProfileEvidenceError.invalidResponse)); return
        }
        lock.withLock { acceptedResponse = true }
        completionHandler(.allow)
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, willCacheResponse proposedResponse: CachedURLResponse,
                    completionHandler: @escaping @Sendable (CachedURLResponse?) -> Void) {
        completionHandler(nil)
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        let fits = lock.withLock { () -> Bool in
            guard !completed, acceptedResponse, data.count <= limit - buffer.count else { return false }
            buffer.append(data); return true
        }
        if !fits { finish(.failure(AppleProfileEvidenceError.responseTooLarge)) }
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        if error != nil { finish(.failure(AppleProfileEvidenceError.unavailable)); return }
        let data = lock.withLock { acceptedResponse ? buffer : Data() }
        guard !data.isEmpty else { finish(.failure(AppleProfileEvidenceError.invalidResponse)); return }
        finish(.success(data))
    }
}
