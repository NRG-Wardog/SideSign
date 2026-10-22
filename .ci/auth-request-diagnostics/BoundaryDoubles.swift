import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

// No Foundation.URLSession, provider, native loader or real credentials are executed.
enum FixtureFailure: Error { case assertion(String), unscripted, account }
func expect(_ condition: @autoclosure () throws -> Bool, _ message: String) throws {
    guard try condition() else { throw FixtureFailure.assertion(message) }
}
func plist(_ value: [String: any Sendable], format: PropertyListSerialization.PropertyListFormat = .xml) throws -> Data {
    try PropertyListSerialization.data(fromPropertyList: value, format: format, options: 0)
}
func exactValue(_ value: Any) -> String {
    if let n = value as? NSNumber { return "number:\(String(cString: n.objCType)):\(n.stringValue)" }
    if let s = value as? String { return "string:\(s.utf8.count):\(s)" }
    if let d = value as? Data { return "data:\(d.base64EncodedString())" }
    if let d = value as? Date { return "date:\(d.timeIntervalSince1970)" }
    if let d = value as? [String: Any] { return "dict:" + d.keys.sorted().map { "\($0.utf8.count):\($0)=\(exactValue(d[$0]!))" }.joined(separator: "|") }
    if let a = value as? [Any] { return "array:" + a.map(exactValue).joined(separator: "|") }
    return "other:\(String(reflecting: type(of: value)))"
}
func prettyJSONString(from object: Any) -> String { exactValue(object) }
func typedError(_ error: Error) -> String {
    let e = error as NSError
    return "\(String(reflecting: type(of: error))):\(e.domain):\(e.code):\(String(describing: error)):\(error.localizedDescription)"
}
extension Data { func hexEncodedString() -> String { map { String(format: "%02x", $0) }.joined() } }
extension HTTPURLResponse { var safeStatusCode: Int { statusCode } }

actor SyntheticLatch {
    private var open = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    func wait() async { if open { return }; await withCheckedContinuation { waiters.append($0) } }
    func signal() { open = true; let pending = waiters; waiters = []; for waiter in pending { waiter.resume() } }
}
struct Step: @unchecked Sendable {
    var body: Data
    var status = 200
    var mime: String? = "text/x-xml-plist"
    var finalURL: URL? = nil
    var headers: [String: String] = [:]
    var nonHTTP = false
    var error: Error? = nil
    var entered: SyntheticLatch? = nil
    var release: SyntheticLatch? = nil
    var onResponse: (@Sendable () -> Void)? = nil
    var delayNanoseconds: UInt64? = nil
}
public final class FakeSession: @unchecked Sendable {
    private let lock = NSLock()
    private var steps: [Step]
    private var recorded: [URLRequest] = []
    var syntheticForward: (@Sendable (URLRequest) async throws -> (Data, URLResponse))?
    var syntheticInvalidation: (@Sendable () -> Void)?
    init(_ steps: [Step]) { self.steps = steps }
    var requests: [URLRequest] { lock.lock(); defer { lock.unlock() }; return recorded }
    private func consume(_ request: URLRequest) throws -> Step {
        lock.lock(); defer { lock.unlock() }
        recorded.append(request)
        guard !steps.isEmpty else { throw FixtureFailure.unscripted }
        return steps.removeFirst()
    }
    func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        if let syntheticForward { return try await syntheticForward(request) }
        let step = try consume(request)
        await step.entered?.signal(); await step.release?.wait()
        if let delay = step.delayNanoseconds { try await Task.sleep(nanoseconds: delay) }
        step.onResponse?()
        if let error = step.error { throw error }
        let url = step.finalURL ?? request.url!
        if step.nonHTTP { return (step.body, URLResponse(url: url, mimeType: step.mime, expectedContentLength: step.body.count, textEncodingName: nil)) }
        var headers = step.headers
        if let mime = step.mime { headers["Content-Type"] = mime }
        return (step.body, HTTPURLResponse(url: url, statusCode: step.status, httpVersion: "HTTP/1.1", headerFields: headers)!)
    }
}

struct CryptoScenario: Sendable {
    var fail = ""
    var spd = try! plist(["adsid": "synthetic-dsid", "GsIdmsToken": "synthetic-idms", "sk": Data([1,2]), "c": Data([3,4])])
    var token: Data = {
        let t: [String: any Sendable] = ["token": "synthetic-auth-token"]
        let apps: [String: any Sendable] = [Constants.GrandSlam.authApp: t]
        return try! plist(["t": apps])
    }()
}
enum CryptoState { @TaskLocal static var current = CryptoScenario() }
final class SRPClient {
    init?() { if CryptoState.current.fail == "srpInit" { return nil } }
    func startAuthentication() -> Data? { CryptoState.current.fail == "publicKey" ? nil : Data([1,2,3,4]) }
    func processChallenge(username: String, password: Data, salt: Data, serverPublicKey: Data) -> Data? { CryptoState.current.fail == "challenge" ? nil : Data([5,6]) }
    func verifyServerProof(_ proof: Data) -> Bool { CryptoState.current.fail != "proof" }
    func sessionKey() -> Data? { CryptoState.current.fail == "sharedSecret" ? nil : Data([7,8]) }
}
enum CryptoUtilities {
    static func sha256(_ data: Data) -> Data? { CryptoState.current.fail == "hash" ? nil : Data([9,10]) }
    static func pbkdf2SHA256(password: Data, salt: Data, rounds: Int, outputLength: Int) -> Data? { CryptoState.current.fail == "pbkdf2" ? nil : Data([11,12]) }
    static func hmacSHA256(key: Data, strings: [String]) -> Data? {
        let fail = CryptoState.current.fail
        if fail == "hmac" || (fail == "checksum" && strings.first == "apptokens") { return nil }
        return Data([13,14])
    }
    static func aesCBCDecrypt(key: Data, iv: Data, ciphertext: Data) -> Data? { CryptoState.current.fail == "spdDecrypt" ? nil : CryptoState.current.spd }
    static func aesGCMDecrypt(key: Data, nonce: Data, aad: Data, ciphertext: Data, tag: Data) -> Data? { CryptoState.current.fail == "tokenDecrypt" ? nil : CryptoState.current.token }
}
public struct Account: Sendable { public let id: String }
public struct AuthSession: Sendable { public let account: Account; public let session: Session }

public final class DeveloperPortal: @unchecked Sendable {
    public typealias VerificationHandler = @Sendable (TwoFactorRequest) async throws -> TwoFactorResponse
    public typealias AccountRepairHandler = @Sendable (URL, String) async throws -> AccountRepairDecision
    public static let defaultAccountRepairHandler: AccountRepairHandler = { _, _ in .proceed }
    let session: FakeSession
    let customHeaders = SideSignHeaders()
    var failAccount = false
    init(session: FakeSession) { self.session = session }
    func diagnosticCustomHeadersSnapshot() -> DiagnosticCustomHeadersSnapshot { .init(headers: customHeaders, source: .defaultValue) }
    func fetchAccount(session: Session) async throws -> Account { if failAccount { throw FixtureFailure.account }; return Account(id: "synthetic-account") }
}
public final class BaselineDeveloperPortal: @unchecked Sendable {
    public typealias VerificationHandler = @Sendable (TwoFactorRequest) async throws -> TwoFactorResponse
    public typealias AccountRepairHandler = @Sendable (URL, String) async throws -> AccountRepairDecision
    public static let defaultAccountRepairHandler: AccountRepairHandler = { _, _ in .proceed }
    let session: FakeSession
    let customHeaders = SideSignHeaders()
    var failAccount = false
    init(session: FakeSession) { self.session = session }
    func fetchAccount(session: Session) async throws -> Account { if failAccount { throw FixtureFailure.account }; return Account(id: "synthetic-account") }
}
// Existing login spans are inert doubles; the new request collector is actual source.
enum LoginDiagnosticStage { case authSRPInit, authSRPChallenge, authSRPComplete, authDecrypt, authSession, accountLookup, twoFactor, twoFactorDelivery, twoFactorRequest, twoFactorVerify }
enum LoginDiagnosticReason { case notRequired, cancelled, rejected, unavailable, invalidResponse }
enum LoginDiagnosticOutcome { case succeeded, failed }
final class LoginDiagnosticSpan { func finish(_ result: LoginDiagnosticOutcome, reason: LoginDiagnosticReason? = nil, error: Error? = nil) {} }
final class LoginDiagnosticTrace: @unchecked Sendable {
    @TaskLocal static var current: LoginDiagnosticTrace?
    func begin(_ stage: LoginDiagnosticStage) -> LoginDiagnosticSpan { LoginDiagnosticSpan() }
    func skip(_ stage: LoginDiagnosticStage, reason: LoginDiagnosticReason) {}
}

// BEGIN ILOADER NIL-CONTEXT DOUBLE
// Legacy fixture executes full candidate Authentication.swift with this context nil.
// Its unreachable members fail closed instead of silently simulating opt-in success.
public enum ILoaderRemoteError: Error { case consentRequired, resyncUnavailable, httpStatus(Int), invalidResponse, invalidState }
public enum ILoaderRemoteAuthentication {
    @TaskLocal public static var current: ILoaderRemoteAuthenticationContext?
}
public final class ILoaderRemoteAuthenticationContext: @unchecked Sendable {
    public let session = FakeSession([])
    public func fetch() async throws -> AnisetteData { throw FixtureFailure.unscripted }
    public func resynchronize(sim: String) async throws -> AnisetteData { throw FixtureFailure.unscripted }
}
// END ILOADER NIL-CONTEXT DOUBLE
