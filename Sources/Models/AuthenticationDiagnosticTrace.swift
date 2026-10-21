import Foundation
import CoreFoundation

/// Per-attempt, in-memory structural observations. Never stores requests, URLs, bodies,
/// header values, account/device identifiers, secrets, server messages or their hashes.
/// `ar1` is independently validated; a last accepted request is not a later failure cause.
public final class AuthenticationDiagnosticTrace: @unchecked Sendable {
    @TaskLocal public static var current: AuthenticationDiagnosticTrace?
    @TaskLocal static var invocation: Invocation?

    public struct Snapshot: Sendable {
        public let requestTrace: String?
        public let headerProvenance: String?
        public let providerObservation: String?
    }
    fileprivate final class Identity: @unchecked Sendable {}
    public struct ProviderObservationToken: Sendable {
        fileprivate let owner: Identity
        fileprivate let epoch: UInt64
    }
    final class Invocation: @unchecked Sendable {
        weak var owner: AuthenticationDiagnosticTrace?
        let ordinal: Int
        let epoch: UInt64
        init(owner: AuthenticationDiagnosticTrace, ordinal: Int, epoch: UInt64) {
            self.owner = owner; self.ordinal = ordinal; self.epoch = epoch
        }
    }
    enum Boundary: String {
        case notRequested, srpInit, serialization, response, hash, pbkdf2, challenge
        case proof, sharedSecret, spdDecrypt, spdParse, sessionKey, sessionChallenge, checksum
        case twoFactor, accountRepair, accountLookup, complete
    }
    enum Validation: String { case unobserved, passed, failed, retry }
    enum Consumer: String {
        case none, initFields, completeSPD, proofField, proof, sharedSecret, spdDecrypt, spdParse
        case dsid, idms, sessionKey, sessionChallenge, checksum, tokenField, tokenLength
        case tokenDecrypt, tokenParse, tokenPath, xmlAlert, http, peToken, verify
    }
    enum Outcome: String { case started, received, accepted, rejected, transport, empty, parse, status }
    enum Reason: String {
        case none, credentials, appPassword, verification, underlying, rateLimit, xmlAlert
        case http, peToken, incorrectCode, serviceUnavailable, unknown
    }
    final class Request: @unchecked Sendable {
        fileprivate weak var owner: AuthenticationDiagnosticTrace?
        fileprivate let epoch: UInt64
        fileprivate let started: UInt64
        fileprivate var fields: [String]
        fileprivate let provenance: String?
        fileprivate init(owner: AuthenticationDiagnosticTrace, epoch: UInt64, started: UInt64, fields: [String], provenance: String?) {
            self.owner = owner; self.epoch = epoch; self.started = started
            self.fields = fields; self.provenance = provenance
        }
        func response(request: URLRequest, data: Data, response: URLResponse) {
            owner?.observeResponse(self, request: request, data: data, response: response)
        }
        func transport(_ error: Error) {
            owner?.mutate(self) { f in
                guard f[36] == "0" else { return }
                f[8] = "transport"; f[9] = AuthenticationDiagnosticTrace.transportClass(error)
                let elapsed = AuthenticationDiagnosticTrace.milliseconds(since: self.started)
                f[6] = String(elapsed.0); if elapsed.1 { f[7] = "1" }
            }
        }
        func finish(_ outcome: Outcome, reason: Reason = .none) {
            owner?.mutate(self) { $0[8] = outcome.rawValue; $0[35] = reason.rawValue }
        }
        func consumer(_ consumer: Consumer, _ validation: Validation) {
            owner?.mutate(self) { $0[33] = consumer.rawValue; $0[34] = validation.rawValue }
        }
        func parser(plist: Any?, json: Any?, selected: String) {
            owner?.mutate(self) {
                $0[19] = selected
                $0[20] = AuthenticationDiagnosticTrace.root(plist)
                $0[21] = selected == "plist" ? "unobserved" : AuthenticationDiagnosticTrace.root(json)
            }
        }
        func envelope(_ outer: [String: any Sendable], nested: Bool) {
            owner?.mutate(self) { $0[22] = nested ? "nested" : (outer["Response"] == nil ? "topMissing" : "topWrong") }
        }
        func status(_ value: Any?, ec: Any?, hsc: Any?, effective: Int?, source: String) {
            owner?.mutate(self) {
                $0[23] = value == nil ? "missing" : (value is [String: any Sendable] ? "dictionary" : "wrong")
                $0[24] = AuthenticationDiagnosticTrace.strictNumber(ec, hsc: false)
                $0[25] = AuthenticationDiagnosticTrace.strictNumber(hsc, hsc: true)
                $0[26] = effective == nil ? "unobserved" : ((ec as? Int) == nil ? "default" : "cast")
                if let effective { $0[27] = (-99_999_999...99_999_999).contains(effective) ? String(effective) : "out" }
                $0[28] = source
                if source == "top" { $0[22] = "topOnly" }
            }
        }
    }

    private let lock = NSLock()
    private let identity = Identity()
    private let started = DispatchTime.now().uptimeNanoseconds
    private var authCount = 0
    private var requestCount = 0
    private var overflow = false
    private var truncated = false
    private var scopeEpoch: UInt64 = 0
    private var providerEpoch: UInt64 = 0
    private var boundary: Boundary = .notRequested
    private var validation: Validation = .unobserved
    private var history: [Request] = []
    private var decisive: Request?
    private var provider: String?

    public init() {}

    func beginAuthentication() -> Invocation {
        lock.lock(); defer { lock.unlock() }
        if authCount < 65_535 { authCount += 1 } else { overflow = true }
        scopeEpoch &+= 1
        decisive = nil; boundary = .srpInit; validation = .unobserved
        return Invocation(owner: self, ordinal: authCount, epoch: scopeEpoch)
    }
    func authentication(_ boundary: Boundary, _ validation: Validation = .unobserved) {
        lock.lock(); defer { lock.unlock() }
        if let invocation = Self.invocation, invocation.owner === self, invocation.epoch != scopeEpoch { return }
        self.boundary = boundary; self.validation = validation
    }
    func authenticationFailed() {
        lock.lock(); defer { lock.unlock() }
        if let invocation = Self.invocation, invocation.owner === self, invocation.epoch != scopeEpoch { return }
        validation = .failed
    }
    public func beginProviderObservation(_ value: AuthenticationProviderObservation) -> ProviderObservationToken {
        lock.lock(); defer { lock.unlock() }
        providerEpoch &+= 1; scopeEpoch &+= 1
        decisive = nil; boundary = .notRequested; validation = .unobserved
        provider = AuthenticationProviderObservation.validatedEncoded(value.encoded)
        return ProviderObservationToken(owner: identity, epoch: providerEpoch)
    }
    public func setProviderObservation(_ value: AuthenticationProviderObservation, token: ProviderObservationToken) {
        lock.lock(); defer { lock.unlock() }
        guard token.owner === identity, token.epoch == providerEpoch else { return }
        provider = AuthenticationProviderObservation.validatedEncoded(value.encoded)
    }

    /// Call only after the existing builder has finished; the request is not retained.
    func beginRequest(_ request: URLRequest, phase: String, parameters: [String: any Sendable]? = nil,
                      headerVersion: String? = nil, provenance: String? = nil) -> Request {
        lock.lock(); defer { lock.unlock() }
        if requestCount < 65_535 { requestCount += 1 } else { overflow = true }
        let invocation = Self.invocation
        let belongs = invocation?.owner === self
        let epoch = belongs ? invocation!.epoch : scopeEpoch
        let elapsed = Self.milliseconds(since: started)
        let now = DispatchTime.now().uptimeNanoseconds
        let allowedPhases = ["init", "complete", "apptokens", "trustedRequest", "phoneRequest", "trustedVerify", "phoneVerify"]
        let methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "PATCH", "OPTIONS"]
        let method = request.httpMethod.map { methods.contains($0) ? $0 : "other" } ?? "absent"
        let count = request.httpBody?.count ?? 0
        let cpd = Self.cpd(parameters)
        let envelope: String
        if let parameters {
            let service = (parameters["cpd"] as? [String: any Sendable])?["svct"] as? String
            let s = service.map { $0 == Constants.GrandSlam.service ? "builtIn" : "custom" } ?? "unknown"
            let v = headerVersion.map { $0 == Constants.GrandSlam.headerVersion ? "builtIn" : "custom" } ?? "unknown"
            envelope = "headerRequest:\(s):\(v)"
        } else { envelope = "twoFactor" }
        let fields = [String(belongs ? invocation!.ordinal : 0), String(requestCount), allowedPhases.contains(phase) ? phase : "unknown",
                      method, Self.endpoint(request.url), String(elapsed.0), "0", elapsed.1 ? "1" : "0", "started", "none", "-",
                      "unavailable", "unavailable", "u", String(min(count, 16_777_216)), "-", count > 16_777_216 ? "1" : "0",
                      "unobserved", "unobserved", "unobserved", "unobserved", "unobserved", "unobserved", "unobserved",
                      "u", "u", "unobserved", "-", "unobserved", cpd.0, "unobserved", "-", "0", "none", "unobserved", "none", "0", cpd.1,
                      envelope, request.httpBody == nil ? "none" : "plist"]
        let item = Request(owner: self, epoch: epoch, started: now, fields: fields,
                           provenance: provenance.flatMap { AuthenticationHeaderProvenance(encoded: $0)?.encoded })
        history.append(item)
        if history.count > 4 { history.removeFirst(); truncated = true }
        if epoch == scopeEpoch { decisive = item; boundary = .response; validation = .unobserved }
        return item
    }
    private func mutate(_ request: Request, _ operation: (inout [String]) -> Void) {
        lock.lock(); defer { lock.unlock() }
        operation(&request.fields)
    }
    private func observeResponse(_ item: Request, request: URLRequest, data: Data, response: URLResponse) {
        let http = response as? HTTPURLResponse
        let retry = Self.retryAfter(http?.value(forHTTPHeaderField: "Retry-After"))
        mutate(item) {
            let elapsed = Self.milliseconds(since: item.started)
            $0[6] = String(elapsed.0); if elapsed.1 { $0[7] = "1" }
            $0[8] = "received"
            $0[10] = http.map { (100...599).contains($0.statusCode) ? String($0.statusCode) : "invalid" } ?? "-"
            $0[11] = Self.endpoint(response.url)
            $0[12] = Self.relation(request.url, response.url)
            $0[15] = String(min(data.count, 16_777_216))
            if data.count > 16_777_216 { $0[16] = String((Int($0[16]) ?? 0) | 2) }
            $0[17] = Self.mime(response.mimeType); $0[18] = Self.shape(data)
            $0[30] = retry.0; $0[31] = retry.1; $0[32] = retry.2; $0[36] = "1"
        }
    }
    public func snapshot() -> Snapshot {
        lock.lock(); defer { lock.unlock() }
        guard requestCount > 0 || authCount > 0 || boundary != .notRequested else {
            return Snapshot(requestTrace: nil, headerProvenance: nil, providerObservation: provider)
        }
        var lost = truncated
        var prior = history.filter { $0 !== decisive }
        if overflow { prior = []; lost = true }
        if prior.count > 3 { prior = Array(prior.suffix(3)); lost = true }
        if let decisive {
            let eligible = prior.filter { (Int($0.fields[1]) ?? 0) < (Int(decisive.fields[1]) ?? 0) }
            if eligible.count != prior.count { lost = true }
            prior = eligible
        }
        func encode() -> String {
            let rows = prior.map { row in [0, 1, 2, 8, 10, 24, 33, 34].map { row.fields[$0] }.joined(separator: ",") }.joined(separator: "~")
            return ["ar1", String(authCount), String(requestCount), overflow ? "1" : "0", lost ? "1" : "0", boundary.rawValue,
                    validation.rawValue, decisive?.fields.joined(separator: ",") ?? "-", rows].joined(separator: ";")
        }
        var encoded = encode()
        while encoded.utf8.count > 1024 && !prior.isEmpty { prior.removeFirst(); lost = true; encoded = encode() }
        let valid = Self.validatedEncodedSnapshot(encoded)
        return Snapshot(requestTrace: valid, headerProvenance: valid == nil ? nil : decisive?.provenance, providerObservation: provider)
    }
    public func encodedSnapshot() -> String? { snapshot().requestTrace }

    /// Independent closed-schema decoder. Copy this function, not arbitrary producer text,
    /// into consumers. It accepts canonical ASCII only and rejects duplicate/ambiguous ordinals.
    public static func validatedEncodedSnapshot(_ value: String) -> String? {
        guard value.utf8.count <= 1024, value.utf8.allSatisfy({ $0 >= 32 && $0 <= 126 }) else { return nil }
        let p = value.split(separator: ";", omittingEmptySubsequences: false).map(String.init)
        func number(_ s: String, _ range: ClosedRange<Int>) -> Bool { guard let n = Int(s), String(n) == s else { return false }; return range.contains(n) }
        func one(_ s: String, _ values: String) -> Bool { values.split(separator: " ").contains(Substring(s)) }
        func bit(_ s: String) -> Bool { s == "0" || s == "1" }
        func status(_ s: String) -> Bool { s == "-" || s == "invalid" || number(s, 100...599) }
        func code(_ s: String, hsc: Bool = false) -> Bool { one(s, "u m ib is if io ir") || number(s, hsc ? 100...599 : -99_999_999...99_999_999) }
        let phases = "init complete apptokens trustedRequest phoneRequest trustedVerify phoneVerify unknown"
        let outcomes = "started received accepted rejected transport empty parse status"
        let consumers = "none initFields completeSPD proofField proof sharedSecret spdDecrypt spdParse dsid idms sessionKey sessionChallenge checksum tokenField tokenLength tokenDecrypt tokenParse tokenPath xmlAlert http peToken verify"
        let validations = "unobserved passed failed retry"
        let endpoints = "gsa trusted validate phoneRequest phoneVerify apple other unavailable"
        guard p.count == 9, p[0] == "ar1", number(p[1], 0...65_535), number(p[2], 0...65_535), bit(p[3]), bit(p[4]),
              one(p[5], "notRequested srpInit serialization response hash pbkdf2 challenge proof sharedSecret spdDecrypt spdParse sessionKey sessionChallenge checksum twoFactor accountRepair accountLookup complete"),
              one(p[6], validations) else { return nil }
        let auth = Int(p[1])!, requests = Int(p[2])!
        guard auth > 0 || requests > 0 || (p[5] == "serialization" && p[6] == "failed") else { return nil }
        if p[3] == "1" { guard auth == 65_535 || requests == 65_535 else { return nil } }
        var last = requests + 1
        if p[7] != "-" {
            let f = p[7].split(separator: ",", omittingEmptySubsequences: false).map(String.init)
            guard f.count == 40, number(f[0], 0...auth), number(f[1], 1...max(1, requests)), requests > 0,
                  one(f[2], phases), one(f[3], "GET POST PUT DELETE HEAD PATCH OPTIONS other absent"), one(f[4], endpoints),
                  number(f[5], 0...86_400_000), number(f[6], 0...86_400_000), bit(f[7]), one(f[8], outcomes),
                  one(f[9], "none cancelled timeout dns connectivity lost tls url unknown"), status(f[10]), one(f[11], endpoints),
                  one(f[12], "sameURL sameOrigin differentOrigin unavailable"), f[13] == "u", number(f[14], 0...16_777_216),
                  (f[15] == "-" || number(f[15], 0...16_777_216)), number(f[16], 0...3),
                  one(f[17], "unobserved plist json html xml text other missing"), one(f[18], "unobserved empty plistXML plistBinary jsonObject jsonArray html xml text binary"),
                  one(f[19], "unobserved plist json failure"), one(f[20], "unobserved dictionary array scalar invalid"), one(f[21], "unobserved dictionary array scalar invalid"),
                  one(f[22], "unobserved nested topMissing topWrong topOnly"), one(f[23], "unobserved dictionary missing wrong"), code(f[24]), code(f[25], hsc: true),
                  one(f[26], "unobserved default cast"), (one(f[27], "- out") || number(f[27], -99_999_999...99_999_999)), one(f[28], "unobserved status top"),
                  (one(f[29], "u a w") || (f[29].utf8.count == 15 && f[29].allSatisfy { "absedznrco".contains($0) })),
                  one(f[30], "unobserved absent delta date invalid"), (f[31] == "-" || number(f[31], 0...86_400)), bit(f[32]),
                  one(f[33], consumers), one(f[34], validations), one(f[35], "none credentials appPassword verification underlying rateLimit xmlAlert http peToken incorrectCode serviceUnavailable unknown"),
                  bit(f[36]), (f[37] == "u" || number(f[37], 0...32)), one(f[39], "plist none unobserved") else { return nil }
            if !one(f[38], "twoFactor none unobserved") {
                let e = f[38].split(separator: ":", omittingEmptySubsequences: false).map(String.init)
                guard e.count == 3, e[0] == "headerRequest", one(e[1], "builtIn custom unknown"), one(e[2], "builtIn custom unknown") else { return nil }
            }
            if one(f[30], "delta date") { guard f[31] != "-", f[10] != "-" else { return nil } }
            else { guard f[31] == "-", f[32] == "0" else { return nil } }
            if f[36] == "0" {
                guard one(f[8], "started transport"), f[10] == "-", f[15] == "-", f[17] == "unobserved", f[18] == "unobserved",
                      f[11] == "unavailable", f[12] == "unavailable", f[19] == "unobserved", f[20] == "unobserved", f[21] == "unobserved",
                      f[30] == "unobserved", f[31] == "-", f[32] == "0" else { return nil }
            } else {
                guard !one(f[8], "started transport"), f[15] != "-", f[17] != "unobserved", f[18] != "unobserved", f[30] != "unobserved" else { return nil }
            }
            last = Int(f[1])!
        }
        let rows = p[8].isEmpty ? [] : p[8].split(separator: "~", omittingEmptySubsequences: false).map(String.init)
        guard rows.count <= 3 else { return nil }
        var previous = 0
        for row in rows {
            let r = row.split(separator: ",", omittingEmptySubsequences: false).map(String.init)
            guard r.count == 8, number(r[0], 0...auth), number(r[1], 1...max(1, requests)), one(r[2], phases), one(r[3], outcomes), status(r[4]), code(r[5]), one(r[6], consumers), one(r[7], validations),
                  let ordinal = Int(r[1]), ordinal > previous, ordinal < last, ordinal <= requests else { return nil }
            previous = ordinal
        }
        return value
    }

    private static func milliseconds(since value: UInt64) -> (Int, Bool) {
        let now = DispatchTime.now().uptimeNanoseconds
        let ms = now >= value ? (now - value) / 1_000_000 : 0
        return (Int(min(ms, 86_400_000)), ms > 86_400_000)
    }
    private static func root(_ value: Any?) -> String {
        guard let value else { return "invalid" }
        if value is [String: any Sendable] { return "dictionary" }
        if value is [Any] { return "array" }
        return "scalar"
    }
    private static func strictNumber(_ value: Any?, hsc: Bool) -> String {
        guard let value else { return "m" }
        if let n = value as? NSNumber {
            if CFGetTypeID(n) == CFBooleanGetTypeID() { return "ib" }
            let t = String(cString: n.objCType)
            if t == "f" || t == "d" { return "if" }
            let s = n.stringValue
            guard let i = Int(s), String(i) == s, (hsc ? 100...599 : -99_999_999...99_999_999).contains(i) else { return "ir" }
            return s
        }
        if value is String { return "is" }
        return "io"
    }
    private static let cpdKeys = ["bootstrap", "icscrec", "pbe", "prkgen", "svct", "loc", "X-Apple-Locale", "X-Apple-I-MD", "X-Apple-I-MD-M", "X-Mme-Device-Id", "X-Apple-I-MD-LU", "X-Apple-I-MD-RINFO", "X-Apple-I-SRL-NO", "X-Apple-I-Client-Time", "X-Apple-I-TimeZone"]
    private static func cpd(_ parameters: [String: any Sendable]?) -> (String, String) {
        guard let parameters else { return ("u", "u") }
        guard let value = parameters["cpd"] else { return ("a", "u") }
        guard let dictionary = value as? [String: any Sendable] else { return ("w", "u") }
        let signature = cpdKeys.map { key -> String in
            guard let value = dictionary[key] else { return "a" }
            if let n = value as? NSNumber {
                if CFGetTypeID(n) == CFBooleanGetTypeID() { return "b" }
                return ["f", "d"].contains(String(cString: n.objCType)) ? "r" : "n"
            }
            if let s = value as? String { return s.isEmpty ? "e" : "s" }
            if let d = value as? Data { return d.isEmpty ? "z" : "d" }
            if value is [Any] || value is [String: Any] { return "c" }
            return "o"
        }.joined()
        return (signature, String(min(dictionary.keys.filter { !cpdKeys.contains($0) }.count, 32)))
    }
    private static func endpoint(_ url: URL?) -> String {
        guard let url, let host = url.host?.lowercased() else { return "unavailable" }
        if url == Constants.URLs.grandSlamAuth { return "gsa" }
        if url == Constants.URLs.trustedDevice { return "trusted" }
        if url == Constants.URLs.grandSlamValidate { return "validate" }
        if url == Constants.URLs.phoneSecurityCode { return "phoneVerify" }
        if url == Constants.URLs.phonePutURL(mode: "sms") || url == Constants.URLs.phonePutURL(mode: "voice") { return "phoneRequest" }
        return host == "apple.com" || host.hasSuffix(".apple.com") ? "apple" : "other"
    }
    private static func relation(_ a: URL?, _ b: URL?) -> String {
        guard let a, let b, let ah = a.host, let bh = b.host, let ascheme = a.scheme, let bscheme = b.scheme else { return "unavailable" }
        if a == b { return "sameURL" }
        func port(_ u: URL) -> Int? { u.port ?? (u.scheme?.lowercased() == "https" ? 443 : u.scheme?.lowercased() == "http" ? 80 : nil) }
        return ah.lowercased() == bh.lowercased() && ascheme.lowercased() == bscheme.lowercased() && port(a) == port(b) ? "sameOrigin" : "differentOrigin"
    }
    private static func mime(_ value: String?) -> String {
        guard let value else { return "missing" }
        guard value.utf8.count <= 128 else { return "other" }
        let s = value.split(separator: ";", maxSplits: 1).first?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() ?? ""
        if ["application/x-plist", "application/x-apple-plist", "text/x-xml-plist", "application/plist"].contains(s) { return "plist" }
        if s == "application/json" { return "json" }
        if s == "text/html" || s == "application/xhtml+xml" { return "html" }
        if s == "text/xml" || s == "application/xml" { return "xml" }
        if s.hasPrefix("text/") { return "text" }
        return "other"
    }
    private static func shape(_ data: Data) -> String {
        if data.isEmpty { return "empty" }
        let prefix = data.prefix(512)
        if prefix.starts(with: Data("bplist".utf8)) { return "plistBinary" }
        guard let raw = String(data: prefix, encoding: .utf8) else { return "binary" }
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if s.hasPrefix("{") { return "jsonObject" }; if s.hasPrefix("[") { return "jsonArray" }
        if s.hasPrefix("<html") || s.hasPrefix("<!doctype html") { return "html" }
        if s.hasPrefix("<plist") || (s.hasPrefix("<?xml") && s.contains("<plist")) { return "plistXML" }
        if s.hasPrefix("<") { return "xml" }
        return "text"
    }
    private static func retryAfter(_ value: String?) -> (String, String, String) {
        guard let value else { return ("absent", "-", "0") }
        guard value.utf8.count <= 128, !value.isEmpty else { return ("invalid", "-", "0") }
        if value.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }), value == "0" || !value.hasPrefix("0") {
            if let n = UInt64(value) { return ("delta", String(min(n, 86_400)), n > 86_400 ? "1" : "0") }
            return ("delta", "86400", "1")
        }
        let formatter = DateFormatter(); formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0); formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss 'GMT'"; formatter.isLenient = false
        guard let date = formatter.date(from: value), formatter.string(from: date) == value else { return ("invalid", "-", "0") }
        let seconds = max(0, date.timeIntervalSinceNow)
        return ("date", String(Int(min(seconds, 86_400))), seconds > 86_400 ? "1" : "0")
    }
    private static func transportClass(_ error: Error) -> String {
        if error is CancellationError { return "cancelled" }
        guard let e = error as? URLError else { return "unknown" }
        switch e.code {
        case .cancelled: return "cancelled"
        case .timedOut: return "timeout"
        case .cannotFindHost, .dnsLookupFailed: return "dns"
        case .notConnectedToInternet, .cannotConnectToHost: return "connectivity"
        case .networkConnectionLost: return "lost"
        case .secureConnectionFailed, .serverCertificateUntrusted, .serverCertificateHasBadDate, .serverCertificateHasUnknownRoot, .serverCertificateNotYetValid, .clientCertificateRejected, .clientCertificateRequired: return "tls"
        case .badURL, .unsupportedURL: return "url"
        default: return "unknown"
        }
    }
}
