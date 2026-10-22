// Exact scoped request shape from official isideload 0.5.0 (fc7a81a6), not a global profile change.
import Foundation
import CoreFoundation

// Pure request policy is used by production and the synthetic source-owned fixture.
enum ILoaderAuthenticationPolicy {
    static let lookupClientInfo = "<Mac15,7> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
    static let provisioningURLs = [
        "lookup": "https://gsa.apple.com/grandslam/GsService2/lookup",
        "start": "https://gsa.apple.com/grandslam/MidService/startMachineProvisioning",
        "finish": "https://gsa.apple.com/grandslam/MidService/finishMachineProvisioning"
    ]
    static func validHeader(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 4096 && !value.unicodeScalars.contains { $0.value < 32 || $0.value == 127 }
    }
    static func baseHeaders(clientInfo: String, userAgent: String, sms: Bool = false) -> [String: String] {
        ["Content-Type": sms ? "application/json" : "text/x-xml-plist",
         "Accept": sms ? "application/json" : "text/x-xml-plist",
         "X-Mme-Client-Info": clientInfo, "User-Agent": userAgent,
         "X-Xcode-Version": "27.0 (27A5218g)", "X-Apple-App-Info": "com.apple.gs.xcode.auth",
         "Connection": "close"]
    }
    static func clientDictionary(_ data: AnisetteData) -> [String: any Sendable] {
        ["bootstrap": "true", "icscrec": "true", "loc": "en_US", "pbe": "false", "prkgen": "true", "svct": "iCloud",
         "X-Mme-Device-Id": data.deviceID, "X-Apple-I-MD": data.oneTimePassword, "X-Apple-I-MD-M": data.machineID]
    }
    static func twoFactorHeaders(_ data: AnisetteData, dsid: String, token: String, sms: Bool) -> [String: String] {
        var headers = baseHeaders(clientInfo: data.clientInfo, userAgent: data.userAgent, sms: sms)
        headers["X-Mme-Device-Id"] = data.deviceID
        headers["X-Apple-I-MD"] = data.oneTimePassword
        headers["X-Apple-I-MD-M"] = data.machineID
        headers["X-Apple-I-MD-RINFO"] = data.routingInfo
        headers["X-Apple-Identity-Token"] = Data("\(dsid):\(token)".utf8).base64EncodedString()
        return headers
    }
    static func signedInteger(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
              !["f", "d"].contains(String(cString: number.objCType)) else { return nil }
        return Int(number.stringValue)
    }
    static func resyncSIM(_ response: [String: any Sendable]) -> String? {
        guard let status = response["Status"] as? [String: any Sendable], signedInteger(status["hsc"]) == 434 else { return nil }
        return (status["X-Apple-I-MD-DATA"] as? String) ?? (status["X-Apple-I-MD-DATA"] as? Data)?.base64EncodedString()
    }
}

extension ILoaderAuthenticationPolicy {
    enum SMSResult: Equatable { case accepted, incorrectCode, rejected(String?) }
    static func phoneRequest(data: AnisetteData, dsid: String, token: String, phoneID: UInt32, code: String?) throws -> URLRequest {
        var request = URLRequest(url: URL(string: code == nil
            ? "https://gsa.apple.com/auth/verify/phone"
            : "https://gsa.apple.com/auth/verify/phone/securitycode")!)
        request.httpMethod = code == nil ? "PUT" : "POST"
        request.allHTTPHeaderFields = twoFactorHeaders(data, dsid: dsid, token: token, sms: true)
        var body: [String: Any] = ["phoneNumber": ["id": phoneID], "mode": "sms"]
        if let code { body["securityCode"] = ["code": code] }
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        return request
    }
    static func classifySMS(status: Int, data: Data, phoneID: UInt32, verifying: Bool) -> SMSResult {
        if (200..<300).contains(status) { return .accepted }
        let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        if let errors = json?["serviceErrors"] as? [[String: Any]], let first = errors.first {
            let code = first["code"] as? String
            return verifying && code == "-21669" ? .incorrectCode : .rejected(code)
        }
        // Official 412 active-challenge case, not a general success/retry bypass.
        if !verifying, status == 412, let json,
           json["mode"] as? String == "sms", json["type"] as? String == "verification",
           json["authenticationType"] as? String == "hsa2",
           let selected = json["trustedPhoneNumber"] as? [String: Any], validTrustedNumber(selected),
           let selectedID = strictUInt32(selected["id"]), selectedID == phoneID,
           let all = json["trustedPhoneNumbers"] as? [[String: Any]], all.allSatisfy(validTrustedNumber),
           all.contains(where: { strictUInt32($0["id"]) == phoneID }),
           let security = json["securityCode"] as? [String: Any], strictUInt32(security["length"]) == 6,
           ["tooManyCodesSent", "tooManyCodesValidated", "securityCodeLocked", "securityCodeCooldown"].allSatisfy({ strictFalse(security[$0]) }) {
            return .accepted
        }
        return .rejected(nil)
    }
    private static func validTrustedNumber(_ value: [String: Any]) -> Bool {
        strictUInt32(value["id"]) != nil && value["numberWithDialCode"] is String &&
            value["lastTwoDigits"] is String && value["pushMode"] is String
    }
    private static func strictUInt32(_ value: Any?) -> UInt32? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
              String(cString: number.objCType) != "d", String(cString: number.objCType) != "f",
              number.int64Value >= 0, number.uint64Value <= UInt64(UInt32.max) else { return nil }
        return number.uint32Value
    }
    private static func strictFalse(_ value: Any?) -> Bool {
        guard let number = value as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else { return false }
        return !number.boolValue
    }
}

extension ILoaderAuthenticationPolicy {
    static func trustedNumbersRequest(data: AnisetteData, dsid: String, token: String) -> URLRequest {
        var request = URLRequest(url: URL(string: "https://gsa.apple.com/auth")!)
        request.httpMethod = "GET"
        request.allHTTPHeaderFields = twoFactorHeaders(data, dsid: dsid, token: token, sms: true)
        return request
    }
    static func trustedNumbers(_ data: Data) throws -> [TrustedPhoneNumber] {
        guard data.count <= 1_048_576,
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let numbers = root["trustedPhoneNumbers"] as? [[String: Any]],
              numbers.allSatisfy(validTrustedNumber) else { throw ILoaderRemoteError.invalidResponse }
        return numbers.map { number in
            TrustedPhoneNumber(id: String(strictUInt32(number["id"])!), number: number["numberWithDialCode"] as! String)
        }
    }
}
