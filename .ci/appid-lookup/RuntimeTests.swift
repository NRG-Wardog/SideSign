import Foundation

// Only unrelated feature metadata is doubled. AppID decoding and the strict
// parser are compiled unmodified from production sources by run.sh.
public struct Feature: RawRepresentable, Hashable, Sendable {
    public let rawValue: String
    public init(rawValue: String) { self.rawValue = rawValue }
}

@main
@MainActor
struct AppIDLookupTests {
    static var assertions = 0
    static func check(_ condition: Bool, _ label: String) {
        precondition(condition, label)
        assertions += 1
    }
    static func failure(_ data: Data, _ expected: AppIDLookupError, status: Int? = 200) {
        do {
            _ = try AppIDLookupResponse.decode(data: data, statusCode: status)
            preconditionFailure("Expected \(expected)")
        } catch let error as AppIDLookupError {
            check(error == expected, "Expected \(expected), got \(error)")
        } catch { preconditionFailure("Non-finite error: \(type(of: error))") }
    }
    static func main() throws {
        let record: [String: Any] = ["appIdId": "OPAQUE123", "identifier": "com.example.App", "name": "Example"]
        let formats: [(String, ([String: Any]) throws -> Data)] = [
            ("JSON", { try JSONSerialization.data(withJSONObject: $0) }),
            ("XML", { try PropertyListSerialization.data(fromPropertyList: $0, format: .xml, options: 0) }),
            ("binary", { try PropertyListSerialization.data(fromPropertyList: $0, format: .binary, options: 0) })
        ]
        for (format, encode) in formats {
            let valid = try encode(["resultCode": 0, "appIds": [record]])
            let result = try AppIDLookupResponse.decode(data: valid, statusCode: 200)
            check(result.count == 1 && result[0].identifier == "OPAQUE123" && result[0].bundleIdentifier == "com.example.App", "\(format) preserves identity bytes/case")
            let empty = try AppIDLookupResponse.decode(data: encode(["resultCode": 0, "appIds": []]), statusCode: 200)
            check(empty.isEmpty, "\(format) authoritative empty")
            failure(valid, .invalidHTTPResponse, status: nil)
            for status in [0, 199, 300, 401, 403, 429, 500] { failure(valid, .httpFailure, status: status) }
            failure(try encode(["appIds": []]), .missingStatus)
            failure(try encode(["resultCode": "0", "appIds": []]), .missingStatus)
            failure(try encode(["resultCode": true, "appIds": []]), .missingStatus)
            failure(try encode(["resultCode": false, "appIds": []]), .missingStatus)
            failure(try encode(["resultCode": 9120, "appIds": []]), .unsuccessfulStatus)
            failure(try encode(["resultCode": 0, "errors": [["code": "PRIVATE_SENTINEL"]], "appIds": []]), .unsuccessfulStatus)
            failure(try encode(["resultCode": 0]), .missingList)
            for badList in ["", 1, ["wrong": "shape"]] as [Any] {
                failure(try encode(["resultCode": 0, "appIds": badList]), .malformedList)
            }
            for badRecord in [[String: Any](), "", 3, ["appIdId": "A"], ["identifier": "com.example.App"], ["appIdId": 42, "identifier": "com.example.App"], ["appIdId": "A", "identifier": 42]] as [Any] {
                failure(try encode(["resultCode": 0, "appIds": [record, badRecord]]), .malformedRecord)
            }
            for field in ["appIdId", "identifier"] {
                for invalid in ["", " ", " leading", "trailing ", "line\nbreak"] {
                    var bad = record
                    bad[field] = invalid
                    failure(try encode(["resultCode": 0, "appIds": [bad]]), .malformedRecord)
                }
            }
            for wildcard in ["*", "com.example.*"] {
                var wildcardRecord = record
                wildcardRecord["identifier"] = wildcard
                let inventory = try AppIDLookupResponse.decode(data: encode(["resultCode": 0, "appIds": [wildcardRecord]]), statusCode: 200)
                check(inventory[0].bundleIdentifier == wildcard, "Wildcard inventory is preserved, never expanded")
            }
            for (field, value) in [("appIdId", String(repeating: "A", count: 257)),
                                   ("identifier", String(repeating: "a", count: 513)),
                                   ("appIdId", "A_B"), ("appIdId", "é"),
                                   ("identifier", "com.example/other"), ("identifier", "com.é"),
                                   ("identifier", "com.*.example")] {
                var bad = record
                bad[field] = value
                failure(try encode(["resultCode": 0, "appIds": [bad]]), .malformedRecord)
            }
            var boundary = record
            boundary["appIdId"] = String(repeating: "A", count: 256)
            boundary["identifier"] = String(repeating: "a", count: 512)
            let longest = try AppIDLookupResponse.decode(data: encode(["resultCode": 0, "appIds": [boundary]]), statusCode: 200)
            check(longest.count == 1, "Identity size boundary accepted")
            let full = Array(repeating: record, count: AppIDLookupResponse.maximumRecords)
            let atLimit = try AppIDLookupResponse.decode(data: encode(["resultCode": 0, "appIds": full]), statusCode: 200)
            check(atLimit.count == full.count, "Inventory count boundary accepted")
            failure(try encode(["resultCode": 0, "appIds": full + [record]]), .malformedList)
            var conflict = record
            conflict["identifier"] = "com.example.Other"
            failure(try encode(["resultCode": 0, "appIds": [record, conflict]]), .conflictingRecord)
            conflict = record
            conflict["appIdId"] = "OTHER123"
            failure(try encode(["resultCode": 0, "appIds": [record, conflict]]), .conflictingRecord)
            let duplicate = try AppIDLookupResponse.decode(data: encode(["resultCode": 0, "appIds": [record, record]]), statusCode: 200)
            check(duplicate.count == 2, "\(format) duplicates remain ambiguous to caller")
            var caseVariant = record
            caseVariant["identifier"] = "com.example.app"
            caseVariant["appIdId"] = "OTHER123"
            let variants = try AppIDLookupResponse.decode(data: encode(["resultCode": 0, "appIds": [record, caseVariant]]), statusCode: 200)
            check(variants.count == 2 && variants[0].bundleIdentifier != variants[1].bundleIdentifier, "No case normalization")
        }
        failure(Data(repeating: 32, count: AppIDLookupResponse.maximumResponseBytes + 1), .malformedList)
        failure(Data(#"{"resultCode":0,"appIds":null}"#.utf8), .nullList)
        failure(Data(#"{"resultCode":null,"appIds":[]}"#.utf8), .missingStatus)
        failure(Data(#"{"resultCode":0,"appIds":[null]}"#.utf8), .malformedRecord)
        failure(Data(#"{"resultCode":0,"appIds":[{"appIdId":null,"identifier":"example"}]}"#.utf8), .malformedRecord)
        for data in [Data(), Data("<html>unavailable</html>".utf8), Data("{broken".utf8), Data("[]".utf8)] {
            failure(data, .malformedList)
            failure(data, .httpFailure, status: 503)
        }
        print("PASS: \(assertions) strict App ID parser assertions")
    }
}
