import Foundation

/// Finite, payload-free reasons why a preservation lookup is not authoritative.
/// None of these failures establishes that a signing identity is absent.
public enum AppIDLookupError: String, Error, Sendable {
    case invalidHTTPResponse
    case httpFailure
    case missingStatus
    case unsuccessfulStatus
    case missingList
    case nullList
    case malformedList
    case malformedRecord
    case conflictingRecord
}

/// Strict only for preservation callers. Legacy list/create/update decoders are unchanged.
enum AppIDLookupResponse {
    // Bound parsing work. These are inventory limits, not identity normalization.
    static let maximumResponseBytes = 4 * 1024 * 1024
    static let maximumRecords = 4096
    static func decode(data: Data, statusCode: Int?) throws -> [AppID] {
        guard let statusCode else { throw AppIDLookupError.invalidHTTPResponse }
        guard (200..<300).contains(statusCode) else { throw AppIDLookupError.httpFailure }
        guard data.count <= maximumResponseBytes else { throw AppIDLookupError.malformedList }

        // Select the wire format before decoding, so a typed validation failure is
        // never swallowed by a fallback decoder. Do not retain or log raw payloads.
        let response: Envelope
        if (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)) != nil {
            do { response = try PropertyListDecoder().decode(Envelope.self, from: data) }
            catch let error as AppIDLookupError { throw error }
            catch { throw AppIDLookupError.malformedList }
        } else {
            do { response = try JSONDecoder().decode(Envelope.self, from: data) }
            catch let error as AppIDLookupError { throw error }
            catch { throw AppIDLookupError.malformedList }
        }
        return response.appIDs
    }

    private struct Envelope: Decodable {
        let appIDs: [AppID]
        enum CodingKeys: String, CodingKey { case resultCode, appIds, errors }

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            guard let code = try? container.decode(Int.self, forKey: .resultCode) else {
                throw AppIDLookupError.missingStatus
            }
            guard code == 0 else { throw AppIDLookupError.unsuccessfulStatus }
            // A success code accompanied by provider errors is contradictory.
            if container.contains(.errors), !(try container.decodeNil(forKey: .errors)) {
                guard let errors = try? container.nestedUnkeyedContainer(forKey: .errors), errors.isAtEnd else {
                    throw AppIDLookupError.unsuccessfulStatus
                }
            }
            guard container.contains(.appIds) else { throw AppIDLookupError.missingList }
            guard try !container.decodeNil(forKey: .appIds) else { throw AppIDLookupError.nullList }
            var list: UnkeyedDecodingContainer
            do { list = try container.nestedUnkeyedContainer(forKey: .appIds) }
            catch { throw AppIDLookupError.malformedList }

            var appIDs: [AppID] = []
            var bundleByID: [String: String] = [:]
            var idByBundle: [String: String] = [:]
            while !list.isAtEnd {
                guard appIDs.count < maximumRecords else { throw AppIDLookupError.malformedList }
                let record: Record
                do { record = try list.decode(Record.self) }
                catch { throw AppIDLookupError.malformedRecord }
                let appID = record.appID
                if let bundle = bundleByID[appID.identifier], bundle != appID.bundleIdentifier {
                    throw AppIDLookupError.conflictingRecord
                }
                if let id = idByBundle[appID.bundleIdentifier], id != appID.identifier {
                    throw AppIDLookupError.conflictingRecord
                }
                bundleByID[appID.identifier] = appID.bundleIdentifier
                idByBundle[appID.bundleIdentifier] = appID.identifier
                // Keep exact duplicates; callers must detect ambiguous matches.
                appIDs.append(appID)
            }
            self.appIDs = appIDs
        }
    }

    private struct Record: Decodable {
        let appID: AppID
        enum CodingKeys: String, CodingKey { case appIdId, identifier }

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            let id = try container.decode(String.self, forKey: .appIdId)
            let bundle = try container.decode(String.self, forKey: .identifier)
            // Match preservation-origin opaque ID constraints exactly. Bundle
            // inventory may also contain unrelated wildcard registrations; accept
            // those without expanding them or changing exact-match authorization.
            func alphaNumericOrHyphen(_ byte: UInt8) -> Bool {
                (48...57).contains(byte) || (65...90).contains(byte) ||
                    (97...122).contains(byte) || byte == 45
            }
            let bundleStem = bundle.hasSuffix(".*") ? String(bundle.dropLast(2)) : bundle
            let validBundle = bundle == "*" || (!bundleStem.isEmpty &&
                bundleStem.utf8.allSatisfy { alphaNumericOrHyphen($0) || $0 == 46 })
            guard !id.isEmpty, id.utf8.count <= 256,
                  id.utf8.allSatisfy(alphaNumericOrHyphen),
                  !bundle.isEmpty, bundle.utf8.count <= 512, validBundle else {
                throw AppIDLookupError.malformedRecord
            }
            appID = try AppID(from: decoder)
        }
    }
}
