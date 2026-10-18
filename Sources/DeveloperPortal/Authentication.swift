//
//  Authentication.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation
import GSACryptoKit
import AnisetteKit

public extension DeveloperPortal {

    func authenticate(appleID unsanitizedAppleID: String,
                      password: String,
                      anisetteData: AnisetteData,
                      xcodeVersion: String,
                      machinePassword: String? = nil,
                      accountRepairHandler: DeveloperPortal.AccountRepairHandler = DeveloperPortal.defaultAccountRepairHandler,
                      verificationHandler: DeveloperPortal.VerificationHandler? = nil) async throws -> AuthSession
    {
        let trace = LoginDiagnosticTrace.current
        var activeSpan = trace?.begin(.authSRPInit)
        do {
            let sanitizedAppleID = unsanitizedAppleID.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()

            let clientDictionary: [String: any Sendable] = [
                "bootstrap": true,
                "icscrec": true,
                "pbe": false,
                "prkgen": true,
                "svct": customHeaders.grandSlam.service,
                "loc": anisetteData.locale,
                "X-Apple-Locale": anisetteData.locale,
                "X-Apple-I-MD": anisetteData.oneTimePassword,
                "X-Apple-I-MD-M": anisetteData.machineID,
                "X-Mme-Device-Id": anisetteData.deviceID,
                "X-Apple-I-MD-LU": anisetteData.localUserID,
                "X-Apple-I-MD-RINFO": anisetteData.routingInfo,
                "X-Apple-I-SRL-NO": anisetteData.serialNumber,
                "X-Apple-I-Client-Time": anisetteData.clientTime,
                "X-Apple-I-TimeZone": anisetteData.timeZone
            ]

            guard let srpClient = SRPClient(),
                  let publicKey = srpClient.startAuthentication()
            else {
                throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Failed to start SRPClient / generate public key A")
            }

            // 1. Send authentication 'init' request
            let initParameters: [String: any Sendable] = [
                "A2k": publicKey,
                "cpd": clientDictionary,
                "ps": ["s2k", "s2k_fo"],
                "o": "init",
                "u": sanitizedAppleID
            ]

            let initResponse = try await sendAuthenticationRequest(parameters: initParameters, anisetteData: anisetteData)

            guard let c = initResponse["c"] as? String,
                  let salt = initResponse["s"] as? Data,
                  let iterations = initResponse["i"] as? Int,
                  let serverPublicKey = initResponse["B"] as? Data
            else {
                let payload = prettyJSONString(from: initResponse)
                throw ServerError.badServerResponse(reason: "Auth init response missing c/s/i/B parameters", jsonPayload: payload)
            }

            activeSpan?.finish(.succeeded)
            activeSpan = trace?.begin(.authSRPChallenge)

            let sp = initResponse["sp"] as? String
            let isHexadecimal = (sp == "s2k_fo")

            guard let passwordData = password.data(using: .utf8),
                  let digest = CryptoUtilities.sha256(passwordData) else {
                throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Failed to compute SHA256 of password")
            }

            let inputDigest: Data = isHexadecimal ? Data(digest.hexEncodedString().utf8) : digest
            guard let derivedPasswordKey = CryptoUtilities.pbkdf2SHA256(
                password: inputDigest,
                salt: salt,
                rounds: iterations,
                outputLength: digest.count
            ) else {
                throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Failed to derive PBKDF2 password key")
            }

            guard let verificationMessage = srpClient.processChallenge(
                username: sanitizedAppleID,
                password: derivedPasswordKey,
                salt: salt,
                serverPublicKey: serverPublicKey
            ) else {
                throw DeveloperPortalError.authenticationHandshakeFailed(cause: "SRP challenge processing failed")
            }

            activeSpan?.finish(.succeeded)
            activeSpan = trace?.begin(.authSRPComplete)

            // 2. Send authentication 'complete' request
            let completeParameters: [String: any Sendable] = [
                "c": c,
                "cpd": clientDictionary,
                "M1": verificationMessage,
                "o": "complete",
                "u": sanitizedAppleID
            ]

            let completeResponseDictionary = try await sendAuthenticationRequest(parameters: completeParameters, anisetteData: anisetteData)

            guard let encryptedData = completeResponseDictionary["spd"] as? Data else {
                let payload = prettyJSONString(from: completeResponseDictionary)
                throw ServerError.missingKey(key: "spd", jsonPayload: payload)
            }

            guard let serverVerificationMessage = completeResponseDictionary["M2"] as? Data else {
                let payload = prettyJSONString(from: completeResponseDictionary)
                throw ServerError.missingKey(key: "M2", jsonPayload: payload)
            }

            guard srpClient.verifyServerProof(serverVerificationMessage) else {
                throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Server verification proof (M2) mismatch")
            }

            activeSpan?.finish(.succeeded)
            activeSpan = trace?.begin(.authDecrypt)

            guard let sharedSecret = srpClient.sessionKey() else {
                throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Missing session key")
            }

            guard let spdKey = CryptoUtilities.hmacSHA256(key: sharedSecret, strings: ["extra data key:"]),
                  let spdIV = CryptoUtilities.hmacSHA256(key: sharedSecret, strings: ["extra data iv:"]),
                  let decryptedData = CryptoUtilities.aesCBCDecrypt(key: spdKey, iv: spdIV, ciphertext: encryptedData)
            else {
                throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Failed to AES-CBC decrypt SPD payload")
            }

            guard let decryptedDictionary = parsePlistOrJSON(decryptedData) else {
                let rawDecrypted = prettyJSONString(from: decryptedData)
                throw ServerError.invalidResponseFormat(rawPayload: rawDecrypted)
            }

            let adsid = decryptedDictionary["adsid"] as? String
            let dsidString = (decryptedDictionary["dsid"] as? CustomStringConvertible)?.description
            guard let dsid = adsid ?? dsidString else {
                let jsonStr = prettyJSONString(from: decryptedDictionary)
                throw ServerError.missingKey(key: "adsid", jsonPayload: jsonStr)
            }

            let gsIdmsToken = decryptedDictionary["GsIdmsToken"] as? String
            let rawIdmsToken = decryptedDictionary["idmsToken"] as? String
            guard let idmsToken = gsIdmsToken ?? rawIdmsToken else {
                let jsonStr = prettyJSONString(from: decryptedDictionary)
                throw ServerError.missingKey(key: "GsIdmsToken", jsonPayload: jsonStr)
            }

            activeSpan?.finish(.succeeded)
            activeSpan = nil

            // 2FA auth type
            let statusDictionary = completeResponseDictionary["Status"] as? [String: any Sendable]
            let authType = (statusDictionary?["au"] as? String)
               ?? (completeResponseDictionary["au"] as? String)

            let twoFactorAuthContext = TwoFactorAuthContext(
                dsid: dsid, 
                idmsToken: idmsToken, 
                anisetteData: anisetteData, 
                xcodeVersion: xcodeVersion
            )

            switch authType {
                case "trustedDeviceSecondaryAuth", "trustedDevice", "secondaryAuth", "sms", "voice", "phone":
                    let isTrustedDevice = (authType == "trustedDeviceSecondaryAuth" || authType == "trustedDevice")
                    try await handle2FARequest(
                        isTrustedDevice: isTrustedDevice,
                        completeResponseDictionary: completeResponseDictionary,
                        statusDictionary: statusDictionary,
                        context: twoFactorAuthContext,
                        verificationHandler: verificationHandler
                    )
                    // recur coz we just solved 2FA above and this invocation shouldn't come to this case
                    return try await authenticate(
                        appleID: unsanitizedAppleID, 
                        password: password, 
                        anisetteData: anisetteData, 
                        xcodeVersion: xcodeVersion, 
                        machinePassword: machinePassword, 
                        accountRepairHandler: accountRepairHandler, 
                        verificationHandler: verificationHandler
                    )

                case "repair":
                    trace?.skip(.twoFactor, reason: .notRequired)
                    activeSpan = trace?.begin(.authSession)
                    let directRepairURL = completeResponseDictionary["repairUrl"] as? String
                    let directURL = completeResponseDictionary["url"] as? String
                    let statusURL = (statusDictionary?["url"] as? String)
                    let repairURLString = directRepairURL ?? directURL ?? statusURL
                    let repairURL = repairURLString.flatMap { URL(string: $0) } ?? Constants.URLs.developerAccount

                    let rawMessage = (statusDictionary?["em"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)

                    let message: String
                    if let rawMessage, !rawMessage.isEmpty {
                        message = rawMessage
                    } else {
                        message = Constants.defaultAccountRepairMessage
                    }

                    let decision = try await accountRepairHandler(repairURL, message)

                    if decision == .cancel {
                        activeSpan?.finish(.failed, reason: .cancelled)
                        activeSpan = nil
                        throw DeveloperPortalError.accountRepairRequired(url: repairURL, message: message)
                    }

                default:
                    trace?.skip(.twoFactor, reason: .notRequired)
                    break
            }

            if activeSpan == nil {
                activeSpan = trace?.begin(.authSession)
            }
            guard let sessionKey = decryptedDictionary["sk"] as? Data else {
                throw ServerError.missingKey(key: "sk", jsonPayload: prettyJSONString(from: decryptedDictionary))
            }

            guard let c = decryptedDictionary["c"] as? Data else {
                throw ServerError.missingKey(key: "c", jsonPayload: prettyJSONString(from: decryptedDictionary))
            }

            let app = customHeaders.grandSlam.authApp
            guard let checksum = CryptoUtilities.hmacSHA256(key: sessionKey, strings: ["apptokens", dsid, app]) else {
                throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Failed to compute apptokens checksum")
            }

            let appTokensParameters: [String: any Sendable] = [
                "app": [app],
                "c": c,
                "checksum": checksum,
                "cpd": clientDictionary,
                "o": "apptokens",
                "t": idmsToken,
                "u": dsid
            ]

            let fetchedToken = try await fetchAuthToken(app: app, parameters: appTokensParameters, sessionKey: sessionKey, anisetteData: anisetteData)
            let session = Session(
                dsid: dsid,
                authToken: fetchedToken.token,
                anisetteData: anisetteData,
                xcodeVersion: xcodeVersion,
                machinePassword: machinePassword,
                creationDate: fetchedToken.creationDate,
                expirationDate: fetchedToken.expirationDate,
                timeToLive: fetchedToken.timeToLive
            )
            activeSpan?.finish(.succeeded)
            activeSpan = trace?.begin(.accountLookup)
            let account = try await fetchAccount(session: session)
            activeSpan?.finish(.succeeded)
            activeSpan = nil
            return AuthSession(account: account, session: session)
        } catch {
            activeSpan?.finish(.failed, reason: loginDiagnosticFailureReason(for: error), error: error)
            throw error
        }
    }

    func sendAuthenticationRequest(parameters requestParameters: [String: any Sendable], anisetteData: AnisetteData) async throws -> [String: any Sendable] {
        let requestURL = Constants.URLs.grandSlamAuth
        let h = customHeaders

        let parameters: [String: any Sendable] = [
            "Header": ["Version": h.grandSlam.headerVersion],
            "Request": requestParameters
        ]

        let plistData = try PropertyListSerialization.data(fromPropertyList: parameters, format: .xml, options: 0)

        var request = URLRequest(url: requestURL)
        request.httpMethod = "POST"
        request.httpBody = plistData

        let headers: [String: String] = [
            "Content-Type": "text/x-xml-plist",
            "X-MMe-Client-Info": anisetteData.clientInfo,
            "Accept": "*/*",
            "User-Agent": h.grandSlam.userAgent,
            "Connection": "close"
        ]
        headers.forEach { request.setValue($1, forHTTPHeaderField: $0) }

        let (data, response): (Data, URLResponse)
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw error
        }

        let httpResponse = response as? HTTPURLResponse
        let statusCode = httpResponse?.statusCode ?? 0

        guard !data.isEmpty else {
            throw ServerError.badServerResponse(reason: "Auth endpoint returned empty response (0 bytes)", jsonPayload: "0 bytes")
        }

        guard let responseDictionary = parsePlistOrJSON(data) else {
            let rawStr = String(data: data, encoding: .utf8) ?? data.hexEncodedString()
            throw ServerError.invalidResponseFormat(rawPayload: rawStr)
        }

        let dictionary = (responseDictionary["Response"] as? [String: any Sendable]) ?? responseDictionary
        guard let status = dictionary["Status"] as? [String: any Sendable] else {
            let rawStr = prettyJSONString(from: responseDictionary)
            throw ServerError.missingKey(key: "Status", jsonPayload: rawStr)
        }

        let errorCode = status["ec"] as? Int ?? 0
        if errorCode != 0 {
            let errorDesc = status["em"] as? String
            switch errorCode {
            case GrandSlamAuthErrorCodes.incorrectCredentials:
                throw DeveloperPortalError.incorrectCredentials(cause: errorDesc)
            case GrandSlamAuthErrorCodes.appSpecificPasswordRequired,
                 GrandSlamAuthErrorCodes.appSpecificPasswordRequiredFallback:
                throw DeveloperPortalError.appSpecificPasswordRequired(cause: errorDesc)
            case GrandSlamAuthErrorCodes.incorrectVerificationCode:
                throw DeveloperPortalError.incorrectVerificationCode(cause: errorDesc)
            default:
                throw ServerError.underlyingError(code: errorCode, message: errorDesc ?? "Authentication failed")
            }
        }

        return dictionary
    }

    private struct FetchedAuthToken {
        let token: String
        let creationDate: Date
        let expirationDate: Date?
        let timeToLive: TimeInterval?
    }

    private func fetchAuthToken(app: String, parameters: [String: any Sendable], sessionKey: Data, anisetteData: AnisetteData) async throws -> FetchedAuthToken {
        let responseDictionary = try await sendAuthenticationRequest(parameters: parameters, anisetteData: anisetteData)

        guard let encryptedToken = responseDictionary["et"] as? Data else {
            let payload = prettyJSONString(from: responseDictionary)
            throw ServerError.missingKey(key: "et", jsonPayload: payload)
        }

        guard encryptedToken.count > 35 else {
            throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Encrypted token payload is too short (\(encryptedToken.count) bytes)")
        }

        let aad = Data(encryptedToken[..<3])
        let nonce = Data(encryptedToken[3..<19])
        let ciphertext = Data(encryptedToken[19..<(encryptedToken.count - 16)])
        let tag = Data(encryptedToken[(encryptedToken.count - 16)...])

        guard let token = CryptoUtilities.aesGCMDecrypt(key: sessionKey, nonce: nonce, aad: aad, ciphertext: ciphertext, tag: tag) else {
            throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Failed to AES-GCM decrypt auth token")
        }

        guard let tokensDictionary = parsePlistOrJSON(token) else {
            let rawStr = prettyJSONString(from: token)
            throw ServerError.invalidResponseFormat(rawPayload: rawStr)
        }

        guard let appTokens = tokensDictionary["t"] as? [String: any Sendable],
              let tokens = appTokens[app] as? [String: any Sendable],
              let authToken = tokens["token"] as? String
        else {
            let payload = prettyJSONString(from: tokensDictionary)
            throw ServerError.missingKey(key: "t/\(app)/token", jsonPayload: payload)
        }

        let now = Date()
        var expirationDate: Date? = nil
        var timeToLive: TimeInterval? = nil

        if let expiry = tokens["expiry"] as? Date {
            expirationDate = expiry
            timeToLive = expiry.timeIntervalSince(now)
        } else if let expiryStr = tokens["expiry"] as? String, let parsed = ISO8601DateFormatter().date(from: expiryStr) {
            expirationDate = parsed
            timeToLive = parsed.timeIntervalSince(now)
        } else if let ttl = tokens["ttl"] as? Double ?? (tokens["ttl"] as? Int).map(Double.init) {
            timeToLive = ttl
            expirationDate = now.addingTimeInterval(ttl)
        } else if let exp = tokens["expiry-date"] as? Date {
            expirationDate = exp
            timeToLive = exp.timeIntervalSince(now)
        } else if let expStr = tokens["expiry-date"] as? String, let parsed = ISO8601DateFormatter().date(from: expStr) {
            expirationDate = parsed
            timeToLive = parsed.timeIntervalSince(now)
        }

        return FetchedAuthToken(token: authToken, creationDate: now, expirationDate: expirationDate, timeToLive: timeToLive)
    }

    private func parseTrustedPhoneNumbers(from dict: [String: any Sendable]?) -> [TrustedPhoneNumber] {
        var results: [TrustedPhoneNumber] = []
        let list = (dict?["trustedPhoneNumbers"] as? [[String: any Sendable]])
                ?? (dict?["phoneNumbers"] as? [[String: any Sendable]])
                ?? []
        for item in list {
            if let id = (item["id"] as? CustomStringConvertible)?.description.trimmingCharacters(in: .whitespacesAndNewlines), !id.isEmpty {
                let num = (item["numberWithDialCode"] as? String)
                        ?? (item["obfuscatedNumber"] as? String)
                        ?? (item["lastTwoDigits"] as? String).map { "••\($0)" }
                        ?? "Phone \(id)"
                results.append(TrustedPhoneNumber(id: id, number: num))
            }
        }
        if results.isEmpty, let single = dict?["phoneNumber"] as? [String: any Sendable],
           let id = (single["id"] as? CustomStringConvertible)?.description.trimmingCharacters(in: .whitespacesAndNewlines), !id.isEmpty {
            let num = (single["numberWithDialCode"] as? String)
                    ?? (single["obfuscatedNumber"] as? String)
                    ?? (single["lastTwoDigits"] as? String).map { "••\($0)" }
                    ?? "Phone \(id)"
            results.append(TrustedPhoneNumber(id: id, number: num))
        }
        return results
    }

    private func parseXMLUIAlertMessage(from data: Data) -> (title: String?, message: String?) {
        guard let str = String(data: data, encoding: .utf8) else { return (nil, nil) }
        if str.contains("<pinView") {
            return (nil, nil)
        }
        guard let alertTagRange = str.range(of: #"<alert(?![^>]*\bid=)[^>]*>"#, options: .regularExpression) else {
            return (nil, nil)
        }
        let alertTag = String(str[alertTagRange])
        var title: String?
        var message: String?
        if let titleRange = alertTag.range(of: #"(?<=title=")[^"]+"#, options: .regularExpression) {
            title = String(alertTag[titleRange])
        }
        if let msgRange = alertTag.range(of: #"(?<=message=")[^"]+"#, options: .regularExpression) {
            message = String(alertTag[msgRange])
        }
        return (title, message)
    }

    private func parseXMLUIServerInfo(from data: Data) -> (phoneID: String?, mode: String?) {
        guard let str = String(data: data, encoding: .utf8) else { return (nil, nil) }
        guard let range = str.range(of: #"<serverInfo[^>]*>"#, options: .regularExpression) else { return (nil, nil) }
        let tag = String(str[range])
        var phoneID: String?
        var mode: String?
        if let idRange = tag.range(of: #"(?<=phoneNumber\.id=")[^"]+"#, options: .regularExpression) {
            phoneID = String(tag[idRange])
        }
        if let modeRange = tag.range(of: #"(?<=mode=")[^"]+"#, options: .regularExpression) {
            mode = String(tag[modeRange])
        }
        return (phoneID, mode)
    }

    private func throwIfXMLUIErrorAlert(in data: Data, statusCode: Int, actionName: String) throws {
        let (xmluiTitle, xmluiMessage) = parseXMLUIAlertMessage(from: data)
        if xmluiTitle != nil || xmluiMessage != nil {
            let alertMsg = [xmluiTitle, xmluiMessage]
                .compactMap { $0?.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
                .joined(separator: ": ")
            throw DeveloperPortalError.invalid2FAResponse(cause: xmluiMessage ?? alertMsg)
        }
    }

    private func parseXMLUIObfuscatedNumber(from data: Data) -> String? {
        guard let str = String(data: data, encoding: .utf8) else { return nil }
        let patterns = [
            #"(?:to|at)\s+([+•\d\s\(\)-]{4,25})[.\s<]"#,
            #"([+•\d\s\(\)-]*[•]+[+•\d\s\(\)-]*)"#
        ]
        for pattern in patterns {
            if let matchRange = str.range(of: pattern, options: .regularExpression) {
                let matched = String(str[matchRange])
                    .replacingOccurrences(of: "to ", with: "")
                    .replacingOccurrences(of: "at ", with: "")
                    .trimmingCharacters(in: CharacterSet(charactersIn: ". <\n\r\t"))
                if matched.contains("•") && matched.count >= 3 {
                    return matched
                }
            }
        }
        return nil
    }

    private struct TwoFactorAuthContext {
        let dsid: String
        let idmsToken: String
        let anisetteData: AnisetteData
        let xcodeVersion: String
    }

    private struct TwoFactorAuthPhoneCodeResponse {
        let phoneID: String
        let activeMode: String
        let phoneNumbers: [TrustedPhoneNumber]
        let statusCode: Int
    }

    private enum TwoFactorAuthChannel {
        case trustedDevice
        case sms(phoneID: String)
        case voice(phoneID: String)
    }

    // V3_TFA_TYPED_STATE_V1: wrong-code state comes from SideSign's typed response parser.
    private enum TwoFactorAuthValidationResult {
        case success
        case retry(TwoFactorVerificationFailure)
    }

    private func handle2FARequest(isTrustedDevice: Bool,
                            completeResponseDictionary: [String: any Sendable],
                            statusDictionary: [String: any Sendable]?,
                            context: TwoFactorAuthContext,
                            verificationHandler: VerificationHandler?) async throws 
    {
        let trace = LoginDiagnosticTrace.current
        let twoFactorSpan = trace?.begin(.twoFactor)
        var deliverySpan: LoginDiagnosticSpan?
        do {
            guard let verificationHandler else {
                throw DeveloperPortalError.requiresTwoFactorAuthentication
            }

            var phoneNumbers = parseTrustedPhoneNumbers(from: completeResponseDictionary)
            if phoneNumbers.isEmpty, let statusDictionary {
                phoneNumbers = parseTrustedPhoneNumbers(from: statusDictionary)
            }

            let preferredMode: TwoFactorDeliveryMode = isTrustedDevice ? .trustedDevice : .sms

            var currentRequest: TwoFactorRequest = .selectDeliveryMethod(
                preferredMode: preferredMode,
                phoneNumbers: phoneNumbers
            )
            var activeChannel: TwoFactorAuthChannel? = nil

            while true {
                if case .selectDeliveryMethod = currentRequest {
                    deliverySpan = trace?.begin(.twoFactorDelivery)
                }
                let response = try await verificationHandler(currentRequest)
                if case .cancel = response {
                    deliverySpan?.finish(.failed, reason: .cancelled)
                } else {
                    deliverySpan?.finish(.succeeded)
                }
                deliverySpan = nil

                switch response {
                    case .requestTrustedDevice:
                        try await sendTrustedDevice2FACodeRequest(context: context)
                        activeChannel = .trustedDevice
                        currentRequest = .trustedDevice(error: nil)

                    case .requestSMS(let targetPhoneID):
                        let result = try await sendPhone2FACodeRequest(mode: "sms", phoneID: targetPhoneID, knownPhoneNumbers: phoneNumbers, context: context)
                        phoneNumbers = result.phoneNumbers
                        activeChannel = .sms(phoneID: result.phoneID)
                        currentRequest = .sms(phoneNumbers: phoneNumbers, activeID: result.phoneID, error: nil)

                    case .requestVoice(let targetPhoneID):
                        let result = try await sendPhone2FACodeRequest(mode: "voice", phoneID: targetPhoneID, knownPhoneNumbers: phoneNumbers, context: context)
                        phoneNumbers = result.phoneNumbers
                        activeChannel = .voice(phoneID: result.phoneID)
                        currentRequest = .voice(phoneNumbers: phoneNumbers, activeID: result.phoneID, error: nil)

                    case .verificationCode(let code):
                        guard let channel = activeChannel else {
                            throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Unexpected verification code returned before a delivery method was selected.")
                        }

                        let result: TwoFactorAuthValidationResult
                        switch channel {
                            case .trustedDevice:
                                result = try await validateTrustedDevice2FACode(code: code, context: context)
                            case .sms(let phoneID):
                                result = try await validatePhone2FACode(code: code, phoneID: phoneID, mode: "sms", context: context)
                            case .voice(let phoneID):
                                result = try await validatePhone2FACode(code: code, phoneID: phoneID, mode: "voice", context: context)
                        }

                        switch result {
                            case .success:
                                twoFactorSpan?.finish(.succeeded)
                                return
                            case .retry(let failure):
                                let typedError = "V3_TFA_FAILURE:\(failure.rawValue)"
                                switch channel {
                                    case .trustedDevice:
                                        currentRequest = .trustedDevice(error: typedError)
                                    case .sms(let phoneID):
                                        currentRequest = .sms(phoneNumbers: phoneNumbers, activeID: phoneID, error: typedError)
                                    case .voice(let phoneID):
                                        currentRequest = .voice(phoneNumbers: phoneNumbers, activeID: phoneID, error: typedError)
                                }
                        }

                    case .cancel:
                        throw DeveloperPortalError.userCancelled
                }
            }
        } catch {
            let reason = loginDiagnosticFailureReason(for: error)
            deliverySpan?.finish(.failed, reason: reason, error: error)
            twoFactorSpan?.finish(.failed, reason: reason, error: error)
            throw error
        }
    }

    private func sendTrustedDevice2FACodeRequest(context: TwoFactorAuthContext) async throws {
        let span = LoginDiagnosticTrace.current?.begin(.twoFactorRequest)
        do {
            var request = makeTwoFactorAuthRequest(url: Constants.URLs.trustedDevice, context: context)
            request.httpMethod = "GET"

            let (data, response) = try await session.data(for: request)
            let httpResponse = response as? HTTPURLResponse
            let statusCode = httpResponse?.safeStatusCode ?? 0
            try throwIfXMLUIErrorAlert(in: data, statusCode: statusCode, actionName: "sendTrustedDevice2FACodeRequest")

            guard statusCode == HTTPStatusCodes.ok else {
                let rawStr = prettyJSONString(from: data)
                throw ServerError.badServerResponse(reason: "Trusted device request failed (HTTP \(statusCode))", jsonPayload: rawStr)
            }
            span?.finish(.succeeded)
        } catch {
            span?.finish(.failed, reason: loginDiagnosticFailureReason(for: error), error: error)
            throw error
        }
    }

    private func sendPhone2FACodeRequest(mode requestedMode: String,
                                      phoneID requestedPhoneID: String? = nil,
                                      knownPhoneNumbers: [TrustedPhoneNumber] = [],
                                      context: TwoFactorAuthContext) async throws -> TwoFactorAuthPhoneCodeResponse
    {
        let span = LoginDiagnosticTrace.current?.begin(.twoFactorRequest)
        do {
            let sanitizedPhoneID: String = {
                if let id = requestedPhoneID?.trimmingCharacters(in: .whitespacesAndNewlines), !id.isEmpty {
                    return id
                }
                return "1"
            }()

            let serverInfo: [String: any Sendable] = [
                "mode": requestedMode,
                "phoneNumber.id": sanitizedPhoneID
            ]

            var request = makeTwoFactorAuthRequest(url: Constants.URLs.phonePutURL(mode: requestedMode), context: context)
            request.httpMethod = "POST"
            request.httpBody = try PropertyListSerialization.data(fromPropertyList: [
                "serverInfo": serverInfo
            ], format: .xml, options: 0)

            let (data, response) = try await session.data(for: request)
            let httpResponse = response as? HTTPURLResponse
            let statusCode = httpResponse?.safeStatusCode ?? 0

            let rawStr = prettyJSONString(from: data)

            try throwIfXMLUIErrorAlert(in: data, statusCode: statusCode, actionName: "sendPhone2FACodeRequest")

            let responseDict = parsePlistOrJSON(data)
            let errorCode = responseDict?["ec"] as? Int ?? 0
            let errorMsg = (responseDict?["em"] as? String)
                       ?? ((responseDict?["Status"] as? [String: any Sendable])?["em"] as? String)

            if errorCode == GrandSlamAuthErrorCodes.tooManyAttempts 
                || errorCode == GrandSlamAuthErrorCodes.tooManyCodesRequested 
                || errorCode == GrandSlamAuthErrorCodes.rateLimited 
                || statusCode == HTTPStatusCodes.tooManyRequests
            {
                let msg = errorMsg ?? "Verification codes cannot be sent to this phone number at this time. Please try again later."
                throw DeveloperPortalError.tooManyAttempts(cause: msg)
            } else if errorCode != 0 {
                let msg = errorMsg ?? "Failed to request verification code from Apple."
                throw ServerError.underlyingError(code: errorCode, message: msg)
            }

            guard statusCode == HTTPStatusCodes.ok else {
                let reason = errorMsg ?? HTTPStatusCodes.localizedDescription(for: statusCode)
                throw ServerError.badServerResponse(reason: reason, jsonPayload: rawStr)
            }

            var parsedNumbers = parseTrustedPhoneNumbers(from: responseDict)
            if parsedNumbers.isEmpty {
                parsedNumbers = knownPhoneNumbers
            }
            let singlePhoneDict = responseDict?["phoneNumber"] as? [String: any Sendable]
            let phoneListFirst = (responseDict?["phoneNumbers"] as? [[String: any Sendable]])?.first
            let trustedPhoneListFirst = (responseDict?["trustedPhoneNumbers"] as? [[String: any Sendable]])?.first
            let phoneDict = singlePhoneDict ?? phoneListFirst ?? trustedPhoneListFirst

            let (xmluiServerPhoneID, xmluiServerMode) = parseXMLUIServerInfo(from: data)

            let rawPhoneID = (phoneDict?["id"] as? CustomStringConvertible)?.description.trimmingCharacters(in: .whitespacesAndNewlines)
            let resolvedPhoneID: String? = (rawPhoneID?.isEmpty == false) ? rawPhoneID : xmluiServerPhoneID
            let resolvedRequestedID: String? = (requestedPhoneID?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false) ? requestedPhoneID : nil

            let phoneID = resolvedPhoneID ?? resolvedRequestedID ?? parsedNumbers.first?.id ?? "1"
            let activeMode = (phoneDict?["mode"] as? String) ?? xmluiServerMode ?? requestedMode

            let numberWithDialCode = phoneDict?["numberWithDialCode"] as? String
            let obfuscatedNumber = phoneDict?["obfuscatedNumber"] as? String
            let lastTwoDigits = (phoneDict?["lastTwoDigits"] as? String).map { "••\($0)" }
            let xmluiNumber = parseXMLUIObfuscatedNumber(from: data)
            let matchedNumber = parsedNumbers.first(where: { $0.id == phoneID })?.number

            let numberObfuscated = numberWithDialCode
                                ?? obfuscatedNumber
                                ?? lastTwoDigits
                                ?? xmluiNumber
                                ?? matchedNumber
                                ?? ""
            if let idx = parsedNumbers.firstIndex(where: { $0.id == phoneID }), !numberObfuscated.isEmpty {
                parsedNumbers[idx] = TrustedPhoneNumber(id: phoneID, number: numberObfuscated)
            } else if parsedNumbers.isEmpty && !numberObfuscated.isEmpty {
                parsedNumbers = [TrustedPhoneNumber(id: phoneID, number: numberObfuscated)]
            }

            span?.finish(.succeeded)
            return TwoFactorAuthPhoneCodeResponse(
                phoneID: phoneID,
                activeMode: activeMode,
                phoneNumbers: parsedNumbers,
                statusCode: statusCode
            )
        } catch {
            span?.finish(.failed, reason: loginDiagnosticFailureReason(for: error), error: error)
            throw error
        }
    }

    private func validateTrustedDevice2FACode(code: String, context: TwoFactorAuthContext) async throws -> TwoFactorAuthValidationResult {
        let span = LoginDiagnosticTrace.current?.begin(.twoFactorVerify)
        do {
            var verifyRequest = makeTwoFactorAuthRequest(url: Constants.URLs.grandSlamValidate, context: context)
            verifyRequest.setValue(code, forHTTPHeaderField: "security-code")

            let (verifyData, verifyResponse) = try await session.data(for: verifyRequest)
            let verifyHttpResponse = verifyResponse as? HTTPURLResponse
            let verifyStatusCode = verifyHttpResponse?.safeStatusCode ?? 0

            let result = try parseTwoFactorAuthVerifyResponse(data: verifyData, statusCode: verifyStatusCode, requirePeToken: false, httpResponse: verifyHttpResponse)
            finishTwoFactorVerificationSpan(span, result: result)
            return result
        } catch {
            span?.finish(.failed, reason: loginDiagnosticFailureReason(for: error), error: error)
            throw error
        }
    }

    private func validatePhone2FACode(code: String,
                                      phoneID: String,
                                      mode: String,
                                      context: TwoFactorAuthContext) async throws -> TwoFactorAuthValidationResult
    {
        let span = LoginDiagnosticTrace.current?.begin(.twoFactorVerify)
        do {
            var verifyRequest = makeTwoFactorAuthRequest(url: Constants.URLs.phoneSecurityCode, context: context)
            verifyRequest.httpMethod = "POST"
            verifyRequest.httpBody = try PropertyListSerialization.data(fromPropertyList: [
                "securityCode.code": code,
                "serverInfo": ["mode": mode, "phoneNumber.id": phoneID]
            ], format: .xml, options: 0)

            let (verifyData, verifyResponse) = try await session.data(for: verifyRequest)
            let verifyHttpResponse = verifyResponse as? HTTPURLResponse
            let verifyStatusCode = verifyHttpResponse?.safeStatusCode ?? 0

            let result = try parseTwoFactorAuthVerifyResponse(data: verifyData, statusCode: verifyStatusCode, requirePeToken: true, httpResponse: verifyHttpResponse)
            finishTwoFactorVerificationSpan(span, result: result)
            return result
        } catch {
            span?.finish(.failed, reason: loginDiagnosticFailureReason(for: error), error: error)
            throw error
        }
    }

    private func finishTwoFactorVerificationSpan(_ span: LoginDiagnosticSpan?, result: TwoFactorAuthValidationResult) {
        switch result {
        case .success:
            span?.finish(.succeeded)
        case .retry(let failure):
            let reason: LoginDiagnosticReason
            switch failure {
            case .incorrectCode: reason = .rejected
            case .serviceUnavailable: reason = .unavailable
            case .unknown: reason = .invalidResponse
            }
            span?.finish(.failed, reason: reason)
        }
    }

    private func loginDiagnosticFailureReason(for error: Error) -> LoginDiagnosticReason {
        if error is CancellationError { return .cancelled }
        if let urlError = error as? URLError, urlError.code == .cancelled { return .cancelled }
        if let portalError = error as? DeveloperPortalError {
            switch portalError {
            case .userCancelled: return .cancelled
            case .incorrectCredentials, .incorrectVerificationCode, .appSpecificPasswordRequired, .tooManyAttempts:
                return .rejected
            case .authenticationHandshakeFailed, .invalid2FAResponse:
                return .invalidResponse
            default: return .unavailable
            }
        }
        if let serverError = error as? ServerError {
            switch serverError {
            case .underlyingError: return .rejected
            default: return .invalidResponse
            }
        }
        return .unavailable
    }

    private func parseTwoFactorAuthVerifyResponse(data: Data,
                                                  statusCode: Int,
                                                  requirePeToken: Bool,
                                                  httpResponse: HTTPURLResponse?) throws -> TwoFactorAuthValidationResult
    {
        let verifyDictionary = parsePlistOrJSON(data)
        let (xmluiTitle, xmluiMessage) = parseXMLUIAlertMessage(from: data)
        let errorCode = verifyDictionary?["ec"] as? Int ?? 0
        let statusDict = verifyDictionary?["Status"] as? [String: any Sendable]
        let errorMsg = (verifyDictionary?["em"] as? String)
                    ?? (statusDict?["em"] as? String)
                    ?? xmluiMessage
                    ?? xmluiTitle

        if errorCode == GrandSlamAuthErrorCodes.tooManyAttempts 
            || errorCode == GrandSlamAuthErrorCodes.tooManyCodesRequested 
            || errorCode == GrandSlamAuthErrorCodes.rateLimited 
            || statusCode == HTTPStatusCodes.tooManyRequests
        {
            let msg = errorMsg ?? "Too many verification code attempts. Please try again later."
            throw DeveloperPortalError.tooManyAttempts(cause: msg)
        } else if errorCode == GrandSlamAuthErrorCodes.incorrectVerificationCode {
            return .retry(.incorrectCode)
        } else if errorCode != 0 {
            let msg = errorMsg ?? "2FA verification error"
            throw ServerError.underlyingError(code: errorCode, message: msg)
        }

        if xmluiTitle != nil || xmluiMessage != nil {
            let message = xmluiMessage ?? errorMsg ?? xmluiTitle ?? "Verification failed"
            throw DeveloperPortalError.invalid2FAResponse(cause: message)
        }

        guard statusCode == HTTPStatusCodes.ok else {
            return .retry(statusCode >= 500 || statusCode == 0 ? .serviceUnavailable : .unknown)
        }

        if requirePeToken {
            guard httpResponse?.allHeaderFields.keys.contains(where: { ($0 as? String)?.lowercased() == "x-apple-pe-token" }) == true else {
                return .retry(.unknown)
            }
        }

        return .success
    }

    private func makeTwoFactorAuthRequest(url: URL, context: TwoFactorAuthContext) -> URLRequest {
        let identityToken = "\(context.dsid):\(context.idmsToken)"
        let encodedIdentityToken = Data(identityToken.utf8).base64EncodedString()

        var request = URLRequest(url: url)
        let a = context.anisetteData
        let h = customHeaders
        let headers: [String: String] = [
            "Accept": "application/x-buddyml",
            "Accept-Language": "en-us",
            "Content-Type": "application/x-plist",
            "User-Agent": h.developerServices.userAgent,
            "X-Apple-App-Info": h.grandSlam.authApp,
            "X-Xcode-Version": context.xcodeVersion,
            "X-Apple-Identity-Token": encodedIdentityToken,
            "X-Apple-I-MD": a.oneTimePassword,
            "X-Apple-I-MD-M": a.machineID,
            "X-Mme-Device-Id": a.deviceID,
            "X-MMe-Client-Info": a.clientInfo,
            "X-Apple-I-MD-LU": a.localUserID,
            "X-Apple-I-MD-RINFO": a.routingInfo,
            "X-Apple-I-SRL-NO": a.serialNumber,
            "X-Apple-I-Client-Time": a.clientTime,
            "X-Apple-Locale": a.locale,
            "X-Apple-I-TimeZone": a.timeZone,
            "Connection": "close"
        ]
        headers.forEach { request.setValue($1, forHTTPHeaderField: $0) }
        return request
    }

    private func parsePlistOrJSON(_ data: Data) -> [String: any Sendable]? {
           (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: any Sendable]
        ?? (try? JSONSerialization.jsonObject(with: data, options: [])) as? [String: any Sendable]
    }
}
