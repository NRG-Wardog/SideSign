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

private enum PushedCodeState {
    @TaskLocal static var handled = false
}

public extension DeveloperPortal {

    func authenticate(appleID unsanitizedAppleID: String,
                      password: String,
                      anisetteData: AnisetteData,
                      xcodeVersion: String,
                      machinePassword: String? = nil,
                      accountRepairHandler: DeveloperPortal.AccountRepairHandler = DeveloperPortal.defaultAccountRepairHandler,
                      verificationHandler: DeveloperPortal.VerificationHandler? = nil) async throws -> AuthSession
    {
        let diagnostic = AuthenticationDiagnosticTrace.current
        return try await AuthenticationDiagnosticTrace.$invocation.withValue(diagnostic?.beginAuthentication()) {
        let trace = LoginDiagnosticTrace.current
        var activeSpan = trace?.begin(.authSRPInit)
        do {
            let sanitizedAppleID = unsanitizedAppleID.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            let remoteContext = ILoaderRemoteAuthentication.current
            var anisetteData = anisetteData
            if let remoteContext { anisetteData = try await remoteContext.fetch() }

            let clientDictionary: [String: any Sendable] = remoteContext == nil ? [
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
            ] : ILoaderAuthenticationPolicy.clientDictionary(anisetteData)

            diagnostic?.authentication(.srpInit)
            guard let srpClient = SRPClient(),
                  let publicKey = srpClient.startAuthentication()
            else {
                throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Failed to start SRPClient / generate public key A")
            }

            // 1. Send authentication 'init' request
            var initParameters: [String: any Sendable] = [
                "A2k": publicKey,
                "cpd": clientDictionary,
                "ps": ["s2k", "s2k_fo"],
                "o": "init",
                "u": sanitizedAppleID
            ]

            var (initResponse, initObservation) = try await sendObservedAuthenticationRequest(parameters: initParameters, anisetteData: anisetteData)
            if let remoteContext,
               let status = initResponse["Status"] as? [String: any Sendable], ILoaderAuthenticationPolicy.signedInteger(status["hsc"]) == 434 {
                guard let sim = ILoaderAuthenticationPolicy.resyncSIM(initResponse), !sim.isEmpty else {
                    throw DeveloperPortalError.authenticationHandshakeFailed(cause: "The bounded anisette resynchronization could not complete.")
                }
                initObservation?.consumer(.initFields, .retry)
                anisetteData = try await remoteContext.resynchronize(sim: sim)
                initParameters["cpd"] = ILoaderAuthenticationPolicy.clientDictionary(anisetteData)
                // Official isideload reuses A2k on resync, but complete retains the original CPD.
                (initResponse, initObservation) = try await sendObservedAuthenticationRequest(parameters: initParameters, anisetteData: anisetteData)
                if let status = initResponse["Status"] as? [String: any Sendable], ILoaderAuthenticationPolicy.signedInteger(status["hsc"]) == 434 {
                    throw DeveloperPortalError.authenticationHandshakeFailed(cause: "The bounded anisette resynchronization could not complete.")
                }
            }

            guard let c = initResponse["c"] as? String,
                  let salt = initResponse["s"] as? Data,
                  let iterations = initResponse["i"] as? Int,
                  let serverPublicKey = initResponse["B"] as? Data
            else {
                let payload = prettyJSONString(from: initResponse)
                initObservation?.consumer(.initFields, .failed)
                throw ServerError.badServerResponse(reason: "Auth init response missing c/s/i/B parameters", jsonPayload: payload)
            }

            if remoteContext != nil, ILoaderAuthenticationPolicy.signedInteger(initResponse["i"]) == nil || iterations <= 0 {
                initObservation?.consumer(.initFields, .failed)
                throw ServerError.badServerResponse(reason: "Invalid iLoader authentication response.", jsonPayload: "")
            }
            activeSpan?.finish(.succeeded)
            initObservation?.consumer(.initFields, .passed)
            activeSpan = trace?.begin(.authSRPChallenge)

            let sp = initResponse["sp"] as? String
            if remoteContext != nil, sp != "s2k" && sp != "s2k_fo" {
                throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Unsupported SRP protocol selected")
            }
            let isHexadecimal = (sp == "s2k_fo")

            diagnostic?.authentication(.hash)
            guard let passwordData = password.data(using: .utf8),
                  let digest = CryptoUtilities.sha256(passwordData) else {
                throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Failed to compute SHA256 of password")
            }

            let inputDigest: Data = isHexadecimal ? Data(digest.hexEncodedString().utf8) : digest
            diagnostic?.authentication(.pbkdf2)
            guard let derivedPasswordKey = CryptoUtilities.pbkdf2SHA256(
                password: inputDigest,
                salt: salt,
                rounds: iterations,
                outputLength: digest.count
            ) else {
                throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Failed to derive PBKDF2 password key")
            }

            diagnostic?.authentication(.challenge)
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

            let (completeResponseDictionary, completeObservation) = try await sendObservedAuthenticationRequest(parameters: completeParameters, anisetteData: anisetteData)

            guard let encryptedData = completeResponseDictionary["spd"] as? Data else {
                let payload = prettyJSONString(from: completeResponseDictionary)
                completeObservation?.consumer(.completeSPD, .failed)
                throw ServerError.missingKey(key: "spd", jsonPayload: payload)
            }

            guard let serverVerificationMessage = completeResponseDictionary["M2"] as? Data else {
                let payload = prettyJSONString(from: completeResponseDictionary)
                completeObservation?.consumer(.proofField, .failed)
                throw ServerError.missingKey(key: "M2", jsonPayload: payload)
            }

            diagnostic?.authentication(.proof)
            guard srpClient.verifyServerProof(serverVerificationMessage) else {
                completeObservation?.consumer(.proof, .failed)
                throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Server verification proof (M2) mismatch")
            }

            activeSpan?.finish(.succeeded)
            activeSpan = trace?.begin(.authDecrypt)

            diagnostic?.authentication(.sharedSecret)
            guard let sharedSecret = srpClient.sessionKey() else {
                completeObservation?.consumer(.sharedSecret, .failed)
                throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Missing session key")
            }

            diagnostic?.authentication(.spdDecrypt)
            guard let spdKey = CryptoUtilities.hmacSHA256(key: sharedSecret, strings: ["extra data key:"]),
                  let spdIV = CryptoUtilities.hmacSHA256(key: sharedSecret, strings: ["extra data iv:"]),
                  let decryptedData = CryptoUtilities.aesCBCDecrypt(key: spdKey, iv: spdIV, ciphertext: encryptedData)
            else {
                completeObservation?.consumer(.spdDecrypt, .failed)
                throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Failed to AES-CBC decrypt SPD payload")
            }

            diagnostic?.authentication(.spdParse)
            guard let decryptedDictionary = parsePlistOrJSON(decryptedData) else {
                let rawDecrypted = prettyJSONString(from: decryptedData)
                completeObservation?.consumer(.spdParse, .failed)
                throw ServerError.invalidResponseFormat(rawPayload: rawDecrypted)
            }

            let adsid = decryptedDictionary["adsid"] as? String
            let dsidString = (decryptedDictionary["dsid"] as? CustomStringConvertible)?.description
            guard let dsid = adsid ?? dsidString else {
                let jsonStr = prettyJSONString(from: decryptedDictionary)
                completeObservation?.consumer(.dsid, .failed)
                throw ServerError.missingKey(key: "adsid", jsonPayload: jsonStr)
            }

            let gsIdmsToken = decryptedDictionary["GsIdmsToken"] as? String
            let rawIdmsToken = decryptedDictionary["idmsToken"] as? String
            guard let idmsToken = gsIdmsToken ?? rawIdmsToken else {
                let jsonStr = prettyJSONString(from: decryptedDictionary)
                completeObservation?.consumer(.idms, .failed)
                throw ServerError.missingKey(key: "GsIdmsToken", jsonPayload: jsonStr)
            }

            activeSpan?.finish(.succeeded)
            activeSpan = nil

            completeObservation?.consumer(.idms, .passed)
            // 2FA auth type
            let statusDictionary = completeResponseDictionary["Status"] as? [String: any Sendable]
            let authType = (statusDictionary?["au"] as? String)
               ?? (completeResponseDictionary["au"] as? String)
               ?? ((statusDictionary?["hsc"] as? Int) == 409 ? "pushedCode" : nil)

            let twoFactorAuthContext = TwoFactorAuthContext(
                dsid: dsid, 
                idmsToken: idmsToken, 
                anisetteData: anisetteData, 
                xcodeVersion: xcodeVersion
            )

            switch authType {
                case "trustedDeviceSecondaryAuth", "trustedDevice", "secondaryAuth", "sms", "voice", "phone", "pushedCode":
                    let pushedCode = authType == "pushedCode"
                    guard !pushedCode || !PushedCodeState.handled else {
                        throw DeveloperPortalError.requiresTwoFactorAuthentication
                    }
                    let isTrustedDevice = pushedCode || authType == "trustedDeviceSecondaryAuth" || authType == "trustedDevice"
                    diagnostic?.authentication(.twoFactor)
            try await handle2FARequest(
                        isTrustedDevice: isTrustedDevice,
                        completeResponseDictionary: completeResponseDictionary,
                        statusDictionary: statusDictionary,
                        context: twoFactorAuthContext,
                        verificationHandler: verificationHandler,
                        codeAlreadySent: pushedCode
                    )
                    return try await PushedCodeState.$handled.withValue(PushedCodeState.handled || pushedCode) {
                        try await authenticate(
                            appleID: unsanitizedAppleID,
                            password: password,
                            anisetteData: anisetteData,
                            xcodeVersion: xcodeVersion,
                            machinePassword: machinePassword,
                            accountRepairHandler: accountRepairHandler,
                            verificationHandler: verificationHandler
                        )
                    }

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

                    diagnostic?.authentication(.accountRepair)
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
            diagnostic?.authentication(.sessionKey)
            guard let sessionKey = decryptedDictionary["sk"] as? Data else {
                completeObservation?.consumer(.sessionKey, .failed)
                throw ServerError.missingKey(key: "sk", jsonPayload: prettyJSONString(from: decryptedDictionary))
            }

            diagnostic?.authentication(.sessionChallenge)
            guard let c = decryptedDictionary["c"] as? Data else {
                completeObservation?.consumer(.sessionChallenge, .failed)
                throw ServerError.missingKey(key: "c", jsonPayload: prettyJSONString(from: decryptedDictionary))
            }

            if let remoteContext { anisetteData = try await remoteContext.fetch() }
            let app = remoteContext == nil ? customHeaders.grandSlam.authApp : "com.apple.gs.xcode.auth"
            diagnostic?.authentication(.checksum)
            guard let checksum = CryptoUtilities.hmacSHA256(key: sessionKey, strings: ["apptokens", dsid, app]) else {
                completeObservation?.consumer(.checksum, .failed)
                throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Failed to compute apptokens checksum")
            }

            let appTokensParameters: [String: any Sendable] = [
                "app": [app],
                "c": c,
                "checksum": checksum,
                "cpd": remoteContext == nil ? clientDictionary : ILoaderAuthenticationPolicy.clientDictionary(anisetteData),
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
            diagnostic?.authentication(.accountLookup)
            let account = try await fetchAccount(session: session)
            activeSpan?.finish(.succeeded)
            activeSpan = nil
            diagnostic?.authentication(.complete, .passed)
            return AuthSession(account: account, session: session)
        } catch {
            diagnostic?.authenticationFailed()
            activeSpan?.finish(.failed, reason: loginDiagnosticFailureReason(for: error), error: error)
            throw error
        }
        }
    }

    func sendAuthenticationRequest(parameters requestParameters: [String: any Sendable], anisetteData: AnisetteData) async throws -> [String: any Sendable] {
        let (dictionary, _) = try await sendObservedAuthenticationRequest(parameters: requestParameters, anisetteData: anisetteData)
        return dictionary
    }

    private func sendObservedAuthenticationRequest(parameters requestParameters: [String: any Sendable], anisetteData: AnisetteData) async throws -> ([String: any Sendable], AuthenticationDiagnosticTrace.Request?) {
        let diagnostic = AuthenticationDiagnosticTrace.current
        let requestURL = Constants.URLs.grandSlamAuth
        var diagnosticHeaders = diagnosticCustomHeadersSnapshot()
        if ILoaderRemoteAuthentication.current != nil {
            var effective = diagnosticHeaders.headers
            effective.grandSlam.userAgent = anisetteData.userAgent
            effective.grandSlam.headerVersion = "1.0.1"
            effective.grandSlam.service = "iCloud"
            effective.grandSlam.authApp = "com.apple.gs.xcode.auth"
            diagnosticHeaders = DiagnosticCustomHeadersSnapshot(headers: effective, source: .provider)
        }
        let h = diagnosticHeaders.headers

        let parameters: [String: any Sendable] = [
            "Header": ["Version": h.grandSlam.headerVersion],
            "Request": requestParameters
        ]

        diagnostic?.authentication(.serialization)
        var diagnosticSerialized = false
        defer { if !diagnosticSerialized { diagnostic?.authentication(.serialization, .failed) } }
        let plistData = try PropertyListSerialization.data(fromPropertyList: parameters, format: .xml, options: 0)
        diagnosticSerialized = true

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
        if ILoaderRemoteAuthentication.current != nil {
            request.allHTTPHeaderFields = ILoaderAuthenticationPolicy.baseHeaders(clientInfo: anisetteData.clientInfo, userAgent: anisetteData.userAgent)
        }

        let observation = diagnostic?.beginRequest(request, phase: requestParameters["o"] as? String ?? "unknown",
            parameters: requestParameters, headerVersion: h.grandSlam.headerVersion,
            provenance: AuthenticationHeaderProvenance(anisetteData: anisetteData, grandSlamHeaders: diagnosticHeaders).encoded)
        let (data, response): (Data, URLResponse)
        do {
            (data, response) = try await OwnedODAAuthentication.data(for: request, legacySession: ILoaderRemoteAuthentication.current?.session ?? session, remoteSelected: ILoaderRemoteAuthentication.current != nil)
        } catch {
            observation?.transport(error)
            throw error
        }
        observation?.response(request: request, data: data, response: response)

        let httpResponse = response as? HTTPURLResponse
        let statusCode = httpResponse?.statusCode ?? 0
        if ILoaderRemoteAuthentication.current != nil, !(200..<300).contains(statusCode) {
            observation?.finish(.rejected, reason: .http)
            throw ServerError.invalidResponseFormat(rawPayload: "", responseContext: AuthenticationResponseContext(data: data, httpStatus: statusCode, mimeType: (response as? HTTPURLResponse)?.mimeType))
        }

        guard !data.isEmpty else {
            observation?.finish(.empty)
            throw ServerError.badServerResponse(reason: "Auth endpoint returned empty response (0 bytes)", jsonPayload: "0 bytes")
        }

        let decodedResponse = ILoaderRemoteAuthentication.current == nil
            ? parsePlistOrJSON(data, observation: observation)
            : parseILoaderPlist(data, observation: observation)
        guard let responseDictionary = decodedResponse else {
            observation?.finish(.parse)
            let context = AuthenticationResponseContext(data: data, httpStatus: statusCode, mimeType: response.mimeType)
            throw ServerError.invalidResponseFormat(rawPayload: "[redacted]", responseContext: context)
        }

        if ILoaderRemoteAuthentication.current != nil,
           !(responseDictionary["Response"] is [String: any Sendable]) {
            observation?.finish(.parse)
            throw ServerError.badServerResponse(reason: "Invalid iLoader authentication response.", jsonPayload: "")
        }
        let dictionary = (responseDictionary["Response"] as? [String: any Sendable]) ?? responseDictionary
        observation?.envelope(responseDictionary, nested: responseDictionary["Response"] is [String: any Sendable])
        guard let status = dictionary["Status"] as? [String: any Sendable] else {
            observation?.status(dictionary["Status"], ec: nil, hsc: nil, effective: nil, source: "status")
            observation?.finish(.status)
            let rawStr = prettyJSONString(from: responseDictionary)
            throw ServerError.missingKey(key: "Status", jsonPayload: rawStr)
        }

        if ILoaderRemoteAuthentication.current != nil, ILoaderAuthenticationPolicy.signedInteger(status["hsc"]) == 434 {
            observation?.status(status, ec: status["ec"], hsc: status["hsc"], effective: ILoaderAuthenticationPolicy.signedInteger(status["ec"]) ?? 0, source: "status", strictIntegerConsumer: true)
            guard requestParameters["o"] as? String == "init" else {
                observation?.finish(.rejected, reason: .underlying)
                throw DeveloperPortalError.authenticationHandshakeFailed(cause: "The bounded anisette resynchronization could not complete.")
            }
            observation?.finish(.accepted)
            return (dictionary, observation)
        }
        let errorCode = ILoaderRemoteAuthentication.current == nil ? (status["ec"] as? Int ?? 0) : (ILoaderAuthenticationPolicy.signedInteger(status["ec"]) ?? 0)
        observation?.status(status, ec: status["ec"], hsc: status["hsc"], effective: errorCode, source: "status", strictIntegerConsumer: ILoaderRemoteAuthentication.current != nil)
        if errorCode != 0 {
            let errorDesc = status["em"] as? String
            switch errorCode {
            case GrandSlamAuthErrorCodes.incorrectCredentials:
                observation?.finish(.rejected, reason: .credentials)
                throw DeveloperPortalError.incorrectCredentials(cause: errorDesc)
            case GrandSlamAuthErrorCodes.appSpecificPasswordRequired,
                 GrandSlamAuthErrorCodes.appSpecificPasswordRequiredFallback:
                observation?.finish(.rejected, reason: .appPassword)
                throw DeveloperPortalError.appSpecificPasswordRequired(cause: errorDesc)
            case GrandSlamAuthErrorCodes.incorrectVerificationCode:
                observation?.finish(.rejected, reason: .verification)
                throw DeveloperPortalError.incorrectVerificationCode(cause: errorDesc)
            default:
                observation?.finish(.rejected, reason: .underlying)
                throw ServerError.underlyingError(code: errorCode, message: errorDesc ?? "Authentication failed")
            }
        }

        observation?.finish(.accepted)
        return (dictionary, observation)
    }

    private struct FetchedAuthToken {
        let token: String
        let creationDate: Date
        let expirationDate: Date?
        let timeToLive: TimeInterval?
    }

    private func fetchAuthToken(app: String, parameters: [String: any Sendable], sessionKey: Data, anisetteData: AnisetteData) async throws -> FetchedAuthToken {
        let (responseDictionary, observation) = try await sendObservedAuthenticationRequest(parameters: parameters, anisetteData: anisetteData)

        guard let encryptedToken = responseDictionary["et"] as? Data else {
            let payload = prettyJSONString(from: responseDictionary)
            observation?.consumer(.tokenField, .failed)
                throw ServerError.missingKey(key: "et", jsonPayload: payload)
        }

        guard encryptedToken.count > 35 else {
            observation?.consumer(.tokenLength, .failed)
                throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Encrypted token payload is too short (\(encryptedToken.count) bytes)")
        }

        let aad = Data(encryptedToken[..<3])
        let nonce = Data(encryptedToken[3..<19])
        let ciphertext = Data(encryptedToken[19..<(encryptedToken.count - 16)])
        let tag = Data(encryptedToken[(encryptedToken.count - 16)...])

        guard let token = CryptoUtilities.aesGCMDecrypt(key: sessionKey, nonce: nonce, aad: aad, ciphertext: ciphertext, tag: tag) else {
            observation?.consumer(.tokenDecrypt, .failed)
                throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Failed to AES-GCM decrypt auth token")
        }

        guard let tokensDictionary = parsePlistOrJSON(token) else {
            let rawStr = prettyJSONString(from: token)
            observation?.consumer(.tokenParse, .failed)
                throw ServerError.invalidResponseFormat(rawPayload: rawStr)
        }

        guard let appTokens = tokensDictionary["t"] as? [String: any Sendable],
              let tokens = appTokens[app] as? [String: any Sendable],
              let authToken = tokens["token"] as? String
        else {
            let payload = prettyJSONString(from: tokensDictionary)
            observation?.consumer(.tokenPath, .failed)
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

        observation?.consumer(.tokenPath, .passed)
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

    private func throwIfXMLUIErrorAlert(in data: Data, statusCode: Int, actionName: String, observation: AuthenticationDiagnosticTrace.Request? = nil) throws {
        let (xmluiTitle, xmluiMessage) = parseXMLUIAlertMessage(from: data)
        if xmluiTitle != nil || xmluiMessage != nil {
            let alertMsg = [xmluiTitle, xmluiMessage]
                .compactMap { $0?.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
                .joined(separator: ": ")
            observation?.consumer(.xmlAlert, .failed)
            observation?.finish(.rejected, reason: .xmlAlert)
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
                            verificationHandler: VerificationHandler?,
                            codeAlreadySent: Bool = false) async throws
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

            if ILoaderRemoteAuthentication.current != nil, phoneNumbers.isEmpty {
                phoneNumbers = try await fetchILoaderTrustedNumbers(context: context)
            }
            let preferredMode: TwoFactorDeliveryMode = isTrustedDevice ? .trustedDevice : .sms

            var currentRequest: TwoFactorRequest = codeAlreadySent
                ? .trustedDevice(error: nil)
                : .selectDeliveryMethod(preferredMode: preferredMode, phoneNumbers: phoneNumbers)
            var activeChannel: TwoFactorAuthChannel? = codeAlreadySent ? .trustedDevice : nil

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
        var observation: AuthenticationDiagnosticTrace.Request?
        do {
            let context = try await refreshedILoaderContext(context)
            var request = makeTwoFactorAuthRequest(url: Constants.URLs.trustedDevice, context: context)
            request.httpMethod = "GET"

            observation = AuthenticationDiagnosticTrace.current?.beginRequest(request, phase: "trustedRequest")
            let (data, response) = try await OwnedODAAuthentication.data(for: request, legacySession: ILoaderRemoteAuthentication.current?.session ?? session, remoteSelected: ILoaderRemoteAuthentication.current != nil)
            observation?.response(request: request, data: data, response: response)
            let httpResponse = response as? HTTPURLResponse
            let statusCode = httpResponse?.safeStatusCode ?? 0
            if ILoaderRemoteAuthentication.current == nil {
                try throwIfXMLUIErrorAlert(in: data, statusCode: statusCode, actionName: "sendTrustedDevice2FACodeRequest", observation: observation)
            }

            guard ILoaderRemoteAuthentication.current == nil ? statusCode == HTTPStatusCodes.ok : (200..<300).contains(statusCode) else {
                observation?.consumer(.http, .failed)
                observation?.finish(.rejected, reason: .http)
                let rawStr = prettyJSONString(from: data)
                throw ServerError.badServerResponse(reason: "Trusted device request failed (HTTP \(statusCode))", jsonPayload: rawStr)
            }
            observation?.consumer(.http, .passed)
            observation?.finish(.accepted)
            span?.finish(.succeeded)
        } catch {
            observation?.transport(error)
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
        var observation: AuthenticationDiagnosticTrace.Request?
        do {
            if ILoaderRemoteAuthentication.current != nil {
                guard requestedMode == "sms" else { throw DeveloperPortalError.invalid2FAResponse(cause: "This remote route supports SMS or trusted-device verification, not voice.") }
                let selectedID = requestedPhoneID?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                let target: String
                if selectedID.isEmpty, knownPhoneNumbers.count == 1 { target = knownPhoneNumbers[0].id }
                else { target = selectedID }
                guard !target.isEmpty, knownPhoneNumbers.contains(where: { $0.id == target }) else {
                    throw DeveloperPortalError.invalid2FAResponse(cause: "Select a verified trusted phone number, or use trusted-device verification.")
                }
                let result = try await sendILoaderPhoneCode(phoneID: target, knownPhoneNumbers: knownPhoneNumbers, context: context)
                span?.finish(.succeeded)
                return result
            }
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
            AuthenticationDiagnosticTrace.current?.authentication(.serialization)
            var diagnosticSerialized = false
            defer { if !diagnosticSerialized { AuthenticationDiagnosticTrace.current?.authentication(.serialization, .failed) } }
            request.httpBody = try PropertyListSerialization.data(fromPropertyList: [
                "serverInfo": serverInfo
            ], format: .xml, options: 0)

            diagnosticSerialized = true
            observation = AuthenticationDiagnosticTrace.current?.beginRequest(request, phase: "phoneRequest")
            let (data, response) = try await OwnedODAAuthentication.data(for: request, legacySession: ILoaderRemoteAuthentication.current?.session ?? session, remoteSelected: ILoaderRemoteAuthentication.current != nil)
            observation?.response(request: request, data: data, response: response)
            let httpResponse = response as? HTTPURLResponse
            let statusCode = httpResponse?.safeStatusCode ?? 0

            let rawStr = prettyJSONString(from: data)

            try throwIfXMLUIErrorAlert(in: data, statusCode: statusCode, actionName: "sendPhone2FACodeRequest", observation: observation)

            let responseDict = parsePlistOrJSON(data, observation: observation)
            let errorCode = responseDict?["ec"] as? Int ?? 0
            observation?.status(responseDict?["Status"], ec: responseDict?["ec"], hsc: (responseDict?["Status"] as? [String: any Sendable])?["hsc"], effective: errorCode, source: "top")
            let errorMsg = (responseDict?["em"] as? String)
                       ?? ((responseDict?["Status"] as? [String: any Sendable])?["em"] as? String)

            if errorCode == GrandSlamAuthErrorCodes.tooManyAttempts 
                || errorCode == GrandSlamAuthErrorCodes.tooManyCodesRequested 
                || errorCode == GrandSlamAuthErrorCodes.rateLimited 
                || statusCode == HTTPStatusCodes.tooManyRequests
            {
                let msg = errorMsg ?? "Verification codes cannot be sent to this phone number at this time. Please try again later."
                observation?.finish(.rejected, reason: .rateLimit)
                throw DeveloperPortalError.tooManyAttempts(cause: msg)
            } else if errorCode != 0 {
                let msg = errorMsg ?? "Failed to request verification code from Apple."
                observation?.finish(.rejected, reason: .underlying)
                throw ServerError.underlyingError(code: errorCode, message: msg)
            }

            guard statusCode == HTTPStatusCodes.ok else {
                observation?.consumer(.http, .failed)
                observation?.finish(.rejected, reason: .http)
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

            observation?.consumer(.http, .passed)
            observation?.finish(.accepted)
            span?.finish(.succeeded)
            return TwoFactorAuthPhoneCodeResponse(
                phoneID: phoneID,
                activeMode: activeMode,
                phoneNumbers: parsedNumbers,
                statusCode: statusCode
            )
        } catch {
            observation?.transport(error)
            span?.finish(.failed, reason: loginDiagnosticFailureReason(for: error), error: error)
            throw error
        }
    }

    private func validateTrustedDevice2FACode(code: String, context: TwoFactorAuthContext) async throws -> TwoFactorAuthValidationResult {
        let span = LoginDiagnosticTrace.current?.begin(.twoFactorVerify)
        var observation: AuthenticationDiagnosticTrace.Request?
        do {
            let context = try await refreshedILoaderContext(context)
            var verifyRequest = makeTwoFactorAuthRequest(url: Constants.URLs.grandSlamValidate, context: context)
            verifyRequest.setValue(code, forHTTPHeaderField: "security-code")

            observation = AuthenticationDiagnosticTrace.current?.beginRequest(verifyRequest, phase: "trustedVerify")
            let (verifyData, verifyResponse) = try await OwnedODAAuthentication.data(for: verifyRequest, legacySession: ILoaderRemoteAuthentication.current?.session ?? session, remoteSelected: ILoaderRemoteAuthentication.current != nil)
            observation?.response(request: verifyRequest, data: verifyData, response: verifyResponse)
            let verifyHttpResponse = verifyResponse as? HTTPURLResponse
            let verifyStatusCode = verifyHttpResponse?.safeStatusCode ?? 0

            let result = try parseTwoFactorAuthVerifyResponse(data: verifyData, statusCode: verifyStatusCode, requirePeToken: false, httpResponse: verifyHttpResponse, observation: observation)
            finishTwoFactorVerificationSpan(span, result: result)
            return result
        } catch {
            observation?.transport(error)
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
        var observation: AuthenticationDiagnosticTrace.Request?
        do {
            if ILoaderRemoteAuthentication.current != nil {
                guard mode == "sms" else { throw DeveloperPortalError.invalid2FAResponse(cause: "This remote route supports SMS or trusted-device verification, not voice.") }
                let result = try await verifyILoaderPhoneCode(code: code, phoneID: phoneID, context: context)
                finishTwoFactorVerificationSpan(span, result: result)
                return result
            }
            var verifyRequest = makeTwoFactorAuthRequest(url: Constants.URLs.phoneSecurityCode, context: context)
            verifyRequest.httpMethod = "POST"
            AuthenticationDiagnosticTrace.current?.authentication(.serialization)
            var diagnosticSerialized = false
            defer { if !diagnosticSerialized { AuthenticationDiagnosticTrace.current?.authentication(.serialization, .failed) } }
            verifyRequest.httpBody = try PropertyListSerialization.data(fromPropertyList: [
                "securityCode.code": code,
                "serverInfo": ["mode": mode, "phoneNumber.id": phoneID]
            ], format: .xml, options: 0)

            diagnosticSerialized = true
            observation = AuthenticationDiagnosticTrace.current?.beginRequest(verifyRequest, phase: "phoneVerify")
            let (verifyData, verifyResponse) = try await OwnedODAAuthentication.data(for: verifyRequest, legacySession: ILoaderRemoteAuthentication.current?.session ?? session, remoteSelected: ILoaderRemoteAuthentication.current != nil)
            observation?.response(request: verifyRequest, data: verifyData, response: verifyResponse)
            let verifyHttpResponse = verifyResponse as? HTTPURLResponse
            let verifyStatusCode = verifyHttpResponse?.safeStatusCode ?? 0

            let result = try parseTwoFactorAuthVerifyResponse(data: verifyData, statusCode: verifyStatusCode, requirePeToken: true, httpResponse: verifyHttpResponse, observation: observation)
            finishTwoFactorVerificationSpan(span, result: result)
            return result
        } catch {
            observation?.transport(error)
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
                                                  httpResponse: HTTPURLResponse?,
                                                  observation: AuthenticationDiagnosticTrace.Request? = nil) throws -> TwoFactorAuthValidationResult
    {
        let verifyDictionary = ILoaderRemoteAuthentication.current == nil
            ? parsePlistOrJSON(data, observation: observation)
            : parseILoaderPlist(data, observation: observation)
        if ILoaderRemoteAuthentication.current != nil, verifyDictionary == nil {
            observation?.finish(.parse)
            throw ServerError.badServerResponse(reason: "Invalid iLoader authentication response.", jsonPayload: "")
        }
        let (xmluiTitle, xmluiMessage) = parseXMLUIAlertMessage(from: data)
        let errorCode = ILoaderRemoteAuthentication.current == nil
            ? (verifyDictionary?["ec"] as? Int ?? 0)
            : (ILoaderAuthenticationPolicy.signedInteger(((verifyDictionary?["Status"] as? [String: any Sendable]) ?? verifyDictionary)?["ec"]) ?? 0)
        let statusDict = verifyDictionary?["Status"] as? [String: any Sendable]
        observation?.status(verifyDictionary?["Status"], ec: ILoaderRemoteAuthentication.current == nil ? verifyDictionary?["ec"] : (statusDict ?? verifyDictionary)?["ec"], hsc: statusDict?["hsc"], effective: errorCode, source: ILoaderRemoteAuthentication.current != nil && statusDict != nil ? "status" : "top", strictIntegerConsumer: ILoaderRemoteAuthentication.current != nil)
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
            observation?.finish(.rejected, reason: .rateLimit)
            throw DeveloperPortalError.tooManyAttempts(cause: msg)
        } else if errorCode == GrandSlamAuthErrorCodes.incorrectVerificationCode {
            observation?.consumer(.verify, .retry)
            observation?.finish(.rejected, reason: .incorrectCode)
            return .retry(.incorrectCode)
        } else if errorCode != 0 {
            let msg = errorMsg ?? "2FA verification error"
            observation?.finish(.rejected, reason: .underlying)
            throw ServerError.underlyingError(code: errorCode, message: msg)
        }

        if xmluiTitle != nil || xmluiMessage != nil {
            let message = xmluiMessage ?? errorMsg ?? xmluiTitle ?? "Verification failed"
            observation?.consumer(.xmlAlert, .failed)
            observation?.finish(.rejected, reason: .xmlAlert)
            throw DeveloperPortalError.invalid2FAResponse(cause: message)
        }

        guard ILoaderRemoteAuthentication.current == nil ? statusCode == HTTPStatusCodes.ok : (200..<300).contains(statusCode) else {
            observation?.consumer(.http, .retry)
            observation?.finish(.rejected, reason: statusCode >= 500 || statusCode == 0 ? .serviceUnavailable : .unknown)
            return .retry(statusCode >= 500 || statusCode == 0 ? .serviceUnavailable : .unknown)
        }

        if requirePeToken {
            guard httpResponse?.allHeaderFields.keys.contains(where: { ($0 as? String)?.lowercased() == "x-apple-pe-token" }) == true else {
                observation?.consumer(.peToken, .retry)
                observation?.finish(.rejected, reason: .peToken)
                return .retry(.unknown)
            }
        }

        observation?.consumer(.verify, .passed)
        observation?.finish(.accepted)
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
        // Choose once before applying headers: Foundation need not remove old fields
        // when allHTTPHeaderFields is assigned after individual legacy fields.
        let effectiveHeaders = ILoaderRemoteAuthentication.current == nil ? headers :
            ILoaderAuthenticationPolicy.twoFactorHeaders(a, dsid: context.dsid, token: context.idmsToken, sms: false)
        effectiveHeaders.forEach { request.setValue($1, forHTTPHeaderField: $0) }
        return request
    }

    private func refreshedILoaderContext(_ context: TwoFactorAuthContext) async throws -> TwoFactorAuthContext {
        guard let remote = ILoaderRemoteAuthentication.current else { return context }
        let data = try await remote.fetch()
        return TwoFactorAuthContext(dsid: context.dsid, idmsToken: context.idmsToken,
            anisetteData: data, xcodeVersion: context.xcodeVersion)
    }

    private func parseILoaderPlist(_ data: Data, observation: AuthenticationDiagnosticTrace.Request?) -> [String: any Sendable]? {
        let plist = try? PropertyListSerialization.propertyList(from: data, format: nil)
        let dictionary = plist as? [String: any Sendable]
        observation?.parser(plist: plist, json: nil, selected: dictionary == nil ? "failure" : "plist")
        return dictionary
    }

    private func fetchILoaderTrustedNumbers(context: TwoFactorAuthContext) async throws -> [TrustedPhoneNumber] {
        guard let remote = ILoaderRemoteAuthentication.current else { throw ILoaderRemoteError.consentRequired }
        let context = try await refreshedILoaderContext(context)
        let request = ILoaderAuthenticationPolicy.trustedNumbersRequest(data: context.anisetteData, dsid: context.dsid, token: context.idmsToken)
        let observation = AuthenticationDiagnosticTrace.current?.beginRequest(request, phase: "unknown")
        let data: Data
        do {
            let (received, response) = try await remote.session.data(for: request)
            data = received
            observation?.response(request: request, data: data, response: response)
        } catch {
            observation?.transport(error)
            if error is CancellationError || (error as? URLError)?.code == .cancelled { throw error }
            // Optional discovery failure does not block trusted-device verification.
            return []
        }
        do {
            observeILoaderJSON(data, observation: observation)
            let numbers = try ILoaderAuthenticationPolicy.trustedNumbers(data)
            observation?.finish(.accepted)
            return numbers
        } catch {
            observation?.finish(.parse)
            return []
        }
    }

    private func sendILoaderPhoneCode(phoneID: String, knownPhoneNumbers: [TrustedPhoneNumber], context: TwoFactorAuthContext) async throws -> TwoFactorAuthPhoneCodeResponse {
        guard let remote = ILoaderRemoteAuthentication.current, let id = UInt32(phoneID) else { throw DeveloperPortalError.invalid2FAResponse(cause: "A verified trusted phone number is required.") }
        let context = try await refreshedILoaderContext(context)
        let request = try ILoaderAuthenticationPolicy.phoneRequest(data: context.anisetteData,
            dsid: context.dsid, token: context.idmsToken, phoneID: id, code: nil)
        let observation = AuthenticationDiagnosticTrace.current?.beginRequest(request, phase: "phoneRequest")
        do {
            let (data, response) = try await remote.session.data(for: request)
            observation?.response(request: request, data: data, response: response)
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            if !(200..<300).contains(status) { observeILoaderJSON(data, observation: observation) }
            let result = ILoaderAuthenticationPolicy.classifySMS(status: status, data: data, phoneID: id, verifying: false)
            switch result {
            case .accepted:
                observation?.finish(.accepted)
                return TwoFactorAuthPhoneCodeResponse(phoneID: String(id), activeMode: "sms", phoneNumbers: knownPhoneNumbers, statusCode: status)
            case .incorrectCode:
                observation?.finish(.rejected, reason: .incorrectCode)
                throw DeveloperPortalError.incorrectVerificationCode(cause: nil)
            case .rejected(let code):
                observation?.finish(.rejected, reason: .underlying)
                if code == "-22979" || code == "-22981" {
                    return TwoFactorAuthPhoneCodeResponse(phoneID: String(id), activeMode: "sms", phoneNumbers: knownPhoneNumbers, statusCode: status)
                }
                throw DeveloperPortalError.invalid2FAResponse(cause: "Apple did not accept the SMS request.")
            }
        } catch {
            observation?.transport(error)
            throw error
        }
    }

    private func verifyILoaderPhoneCode(code: String, phoneID: String, context: TwoFactorAuthContext) async throws -> TwoFactorAuthValidationResult {
        guard let remote = ILoaderRemoteAuthentication.current, let id = UInt32(phoneID) else { throw DeveloperPortalError.invalid2FAResponse(cause: "A verified trusted phone number is required.") }
        let context = try await refreshedILoaderContext(context)
        let request = try ILoaderAuthenticationPolicy.phoneRequest(data: context.anisetteData,
            dsid: context.dsid, token: context.idmsToken, phoneID: id, code: code)
        let observation = AuthenticationDiagnosticTrace.current?.beginRequest(request, phase: "phoneVerify")
        do {
            let (data, response) = try await remote.session.data(for: request)
            observation?.response(request: request, data: data, response: response)
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            if !(200..<300).contains(status) { observeILoaderJSON(data, observation: observation) }
            switch ILoaderAuthenticationPolicy.classifySMS(status: status, data: data, phoneID: id, verifying: true) {
            case .accepted: observation?.finish(.accepted); return .success
            case .incorrectCode:
                observation?.consumer(.verify, .retry)
                observation?.finish(.rejected, reason: .incorrectCode)
                return .retry(.incorrectCode)
            case .rejected:
                observation?.finish(.rejected, reason: .underlying)
                throw DeveloperPortalError.invalid2FAResponse(cause: "Apple did not accept the SMS verification.")
            }
        } catch {
            observation?.transport(error)
            throw error
        }
    }

    private func observeILoaderJSON(_ data: Data, observation: AuthenticationDiagnosticTrace.Request?) {
        let object = try? JSONSerialization.jsonObject(with: data)
        observation?.parser(plist: nil, json: object, selected: object is [String: Any] ? "json" : "failure")
    }

    private func parsePlistOrJSON(_ data: Data, observation: AuthenticationDiagnosticTrace.Request? = nil) -> [String: any Sendable]? {
        let plist = try? PropertyListSerialization.propertyList(from: data, format: nil)
        if let dictionary = plist as? [String: any Sendable] {
            observation?.parser(plist: plist, json: nil, selected: "plist")
            return dictionary
        }
        let json = try? JSONSerialization.jsonObject(with: data, options: [])
        let dictionary = json as? [String: any Sendable]
        observation?.parser(plist: plist, json: json, selected: dictionary == nil ? "failure" : "json")
        return dictionary
    }
}
