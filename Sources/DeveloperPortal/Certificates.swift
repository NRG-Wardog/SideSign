//
//  Certificates.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation
import CodeSignKit

public extension DeveloperPortal {

    func fetchCertificates(for team: Team, session: Session) async throws -> [X509Certificate] {
        debugLog("[SideSign] fetchCertificates starting...")

        let endpoint: X509Certificate.CertificateEndpoint = (team.type != .free) ? .developerPortal : .developerServices2

        var request = URLRequest(url: endpoint.url)
        request.httpMethod = "GET"

        let certificates: [X509Certificate]
        switch endpoint {
        case .developerPortal:
            let response: CertificatesResponseDeveloperPortal = try await sendServicesRequest(request, session: session, team: team)
            certificates = response.data?.compactMap { $0.toCertificate() } ?? []
        case .developerServices2:
            let response: CertificatesResponseDeveloperServices2 = try await sendServicesRequest(request, session: session, team: team)
            certificates = response.data?.compactMap { $0.toCertificate() } ?? []
        }

        return certificates
    }

    func addCertificate(machineName: String, type: CertificateType, to team: Team, session: Session) async throws -> KeyStore {
        debugLog("[SideSign] addCertificate starting...")

        if team.type == .free && type.isPaidOnly {
            throw DeveloperPortalError.invalidParameters(cause: "Free Apple Developer accounts cannot create \(type.displayName) certificates. Only Apple Development certificates are supported.")
        }

        let request = try CertificateRequest(machineName: machineName)
        return try await addCertificate(request: request, machineIdentifier: UUID().uuidString.uppercased(),
                                        type: type, to: team, session: session)
    }

    // The caller retains this exact request before submitting it. This overload
    // never generates replacement key material or a replacement machine ID.
    func addCertificate(request certRequest: CertificateRequest, machineIdentifier: String,
                        type: CertificateType, to team: Team, session: Session) async throws -> KeyStore {
        guard !certRequest.privateKey.isEmpty, !certRequest.csrData.isEmpty,
              UUID(uuidString: machineIdentifier) != nil else {
            throw DeveloperPortalError.invalidParameters(cause: "Invalid prepared certificate request.")
        }
        if team.type == .free && type.isPaidOnly {
            throw DeveloperPortalError.invalidParameters(cause: "This certificate type requires a paid account.")
        }
        let machineName = certRequest.machineName

        let csrString = String(decoding: certRequest.csrData, as: UTF8.self)

        let parameters = [
            "csrContent": csrString,
            "machineName": machineName,
            "machineId": machineIdentifier
        ]

        let submitURL: URL
        switch type.category {
        case .distribution:
            submitURL = Constants.URLs.submitDistributionCSR
        case .development:
            submitURL = Constants.URLs.submitDevelopmentCSR
        }

        let response: AddCertificateResponse = try await sendRequest(
            url: submitURL,
            additionalParameters: parameters,
            session: session,
            team: team,
            resultCodeHandler: { code, message in
                switch code {
                case DeveloperPortalResultCodes.invalidCertificateRequest:
                    return DeveloperPortalError.invalidCertificateRequest(cause: message)
                case DeveloperPortalResultCodes.maximumCertificatesReachedAlternate, DeveloperPortalResultCodes.maximumCertificatesReached:
                    return DeveloperPortalError.tooManyCertificates(cause: message)
                default: return nil
                }
            }
        )

        let cert: X509Certificate
        if let directCert = response.certRequest?.toCertificate() {
            cert = directCert
        } else {
            let serial = response.certRequest?.serialNumber
            let certId = response.certRequest?.certificateId ?? response.certRequest?.certRequestId
            let allCerts = try await fetchCertificates(for: team, session: session)

            guard let matchedCert = allCerts.first(where: {
                if let serial, $0.serialNumber.caseInsensitiveCompare(serial) == .orderedSame { return true }
                if let certId, $0.identifier == certId { return true }
                return false
            }) else {
                debugLog("[SideSign] addCertificate error: Failed to retrieve new certificate from Developer Portal")
                throw ServerError.badServerResponse(reason: "Failed to retrieve new certificate from Developer Portal", jsonPayload: "")
            }
            cert = matchedCert
        }

        debugLog("[SideSign] addCertificate succeeded")
        return KeyStore(certificate: cert, privateKey: certRequest.privateKey)
    }

    func revokeCertificate(_ certificate: X509Certificate, for team: Team, session: Session) async throws -> Bool {
        let certIdentifier = certificate.identifier ?? certificate.serialNumber
        debugLog("[SideSign] revokeCertificate starting...")

        let endpoint: X509Certificate.CertificateEndpoint
        if let source = certificate.sourceEndpoint {
            endpoint = source
        } else {
            endpoint = (team.type != .free) ? .developerPortal : .developerServices2
        }

        let url = endpoint.url.appendingPathComponent(certIdentifier)
        var request = URLRequest(url: url)
        request.httpMethod = "DELETE"

        let _: EmptyResponse = try await sendServicesRequest(request, additionalParameters: nil, session: session, team: team)
        debugLog("[SideSign] revokeCertificate succeeded")
        return true
    }
}
