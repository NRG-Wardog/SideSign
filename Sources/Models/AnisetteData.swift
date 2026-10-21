//
//  AnisetteData.swift
//  SideSign
//
//  Created by Magesh K on 07/09/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation
import AnisetteKit

public struct AnisetteData: Sendable, Codable, Equatable, Hashable {
    public var machineID: String
    public var oneTimePassword: String
    public var localUserID: String
    public var routingInfo: String
    public var deviceID: String
    public var serialNumber: String
    public var clientInfo: String {
        didSet {
            // Public caller mutation invalidates the original selection, even
            // when it happens to produce the same advertised family.
            diagnosticHeaderProvenance = AnisetteHeaderProvenance(
                source: .caller, provider: diagnosticHeaderProvenance.provider,
                context: diagnosticHeaderProvenance.context)
        }
    }
    public var userAgent: String
    public var clientTime: String
    public var locale: String
    public var timeZone: String

    // Observation only: never persisted, sent as a request header, or included
    // in value identity. Decoded sessions have unknown provenance by design.
    private(set) var diagnosticHeaderProvenance = AnisetteHeaderProvenance()

    enum CodingKeys: String, CodingKey {
        case machineID
        case oneTimePassword
        case localUserID
        case routingInfo
        case deviceID
        case serialNumber
        case clientInfo
        case userAgent
        case clientTime
        case locale
        case timeZone
    }

    mutating func recordDiagnosticHeaderProvenance(source: AuthenticationHeaderSource,
                                                   provider: AuthenticationProviderMode,
                                                   context: AuthenticationAnisetteContext = .init()) {
        diagnosticHeaderProvenance = AnisetteHeaderProvenance(source: source, provider: provider, context: context)
    }

    mutating func markDiagnosticCacheHit(age: TimeInterval, requestedClientInfo: String) {
        // Observe this hit without relabeling unknown legacy generation facts.
        diagnosticHeaderProvenance = AnisetteHeaderProvenance(
            source: diagnosticHeaderProvenance.source, provider: diagnosticHeaderProvenance.provider,
            context: diagnosticHeaderProvenance.context.observingCacheHit(
                age: age, requestedClientInfo: requestedClientInfo, usedClientInfo: clientInfo))
    }

    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.machineID == rhs.machineID &&
        lhs.oneTimePassword == rhs.oneTimePassword &&
        lhs.localUserID == rhs.localUserID &&
        lhs.routingInfo == rhs.routingInfo &&
        lhs.deviceID == rhs.deviceID &&
        lhs.serialNumber == rhs.serialNumber &&
        lhs.clientInfo == rhs.clientInfo &&
        lhs.userAgent == rhs.userAgent &&
        lhs.clientTime == rhs.clientTime &&
        lhs.locale == rhs.locale &&
        lhs.timeZone == rhs.timeZone
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(machineID)
        hasher.combine(oneTimePassword)
        hasher.combine(localUserID)
        hasher.combine(routingInfo)
        hasher.combine(deviceID)
        hasher.combine(serialNumber)
        hasher.combine(clientInfo)
        hasher.combine(userAgent)
        hasher.combine(clientTime)
        hasher.combine(locale)
        hasher.combine(timeZone)
    }

    public var deviceUniqueIdentifier: String {
        get { deviceID }
        set { deviceID = newValue }
    }

    public var deviceDescription: String {
        get { clientInfo }
        set { clientInfo = newValue }
    }

    public var deviceSerialNumber: String {
        get { serialNumber }
        set { serialNumber = newValue }
    }

    public init(
        machineID: String,
        oneTimePassword: String,
        localUserID: String,
        routingInfo: String,
        deviceID: String,
        serialNumber: String,
        clientInfo: String,
        userAgent: String,
        clientTime: String,
        locale: String,
        timeZone: String
    ) {
        self.machineID = machineID
        self.oneTimePassword = oneTimePassword
        self.localUserID = localUserID
        self.routingInfo = routingInfo
        self.deviceID = deviceID
        self.serialNumber = serialNumber
        self.clientInfo = clientInfo
        self.userAgent = userAgent
        self.clientTime = clientTime
        self.locale = locale
        self.timeZone = timeZone
    }

    public func toRequestHeaders() -> AnisetteRequestHeaders {
        AnisetteRequestHeaders().with {
            $0.machineID = self.machineID
            $0.oneTimePassword = self.oneTimePassword
            $0.localUserID = self.localUserID
            $0.routingInfo = self.routingInfo
            $0.deviceID = self.deviceID
            $0.serialNumber = self.serialNumber
            $0.clientInfo = self.clientInfo
            $0.userAgent = self.userAgent
            $0.clientTime = self.clientTime
            $0.locale = self.locale
            $0.timeZone = self.timeZone
        }
    }
}
