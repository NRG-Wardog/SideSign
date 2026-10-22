// Same-file private probe only. Production policy/transport bodies remain unchanged.
extension DeveloperPortal {
    func fixtureRemoteTwoFactor(_ operation: Int) async throws -> String {
        if operation != 1 { return try await fixtureTwoFactor(operation) }
        let context = TwoFactorAuthContext(dsid:"synthetic-dsid",idmsToken:"synthetic-idms",anisetteData:fixedAnisette(),xcodeVersion:"synthetic-xcode")
        let result = try await sendPhone2FACodeRequest(mode:"sms",phoneID:"1",
            knownPhoneNumbers:[TrustedPhoneNumber(id:"1",number:"synthetic-number")],context:context)
        return "phone:\(result.phoneID):\(result.activeMode):\(result.statusCode):\(result.phoneNumbers)"
    }
}
