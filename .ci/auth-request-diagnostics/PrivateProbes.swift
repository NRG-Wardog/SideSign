// Appended in the same file as the complete production extension; no body is replaced.
extension DeveloperPortal {
    func fixtureTwoFactor(_ operation: Int) async throws -> String {
        let context = TwoFactorAuthContext(dsid: "synthetic-dsid", idmsToken: "synthetic-idms", anisetteData: fixedAnisette(), xcodeVersion: "synthetic-xcode")
        if operation == 0 { try await sendTrustedDevice2FACodeRequest(context: context); return "requested" }
        if operation == 1 {
            let result = try await sendPhone2FACodeRequest(mode: "sms", phoneID: "1", context: context)
            return "phone:\(result.phoneID):\(result.activeMode):\(result.statusCode):\(result.phoneNumbers)"
        }
        let result: TwoFactorAuthValidationResult
        if operation == 2 { result = try await validateTrustedDevice2FACode(code: "123456", context: context) }
        else { result = try await validatePhone2FACode(code: "123456", phoneID: "1", mode: "sms", context: context) }
        switch result { case .success: return "success"; case .retry(let failure): return "retry:\(failure.rawValue)" }
    }
}
