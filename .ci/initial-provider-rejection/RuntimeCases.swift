// Runs the complete production authenticate and request parser with fake transport/crypto.
// Owned context lifecycle itself is covered by the separate actual-context suite.
func initialProviderRejectionCases() async throws {
    func rejected(_ ec: any Sendable = -80045, hsc: any Sendable = 500, nested: Bool = true) throws -> Data {
        let status: [String: any Sendable] = ["ec": ec, "hsc": hsc]
        let response: [String: any Sendable] = ["Status": status]
        return try plist(nested ? ["Response": response] : response)
    }
    let exact = Step(body: try rejected())
    let owned = FixtureOwnedODAContext()
    let trace = AuthenticationDiagnosticTrace()
    let positive = await OwnedODAAuthentication.$current.withValue(owned) {
        await runAuth([exact], scenario: .init(), baseline: false, trace: trace)
    }
    try expect(positive.value.contains("OwnedODAInitialProviderRejection"), "source minted owned initial rejection")
    try expect(positive.requests.count == 1, "no proof, complete, token or hidden retry")
    let row = try detail(trace)
    try expect(row[24] == "-80045" && row[25] == "500", "original rejection diagnostics retained")
    let legacy = await runAuth([exact], scenario: .init(), baseline: false, trace: nil)
    try expect(!legacy.value.contains("OwnedODAInitialProviderRejection"), "legacy route unchanged")
    try compareRequests(positive.requests, legacy.requests, "owned initial rejection preserves wire")
    let generic = await OwnedODAAuthentication.$current.withValue(owned) {
        await runSend(exact, parameters(), baseline: false, trace: nil)
    }
    try expect(!generic.value.contains("OwnedODAInitialProviderRejection"), "generic public sender ineligible")
    let negatives: [(String, Step)] = [
        ("http429", Step(body: exact.body, status: 429)),
        ("http500", Step(body: exact.body, status: 500)),
        ("http201", Step(body: exact.body, status: 201)),
        ("redirect", Step(body: exact.body, finalURL: URL(string: "https://example.invalid/GsService2")!)),
        ("nonHTTP", Step(body: exact.body, nonHTTP: true)),
        ("timeout", Step(body: Data(), error: URLError(.timedOut))),
        ("lostResponse", Step(body: Data(), error: URLError(.networkConnectionLost))),
        ("cancel", Step(body: Data(), error: CancellationError())),
        ("empty", Step(body: Data())),
        ("malformed", Step(body: Data("<plist>broken".utf8))),
        ("json", Step(body: Data("{\"Response\":{\"Status\":{\"ec\":-80045,\"hsc\":500}}}".utf8))),
        ("topLevel", Step(body: try rejected(nested: false))),
        ("stringEC", Step(body: try rejected("-80045"))),
        ("realEC", Step(body: try rejected(-80045.0))),
        ("boolEC", Step(body: try rejected(true))),
        ("wrongEC", Step(body: try rejected(-20101))),
        ("stringHSC", Step(body: try rejected(hsc: "500"))),
        ("realHSC", Step(body: try rejected(hsc: 500.0))),
        ("boolHSC", Step(body: try rejected(hsc: true))),
        ("otherHSC", Step(body: try rejected(hsc: 409)))
    ]
    for (name, step) in negatives {
        let result = await OwnedODAAuthentication.$current.withValue(owned) {
            await runAuth([step], scenario: .init(), baseline: false, trace: nil)
        }
        try expect(!result.value.contains("OwnedODAInitialProviderRejection"), "fail closed \(name)")
        try expect(result.requests.count == 1, "no retry \(name)")
    }
    for (name, steps) in [("complete", [Step(body: try initOK()), exact]),
                          ("token", [Step(body: try initOK()), Step(body: try completeOK()), exact])] {
        let result = await OwnedODAAuthentication.$current.withValue(owned) {
            await runAuth(steps, scenario: .init(), baseline: false, trace: nil)
        }
        try expect(!result.value.contains("OwnedODAInitialProviderRejection"), "post-init \(name) ineligible")
        try expect(result.requests.count == steps.count, "no retry after \(name)")
    }
    let tfaStatus: [String: any Sendable] = ["ec": 0, "au": "trustedDevice"]
    let tfaComplete: [String: any Sendable] = ["Status": tfaStatus, "spd": Data([3]), "M2": Data([4])]
    let success = Step(body: try accepted())
    let recursiveSteps = [Step(body: try initOK()), Step(body: try plist(tfaComplete)), success, success, exact]
    let recursive = await OwnedODAAuthentication.$current.withValue(owned) {
        await runAuth(recursiveSteps, scenario: .init(), baseline: false, trace: nil, twoFactor: true)
    }
    try expect(recursive.requests.count == 5, "actual post-2FA recursive init reached")
    try expect(!recursive.value.contains("OwnedODAInitialProviderRejection"), "recursive post-2FA init ineligible without diagnostics")
    let revoked = FixtureOwnedODAContext()
    let revokedResult = await OwnedODAAuthentication.$current.withValue(revoked) {
        await runAuth([Step(body: exact.body, onResponse: { revoked.invalidate() })], scenario: .init(), baseline: false, trace: nil)
    }
    try expect(!revokedResult.value.contains("OwnedODAInitialProviderRejection"), "revocation after response wins before minting")
    print("INITIAL_PROVIDER_REJECTION_AUTH_PASS cases=27 actual_authenticate=true native_provider=false")
}
