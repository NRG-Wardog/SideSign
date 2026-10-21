    public var activeMode: AnisetteMode? = nil
    private var remoteCache: RemoteAnisetteCacheEntry? = nil
    let state = FixtureState()
    private func getClient(for mode: AnisetteMode, clientInfo: String) async throws -> AnisetteClient {
        if state.setupFails { throw FixtureError.rejected }
        let provider: any FakeProvider
        switch state.adapterOverride {
        case "native": provider = NativeAnisetteDataProvider()
        case "unknown": provider = UnknownAnisetteDataProvider()
        default:
            if case .remote = mode { provider = RemoteAnisetteDataProvider() }
            else { provider = UnicornAnisetteDataProvider() }
        }
        return AnisetteClient(provider: provider, clientInfo: clientInfo, state: state)
    }
    func fixtureReplaceCache(data: AnisetteData, timestamp: Date, server: URL, identifier: UUID) {
        remoteCache = RemoteAnisetteCacheEntry(serverURL: server, identifier: identifier,
                                              data: data, newAdiBlob: nil, timestamp: timestamp)
    }
