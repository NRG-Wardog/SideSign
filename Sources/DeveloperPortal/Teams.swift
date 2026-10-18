//
//  Teams.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation

public extension DeveloperPortal {

    func fetchTeams(for account: Account, session: Session) async throws -> [Team] {
        debugLog("[SideSign] fetchTeams starting...")

        let response: ListTeamsResponse = try await sendRequest(url: Constants.URLs.listTeams, session: session)

        let teams = (response.teams ?? []).map { team in
            var mutable = team
            mutable.account = account
            return mutable
        }

        if teams.isEmpty {
            debugLog("[SideSign] fetchTeams error: No teams found for account")
            throw DeveloperPortalError.noTeams
        }
        return teams
    }
}
