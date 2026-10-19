#!/usr/bin/env python3
"""Portable source invariants only, NOT Swift compilation or runtime transport tests.
The executable synthetic Swift tests are in RemoteReserveTests.swift and
AnisetteKit/EphemeralAnisetteTests.swift; run only their named suites on a Swift host.
"""
import hashlib
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AK = ROOT.parent / "AnisetteKit"

class RemoteReserveSourceTests(unittest.TestCase):
    def setUp(self):
        self.reserve = (ROOT / "Sources/Anisette/RemoteReserveAnisette.swift").read_text()
        self.transport = (ROOT / "Sources/Anisette/RemoteReserveTransport.swift").read_text()
        self.client = (AK / "Sources/AnisetteClient.swift").read_text()
        self.tests = (ROOT / "Tests/SideSignTests/RemoteReserveTests.swift").read_text()

    def test_historical_manager_and_provider_are_byte_identical(self):
        for path in ["Sources/Anisette/AnisetteDataManager.swift", "Sources/Anisette/RemoteAnisetteDataProvider.swift"]:
            baseline = subprocess.check_output(["git", "show", "c733332b0d64022cd603ab9ac5de054413729aab:" + path], cwd=ROOT)
            self.assertEqual((ROOT / path).read_bytes(), baseline, path)

    def test_explicit_api_has_no_manager_cache_native_or_filesystem_path(self):
        for forbidden in ["URLSession.shared", "remoteCache", "getClient(", "fetchAnisetteDataWithFailover", "FileManager", "NativeAnisette", "UnicornAnisette", "libraryDirectoryResolver:"]:
            self.assertNotIn(forbidden, self.reserve)
        self.assertIn("storage: .ephemeral(existingBlob: existingAdiBlob)", self.reserve)
        self.assertIn("requestTransport:", self.reserve)
        self.assertNotIn("headers customHeaders", self.reserve)
        self.assertLess(self.reserve.index("expectedDescriptor != descriptor"), self.reserve.index("let identifierBytes"))

    def test_ephemeral_returns_before_filesystem_paths_and_gates_routing(self):
        block = self.client.split("private func resolveProvisioningBlob", 1)[1].split("let uuidProvDir", 1)[0]
        self.assertIn("if case .ephemeral(let existing)", block)
        self.assertIn("return (existing, nil, {})", block)
        self.assertIn("return (blob, blob, {})", block)
        self.assertNotIn("FileManager", block)
        self.assertIn("guard !provider.requiresLocalLibraries", self.client)
        self.assertIn("persistRoutingInfo: !ephemeral", self.client)
        self.assertIn("ephemeral ? getCachedRoutingInfo(for: identifier) : getStoredRoutingInfo", self.client)
        self.assertIn("if persistRoutingInfo {", self.client)

    def test_bounds_cancellation_and_no_redirects_are_explicit(self):
        self.assertIn("data.count <= maximumBytes - body.count", self.transport)
        self.assertIn("task.maximumMessageSize = RemoteReserveValidation.maximumResponseBytes", self.transport)
        self.assertGreaterEqual(self.transport.count("completionHandler(nil)"), 2)
        self.assertIn("self.task.currentRequest?.url == self.url", self.transport)
        self.assertIn("withTaskCancellationHandler", self.transport)
        self.assertIn("configuration.urlCredentialStorage = nil", self.transport)
        self.assertIn("configuration.httpCookieStorage = nil", self.transport)
        self.assertNotIn("URLSession.shared", self.transport)
        self.assertNotIn("while true", self.reserve)
        self.assertNotIn("try? await", self.reserve + self.transport)

    def test_apple_urls_validated_before_transmission(self):
        pos = self.reserve.index("try RemoteReserveValidation.validateAppleRequest(request)")
        self.assertLess(pos, self.reserve.index("let result = try await transport.data(for: request", pos))
        self.assertIn('c.host?.lowercased() == "gsa.apple.com"', self.reserve)
        self.assertIn('c.scheme == "https"', self.reserve)
        self.assertIn("c.user == nil, c.password == nil", self.reserve)

    def test_reference_uuid_and_synthetic_runtime_suite_are_present(self):
        self.assertIn('body["identifier"] == "AAECAwQFBgcICQoLDA0ODw=="', self.tests)
        expected = hashlib.sha256(bytes(range(16))).hexdigest()
        self.assertIn(expected, self.tests)
        for scenario in ["mismatchedDescriptorStopsBeforeIdentityTransmission", "v3FailureNeverDowngradesReprovisionsOrRotates", "cancellationDuringSocketReceiveClosesWithoutFallback", "duplicateOrReorderedProtocolStepsFailClosed", "maliciousAppleLookupURLIsNeverRequested"]:
            self.assertIn(scenario, self.tests)

    def test_stage_ids_are_append_only(self):
        trace = (AK / "Sources/LoginDiagnosticTrace.swift").read_text().split("public enum LoginDiagnosticOutcome")[0]
        stages = [v.strip() for row in trace.splitlines() if row.strip().startswith("case ") for v in row.strip()[5:].split(",")]
        self.assertEqual(stages[55:], ["nativeLibraryInitialization", "nativeRelocation", "remoteDescriptor", "remoteStart", "remoteEnd", "remoteHeaders"])
        self.assertIn("provider.requiresLocalLibraries ? .nativeOTP : .remoteHeaders", self.client)

if __name__ == "__main__":
    unittest.main(verbosity=2)
