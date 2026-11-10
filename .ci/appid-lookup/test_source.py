"""Wiring contracts complement (not replace) actual Swift parser execution."""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]

class SourceContracts(unittest.TestCase):
    def test_strict_path_is_read_only_and_does_not_default_empty(self):
        source = (ROOT / 'Sources/DeveloperPortal/AppIDs.swift').read_text()
        strict = source.split('func fetchAppIDsPreservingIdentity(', 1)[1].split('    func fetchAppIDs(', 1)[0]
        self.assertIn('url: Constants.URLs.listAppIDs', strict)
        self.assertIn('responseDecoder:', strict)
        self.assertIn('AppIDLookupResponse.decode(data: data, statusCode: statusCode)', strict)
        for forbidden in ('?? []', 'addAppID', 'deleteAppID', 'updateAppID', 'lowercased'):
            self.assertNotIn(forbidden, strict)
        legacy = source.split('    func fetchAppIDs(', 1)[1].split('    func addAppID(', 1)[0]
        self.assertIn('response.appIds ?? []', legacy)
        self.assertNotIn('responseDecoder', legacy)

    def test_dispatcher_validates_before_legacy_status_or_empty_fallback(self):
        source = (ROOT / 'Sources/DeveloperPortal/DeveloperPortalAPI.swift').read_text()
        dispatcher = source.split('    func sendRequest<T:', 1)[1].split('// JSON Services Request Dispatcher', 1)[0]
        self.assertIn('responseDecoder: ((Data, Int?) throws -> T)? = nil', dispatcher)
        self.assertLess(dispatcher.index('return try responseDecoder(data, httpResponse?.statusCode)'), dispatcher.index('guard !data.isEmpty'))
        services = source.split('// JSON Services Request Dispatcher', 1)[1]
        self.assertNotIn('responseDecoder', services)
        protocol = source.split('public protocol DeveloperPortalAPI:', 1)[1].split('public extension DeveloperPortalAPI', 1)[0]
        self.assertIn('func fetchAppIDsPreservingIdentity(', protocol)
        default = source.split('public extension DeveloperPortalAPI {', 1)[1].split('    func authenticate(', 1)[0]
        self.assertIn('throw AppIDLookupError.invalidHTTPResponse', default)
        self.assertNotIn('fetchAppIDs(for:', default)

    def test_runtime_uses_production_sources(self):
        run = (ROOT / '.ci/appid-lookup/run.sh').read_text()
        self.assertIn('Sources/Models/AppID.swift', run)
        self.assertIn('Sources/DeveloperPortal/AppIDLookupResponse.swift', run)
        workflow = (ROOT / '.github/workflows/build-all.yml').read_text()
        self.assertIn('bash .ci/appid-lookup/run.sh', workflow)

if __name__ == '__main__':
    unittest.main()
