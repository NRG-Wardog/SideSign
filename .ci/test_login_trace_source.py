"""Offline source regression for P0 login trace instrumentation.

This is not a Swift compiler, integration test, Apple login, or native build.
The pinned hashes compare the pre-instrumentation c55f53ee authentication logic
(after removing log-only code) with the candidate (after removing the exact
trace wrappers). Payloads, handlers, typed retries, cancellation and request
order must remain source-identical modulo whitespace.
Run with: python3 -B .ci/test_login_trace_source.py
"""
from pathlib import Path
import re
import hashlib
import unittest

def functions(source):
    pattern = re.compile(r'^    (?:(?:public|private) )?func ([A-Za-z_][A-Za-z0-9_]*)[^\n]*', re.M)
    matches = list(pattern.finditer(source))
    return {m.group(1): source[m.start():matches[i+1].start() if i+1<len(matches) else len(source)].rstrip() for i,m in enumerate(matches)}

def remove_logs(source):
    source=re.sub(r'^[ \t]*(?:verboseLog|debugLog)\(""".*?"""\)\n', '', source, flags=re.M|re.S)
    source=re.sub(r'^[ \t]*(?:verboseLog|debugLog)\(.*\)\n', '', source, flags=re.M)
    source=re.sub(r'\n\s*if let allHeaders = (?:request|verifyRequest)\.allHTTPHeaderFields \{\s*\}', '', source)
    source=re.sub(r'\n\s*if let payloadString = formatPayload\(data\) \{\s*\}', '', source)
    source=re.sub(r'        let ttlDesc: String\n.*?(?=        return FetchedAuthToken)', '', source, flags=re.S)
    source=re.sub(r'\n        if !(?:teams|devices|certificates)\.isEmpty \{\n.*?\n        \}\n', '\n', source, count=1, flags=re.S)
    return source

def normalized(source):
    return re.sub(r'\s+', ' ', source).strip()

def remove_trace(source, name):
    if name in {'authenticate', 'handle2FARequest', 'sendTrustedDevice2FACodeRequest', 'sendPhone2FACodeRequest', 'validateTrustedDevice2FACode', 'validatePhone2FACode'}:
        marker = '\n        } catch {'
        a=source.rfind(marker)
        assert a >= 0, name
        # Preserve any following nested declarations belonging to this section.
        b=source.index('\n        }', a+len(marker))
        source=source[:a]+source[b+len('\n        }'):]
        source=source.replace('        do {\n','',1)
    source=re.sub(r'\n\s*if activeSpan == nil \{\s*activeSpan = trace\?\.begin\(\.authSession\)\s*\}', '',source)
    source=re.sub(r'\n\s*if case \.selectDeliveryMethod = currentRequest \{\s*deliverySpan = trace\?\.begin\(\.twoFactorDelivery\)\s*\}', '',source)
    source=re.sub(r'\n\s*if case \.cancel = response \{\s*deliverySpan\?\.finish\(\.failed, reason: \.cancelled\)\s*\} else \{\s*deliverySpan\?\.finish\(\.succeeded\)\s*\}', '',source)
    source=re.sub(r'^[ \t]*(?:let trace = LoginDiagnosticTrace\.current|var activeSpan = trace\?\.begin\(\.authSRPInit\)|let twoFactorSpan = trace\?\.begin\(\.twoFactor\)|var deliverySpan: LoginDiagnosticSpan\?|let span = LoginDiagnosticTrace\.current\?\.begin\(\.(?:twoFactorRequest|twoFactorVerify)\))\n', '',source,flags=re.M)
    source=re.sub(r'^[ \t]*(?:(?:activeSpan|deliverySpan) = (?:nil|trace\?\.begin\(\.[A-Za-z]+\))|(?:activeSpan|deliverySpan|twoFactorSpan|span)\?\.finish\(.*\)|trace\?\.skip\(\.twoFactor, reason: \.notRequired\))\n', '',source,flags=re.M)
    if name in {'validateTrustedDevice2FACode', 'validatePhone2FACode'}:
        source=source.replace('let result = try parseTwoFactorAuthVerifyResponse','return try parseTwoFactorAuthVerifyResponse')
        source=re.sub(r'^\s*finishTwoFactorVerificationSpan\(span, result: result\)\n\s*return result\n','\n',source,flags=re.M)
    return source


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_AUTH_CORE = {'authenticate': 'fb8d1f2f9beb0d663de4ef65f95e394b49b65d717313e5d80b6c0a5a43af66cd',
 'fetchAuthToken': 'a6d8cc2dd926059f87dae4ce0fe1c1de0252d1e1692fd87eac9acb294a66f343',
 'handle2FARequest': '0777388621af3daa0b20264f82e349ebf4ec00635ba8b565721987a153c3d5b4',
 'makeTwoFactorAuthRequest': 'ea24124e1058988a1a9c410c61d0e42c037ce20abc05fa51f3cf544247ed98c0',
 'parsePlistOrJSON': '83057599316c088251b331d1aaf4454cd7d337db62d22215b7f0240a36d91b2a',
 'parseTrustedPhoneNumbers': 'cfffac0d81ce82b97b64171674551f3e455ae1df2618c808b132c243b62c4e46',
 'parseTwoFactorAuthVerifyResponse': 'd1a93e8fe02d99b560364634c153b02284fd3d69e345395690e9c21b1553ec88',
 'parseXMLUIAlertMessage': 'd9355a432060b7d4227aa974f5e41e5b728dcbd9d4c70c3b0592edd6831fb4e1',
 'parseXMLUIObfuscatedNumber': '366c758590f3cdaf2167d609c92b114eb3312f50bc16cd9faad050f008403037',
 'parseXMLUIServerInfo': 'ceba25c7fe65cb76783795fbac3bb233f30fe49e7761ce1a7ea05b9c163d9cc8',
 'sendAuthenticationRequest': '1cf13f86a5ca3a35c0b08a6bfede4fa46677fd55cae0c1fe16152b036efd775c',
 'sendPhone2FACodeRequest': 'ebf14c067dfabe23fdd74e5a569ed2176a0c715745be839729bd0dbe5a429d52',
 'sendTrustedDevice2FACodeRequest': 'ef698309927f8cb0f6d9eef627a3a9d4d00ec4d88e5d28be5150eaac8181da2c',
 'throwIfXMLUIErrorAlert': '5e1d6176d5f80890412b1531c1f0c0980c923c797d1d36003af695e9c636c2fb',
 'validatePhone2FACode': '93e62daa577244d0ca809a9cbe877c58440768b628f5d871ec7574c3a03ef142',
 'validateTrustedDevice2FACode': 'd737306b625c1dec93509c4c806af3ce4bf6cba3f976919778bc037dbbf0f82f'}
EXPECTED_PORTAL_CORE = '97bfa34476a7fb456c9f8ecef74744ecf87104d9d96742d7e0aa54dc15dd1664'
EXPECTED_TEAMS_CORE = '429a22e864589c9b4bfafa7244407f5aa1a9e630b95c8a179a71f69ebda30d90'
EXPECTED_MANAGER_CORE = 'cb49423d8ae3cfe2a5f6712eb491eef8159b8f5537416383f829527c8cfda38a'

def reverse_reviewed_integrity_fix(source):
    """Undo exactly the approved one-line throw for the historical trace proof."""
    after = '                throw AnisetteError.sha256Mismatch(expected: expectedSHA, actual: zipSHA)\n'
    before = '                debugLog("[AnisetteDataManager] SHA-256 mismatch. Proceeding with extraction.")\n'
    if source.count(after) != 1:
        raise ValueError('Expected exactly one reviewed integrity throw')
    if before in source:
        raise ValueError('Old proceed-on-mismatch log must remain absent')
    return source.replace(after, before, 1)

EXPECTED_PROVISIONING_CORE = {'Devices.swift': 'c3315d7abcfdef9e737a502251fbffdfe1a1b75e76b006712df9566164455299', 'Certificates.swift': 'bf0f27b22308c3e18214ae367e6d24dab1d5cc9a2f196cdbaff9e14ed75f8577'}

class LoginTraceSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.auth = (ROOT / 'Sources/DeveloperPortal/Authentication.swift').read_text()
        cls.portal = (ROOT / 'Sources/DeveloperPortal/DeveloperPortalAPI.swift').read_text()
        cls.portal = cls.portal[cls.portal.index('    public func fetchAccount(session: Session)'):]
        cls.teams = (ROOT / 'Sources/DeveloperPortal/Teams.swift').read_text()
        cls.manager = (ROOT / 'Sources/Anisette/AnisetteDataManager.swift').read_text()
        cls.methods = functions(cls.auth)
        cls.provisioning = {name: (ROOT / 'Sources/DeveloperPortal' / name).read_text() for name in ('Devices.swift', 'Certificates.swift')}

    def test_original_authentication_logic_is_preserved(self):
        for name, expected in EXPECTED_AUTH_CORE.items():
            with self.subTest(method=name):
                core = normalized(remove_trace(self.methods[name], name))
                self.assertEqual(hashlib.sha256(core.encode()).hexdigest(), expected)

    def test_portal_and_anisette_logic_is_preserved(self):
        for name, content, expected in [('portal', self.portal, EXPECTED_PORTAL_CORE), ('anisette', reverse_reviewed_integrity_fix(self.manager), EXPECTED_MANAGER_CORE)]:
            with self.subTest(method=name):
                core = normalized(remove_logs(content))
                self.assertEqual(hashlib.sha256(core.encode()).hexdigest(), expected)

    def test_authentication_and_account_have_no_free_form_log_sinks(self):
        for source in (self.auth, self.portal):
            self.assertNotRegex(source, r'\b(?:debugLog|verboseLog|print|NSLog|os_log)\s*\(')
            self.assertNotIn('Logger(', source)
            self.assertNotRegex(source, r'\blogger\.')

    def test_anisette_logs_are_fixed_literals(self):
        calls = re.findall(r'^[ \t]*(?:debugLog|verboseLog)\((.*)\)$', self.manager, re.M)
        # The reviewed integrity throw replaces exactly one manager log.
        self.assertEqual(len(calls), 8)
        for call in calls:
            self.assertRegex(call, r'^"[^"\\]*"$')

    def test_teams_logs_are_fixed_literals_and_logic_is_preserved(self):
        calls = re.findall(r'^[ \t]*(?:debugLog|verboseLog)\((.*)\)$', self.teams, re.M)
        self.assertEqual(len(calls), 2)
        for call in calls:
            self.assertRegex(call, r'^"[^"\\]*"$')
        core = normalized(remove_logs(self.teams))
        self.assertEqual(hashlib.sha256(core.encode()).hexdigest(), EXPECTED_TEAMS_CORE)

    def test_provisioning_logs_are_fixed_literals_and_logic_is_preserved(self):
        for name, source in self.provisioning.items():
            with self.subTest(file=name):
                calls = re.findall(r'^[ \t]*(?:debugLog|verboseLog)\((.*)\)$', source, re.M)
                self.assertGreater(len(calls), 0)
                for call in calls:
                    self.assertRegex(call, r'^"[^"\\]*"$')
                core = normalized(remove_logs(source))
                self.assertEqual(hashlib.sha256(core.encode()).hexdigest(), EXPECTED_PROVISIONING_CORE[name])

    def test_every_authentication_stage_is_present_and_ordered(self):
        main = self.methods['authenticate']
        stages = ['authSRPInit', 'authSRPChallenge', 'authSRPComplete', 'authDecrypt', 'authSession', 'accountLookup']
        positions = [main.index('.begin(.' + stage + ')') for stage in stages]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(main.count('activeSpan?.finish(.succeeded)'), 6)
        self.assertIn('activeSpan?.finish(.failed, reason: loginDiagnosticFailureReason(for: error), error: error)\n            throw error', main)
        self.assertIn('trace?.skip(.twoFactor, reason: .notRequired)', main)
        self.assertIn('activeSpan?.finish(.failed, reason: .cancelled)', main)

    def test_two_factor_outcomes_are_terminal_and_retry_safe(self):
        two_factor = self.methods['handle2FARequest']
        self.assertIn('.begin(.twoFactor)', two_factor)
        self.assertIn('.begin(.twoFactorDelivery)', two_factor)
        self.assertIn('twoFactorSpan?.finish(.succeeded)\n                                return', two_factor)
        self.assertIn('twoFactorSpan?.finish(.failed, reason: reason, error: error)\n            throw error', two_factor)
        self.assertIn('deliverySpan?.finish(.failed, reason: .cancelled)', two_factor)
        for name in ('sendTrustedDevice2FACodeRequest', 'sendPhone2FACodeRequest'):
            self.assertIn('.begin(.twoFactorRequest)', self.methods[name])
            self.assertIn('span?.finish(.succeeded)', self.methods[name])
        for name in ('validateTrustedDevice2FACode', 'validatePhone2FACode'):
            self.assertIn('.begin(.twoFactorVerify)', self.methods[name])
            self.assertIn('finishTwoFactorVerificationSpan(span, result: result)', self.methods[name])
        for name in ('sendTrustedDevice2FACodeRequest', 'sendPhone2FACodeRequest', 'validateTrustedDevice2FACode', 'validatePhone2FACode'):
            self.assertIn('span?.finish(.failed, reason: loginDiagnosticFailureReason(for: error), error: error)\n            throw error', self.methods[name])
        classify = self.methods['finishTwoFactorVerificationSpan']
        self.assertIn('case .incorrectCode: reason = .rejected', classify)
        self.assertIn('case .serviceUnavailable: reason = .unavailable', classify)
        self.assertIn('case .unknown: reason = .invalidResponse', classify)

    def test_cancellation_is_classified_without_description(self):
        classify = self.methods['loginDiagnosticFailureReason']
        self.assertIn('error is CancellationError', classify)
        self.assertIn('urlError.code == .cancelled', classify)
        self.assertIn('case .userCancelled: return .cancelled', classify)
        for sensitive in ('localizedDescription', 'userInfo', 'String(describing:', 'String(reflecting:'):
            self.assertNotIn(sensitive, classify)

    def test_stages_are_closed_enums_and_no_global_verbosity_is_enabled(self):
        stages = re.findall(r'\.begin\(([^)]+)\)', self.auth)
        self.assertEqual(set(stages), {'.authSRPInit', '.authSRPChallenge', '.authSRPComplete', '.authDecrypt', '.authSession', '.accountLookup', '.twoFactor', '.twoFactorDelivery', '.twoFactorRequest', '.twoFactorVerify'})
        self.assertNotIn('setLogging(true)', self.auth + self.portal + self.manager + self.teams)
        self.assertNotIn('Task.detached', self.auth)
        self.assertNotIn('Task {', self.auth)
        self.assertNotIn('Task.sleep', self.auth)


if __name__ == '__main__':
    unittest.main(verbosity=2)
