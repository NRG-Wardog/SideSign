from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]

class Contract(unittest.TestCase):
    def test_default_is_unchanged(self):
        source = (ROOT / 'Sources/CodeSigning/CodeSignerAPI.swift').read_text()
        self.assertIn('extensionStrategy: .perExtension, progress: progress)', source)
        self.assertIn('filteredEntitlements = mainSigningEntitlements', source)
        self.assertIn('selectedProfile = reuseMain ? mainProfile : profiles.first', source)
        self.assertIn('reasons: ["mainProfileExpired"]', source)
        self.assertIn('return decisions', source)

    def test_policy_is_conservative(self):
        source = (ROOT / 'Sources/CodeSigning/ExtensionSigningPolicy.swift').read_text()
        for reason in ['keychainGroupsMismatch', 'appGroupsMismatch', 'capabilitiesMismatch',
                       'invalidExtensionApplicationIdentifier', 'mainSigningIdentityUnavailable']:
            self.assertIn(reason, source)
        self.assertIn('union(extensionEntitlements.keys)', source)
        self.assertIn('format: .xml', source)

if __name__ == '__main__': unittest.main()
