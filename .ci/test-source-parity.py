"""Narrow end-to-end checks for the sole test-import parity exception.

Run on the committed correction with python3 -B .ci/test-source-parity.py.
Mutation commits live only in a temporary clone; the source checkout is read-only.
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEST_PATH = 'Tests/SideSignTests/SideSignTests.swift'


class TestImportParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='sidesign-test-import-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.repo = Path(cls.temp.name) / 'source'
        subprocess.run(['git', 'clone', '--quiet', '--no-hardlinks', str(ROOT), str(cls.repo)], check=True)
        cls.head = cls.git('rev-parse', 'HEAD').stdout.strip()
        cls.git('config', 'user.name', 'Dorian Salomon')
        cls.git('config', 'user.email', '72792463+NRG-Wardog@users.noreply.github.com')

    @classmethod
    def git(cls, *args):
        return subprocess.run(['git', '-C', str(cls.repo), *args], check=True, capture_output=True, text=True)

    def setUp(self):
        self.git('reset', '--hard', self.head)
        self.git('clean', '-fd')

    def proof(self, *, optimized=False):
        return subprocess.run([sys.executable, '-B', *(['-O'] if optimized else []),
                               str(self.repo / '.ci/source-parity.py')], capture_output=True, text=True)

    def reject_commit(self, message):
        self.git('add', '-A')
        self.git('commit', '--quiet', '-m', 'Isolated parity rejection fixture')
        for optimized in (False, True):
            result = self.proof(optimized=optimized)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn(message, result.stderr)

    def test_exact_import_passes(self):
        for optimized in (False, True):
            result = self.proof(optimized=optimized)
            self.assertEqual(result.returncode, 0, result.stderr)
            proof = json.loads(result.stdout)
            self.assertEqual(proof['status'], 'exact_frozen_runtime_with_test_import_pass')
            self.assertEqual(proof['product_files_verified'], 61)
            self.assertEqual(proof['migrated_files'], 4)
            self.assertEqual([row['path'] for row in proof['test_only_changes']], [TEST_PATH])
            self.assertEqual(proof['behavior_changes'], [])

    def test_missing_or_additional_import_and_changed_assertion_fail(self):
        path = self.repo / TEST_PATH
        original = path.read_bytes()
        changes = [original.replace(b'import Foundation\n', b'', 1),
                   original.replace(b'import Foundation\n', b'import Foundation\nimport Foundation\n', 1),
                   original.replace(b'#expect(entries.count == 2)', b'#expect(entries.count == 3)', 1)]
        for case, content in zip(('missing import', 'duplicate import', 'changed assertion'), changes):
            with self.subTest(case=case):
                self.setUp()
                path.write_bytes(content)
                self.reject_commit('differs beyond exact Foundation import')

    def test_test_mode_change_fails(self):
        (self.repo / TEST_PATH).chmod(0o755)
        self.reject_commit('mode/type mismatch')

    def test_runtime_changes_fail(self):
        for name, message in [('Sources/Logging.swift', 'frozen source mismatch'),
                              ('Sources/Models/X509Certificate.swift', 'changed outside migrated subsystem')]:
            with self.subTest(path=name):
                self.setUp()
                path = self.repo / name
                path.write_bytes(path.read_bytes() + b'\n// arbitrary runtime change\n')
                self.reject_commit(message)

    def test_extra_test_file_fails(self):
        (self.repo / 'Tests/SideSignTests/Unexpected.swift').write_text('import Foundation\n')
        self.reject_commit('unexpected committed inventory')

    def test_frozen_manifest_change_fails(self):
        path = self.repo / '.ci/source-parity.json'
        path.write_bytes(path.read_bytes() + b'\n')
        self.reject_commit('frozen source manifest changed')


if __name__ == '__main__':
    unittest.main(verbosity=2)
