#!/usr/bin/env python3
"""Portable source/generator tests, NOT Swift compilation or runtime execution."""
import base64
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
import zipfile

import generate


class SourceAndFixtureTests(unittest.TestCase):
    def setUp(self):
        self.manifest, self.sources, self.spans = generate.verified_sources()

    def test_production_delta_is_exactly_one_reviewed_replacement(self):
        manager = self.sources["Sources/Anisette/AnisetteDataManager.swift"]
        after = b'                throw AnisetteError.sha256Mismatch(expected: expectedSHA, actual: zipSHA)\n'
        before = b'                debugLog("[AnisetteDataManager] SHA-256 mismatch. Proceeding with extraction.")\n'
        self.assertEqual(manager.count(after), 1)
        self.assertNotIn(before, manager)
        historical = manager.replace(after, before, 1)
        self.assertEqual(generate.sha(historical), "bdcb3b55ae889313116081af79a8d21d731010ebd0e27e9b4f16890c0535d2ae")

    def test_source_order_keeps_throw_before_staging_extraction_and_provider(self):
        # This is lexical source evidence, never labeled runtime execution.
        source = self.spans["download"]
        ordered = [b'defer { isCaching = false }', b'try fm.createDirectory(at: libDir',
                   b'let zipData = try await resolveZipData(from: oda)',
                   b'if let expectedSHA = oda.sha256, !expectedSHA.isEmpty',
                   b'if zipSHA.caseInsensitiveCompare(expectedSHA) != .orderedSame',
                   b'throw AnisetteError.sha256Mismatch(expected: expectedSHA, actual: zipSHA)',
                   b'let tempZipURL =', b'try zipData.write(', b'try fm.unzipArchive(',
                   b'guard AnisetteClient.validateLibrariesExist(', b'self.localProvider = try AnisetteClient(']
        positions = [source.index(token) for token in ordered]
        self.assertEqual(positions, sorted(positions))

    def test_inverse_guard_rejects_missing_throw_even_under_python_optimization(self):
        script = '''
import runpy, sys
from pathlib import Path
root = Path(sys.argv[1])
scope = runpy.run_path(str(root / '.ci/test_login_trace_source.py'))
source = (root / 'Sources/Anisette/AnisetteDataManager.swift').read_text()
line = '                throw AnisetteError.sha256Mismatch(expected: expectedSHA, actual: zipSHA)\\n'
for mutated in (source.replace(line, ''), source + line):
    try:
        scope['reverse_reviewed_integrity_fix'](mutated)
    except ValueError:
        continue
    raise SystemExit('inverse proof accepted a missing/duplicate throw')
'''
        result = subprocess.run([sys.executable, '-B', '-O', '-c', script, str(generate.ROOT)],
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_complete_methods_are_unmodified_in_generated_source(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "generated"
            receipt = generate.materialize(output)
            data = (output / "ProductionDownload.swift").read_bytes()
            for name in ("oda_info", "anisette_error", "manager_state", "download", "resolve", "sha256", "http_response"):
                self.assertEqual(data.count(self.spans[name]), 1, name)
            self.assertEqual((output / "Archive.swift").read_bytes(), self.sources["Sources/Archiver/Archive.swift"])
            self.assertEqual((output / "ProductionUnzip.swift").read_bytes().count(self.spans["unzip"]), 1)
            self.assertEqual(receipt["swift_execution"], "not_attempted_by_generator")

    def test_generated_outputs_and_receipt_are_deterministic(self):
        with tempfile.TemporaryDirectory() as temp:
            first, second = Path(temp) / "one", Path(temp) / "two"
            self.assertEqual(generate.materialize(first), generate.materialize(second))
            self.assertEqual({p.name: p.read_bytes() for p in first.iterdir()},
                             {p.name: p.read_bytes() for p in second.iterdir()})

    def test_generation_refuses_existing_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(FileExistsError):
                generate.materialize(Path(temp))

    def test_unreviewed_production_mutations_are_rejected(self):
        mutations = {
            "old_log": ("Sources/Anisette/AnisetteDataManager.swift", b'throw AnisetteError.sha256Mismatch(expected: expectedSHA, actual: zipSHA)', b'debugLog("mismatch")'),
            "expected_hash": ("Sources/Anisette/AnisetteDataManager.swift", b'let zipSHA = computeSHA256(data: zipData)', b'let zipSHA = expectedSHA'),
            "reset": ("Sources/Anisette/AnisetteDataManager.swift", b'defer { isCaching = false }', b'defer { isCaching = true }'),
            "archive_write": ("Sources/Archiver/Archive.swift", b'options: .atomic', b'options: []'),
            "unzip": ("Sources/Archiver/FileManagerZip.swift", b'try archive.extractCurrentFile(to: outputURL)', b'// no extraction'),
        }
        for label, (path, before, after) in mutations.items():
            with self.subTest(mutation=label), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                for name, data in self.sources.items():
                    target = root / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if name == path:
                        self.assertIn(before, data)
                        data = data.replace(before, after, 1)
                    target.write_bytes(data)
                with self.assertRaisesRegex(ValueError, "Unreviewed production source"):
                    generate.verified_sources(root)

    def test_synthetic_zips_are_complete_inert_and_different(self):
        old, new = generate.synthetic_zip("OLD"), generate.synthetic_zip("NEW")
        self.assertNotEqual(generate.sha(old), generate.sha(new))
        for generation, data in (("OLD", old), ("NEW", new)):
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                self.assertEqual(archive.namelist(), list(generate.NAMES))
                self.assertIsNone(archive.testzip())
                for name in generate.NAMES:
                    content = archive.read(name)
                    self.assertEqual(content, f"INERT SYNTHETIC {generation} {name}\n".encode())
                    self.assertFalse(content.startswith(b'\x7fELF'))
                    self.assertEqual(archive.getinfo(name).compress_type, zipfile.ZIP_STORED)

    def test_fixture_swift_literals_bind_exact_decoded_archive_hashes(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "generated"
            receipt = generate.materialize(output)
            source = (output / "FixtureData.swift").read_text()
            for name in ("new", "old", "invalid"):
                payload = re.search(rf'let {name}Base64 = "([^"]+)"', source).group(1)
                digest = re.search(rf'let {name}SHA = "([^"]+)"', source).group(1)
                raw = base64.b64decode(payload, validate=True)
                self.assertEqual(generate.sha(raw), digest)
                self.assertEqual(receipt["fixtures"][name], {"sha256": digest, "bytes": len(raw)})
                self.assertNotEqual(generate.sha(payload.encode()), digest)

    def test_boundary_has_no_native_provider_or_network_implementation(self):
        source = (generate.HERE / "BoundaryDoubles.swift").read_text()
        self.assertNotIn("import AnisetteKit", source)
        self.assertNotIn("Foundation.URLSession.shared", source)
        self.assertNotIn("dataTask(", source)
        self.assertIn("throw URLError(.notConnectedToInternet)", source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
