#!/usr/bin/env python3
"""Materialize exact, hash-bound production spans plus synthetic boundaries.

Generation/source checks are portable. They are NOT Swift runtime tests.
No network, package resolver, native provider, or proprietary assets are used.
"""
import argparse
import base64
import hashlib
import io
import json
from pathlib import Path
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
NAMES = ("libstoreservicescore.so", "libCoreADI.so")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verified_sources(root=ROOT):
    manifest = json.loads((HERE / "source-spans.json").read_text())
    sources = {}
    for path, expected in manifest["source_files"].items():
        data = (root / path).read_bytes()
        if len(data) != expected["bytes"] or sha(data) != expected["sha256"]:
            raise ValueError("Unreviewed production source: " + path)
        sources[path] = data
    spans = {}
    for name, expected in manifest["spans"].items():
        data = sources[expected["path"]]
        part = data[expected["offset"]:expected["offset"] + expected["bytes"]]
        if sha(part) != expected["sha256"]:
            raise ValueError("Source span mismatch: " + name)
        spans[name] = part
    return manifest, sources, spans


def synthetic_zip(generation):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name in NAMES:
            entry = zipfile.ZipInfo(name, (2000, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, f"INERT SYNTHETIC {generation} {name}\n".encode())
    return output.getvalue()


def materialize(output, root=ROOT):
    manifest, sources, spans = verified_sources(root)
    output.mkdir(parents=True, exist_ok=False)
    generated = {}
    generated["ProductionDownload.swift"] = (
        b"// Generated from source-spans.json. Production spans are copied unchanged.\n"
        b"// The production import Crypto is replaced by Apple CryptoKit for this standalone fixture.\n"
        b"import Foundation\nimport CryptoKit\n\n"
        + spans["oda_info"] + spans["anisette_error"] + spans["http_response"]
        + b"public final class DownloadFixture: @unchecked Sendable {\n"
        + spans["manager_state"]
        + b"    public let remoteLibsDir: URL\n    public let provisioningDir: URL\n"
        b"    public init(root: URL) {\n"
        b"        remoteLibsDir = root.appendingPathComponent(\"libraries\")\n"
        b"        provisioningDir = root.appendingPathComponent(\"provisioning\")\n    }\n"
        b"    var fixtureIsCaching: Bool { isCaching }\n"
        b"    var fixtureProvider: AnisetteClient? { localProvider }\n"
        + spans["download"] + spans["resolve"] + spans["sha256"] + b"}\n"
    )
    generated["Archive.swift"] = sources["Sources/Archiver/Archive.swift"]
    generated["ProductionUnzip.swift"] = b"import Foundation\n\n" + spans["unzip"] + b"}\n"
    for name in ("BoundaryDoubles.swift", "RuntimeTests.swift"):
        generated[name] = (HERE / name).read_bytes()
    fixtures = {"new": synthetic_zip("NEW"), "old": synthetic_zip("OLD"),
                "invalid": b"INERT SYNTHETIC not a ZIP\n"}
    lines = ["// Deterministic, inert Python-generated ZIP fixtures.\n", "enum FixtureData {\n"]
    fixture_receipt = {}
    for name, data in fixtures.items():
        lines.append(f'    static let {name}Base64 = "{base64.b64encode(data).decode()}"\n')
        lines.append(f'    static let {name}SHA = "{sha(data)}"\n')
        fixture_receipt[name] = {"sha256": sha(data), "bytes": len(data)}
    lines.append("}\n")
    generated["FixtureData.swift"] = "".join(lines).encode()
    for name, data in generated.items():
        (output / name).write_bytes(data)
    receipt = {
        "schema_version": 1,
        "kind": "generated-source-identity-not-runtime-evidence",
        "source_manifest_sha256": sha((HERE / "source-spans.json").read_bytes()),
        "generator_sha256": sha(Path(__file__).read_bytes()),
        "production_source_files": manifest["source_files"],
        "production_spans": manifest["spans"],
        "generated": {n: {"sha256": sha(b), "bytes": len(b)} for n, b in generated.items()},
        "fixtures": fixture_receipt,
        "boundaries": ["Foundation FileManager forwarding facade with isolated temp directory",
                       "AnisetteClient inert constructor/existence-check double; no native implementation",
                       "URLSession deny-only boundary; no network implementation",
                       "synthetic Constants and logging observations", "CryptoKit SHA256 import on Apple"],
        "swift_compilation": "not_attempted_by_generator",
        "swift_execution": "not_attempted_by_generator",
    }
    (output / "generation-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="New output directory; existing paths are rejected")
    args = parser.parse_args()
    receipt = materialize(args.output)
    print(json.dumps({"generated": str(args.output), "kind": receipt["kind"]}))
