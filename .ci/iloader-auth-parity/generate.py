#!/usr/bin/env python3
"""Generate a source-owned, offline ILoader opt-in authentication fixture. Never executes Swift."""
from pathlib import Path
import argparse, hashlib, importlib.util, json, re, tempfile
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
LEGACY = HERE.parent / 'auth-request-diagnostics'
OFFICIAL_REF = 'fc7a81a6de678aa707e05399ffafb8be0ad56921'
OUTPUTS = ('CandidateAuthentication.swift', 'AuthenticationDiagnosticTrace.swift',
           'Errors.swift', 'Types.swift', 'BoundaryDoubles.swift',
           'ILoaderRemoteAnisette.swift', 'RuntimeTests.swift')

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def load_legacy():
    spec = importlib.util.spec_from_file_location('legacy_auth_fixture_generator', LEGACY / 'generate.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def generate(output, sidestore_root=None):
    output.mkdir(parents=True, exist_ok=True)
    old = load_legacy()
    with tempfile.TemporaryDirectory() as temporary:
        generated = Path(temporary)
        legacy_evidence = old.generate(generated)
        content = {name: (generated / name).read_text() for name in OUTPUTS[:5]}
    # A nil-context double is necessary only in the unchanged legacy fixture.
    # Here the entire production context executes against in-memory boundaries.
    begin = '// BEGIN ILOADER NIL-CONTEXT DOUBLE\n'
    end = '// END ILOADER NIL-CONTEXT DOUBLE\n'
    boundaries = content['BoundaryDoubles.swift']
    assert boundaries.count(begin) == boundaries.count(end) == 1
    content['BoundaryDoubles.swift'] = boundaries.split(begin)[0] + boundaries.split(end)[1]
    content['BoundaryDoubles.swift'] = content['BoundaryDoubles.swift'].replace('case authSRPInit,', 'case provisioning, appleLookup, appleSPIM, appleFinish, primaryProvider, authSRPInit,').replace('case notRequired,', 'case cached, notRequired,')
    context_path = ROOT / 'Sources/Anisette/ILoaderRemoteAnisette.swift'
    context = context_path.read_text()
    # Complete production bodies retained; only external module/type boundaries replaced.
    context = re.sub(r'^import (?:Crypto|CryptoKit|AnisetteKit|GSACryptoKit)\n', '', context, flags=re.M)
    context = re.sub(r'\bURLSession\b', 'FakeSession', context)
    context = re.sub(r'\bURLSessionWebSocketTask\b', 'FakeWebSocketTask', context)
    context = re.sub(r'\bURLSessionConfiguration\b', 'FakeSessionConfiguration', context)
    context = re.sub(r'\bURLSessionTaskDelegate\b', 'FakeSessionTaskDelegate', context)
    context = re.sub(r'\bURLSessionTask\b', 'FakeSessionTask', context)
    content['ILoaderRemoteAnisette.swift'] = '#if canImport(FoundationNetworking)\nimport FoundationNetworking\n#endif\n' + context
    content['BoundaryDoubles.swift'] += '\n' + (HERE / 'ProviderDoubles.swift').read_text()
    content['RuntimeTests.swift'] = (HERE / 'RuntimeTests.swift').read_text()
    content['CandidateAuthentication.swift'] += '\n' + (HERE / 'PrivateProbes.swift').read_text()
    sidestore_root = sidestore_root or ROOT.parent / 'SideStore'
    factory_path = sidestore_root / 'SideStore/Core/Anisette/AnisetteProvider.swift'
    factory = factory_path.read_text()
    # Retain the complete actual attempt, authorization, handoff and continuity
    # declarations. The dedicated identity suite owns real store/lease execution.
    begin = '// V3_REMOTE_IDENTITY_RUNTIME_BEGIN'
    end = '// V3_REMOTE_REQUEST_LEASES_BEGIN'
    actor = 'private actor ILoaderAttemptAnisetteSource {'
    assert factory.count(begin) == factory.count(end) == factory.count(actor) == 1
    attempt_body = factory.split(begin, 1)[1].split(end, 1)[0]
    source_actor = actor + factory.split(actor, 1)[1]
    keychain_path = sidestore_root / 'AltStore/Core/Components/Keychain.swift'
    keychain = keychain_path.read_text()
    core_begin = '// V3_REMOTE_IDENTITY_RECORD_CORE_BEGIN'
    core_end = '// V3_REMOTE_IDENTITY_RECORD_CORE_END'
    assert keychain.count(core_begin) == keychain.count(core_end) == 1
    record_core = keychain.split(core_begin, 1)[1].split(core_end, 1)[0]
    content['Types.swift'] += '\n' + record_core + '\n' + (attempt_body + '\n' + source_actor).replace('SideSign.AnisetteError', 'AnisetteError')
    content['BoundaryDoubles.swift'] += '\n' + (HERE / 'IdentityBoundaryDoubles.swift').read_text()
    for name, text in content.items():
        (output / name).write_text(text)
    assert set(content) == set(OUTPUTS)
    inputs = dict(legacy_evidence['inputs'])
    inputs[str(context_path.relative_to(ROOT))] = digest(context_path)
    inputs['SideStore/SideStore/Core/Anisette/AnisetteProvider.swift'] = digest(factory_path)
    inputs['SideStore/AltStore/Core/Components/Keychain.swift'] = digest(keychain_path)
    for path in HERE.rglob('*'):
        if path.is_file() and '__pycache__' not in str(path):
            inputs[str(path.relative_to(ROOT))] = digest(path)
    evidence = {
        'schema': 'iloader-auth-parity-source-evidence-v1',
        'official_reference': OFFICIAL_REF,
        'baseline_commit': legacy_evidence['baseline_commit'],
        'inputs': inputs,
        'outputs': {name: digest(output / name) for name in OUTPUTS},
        'output_closure': list(OUTPUTS),
        'boundary_replacements': ['URLSession -> FakeSession', 'URLSessionWebSocketTask -> FakeWebSocketTask', 'URLSessionConfiguration -> FakeSessionConfiguration', 'URLSessionTaskDelegate -> FakeSessionTaskDelegate', 'URLSessionTask -> FakeSessionTask', 'synthetic crypto', 'inert empty identity store/account environment and manual-registry boundary; real persistence and leases covered by remote-identity-reuse', 'same-file private remote probe supplies a verified synthetic phone'],
        'network': False, 'native_provider': False, 'swift_executed': False,
    }
    (output / 'source-evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
    return evidence

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', required=True, type=Path)
    parser.add_argument('--sidestore-root', type=Path)
    args = parser.parse_args()
    evidence = generate(args.output_dir, args.sidestore_root)
    print(json.dumps({'generated': len(evidence['outputs']), 'swift_executed': False}))
