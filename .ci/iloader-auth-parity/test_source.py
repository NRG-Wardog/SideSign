#!/usr/bin/env python3
"""Offline source/closure checks, not Swift execution or Apple acceptance."""
from pathlib import Path
import argparse, ast, hashlib, importlib.util, json, re, tempfile
import generate
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]

def code_mask(source):
    out = []; i = 0; quote = None; depth = 0; comment = False
    while i < len(source):
        c = source[i]
        if comment:
            out.append('\n' if c == '\n' else ' ')
            if c == '\n': comment = False
            i += 1; continue
        if depth:
            if source.startswith('/*', i): depth += 1; out.extend('  '); i += 2
            elif source.startswith('*/', i): depth -= 1; out.extend('  '); i += 2
            else: out.append('\n' if c == '\n' else ' '); i += 1
            continue
        if quote:
            if c == '\\': out.extend('  '); i += 2; continue
            if source.startswith(quote, i): out.extend(' ' * len(quote)); i += len(quote); quote = None
            else: out.append('\n' if c == '\n' else ' '); i += 1
            continue
        if source.startswith('//', i): comment = True; out.extend('  '); i += 2; continue
        if source.startswith('/*', i): depth = 1; out.extend('  '); i += 2; continue
        if source.startswith('#"', i): quote = '"#'; out.extend('  '); i += 2; continue
        if c == '"': quote = '"""' if source.startswith('"""', i) else '"'; out.extend(' ' * len(quote)); i += len(quote); continue
        out.append(c); i += 1
    assert not quote and not depth, 'Unterminated lexical scope'
    return ''.join(out)

def top_types(source):
    found = []; depth = 0
    for line in code_mask(source).splitlines():
        if depth == 0:
            match = re.match(r'\s*(?:(?:public|private|internal|fileprivate|final|open|nonisolated)\s+|@\w+\s+)*(?:class|struct|enum|protocol|actor|typealias)\s+(\w+)\b', line)
            if match: found.append(match[1])
        depth += line.count('{') - line.count('}')
        assert depth >= 0, 'Unbalanced Swift braces'
    assert depth == 0, 'Unclosed Swift braces'
    return found

def check(sidestore_root=None):
    checks = []
    reference = json.loads((HERE/'official-reference.json').read_text())
    assert reference['ref'] == generate.OFFICIAL_REF
    assert len(reference['files']) == 5 and all(re.fullmatch('[0-9a-f]{64}', x) for x in reference['files'].values())
    checks.append('official-source-five-hash-reference')
    auth = (ROOT/'Sources/DeveloperPortal/Authentication.swift').read_text()
    projected = auth
    for path in [HERE/'authentication-projection.json', HERE.parent/'auth-request-diagnostics/instrumentation-projection.json']:
        for old, new, count in reversed(json.loads(path.read_text())):
            assert projected.count(new) == count, 'Reverse projection count: '+new[:120]
            projected = projected.replace(new, old)
    baseline = HERE.parent/'auth-request-diagnostics/baseline/Authentication.swift'
    assert projected == baseline.read_text() and generate.digest(baseline) == generate.load_legacy().BASE_SHA
    checks.append('two-layer-exact-original-baseline-projection')
    # Darwin request header assignment must never inherit the legacy header set.
    # Require the actual production builder to choose the complete map first,
    # then apply it once to the fresh request, retaining the nil-context branch.
    builder = code_mask(auth.split('private func makeTwoFactorAuthRequest(', 1)[1].split('private func refreshedILoaderContext(', 1)[0])
    assert builder.count('request.setValue(') == 1
    assert 'request.allHTTPHeaderFields' not in builder
    assert re.search(r'let effectiveHeaders = ILoaderRemoteAuthentication\.current == nil \? headers :\s*ILoaderAuthenticationPolicy\.twoFactorHeaders\(a, dsid: context\.dsid, token: context\.idmsToken, sms: false\)\s*effectiveHeaders\.forEach \{ request\.setValue\(\$1, forHTTPHeaderField: \$0\) \}', builder), '2FA header maps must be exclusive before application'
    source = (ROOT/'Sources/Anisette/ILoaderRemoteAnisette.swift').read_text()
    for token in ['age >= 0 && age < 61','didResynchronize','Task.checkCancellation()','completionHandler(nil)','httpShouldSetCookies = false','acquisitionTimeoutNanoseconds','withThrowingTaskGroup','state.profile.endpoint == endpoint','profile == state.profile','SHA256.hash(data: identity)']:
        assert token in source, token
    for forbidden in ['UserDefaults.', 'Keychain.', 'FileManager.', 'AnisetteDataManager.shared', 'RemoteAnisetteDataProvider(']:
        assert forbidden not in source, forbidden
    checks.append('scoped-lifecycle-no-persistent-or-native-provider')
    for path in [HERE/'generate.py',HERE/'test_source.py']:
        ast.parse(path.read_text(),filename=str(path))
    with tempfile.TemporaryDirectory() as temporary:
        output = Path(temporary)
        receipt = generate.generate(output,sidestore_root)
        assert receipt['schema'] == 'iloader-auth-parity-source-evidence-v1'
        assert set(receipt['outputs']) == set(generate.OUTPUTS) and len(receipt['outputs']) == 7
        assert receipt['output_closure'] == list(generate.OUTPUTS)
        assert receipt['network'] is receipt['native_provider'] is receipt['swift_executed'] is False
        all_types = []
        for name in generate.OUTPUTS:
            assert receipt['outputs'][name] == generate.digest(output/name)
            all_types.extend(top_types((output/name).read_text()))
        for name in generate.OUTPUTS:
            stack = []
            for char in code_mask((output/name).read_text()):
                if char in '([{': stack.append(char)
                elif char in ')]}': assert stack and stack.pop() == {')':'(',']':'[','}':'{'}[char], 'Unbalanced delimiter in '+name
            assert not stack, 'Unclosed delimiter in '+name
        assert len(all_types) == len(set(all_types)), 'Duplicate top-level types: '+str([x for x in all_types if all_types.count(x)>1])
        checks.append('seven-file-hashed-unique-top-level-closure')
        # Full Authentication body is never replaced by a fixture implementation.
        assert generate.load_legacy().clean(auth) in (output/'CandidateAuthentication.swift').read_text()
        types = (output/'Types.swift').read_text()
        assert generate.load_legacy().clean((ROOT/'Sources/DeveloperPortal/ILoaderAuthenticationPolicy.swift').read_text()).strip() in types
        factory_root = sidestore_root or ROOT.parent/'SideStore'
        factory = (factory_root/'SideStore/Core/Anisette/AnisetteProvider.swift').read_text()
        marker = '// One credentials Submit owns this experimental route.'
        suffix = marker + factory.split(marker,1)[1]
        assert suffix.replace('SideSign.AnisetteError','AnisetteError') in types
        context = (output/'ILoaderRemoteAnisette.swift').read_text()
        expected = re.sub(r'^import (?:Crypto|CryptoKit|AnisetteKit|GSACryptoKit)\n','',source,flags=re.M)
        for old,new in [('URLSession','FakeSession'),('URLSessionWebSocketTask','FakeWebSocketTask'),('URLSessionConfiguration','FakeSessionConfiguration'),('URLSessionTaskDelegate','FakeSessionTaskDelegate'),('URLSessionTask','FakeSessionTask')]:
            expected = re.sub(r'\b'+old+r'\b',new,expected)
        assert expected in context
        checks.append('complete-production-auth-policy-provider-factory-bodies')
        for required in ['FakeSession','FakeSessionConfiguration','FakeSessionTaskDelegate','FakeSessionTask','FakeWebSocketTask','SHA256','ILoaderRemoteAuthenticationContext','ILoaderRemoteAnisetteClient','ILoaderRemoteError','AnisetteError','ALTAnisetteData','ILoaderAttemptAnisetteSource']:
            assert required in all_types, 'Unclosed explicit boundary: '+required
        for name in generate.OUTPUTS:
            masked = code_mask((output/name).read_text())
            assert not re.search(r'\bURLSession(?:WebSocketTask|Configuration|TaskDelegate|Task)?\b',masked), 'Real network boundary in '+name
        checks.append('explicit-fake-network-and-crypto-symbol-boundaries')
    tests = (HERE/'RuntimeTests.swift').read_text()
    for token in ['testFactoryLifecycle','testAuthResync','testStageFreshness','testTrustedVerification','testTimeoutAndLateCancellation','60.999','clock.set(61)','same A2k','complete ORIGINAL CPD','error80045','topLevelFallback','jsonFallback','nestedMissingECWins','ILOADER_AUTH_PARITY_FIXTURE_PASS','iloader-auth-parity-cases-v1','AuthenticationDiagnosticTrace.validatedEncodedSnapshot(encoded)','AuthenticationHeaderProvenance(encoded:encoded)','AuthenticationProviderObservation.validatedEncoded(encoded)','testDiagnosticBoundaries','if case .assertion = error { throw error }','hangOnEmpty:true','fixtureRemoteTwoFactor(operation)']:
        assert token in tests,token
    assert not re.search(r'expect\([^\n]*\bawait\b',tests), 'Await in synchronous autoclosure'
    assert 'print("ILOADER_AUTH_PARITY_FIXTURE_PASS")' in tests
    for token in ['try expect(actual == wanted,', 'unexpected=\\(unexpected)', 'missing=\\(missing)', 'changed=\\(changed)']:
        assert token in tests, 'Exact header comparison and key-only delta required: '+token
    assert 'knownPhoneNumbers:[TrustedPhoneNumber(id:"1",number:"synthetic-number")]' in (HERE/'PrivateProbes.swift').read_text()
    checks.append('runtime-vector-and-export-contract')
    return {'schema':'iloader-auth-parity-static-v1','checks':checks,'check_count':len(checks),'swift_executed':False}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sidestore-root',type=Path)
    parser.add_argument('--report',type=Path)
    args = parser.parse_args()
    result = check(args.sidestore_root)
    if args.report:
        args.report.parent.mkdir(parents=True,exist_ok=True)
        args.report.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
