#!/usr/bin/env python3
"""Offline source/reconstruction gates, not Swift runtime or release clearance."""
from pathlib import Path
import unittest, hashlib, json, tempfile, re
import generate
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
BASE=HERE/'baseline/Authentication.swift'
AUTH=ROOT/'Sources/DeveloperPortal/Authentication.swift'
MODEL=ROOT/'Sources/Models/AuthenticationDiagnosticTrace.swift'
def legacy_authentication(source):
 # New opt-in behavior is reversible independently of the original diagnostic
 # instrumentation. Runtime equivalence still executes the full, unprojected
 # candidate with ILoaderRemoteAuthentication.current == nil.
 owned = HERE.parent/'owned-oda/authentication-projection.json'
 for old,new,count in reversed(json.loads(owned.read_text())):
  assert source.count(new)==count, 'Owned ODA reverse projection mismatch'
  source=source.replace(new,old)
 projection = HERE.parent/'iloader-auth-parity/authentication-projection.json'
 if projection.exists():
  for old,new,count in reversed(json.loads(projection.read_text())):
   assert source.count(new)==count, 'Opt-in reverse projection mismatch: '+new[:100]
   source=source.replace(new,old)
 return source

def balanced(source):
 stack=[]; i=0
 while i<len(source):
  if source.startswith('//',i):
   e=source.find('\n',i);i=len(source) if e<0 else e+1;continue
  if source.startswith('/*',i):
   e=source.find('*/',i+2);assert e>=0;i=e+2;continue
  if source.startswith('#"',i):
   e=source.find('"#',i+2);assert e>=0;i=e+2;continue
  if source[i]=='"':
   i+=1
   while i<len(source):
    if source[i]=='\\': i+=2
    elif source[i]=='"': i+=1;break
    else: i+=1
   else: raise AssertionError('unterminated string')
   continue
  c=source[i]
  if c in '([{':stack.append(c)
  elif c in ')]}':assert stack and stack.pop()=={')':'(',']':'[','}':'{'}[c],f'delimiter line {source.count(chr(10),0,i)+1}'
  i+=1
 assert not stack
class SourceTests(unittest.TestCase):
 def test_exact_baseline(self):
  manifest=json.loads((HERE/'baseline/manifest.json').read_text())
  self.assertEqual(manifest['commit'],'9757970d656135f0b21dc00700507d099f170320')
  self.assertEqual(generate.digest(BASE),manifest['sha256'])
 def test_exact_reverse_projection(self):
  s=legacy_authentication(AUTH.read_text())
  for old,new,count in reversed(json.loads((HERE/'instrumentation-projection.json').read_text())):
   self.assertEqual(s.count(new),count,new[:100]);s=s.replace(new,old)
  self.assertEqual(s,BASE.read_text())
 def test_original_throws_and_transport(self):
  original=BASE.read_text();candidate=legacy_authentication(AUTH.read_text())
  throws=lambda s:[x.strip() for x in s.splitlines() if x.strip().startswith('throw ')]
  self.assertEqual(len(throws(original)),48);self.assertEqual(throws(original),throws(candidate))
  self.assertEqual(candidate.count('session.data(for:'),5)
  for s in ['status["ec"] as? Int ?? 0','responseDict?["ec"] as? Int ?? 0','verifyDictionary?["ec"] as? Int ?? 0','(statusDictionary?["hsc"] as? Int) == 409']:
   self.assertIn(s,candidate)
  errors=ROOT/'Sources/Models/Errors.swift'
  self.assertEqual(generate.digest(errors),'2f07da739407a4579754c12513183a4f96c1e7bbd1308a6a49288e396047a500')
 def test_bounds_and_privacy(self):
  model=MODEL.read_text()
  for item in ['value.utf8.count <= 1024','f.count == 40','p.count == 9','rows.count <= 3','65_535','16_777_216','86_400_000','CFBooleanGetTypeID','token.owner === identity','token.epoch == providerEpoch','decisive = nil','history.count > 4','prior.count > 3','"u"']:
   self.assertIn(item,model)
  for illegal in ['UserDefaults','print(','Logger','URLSession','localizedDescription','allHTTPHeaderFields','absoluteString','CryptoUtilities']:
   self.assertNotIn(illegal,model)
  retained=model[model.index('final class Request:'):model.index('func response(request:')]
  for illegal in [': URLRequest',': URL',': Data',': Error',': [String: Any]']:
   self.assertNotIn(illegal,retained)
 def test_runtime_fixture_shape(self):
  tests=(HERE/'RuntimeTests.swift').read_text()
  for item in ['exactValue(dictionary)','s.dsid, s.authToken','for (index,key) in cpdKeys.enumerated()','initMissing:','initWrong:','SyntheticLatch()','Task {','currentScopeUnavailable','providerPreAuth','serializationBeforeRequest','twoFactor:','AUTH_REQUEST_DIAGNOSTICS_FIXTURE_PASS','legacyInvalid:','concurrentInvocations']:
   self.assertIn(item,tests)
  self.assertNotIn('Task<[String: Any]',tests)
  self.assertIn('let status: [String:any Sendable] = ["ec":code,"hsc":true,"em":"em-secret"]',tests)
  self.assertIn('p.count == 22',(ROOT/'Sources/Models/AuthenticationHeaderProvenance.swift').read_text())
 def test_full_source_generation(self):
  with tempfile.TemporaryDirectory() as temporary:
   out=Path(temporary); evidence=generate.generate(out)
   self.assertEqual(len(evidence['outputs']),7)
   self.assertEqual(evidence['schema'],'auth-request-source-evidence-v1')
   generated=(out/'CandidateAuthentication.swift').read_text()
   self.assertIn(generate.clean(AUTH.read_text()),generated)
   self.assertIn('public final class FakeSession',(out/'BoundaryDoubles.swift').read_text())
   boundary=(out/'BoundaryDoubles.swift').read_text()
   self.assertIn('// BEGIN ILOADER NIL-CONTEXT DOUBLE',boundary)
   self.assertIn('public enum ILoaderRemoteError: Error',boundary)
   self.assertIn('case consentRequired, resyncUnavailable, httpStatus(Int), invalidResponse, invalidState',boundary)
   for name in evidence['outputs']:
    balanced((out/name).read_text());self.assertEqual(evidence['outputs'][name],generate.digest(out/name))
   self.assertIn('public struct AuthenticationHeaderProvenance',(out/'Types.swift').read_text())
   self.assertNotIn('import GSACryptoKit',generated);self.assertNotIn('import AnisetteKit',generated)
 def test_no_current_and_response_invariants(self):
  m=MODEL.read_text()
  for token in ['p[5] == "serialization" && p[6] == "failed"','!one(f[8], "started transport")','f[30] == "unobserved"','f[10] != "-"','ordinal > previous','ordinal < last','scopeEpoch &+= 1']:
   self.assertIn(token,m)
if __name__=='__main__': unittest.main(verbosity=2)
