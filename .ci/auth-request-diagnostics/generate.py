#!/usr/bin/env python3
"""Generate seven fake-only Swift files from complete owned auth source. No execution."""
from pathlib import Path
import argparse, hashlib, json, re
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
BASE_SHA='ce5bc5c16552a3f5fda370a7f301ec973be3f3f81b0221c6c3257befe60a2849'
def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def clean(s):
 return '\n'.join(l for l in s.splitlines() if l not in ['import GSACryptoKit','import AnisetteKit','import CodeSignKit'])+'\n'
def extract(s,start,end):
 assert s.count(start)==1,start
 return start+s.split(start,1)[1].split(end,1)[0]
def generate(output):
 output.mkdir(parents=True,exist_ok=True)
 baseline=HERE/'baseline/Authentication.swift'
 assert digest(baseline)==BASE_SHA
 files={}
 def read(path):
  p=ROOT/path; files[str(p.relative_to(ROOT))]=digest(p); return p.read_text()
 auth=read('Sources/DeveloperPortal/Authentication.swift')
 probes=(HERE/'PrivateProbes.swift').read_text()
 api=read('Sources/DeveloperPortal/DeveloperPortalAPI.swift')
 constants=read('Sources/Constants.swift')
 anisette=read('Sources/Models/AnisetteData.swift')
 types=extract(api,'public struct TrustedPhoneNumber:', 'public extension DeveloperPortal {')
 types+=extract(constants,'public enum Constants {','    public enum Anisette {')+'}\n'
 types+=extract(constants,'public enum GrandSlamAuthErrorCodes {','public enum DeveloperPortalResultCodes')
 types+=extract(constants,'public enum HTTPStatusCodes {','public enum UIDeviceFamilyCodes')
 types+=read('Sources/SideSignHeaders.swift')
 types+=read('Sources/Models/AuthenticationHeaderProvenance.swift')
 # The only omitted AnisetteData member is an unrelated outbound conversion method.
 types+=anisette.split('    public func toRequestHeaders()',1)[0]+'}\n'
 types+=read('Sources/Models/Session.swift')
 types='import Foundation\n#if canImport(FoundationNetworking)\nimport FoundationNetworking\n#endif\n'+clean(types)
 prefix='import Foundation\n#if canImport(FoundationNetworking)\nimport FoundationNetworking\n#endif\n'
 generated={
  'CandidateAuthentication.swift':prefix+clean(auth)+'\n'+probes,
  'BaselineAuthentication.swift':prefix+re.sub(r'\bDeveloperPortal\b','BaselineDeveloperPortal',clean(baseline.read_text())+'\n'+probes),
  'AuthenticationDiagnosticTrace.swift':prefix+read('Sources/Models/AuthenticationDiagnosticTrace.swift'),
  'Errors.swift':read('Sources/Models/Errors.swift').split('public enum SignerError:',1)[0],
  'Types.swift':types,
  'BoundaryDoubles.swift':(HERE/'BoundaryDoubles.swift').read_text(),
  'RuntimeTests.swift':(HERE/'RuntimeTests.swift').read_text(),
 }
 for name,content in generated.items(): (output/name).write_text(content)
 for path in HERE.rglob('*'):
  if path.is_file() and '__pycache__' not in str(path): files[str(path.relative_to(ROOT))]=digest(path)
 evidence={'schema':'auth-request-source-evidence-v1','baseline_commit':'9757970d656135f0b21dc00700507d099f170320','baseline_sha256':BASE_SHA,'inputs':files,'outputs':{n:digest(output/n) for n in generated},'network':False,'native_provider':False,'swift_executed':False}
 (output/'source-evidence.json').write_text(json.dumps(evidence,indent=2)+'\n')
 return evidence
if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('--output-dir',required=True,type=Path)
 a=parser.parse_args(); result=generate(a.output_dir); print(json.dumps({'generated':len(result['outputs']),'swift_executed':False}))
