#!/usr/bin/env python3
"""Reconstructed source-owned fake fixture; no Swift/native/network execution."""
import argparse, hashlib, json, re
from pathlib import Path
p=argparse.ArgumentParser()
p.add_argument('--sources',type=Path,required=True)
p.add_argument('--sidesign-root',type=Path)
p.add_argument('--anisettekit-root',type=Path)
p.add_argument('--output',type=Path,required=True)
p.add_argument('--manifest',type=Path,required=True)
a=p.parse_args();here=Path(__file__).resolve().parent;used={}
def digest(s):return hashlib.sha256(s.encode()).hexdigest()
def source_path(rel):
 repo,path=rel.split('/',1)
 if repo=='SideSign':root=a.sidesign_root or (a.sources/'SideSign' if (a.sources/'SideSign').exists() else a.sources/'SideStore/Dependencies/SideSign')
 elif repo=='AnisetteKit':root=a.anisettekit_root or a.sources/'AnisetteKit'
 else:root=a.sources/repo
 return root/path
def read(rel):
 s=source_path(rel).read_text();used[rel]={'sha256':digest(s)};return s
def strip(s):return '\n'.join(x for x in s.splitlines() if not x.startswith('import '))
def block(s,anchor):
 assert s.count(anchor)==1,anchor
 start=s.index(anchor);i=s.index('{',start)+1;depth=1
 while depth:
  if s[i]=='{':depth+=1
  if s[i]=='}':depth-=1
  i+=1
 return s[start:i]
bmanifest=json.loads((here/'baseline/manifest.json').read_text())
def base(rel):
 m=bmanifest['sources'][rel];s=(here/'baseline'/m['embedded_file']).read_text()
 assert digest(s)==m['sha256'],'Baseline hash mismatch: '+rel
 used['baseline/'+rel]={'sha256':digest(s),'commit':bmanifest[rel.split('/')[0]]};return s
parts=['import Foundation\n#if canImport(FoundationNetworking)\nimport FoundationNetworking\n#endif\n']
for rel in ['AnisetteKit/Sources/Constants.swift','SideSign/Sources/Constants.swift','SideSign/Sources/SideSignHeaders.swift','AnisetteKit/Sources/AnisetteRequestHeaders.swift','AnisetteKit/Sources/AnisetteHeadersDTO.swift','SideSign/Sources/Models/AuthenticationHeaderProvenance.swift','SideSign/Sources/Models/AnisetteData.swift']:
 parts.append(strip(read(rel)))
parts.append(re.sub(r'\bAnisetteData\b','BaselineAnisetteData',strip(base('SideSign/Sources/Models/AnisetteData.swift'))))
portal=read('SideSign/Sources/DeveloperPortal/DeveloperPortalAPI.swift')
portal=portal[portal.index('public final class DeveloperPortal:'):portal.index('    func formatDate(')]+'}\n'
parts.append(portal.replace('DeveloperPortal: DeveloperPortalAPI, Sendable','DeveloperPortal: Sendable'))
manager=read('SideSign/Sources/Anisette/AnisetteDataManager.swift')
parts.append(block(manager,'public enum AnisetteMode:'))
parts.append((here/'fixture_support.swift').read_text())
for name,source,isbase in [('AnisetteDataManager',manager,False),('BaselineManager',base('SideSign/Sources/Anisette/AnisetteDataManager.swift'),True)]:
 anchors=['private struct RemoteAnisetteCacheEntry','public func clearCache()','public static func validateAndCreateAnisetteData(from dictionary:','public func fetchAnisetteData(','public func fetchAnisetteDataWithFailover(']
 if not isbase:anchors+=['private static func diagnosticAdapter(','private static func diagnosticMode(']
 body='\n'.join(block(source,x) for x in anchors)+'\n'+(here/'manager_support.swift').read_text()
 if isbase:body=re.sub(r'\bAnisetteData\b','BaselineAnisetteData',body)
 parts.append('public final class '+name+': @unchecked Sendable {\n'+body+'\n}')
config=read('SideStore/SideStore/Core/Anisette/AnisetteConfigManager.swift');old=base('SideStore/SideStore/Core/Anisette/AnisetteConfigManager.swift')
parts.append(block(config,'public struct AnisetteConfig:'))
parts.append('''enum AppConstants { enum Anisette {
 static let defaultClientInfo = AnisetteConstants.defaultClientInfo
 static let defaultUserAgent = AnisetteConstants.defaultUserAgent
}}
''')
prefix='''struct FakeConfigManager {
'''+block(config,'public nonisolated static func defaultClientInfo(')+'''
 static func resolve(udClientInfo: String?, udUserAgent: String? = nil,
                     fileConfig: AnisetteConfig?, onDeviceAndroid: Bool = true)
'''
resolve_args=''' let udDeviceID: String? = nil; let udLocalUserID: String? = nil
 let udLocale: String? = nil; let udTimeZone: String? = nil
 let udXcodeVersion: String? = nil; let udSerialNumber: String? = nil; let udRoutingInfo: String? = nil
'''
selection=config[config.index('        let resolvedClientInfo   ='):config.index('    public func makeRequestHeaders')].rsplit('\n    }',1)[0]
parts.append(prefix+' -> (config: AnisetteConfig, clientInfoSource: AuthenticationHeaderSource) {\n'+resolve_args+selection+'''
 }
 static func headers(_ selected: (config: AnisetteConfig, clientInfoSource: AuthenticationHeaderSource), forOnDeviceAndroid: Bool = true)
   -> (headers: AnisetteRequestHeaders, clientInfoSource: AuthenticationHeaderSource) {
'''+config[config.index('        let config = selected.config'):config.index('    public func resolvedXcodeVersion')].rsplit('\n    }',1)[0]+'\n }\n}')
selection=old[old.index('        let resolvedClientInfo   ='):old.index('    public func makeRequestHeaders')].rsplit('\n    }',1)[0]
parts.append(prefix.replace('FakeConfigManager','BaselineConfigManager')+' -> AnisetteConfig {\n'+resolve_args+selection+'''
 }
 static func headers(_ config: AnisetteConfig, forOnDeviceAndroid: Bool = true) -> AnisetteRequestHeaders {
'''+old[old.index('        return AnisetteRequestHeaders().with {'):old.index('    public func resolvedXcodeVersion')].rsplit('\n    }',1)[0]+'\n }\n}')
parts.append((here/'fixture_tests.swift').read_text())
def swift_code_mask(source):
 out=[];i=0;line_comment=False;block_depth=0;quote=None
 while i<len(source):
  c=source[i]
  if line_comment:
   out.append('\n' if c=='\n' else ' ')
   if c=='\n':line_comment=False
   i+=1;continue
  if block_depth:
   if source.startswith('/*',i):block_depth+=1;out.extend('  ');i+=2
   elif source.startswith('*/',i):block_depth-=1;out.extend('  ');i+=2
   else:out.append('\n' if c=='\n' else ' ');i+=1
   continue
  if quote:
   if c=='\\':out.extend('  ');i+=2;continue
   if source.startswith(quote,i):out.extend(' '*len(quote));i+=len(quote);quote=None
   else:out.append('\n' if c=='\n' else ' ');i+=1
   continue
  if source.startswith('//',i):line_comment=True;out.extend('  ');i+=2;continue
  if source.startswith('/*',i):block_depth=1;out.extend('  ');i+=2;continue
  if c=='"':quote='"""' if source.startswith('"""',i) else '"';out.extend(' '*len(quote));i+=len(quote);continue
  out.append(c);i+=1
 return ''.join(out)
def assert_unique_top_level_types(source):
 depth=0;seen=set()
 for line in swift_code_mask(source).splitlines():
  if depth==0:
   m=re.match(r'\s*(?:(?:public|private|internal|fileprivate|final|open)\s+|@\w+\s+)*(?:class|struct|enum|protocol|actor)\s+(\w+)\b',line)
   if m:
    name=m.group(1);assert name not in seen,'Duplicate top-level Swift type: '+name;seen.add(name)
  depth+=line.count('{')-line.count('}');assert depth>=0,'Unbalanced generated Swift scope'
 assert depth==0,'Unclosed generated Swift scope'
 return sorted(seen)
generated='\n\n'.join(parts)+'\n';types=assert_unique_top_level_types(generated)
assert generated.count('enum AppConstants {')==1,'Shared AppConstants must be emitted once'
try:assert_unique_top_level_types(generated+'\nenum AppConstants {}\n')
except AssertionError as failure:assert 'Duplicate top-level Swift type: AppConstants' in str(failure)
else:raise AssertionError('Duplicate negative mutation was not rejected')
for name in ['generate_fixture.py','fixture_support.swift','manager_support.swift','fixture_tests.swift']:
 used['fixture/'+name]={'sha256':hashlib.sha256((here/name).read_bytes()).hexdigest()}
a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(generated)
a.manifest.write_text(json.dumps({'kind':'reconstructed_source_owned_fake_only_not_executed','sources':used,'generated_sha256':digest(generated),'generator_checks':{'unique_top_level_types':types,'duplicate_type_mutation_rejected':True}},indent=2)+'\n')
print('Generated source-owned hp2 fake fixture (not executed): '+str(a.output))
