#!/usr/bin/env python3
"""Reconstructed static privacy/behavior guards; not a Swift runtime result."""
import argparse,hashlib,json,re
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--sources',type=Path,required=True);p.add_argument('--report',type=Path);p.add_argument('--sidesign-root',type=Path);p.add_argument('--anisettekit-root',type=Path);a=p.parse_args()
r=a.sources;h=Path(__file__).resolve().parent;checks=[]
def check(v,label):
 assert v,label
 checks.append(label)
def read(path):
 repo,rel=path.split('/',1)
 if repo=='SideSign':root=a.sidesign_root or (r/'SideSign' if (r/'SideSign').exists() else r/'SideStore/Dependencies/SideSign')
 elif repo=='AnisetteKit':root=a.anisettekit_root or r/'AnisetteKit'
 else:root=r/repo
 return (root/rel).read_text()
def block(s,anchor):
 check(s.count(anchor)==1,'unique anchor: '+anchor)
 st=s.index(anchor);i=s.index('{',st)+1;depth=1
 while depth:
  if s[i]=='{':depth+=1
  if s[i]=='}':depth-=1
  i+=1
 return s[st:i]
bm=json.loads((h/'baseline/manifest.json').read_text())
def base(rel):
 m=bm['sources'][rel];s=(h/'baseline'/m['embedded_file']).read_text();check(hashlib.sha256(s.encode()).hexdigest()==m['sha256'],'pinned baseline '+rel);return s
model=read('SideSign/Sources/Models/AuthenticationHeaderProvenance.swift');data=read('SideSign/Sources/Models/AnisetteData.swift');manager=read('SideSign/Sources/Anisette/AnisetteDataManager.swift')
olddata=base('SideSign/Sources/Models/AnisetteData.swift');oldmanager=base('SideSign/Sources/Anisette/AnisetteDataManager.swift')
for anchor in ['public func toRequestHeaders()','public init(']:check(block(data,anchor)==block(olddata,anchor),'unchanged anisette '+anchor)
fields=re.findall(r'public var (\w+): String\n',olddata);keys=re.findall(r'case (\w+)',block(data,'enum CodingKeys:'))
check(keys==fields,'Codable keys exactly original11 value fields')
check(re.findall(r'hasher.combine\((\w+)\)',block(data,'public func hash(into'))==fields,'hash order equals original stored fields')
check(re.findall(r'lhs\.(\w+) == rhs\.\1',block(data,'public static func =='))==fields,'equality exactly original stored fields')
for anchor in ['private func getClient(','private struct RemoteAnisetteCacheEntry','public func clearCache()','public static func validateAndCreateAnisetteData(from dictionary:']:
 check(block(manager,anchor)==block(oldmanager,anchor),'unchanged manager '+anchor)
fetch=block(manager,'public func fetchAnisetteData(');oldfetch=block(oldmanager,'public func fetchAnisetteData(')
for text in ['cache.serverURL == serverURL','cache.identifier == identifier','< Constants.Anisette.remoteCacheDuration','storage: .memory(existingBlob: existingAdiBlob)','headers: headers','timestamp: Date()']:
 check(text in fetch and text in oldfetch,'preserved acquisition behavior '+text)
check(fetch.count('Date().timeIntervalSince(cache.timestamp)')==oldfetch.count('Date().timeIntervalSince(cache.timestamp)')==1,'one original cache age observation')
check(fetch[fetch.index('        } catch {'):]==oldfetch[oldfetch.index('        } catch {'):],'unchanged acquisition catch/retry handling')
check('client.provider is RemoteAnisetteDataProvider' in manager and 'client.provider is UnicornAnisetteDataProvider' in manager,'actual client provider adapter observed')
check('else if client.provider is NativeAnisetteDataProvider' not in manager,'no conditional compilation through else chain')
check('Date(' not in model and 'UserDefaults' not in model.replace('case userDefaults = "UserDefaults"',''),'provenance has no time/config reads')
check('Codable' not in model and 'Hashable' not in model,'metadata has no persistence/identity conformance')
check('p.count == 22' in model and 'encoded.utf8.count <= 512' in model and 'p[0] == "hp2"' in model,'strict hp2 count/version/budget')
known=read('SideSign/Sources/Anisette/VerifiedAppleMusicLibraries.swift');hashes=re.findall(r'static let (?:coreADIHash|storeServicesHash) = "([0-9a-f]{64})"',model)
check(len(hashes)==2 and all(x in known for x in hashes),'public hash allowlist equals selected verifier')
check('Self.validateLibrariesExist' not in model and 'loadedMapping: LoadedMapping = .unobserved' in model,'selected verification does not claim mapping identity')
check('existingAdiBlob?.isEmpty == false ? .present : .absent' in fetch,'blob input matches empty-or-absent provisioning semantics')
check('historicalBlobAssociation: .notRecorded' in fetch,'no invented historical blob association')
check('guard age.isFinite, age >= 0' in model,'negative/nonfinite cache age unknown')
cachehit=block(data,'mutating func markDiagnosticCacheHit(')
check('source: diagnosticHeaderProvenance.source' in cachehit and 'provider: diagnosticHeaderProvenance.provider' in cachehit,'cache preserves data-owned source/provider')
config=read('SideStore/SideStore/Core/Anisette/AnisetteConfigManager.swift');oldconfig=base('SideStore/SideStore/Core/Anisette/AnisetteConfigManager.swift')
check(re.findall(r'let (?:ud\w+|onDeviceAndroid)\s*=.*',config)==re.findall(r'let (?:ud\w+|onDeviceAndroid)\s*=.*',oldconfig),'same configuration read expressions/count')
check(re.findall(r'let resolved\w+\s*=.*',config)==re.findall(r'let resolved\w+\s*=.*',oldconfig),'unchanged configuration precedence')
check(block(config,'public nonisolated static func defaultClientInfo(')==block(oldconfig,'public nonisolated static func defaultClientInfo('),'unchanged advertised default')
portal=read('SideSign/Sources/DeveloperPortal/DeveloperPortalAPI.swift')
check('headersLock.withLock {\n            DiagnosticCustomHeadersSnapshot(headers: cachedCustomHeaders, source: cachedHeaderSource)' in portal,'atomic selected header/source snapshot')
check('cachedCustomHeaders = headers\n            cachedHeaderSource = diagnosticSource' in portal,'atomic header/source write')
check('p.count == 12' in model and 'encoded.utf8.count <= 256' in model and 'p[0] == "ap1"' in model,'strict ap1 count/version/budget')
check('public let requestAssociation: RequestAssociation = .unobserved' in model,'preauth association explicitly unobserved')
check(fetch.index('beginProviderObservation(providerObservation)') < fetch.index('try await getClient('),'selection precedes setup failure')
check(fetch.index('let readyObservation') < fetch.index('try await client.getAnisetteData('),'observed ready client precedes provider failure')
check(fetch.count('token: providerObservationToken')==3,'provider stage updates retain acquisition token')
check('requestedClientInfoFamily: .classify(clientInfo)' in fetch,'requested input compared with actual used output')
branches=read('SideStore/SideStore/Core/Anisette/AnisetteProvider.swift')
check(branches.count('UserDefaults.standard.useOnDeviceAnisette')==1,'branch capture adds no preference reads')
check('beginProviderObservation(.selectedBranch(onDevice: true))' in branches and 'beginProviderObservation(.selectedBranch(onDevice: false))' in branches,'actual source branch before acquisition prerequisites')
check('requested.utf8.elementsEqual(used.utf8) ? .same : .different' in model,'cache exact equality uses existing UTF8 bytes without hashes')
check('usedClientInfo: clientInfo' in cachehit,'exact equality observes actual cache return')
check('cache == .cacheHit || (age == .unknown && cacheExact == .unknown)' in model,'non-hit exact equality unknown')
report={'kind':'reconstructed_static_source_checks_only','passed':len(checks),'checks':checks,'swift_executed':False}
if a.report:a.report.write_text(json.dumps(report,indent=2)+'\n')
print('PASS hp2_profile_provenance static_source_checks='+str(len(checks))+'; Swift not executed')
