import hashlib
import json
import re
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def restore_legacy_portal_wire(text, projection):
 # This finite proof is reviewed separately from the immutable legacy wire hash.
 # Re-pinning a successor digest cannot authorize new source or broader edits.
 proof=json.dumps(projection,sort_keys=True,separators=(',',':')).encode()
 if hashlib.sha256(proof).hexdigest()!='01e8ff6638f1c40e3b848435fdd8ae06b688a6191585511d07289bd7b4cf762e':
  raise ValueError('unreviewed strict lookup projection')
 if hashlib.sha256(text.encode()).hexdigest()!=projection['after_sha256']:
  raise ValueError('unexpected strict lookup source')
 for edit in reversed(projection['edits']):
  if text.count(edit['after'])!=edit['count']:
   raise ValueError('strict lookup edit multiplicity changed')
  text=text.replace(edit['after'],edit['before'])
 if hashlib.sha256(text.encode()).hexdigest()!=projection['before_sha256']:
  raise ValueError('strict lookup inverse differs from its predecessor')
 old='(scopedRemote?.session ?? session).data(for: request)'
 new='OwnedODAAuthentication.data(for: request, legacySession: scopedRemote?.session ?? session, remoteSelected: scopedRemote != nil, validateAfterResponse: false)'
 if text.count(new)!=2:
  raise ValueError('owned transport edit multiplicity changed')
 return text.replace(new,old)

class OwnedSourceTests(unittest.TestCase):
 def test_legacy_auth_wire_byte_parity(self):
  text=(ROOT/'Sources/DeveloperPortal/Authentication.swift').read_text()
  # Reverse only the separately reviewed initial-rejection control-flow delta.
  # Keep the historical transport/wire baseline hash unchanged.
  for old,new,count in reversed(json.loads((ROOT/'.ci/initial-provider-rejection/authentication-projection.json').read_text())):
   self.assertEqual(text.count(new),count)
   text=text.replace(new,old)
  pattern=r'OwnedODAAuthentication\.data\(for: (request|verifyRequest), legacySession: ILoaderRemoteAuthentication\.current\?\.session \?\? session, remoteSelected: ILoaderRemoteAuthentication\.current != nil\)'
  restored,count=re.subn(pattern,r'(ILoaderRemoteAuthentication.current?.session ?? session).data(for: \1)',text)
  self.assertEqual(count,5)
  self.assertEqual(hashlib.sha256(restored.encode()).hexdigest(),'bf91f0e5504432f5309002fa4a9a157e8b299dfb79ee13e38d6adb985838ac2d')
 def test_legacy_portal_wire_byte_parity(self):
  text=(ROOT/'Sources/DeveloperPortal/DeveloperPortalAPI.swift').read_text()
  projection=json.loads((ROOT/'.ci/owned-oda/strict-appid-portal-projection.json').read_text())
  restored=restore_legacy_portal_wire(text,projection)
  self.assertEqual(hashlib.sha256(restored.encode()).hexdigest(),'2004baeb59506f30b3e8f9dfb3200b0ad15b711a2892729dfecee6cb8c563b4a')
  # Keep the five-test receipt schema. These subcases exercise both ordinary
  # drift and maliciously re-pinned successor/projection values in memory.
  for name,old,new in [
   ('legacy-header','"Content-Type": "text/x-xml-plist"','"Content-Type": "application/json"'),
   ('strict-decoder','return try responseDecoder(data, httpResponse?.statusCode)','return try responseDecoder(data, 200)'),
   ('default-conformer','throw AppIDLookupError.invalidHTTPResponse','return []'),
   ('duplicate-strict-block',projection['edits'][3]['after'],projection['edits'][3]['after']*2),
  ]:
   with self.subTest(mutation=name):
    self.assertIn(old,text)
    changed=text.replace(old,new)
    with self.assertRaises(ValueError):restore_legacy_portal_wire(changed,projection)
    repinned=json.loads(json.dumps(projection))
    repinned['after_sha256']=hashlib.sha256(changed.encode()).hexdigest()
    for edit in repinned['edits']:edit['after']=edit['after'].replace(old,new)
    with self.assertRaisesRegex(ValueError,'unreviewed strict lookup projection'):
     restore_legacy_portal_wire(changed,repinned)
  with self.subTest(mutation='repinned-predecessor'):
   repinned=json.loads(json.dumps(projection));repinned['before_sha256']='0'*64
   with self.assertRaisesRegex(ValueError,'unreviewed strict lookup projection'):
    restore_legacy_portal_wire(text,repinned)
 def test_join_and_publication(self):
  text=(ROOT/'Sources/Anisette/OwnedODAAuthenticationContext.swift').read_text()
  self.assertIn('_ = await task?.result',text)
  self.assertLess(text.index('active = child'),text.index('return child'))
  self.assertIn('guard !invalidated, !fetching, pendingBlob == expected',text)
  self.assertNotIn('Task.detached',text)
 def test_owned_snapshot_empty_only_cleanup(self):
  text=(ROOT/'Sources/Anisette/OwnedODANativeSource.swift').read_text()
  self.assertIn('verifiedLibraries: libraries',text)
  self.assertIn('held.st_dev == named.st_dev, held.st_ino == named.st_ino',text)
  self.assertIn('unlinkat(parentFD, name, AT_REMOVEDIR)',text)
  self.assertIn('parent.resolvingSymlinksInPath().standardizedFileURL',text)
  self.assertNotIn('removeItem',text)
 def test_custom_bounds_and_snapshot_validation(self):
  text=(ROOT/'Sources/Anisette/OwnedODALibraryPreparation.swift').read_text()
  for witness in ['try VerifiedAppleMusicLibraries.validate(bytes, library: library)', 'observed == expected', 'expected.count == 64', 'entries.count <= 1024', 'entry.uncompressedSize <= 16 * 1024 * 1024', 'Set(entries.map(\\.filename)).count == entries.count', 'completionHandler(nil)', 'data.count <= maximum - bytes.count', 'url.scheme?.lowercased() == "https"']:
   self.assertIn(witness,text)
if __name__=='__main__':unittest.main()
