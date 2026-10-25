import hashlib
import re
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
class OwnedSourceTests(unittest.TestCase):
 def test_legacy_auth_wire_byte_parity(self):
  text=(ROOT/'Sources/DeveloperPortal/Authentication.swift').read_text()
  pattern=r'OwnedODAAuthentication\.data\(for: (request|verifyRequest), legacySession: ILoaderRemoteAuthentication\.current\?\.session \?\? session, remoteSelected: ILoaderRemoteAuthentication\.current != nil\)'
  restored,count=re.subn(pattern,r'(ILoaderRemoteAuthentication.current?.session ?? session).data(for: \1)',text)
  self.assertEqual(count,5)
  self.assertEqual(hashlib.sha256(restored.encode()).hexdigest(),'bf91f0e5504432f5309002fa4a9a157e8b299dfb79ee13e38d6adb985838ac2d')
 def test_legacy_portal_wire_byte_parity(self):
  text=(ROOT/'Sources/DeveloperPortal/DeveloperPortalAPI.swift').read_text()
  old='(scopedRemote?.session ?? session).data(for: request)'
  new='OwnedODAAuthentication.data(for: request, legacySession: scopedRemote?.session ?? session, remoteSelected: scopedRemote != nil, validateAfterResponse: false)'
  self.assertEqual(text.count(new),2)
  self.assertEqual(hashlib.sha256(text.replace(new,old).encode()).hexdigest(),'2004baeb59506f30b3e8f9dfb3200b0ad15b711a2892729dfecee6cb8c563b4a')
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
