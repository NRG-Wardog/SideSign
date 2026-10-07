"""Check maintained source against recorded frozen OLD hashes, without patchers.

This is an accidental-drift guard. The integration compatibility registry binds
this manifest and the selected fork commit during the reviewed pin transition.
"""
import hashlib, json, os, stat, subprocess
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
SPEC = json.loads((ROOT / '.ci/source-parity.json').read_text())
FROZEN_SOURCE_CHECKPOINT = 'aaa4375a59075a7b0a446cf4c2dc8193c247a875'
TEST_IMPORT_PATH = 'Tests/SideSignTests/SideSignTests.swift'
TEST_PROOF_PATH = '.ci/test-source-parity.py'

def git(*args):
    env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    env.update(GIT_NO_REPLACE_OBJECTS='1', GIT_GRAFT_FILE=os.devnull, GIT_NO_LAZY_FETCH='1', GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1')
    return subprocess.check_output(['git', '-c', 'advice.graftFileDeprecated=false', '--no-replace-objects', '-C', str(ROOT), '--work-tree', str(ROOT), *args], env=env)

def inventory(rev):
    result = {}
    for row in git('ls-tree', '-rz', rev).split(b'\x00'):
        if row:
            metadata, path = row.split(b'\t')
            mode, kind, oid = metadata.decode().split()
            result[path.decode()] = (mode, kind, oid)
    return result

def digest(data):
    return hashlib.sha256(data).hexdigest()

def require(condition, message='source parity failed'):
    if not condition:
        raise ValueError(message)

def verify():
    # Keep the original OLD/runtime evidence intact. This is one test-only fix.
    git('merge-base', '--is-ancestor', FROZEN_SOURCE_CHECKPOINT, 'HEAD')
    require((ROOT / '.ci/source-parity.json').read_bytes() ==
            git('show', FROZEN_SOURCE_CHECKPOINT + ':.ci/source-parity.json'),
            'frozen source manifest changed')
    base = SPEC['upstream_base']
    git('merge-base', '--is-ancestor', base, 'HEAD')
    require(git('rev-parse', '--is-shallow-repository').strip() == b'false', 'shallow source history')
    original = inventory(base)
    actual = inventory('HEAD')
    delta = {r['path']: r for r in SPEC['files']}
    product = set(original) | set(delta)
    require(set(actual) == product | set(SPEC['metadata_files']) | {TEST_PROOF_PATH}, 'unexpected committed inventory')
    checked = 0
    submodules = []
    test_only_changes = []
    for name in sorted(product):
        mode, kind, oid = actual[name]
        old = original.get(name)
        if kind == 'commit':
            require(old == (mode, kind, oid), 'changed upstream gitlink')
            submodules.append({'path': name, 'commit': oid, 'checkout_verified': False})
            continue
        require(kind == 'blob', 'source parity failed')
        content = git('cat-file', 'blob', oid)
        if name == TEST_IMPORT_PATH:
            require(old is not None and (mode, kind) == old[:2], name + ' mode/type mismatch')
            frozen = git('cat-file', 'blob', old[2])
            anchor = b'\nimport Testing\n'
            require(frozen.count(anchor) == 1, name + ' frozen import anchor mismatch')
            expected = frozen.replace(anchor, b'\nimport Foundation\nimport Testing\n', 1)
            require(content == expected, name + ' differs beyond exact Foundation import')
            test_only_changes.append({'path': name, 'change': 'add explicit Foundation import',
                                      'frozen_sha256': digest(frozen), 'new_sha256': digest(content)})
        elif name in delta:
            require(digest(content) == delta[name]['new_source_sha256'], name + ' frozen source mismatch')
            require(mode == delta[name]['git_mode'], name + ' mode mismatch')
        else:
            require(old == (mode, kind, oid), name + ' changed outside migrated subsystem')
        path = ROOT / name
        if mode == '120000':
            require(path.is_symlink() and os.readlink(path).encode() == content, name + ' symlink drift')
        else:
            info = path.lstat()
            require(stat.S_ISREG(info.st_mode), name + ' unsafe file type')
            require(('100755' if info.st_mode & 73 else '100644') == mode, name + ' mode drift')
            require(path.read_bytes() == content, name + ' worktree drift')
        checked += 1
    files = set()
    gitlinks = {entry['path'] for entry in submodules}
    for directory, dirs, names in os.walk(ROOT, followlinks=False):
        rel = Path(directory).relative_to(ROOT)
        if rel == Path('.'):
            dirs[:] = [name for name in dirs if name != '.git']
            names = [name for name in names if name != '.git']
        dirs[:] = [name for name in dirs if (rel / name).as_posix() not in gitlinks]
        for name in list(dirs):
            path = Path(directory) / name
            if path.is_symlink():
                files.add((rel / name).as_posix())
                dirs.remove(name)
        files.update(((rel / name).as_posix() for name in names))
    require(files == set(actual) - gitlinks, 'unexpected filesystem inventory')
    return {'owner': SPEC['owner'], 'status': 'exact_frozen_runtime_with_test_import_pass', 'source_checkpoint': FROZEN_SOURCE_CHECKPOINT, 'test_only_changes': test_only_changes, 'upstream_base': base, 'fork_commit': git('rev-parse', 'HEAD').decode().strip(), 'product_files_verified': checked, 'migrated_files': len(delta), 'submodules': submodules, 'behavior_changes': []}
if __name__ == '__main__':
    print(json.dumps(verify(), indent=2))
