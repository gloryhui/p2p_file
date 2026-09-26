#!/usr/bin/env python3
"""Verify candidate archive SHA256 and every unpacked file without trusting paths."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile
import tempfile
import zipfile


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def relative(name):
    path = PurePosixPath(name)
    if not name or '\\' in name or path.is_absolute() or '..' in path.parts or ':' in name:
        raise ValueError('unsafe package path')
    return path


def verify(candidate, require_candidate=True):
    candidate = Path(candidate).resolve()
    info = json.loads(candidate.read_text(encoding='utf-8'))
    if require_candidate and (not info['candidate'] or info['source_state'] != 'clean'):
        raise ValueError('preflight is not a final candidate')
    archive = candidate.parent / relative(info['archive'])
    if sha(archive) != info['archive_sha256'] or archive.stat().st_size != info['archive_bytes']:
        raise ValueError('archive checksum/size mismatch')
    with tempfile.TemporaryDirectory(prefix='p2p-package-verification-') as temporary:
        root = Path(temporary)
        if zipfile.is_zipfile(archive):
            with zipfile.ZipFile(archive) as z:
                entries = z.infolist()
                names = set()
                for member in entries:
                    name = relative(member.filename).as_posix()
                    if name in names or (member.external_attr >> 16) & 0o170000 == 0o120000:
                        raise ValueError('duplicate/symlink package member')
                    names.add(name)
                z.extractall(root)
        else:
            with tarfile.open(archive, 'r:gz') as tar:
                names = set()
                for member in tar.getmembers():
                    name = relative(member.name).as_posix()
                    if name in names or not (member.isfile() or member.isdir()):
                        raise ValueError('duplicate/non-regular package member')
                    names.add(name)
                tar.extractall(root, filter='data')
        children = list(root.iterdir())
        if len(children) != 1 or not children[0].is_dir():
            raise ValueError('expected one package root')
        package = children[0]
        actual = json.loads((package / 'build-info.json').read_text(encoding='utf-8'))
        for key in actual:
            if actual[key] != info[key]:
                raise ValueError('archive and candidate metadata differ: ' + key)
        binary = package / relative(info['executable'])
        if binary.stat().st_size != info['executable_bytes'] or sha(binary) != info['executable_sha256']:
            raise ValueError('executable checksum/size mismatch')
        expected = set()
        for line in (package / 'SHA256SUMS').read_text(encoding='utf-8').splitlines():
            checksum, name = line.split('  ', 1)
            file = package / relative(name)
            if name in expected or not file.is_file() or sha(file) != checksum:
                raise ValueError('unpacked checksum mismatch/duplicate: ' + name)
            expected.add(name)
        files = {p.relative_to(package).as_posix() for p in package.rglob('*') if p.is_file()}
        if files != expected | {'SHA256SUMS'}:
            raise ValueError('unlisted/missing package content')
        resources = package / relative(info['license_material']) if info['license_material'] != '.' else package
        dependencies = json.loads((resources / 'dependencies.json').read_text(encoding='utf-8'))['packages']
        if len(dependencies) != info['dependency_packages']:
            raise ValueError('dependency inventory mismatch')
        for item in dependencies:
            if sha(resources / relative(item['source_archive'])) != item['source_sha256']:
                raise ValueError('original dependency source checksum mismatch')
    return {'result': 'PASS', 'build_sha': info['build_sha'], 'target': info['target'], 'archive_sha256': info['archive_sha256'], 'dependency_packages': len(dependencies)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('candidate', type=Path)
    parser.add_argument('--allow-preflight', action='store_true')
    args = parser.parse_args()
    print(json.dumps(verify(args.candidate, not args.allow_preflight)))


if __name__ == '__main__':
    main()
