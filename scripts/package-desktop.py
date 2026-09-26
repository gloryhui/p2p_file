#!/usr/bin/env python3
"""Create an auditable native candidate outside the checkout; never publish a Release."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import struct
import subprocess
import tarfile
import time
import tomllib
import zipfile

TARGETS = {
    'x86_64-unknown-linux-gnu': ('Linux', 'Ubuntu 24.04 x86_64'),
    'x86_64-pc-windows-msvc': ('Windows', 'Windows 10 22H2 / Windows 11 x64'),
    'aarch64-apple-darwin': ('Darwin', 'macOS 13+ Apple Silicon arm64'),
}
REPO = Path(__file__).resolve().parent.parent


def run(args):
    return subprocess.check_output(args, cwd=REPO, text=True, encoding='utf-8').strip()


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def architecture(path, target):
    with path.open('rb') as stream:
        header = stream.read(64)
        if target.endswith('linux-gnu'):
            if header[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', header, 18)[0] != 62:
                raise ValueError('expected ELF64 little-endian x86_64')
        elif target.endswith('windows-msvc'):
            if header[:2] != b'MZ':
                raise ValueError('expected PE executable')
            stream.seek(struct.unpack_from('<I', header, 60)[0])
            if stream.read(6) != b'PE\0\0\x64\x86':
                raise ValueError('expected native PE x64')
        elif header[:4] != b'\xcf\xfa\xed\xfe' or struct.unpack_from('<I', header, 4)[0] != 0x0100000c:
            raise ValueError('expected thin Mach-O arm64; Intel/fat artifacts are not supported')


def dependency_bundle(destination):
    # Conservatively retain every resolved package, including build/optional and
    # other-target packages. Do not mislabel this inventory as a linked SBOM.
    metadata = json.loads(run(['cargo', 'metadata', '--locked', '--features', 'gui', '--format-version', '1']))
    lock = tomllib.loads((REPO / 'Cargo.lock').read_text(encoding='utf-8'))
    checksums = {(p['name'], p['version']): p.get('checksum') for p in lock['package']}
    records = []
    sources = destination / 'third-party-sources'
    sources.mkdir()
    notices = destination / 'licenses'
    notices.mkdir()
    for package in sorted(metadata['packages'], key=lambda p: (p['name'], p['version'])):
        if package['source'] is None:
            continue
        if not package['source'].startswith('registry+'):
            raise ValueError('unsupported dependency source; a verified source archive is required')
        root = Path(package['manifest_path']).parent
        original = root.parents[1].parent / 'cache' / root.parent.name / (root.name + '.crate')
        expected = checksums[(package['name'], package['version'])]
        if not original.is_file() or not expected or digest(original) != expected:
            raise ValueError(f"missing or checksum-mismatched upstream archive: {root.name}")
        shutil.copyfile(original, sources / original.name)
        license_dir = notices / root.name
        license_dir.mkdir()
        provided = []
        for item in sorted(root.iterdir()):
            if item.is_file() and item.name.upper().startswith(('LICENSE', 'LICENCE', 'COPYING', 'NOTICE', 'COPYRIGHT', 'README')):
                shutil.copyfile(item, license_dir / item.name)
                provided.append(item.name)
        if package['license_file']:
            item = (root / package['license_file']).resolve()
            if root.resolve() not in item.parents or not item.is_file():
                raise ValueError(f'invalid declared license_file: {root.name}')
            filename = 'declared-' + item.name
            shutil.copyfile(item, license_dir / filename)
            provided.append(filename)
        record = {key: package[key] for key in ['name', 'version', 'license', 'authors', 'repository']}
        record.update(source=package['source'], source_archive='third-party-sources/' + original.name,
                      source_sha256=expected, provided_notices=provided,
                      notice_scope='Original crate archive includes remaining nested copyright/license/source material; declared SPDX expression is unmodified.')
        if not record['license'] and not package['license_file']:
            raise ValueError(f'missing dependency license declaration: {root.name}')
        records.append(record)
    (destination / 'dependencies.json').write_text(json.dumps({'scope': 'All Cargo-resolved packages, overinclusive of build/optional/other targets; not a linked-only SBOM.', 'packages': records}, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return len(records)


def pe_imports(path):
    data = path.read_bytes()
    pe = struct.unpack_from('<I', data, 60)[0]
    sections = struct.unpack_from('<H', data, pe + 6)[0]
    size = struct.unpack_from('<H', data, pe + 20)[0]
    optional = pe + 24
    if struct.unpack_from('<H', data, optional)[0] != 0x20b:
        raise ValueError('expected PE32+ optional header')
    table = optional + size
    ranges = []
    for index in range(sections):
        offset = table + index * 40
        virtual_size, rva, raw_size, raw = struct.unpack_from('<IIII', data, offset + 8)
        ranges.append((rva, max(virtual_size, raw_size), raw, raw_size))
    def file_offset(rva):
        for begin, length, raw, raw_size in ranges:
            if begin <= rva < begin + length and rva - begin < raw_size:
                return raw + rva - begin
        raise ValueError('unmapped PE import RVA')
    import_rva, import_size = struct.unpack_from('<II', data, optional + 112 + 8)
    if not import_rva:
        return []
    imports = []
    offset = file_offset(import_rva)
    for index in range(min(import_size // 20, 512)):
        entry = struct.unpack_from('<IIIII', data, offset + index * 20)
        if not any(entry):
            return sorted(set(imports))
        name_offset = file_offset(entry[3])
        end = data.find(b'\0', name_offset, name_offset + 512)
        if end < 0:
            raise ValueError('invalid bounded PE import name')
        imports.append(data[name_offset:end].decode('ascii'))
    raise ValueError('unterminated PE import table')


def macos_minimum(load_commands):
    minimum = []
    for block in re.split(r'Load command \d+', load_commands):
        if re.search(r'^\s*cmd\s+LC_BUILD_VERSION\s*$', block, re.MULTILINE):
            # LC_BUILD_VERSION also contains linker-tool `version` records. Only
            # `minos` is the deployment minimum; sdk/tool versions are unrelated.
            matches = re.findall(r'^\s*minos\s+(\d+\.\d+(?:\.\d+)?)\s*$', block, re.MULTILINE)
        elif re.search(r'^\s*cmd\s+LC_VERSION_MIN_MACOSX\s*$', block, re.MULTILINE):
            matches = re.findall(r'^\s*version\s+(\d+\.\d+(?:\.\d+)?)\s*$', block, re.MULTILINE)
        else:
            continue
        if len(matches) != 1:
            raise ValueError('missing/ambiguous Mach-O deployment minimum')
        minimum.extend(matches)
    versions = [tuple(map(int, (v.split('.') + ['0', '0'])[:3])) for v in minimum]
    if not versions or any(v > (13, 0, 0) for v in versions):
        raise ValueError('binary deployment minimum exceeds the product macOS13 minimum')
    return minimum


def signature_command(executable, parent_env):
    # An outer pwsh process can export a PSModulePath containing Core-only
    # modules. Passing it to Windows PowerShell5 breaks Security-module loading.
    # Give the actual chosen host its own default built-in module search path.
    host = shutil.which('pwsh') or shutil.which('powershell')
    if not host:
        raise ValueError('native PowerShell host required for actual Authenticode inspection')
    environment = parent_env.copy()
    environment.pop('PSModulePath', None)
    environment['P2P_PACKAGE_EXECUTABLE'] = str(executable)
    command = [host, '-NoProfile', '-NonInteractive', '-Command',
               '(Get-AuthenticodeSignature -LiteralPath $env:P2P_PACKAGE_EXECUTABLE).Status.ToString()']
    return command, environment


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--target', choices=TARGETS, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--allow-dirty', action='store_true', help='local preflight only, explicitly marks non-candidate metadata')
    args = parser.parse_args()
    output = args.output.resolve()
    if output == REPO or REPO in output.parents:
        parser.error('output must be outside the checkout')
    if output.exists() and any(output.iterdir()):
        parser.error('output must be new or empty; evidence is never overwritten')
    output.mkdir(parents=True, exist_ok=True)
    if platform.system() != TARGETS[args.target][0]:
        parser.error('packaging must execute on the actual native platform')
    head = run(['git', 'rev-parse', 'HEAD'])
    dirty = bool(run(['git', 'status', '--porcelain']))
    if dirty and not args.allow_dirty:
        parser.error('candidate source must be clean; --allow-dirty is preflight evidence only')
    binary = args.binary.resolve()
    architecture(binary, args.target)
    started = time.monotonic()
    info = json.loads(run([str(binary), '--build-info']))
    probe_seconds = time.monotonic() - started
    version_output = run([str(binary), '--version'])
    help_output = run([str(binary), '--help'])
    invalid = subprocess.run([str(binary), '--package-unknown-option'], capture_output=True)
    extra = subprocess.run([str(binary), '--version', 'extra'], capture_output=True)
    if (info['version'] not in version_output or info['build_sha'] not in version_output
            or '--build-info' not in help_output or invalid.returncode != 2 or extra.returncode != 2):
        parser.error('actual metadata/help/invalid-argument CLI boundary failed')
    expected_state = 'dirty' if dirty else 'clean'
    if info['build_sha'] != head or info['target'] != args.target or info['source_state'] != expected_state:
        parser.error('binary metadata differs from the actual head/target/source state; rebuild it')
    version = info['version']
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?', version):
        parser.error('invalid package version')
    stem = f'p2p-desktop-{version}-{args.target}-{head[:12]}'
    package = output / stem
    package.mkdir()
    executable = package / ('p2p-desktop.exe' if platform.system() == 'Windows' else 'p2p-desktop')
    signing = {'status': 'unsigned', 'notarization': 'not applicable', 'certificate': None}
    inspection = {}
    if platform.system() == 'Darwin':
        app = package / 'P2P File.app'
        contents = app / 'Contents'
        (contents / 'MacOS').mkdir(parents=True)
        (contents / 'Resources').mkdir()
        executable = contents / 'MacOS/p2p-desktop'
        with (contents / 'Info.plist').open('wb') as stream:
            plistlib.dump({'CFBundleExecutable': 'p2p-desktop', 'CFBundleIdentifier': 'io.github.gloryhui.p2p-file',
                           'CFBundleName': 'P2P File', 'CFBundleDisplayName': 'P2P File', 'CFBundlePackageType': 'APPL',
                           'CFBundleShortVersionString': version.split('-')[0].split('+')[0], 'CFBundleVersion': '1',
                           'LSMinimumSystemVersion': '13.0', 'NSHighResolutionCapable': True,
                           'NSHumanReadableCopyright': 'See bundled LICENSE and THIRD_PARTY_NOTICES.md',
                           'P2PBuildSHA': head}, stream, sort_keys=True)
    shutil.copy2(binary, executable)
    if platform.system() != 'Windows':
        executable.chmod(0o755)
    if platform.system() == 'Linux':
        inspection['dynamic_dependencies'] = run(['ldd', str(executable)])
        if 'not found' in inspection['dynamic_dependencies']:
            raise ValueError('unresolved native library')
        inspection['elf_versions'] = run(['readelf', '--version-info', str(executable)])
    elif platform.system() == 'Darwin':
        inspection['dynamic_dependencies'] = run(['otool', '-L', str(executable)])
        inspection['mach_o_load_commands'] = run(['otool', '-l', str(executable)])
        # Read only the actual build/min-version load command, not framework versions.
        inspection['deployment_minimum_versions'] = macos_minimum(inspection['mach_o_load_commands'])
    else:
        signature_args, signature_env = signature_command(executable, os.environ)
        inspection['authenticode'] = subprocess.check_output(signature_args, env=signature_env, text=True).strip()
        if inspection['authenticode'] != 'NotSigned':
            raise ValueError('unexpected signature status; candidate signing metadata must be reviewed')
        inspection['dynamic_dependencies'] = pe_imports(executable)
    resources = contents / 'Resources' if platform.system() == 'Darwin' else package
    for source, name in [('LICENSE', 'LICENSE'), ('docs/gpui-mvp/THIRD_PARTY_NOTICES.md', 'THIRD_PARTY_NOTICES.md'), ('packaging/RUNNING.md', 'RUNNING.md')]:
        shutil.copyfile(REPO / source, resources / name)
    shutil.copyfile(REPO / 'packaging/RUNNING.md', package / 'RUNNING.md')
    dependencies = dependency_bundle(resources)
    if platform.system() == 'Darwin':
        subprocess.run(['codesign', '--force', '--sign', '-', str(app)], check=True)
        subprocess.run(['codesign', '--verify', '--strict', str(app)], check=True)
        result = subprocess.run(['codesign', '-dv', '--verbose=4', str(app)], capture_output=True, text=True)
        inspection['codesign'] = result.stdout + result.stderr
        if result.returncode or 'Signature=adhoc' not in inspection['codesign']:
            raise ValueError('expected verified ad-hoc signature without a certificate')
        signing = {'status': 'ad-hoc (no developer certificate)', 'notarization': 'not notarized', 'certificate': None}
    (package / 'native-inspection.json').write_text(json.dumps(inspection, indent=2) + '\n', encoding='utf-8')
    data = dict(schema='p2p-desktop-package/v1', **info, minimum_os=TARGETS[args.target][1],
                candidate=not dirty, signing=signing, license_material=resources.relative_to(package).as_posix(), created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                executable=executable.relative_to(package).as_posix(), executable_bytes=executable.stat().st_size,
                executable_sha256=digest(executable), dependency_packages=dependencies,
                metadata_process_seconds=round(probe_seconds, 6),
                metadata_timing_scope='Native --build-info subprocess only, NOT GUI startup timing.',
                physical_validation='Not inferred from packaging/CI; see Issue #24 mandatory external validation gates.')
    (package / 'build-info.json').write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    checksum_lines = [f'{digest(f)}  {f.relative_to(package).as_posix()}' for f in sorted(package.rglob('*')) if f.is_file()]
    (package / 'SHA256SUMS').write_text('\n'.join(checksum_lines) + '\n', encoding='utf-8')
    if platform.system() == 'Linux':
        archive = output / (stem + '.tar.gz')
        with tarfile.open(archive, 'w:gz') as tar:
            tar.add(package, arcname=stem)
    else:
        archive = output / (stem + '.zip')
        with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z:
            for f in sorted(package.rglob('*')):
                if f.is_file():
                    z.write(f, f.relative_to(output).as_posix())
    data.update(archive=archive.name, archive_bytes=archive.stat().st_size, archive_sha256=digest(archive))
    (output / 'candidate.json').write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    (output / (archive.name + '.sha256')).write_text(f'{data["archive_sha256"]}  {archive.name}\n', encoding='utf-8')
    print(json.dumps(data, ensure_ascii=False))


if __name__ == '__main__':
    main()
