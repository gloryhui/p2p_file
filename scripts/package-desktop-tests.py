#!/usr/bin/env python3
"""Behavior-boundary checks for architecture and candidate archive verification."""
import importlib.util
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
import tempfile
import unittest


def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


pack = module('package-desktop')
verify = module('verify-desktop-package')


class Boundaries(unittest.TestCase):
    def test_architecture_rejects_cross_platform_and_intel_mac(self):
        with tempfile.TemporaryDirectory() as root:
            file = Path(root) / 'binary'
            elf = bytearray(64)
            elf[:6] = b'\x7fELF\x02\x01'
            struct.pack_into('<H', elf, 18, 62)
            file.write_bytes(elf)
            pack.architecture(file, 'x86_64-unknown-linux-gnu')
            with self.assertRaises(ValueError):
                pack.architecture(file, 'aarch64-apple-darwin')
            macho = bytearray(64)
            macho[:4] = b'\xcf\xfa\xed\xfe'
            struct.pack_into('<I', macho, 4, 0x01000007)
            file.write_bytes(macho)
            with self.assertRaises(ValueError):
                pack.architecture(file, 'aarch64-apple-darwin')
            struct.pack_into('<I', macho, 4, 0x0100000c)
            file.write_bytes(macho)
            pack.architecture(file, 'aarch64-apple-darwin')

    def test_pe_x64_imports_use_actual_section_rvas(self):
        with tempfile.TemporaryDirectory() as root:
            file = Path(root) / 'binary.exe'
            data = bytearray(1024)
            data[:2] = b'MZ'
            struct.pack_into('<I', data, 60, 128)
            data[128:134] = b'PE\0\0\x64\x86'
            struct.pack_into('<H', data, 134, 1)
            struct.pack_into('<H', data, 148, 240)
            struct.pack_into('<H', data, 152, 0x20b)
            struct.pack_into('<II', data, 272, 0x1000, 40)
            struct.pack_into('<IIII', data, 392 + 8, 512, 0x1000, 512, 512)
            struct.pack_into('<IIIII', data, 512, 1, 0, 0, 0x1040, 1)
            data[576:589] = b'KERNEL32.dll\0'
            file.write_bytes(data)
            pack.architecture(file, 'x86_64-pc-windows-msvc')
            self.assertEqual(pack.pe_imports(file), ['KERNEL32.dll'])
            struct.pack_into('<I', data, 512 + 12, 0x9000)
            file.write_bytes(data)
            with self.assertRaisesRegex(ValueError, 'unmapped'):
                pack.pe_imports(file)

    def test_macos_minimum_is_not_the_sdk_or_linker_tool_version(self):
        load = """Load command 10
              cmd LC_BUILD_VERSION
          cmdsize 32
         platform macos
            minos 13.0
              sdk 26.0
           ntools 1
             tool ld
          version 1167.5
        """
        self.assertEqual(pack.macos_minimum(load), ['13.0'])
        with self.assertRaisesRegex(ValueError, 'exceeds'):
            pack.macos_minimum(load.replace('minos 13.0', 'minos 14.0'))
        with self.assertRaisesRegex(ValueError, 'missing'):
            pack.macos_minimum(load.replace('minos 13.0', 'tool_version 13.0'))
        legacy = 'Load command 7\n cmd LC_VERSION_MIN_MACOSX\n version 13.0.0\n sdk 26.0\n'
        self.assertEqual(pack.macos_minimum(legacy), ['13.0.0'])
        with self.assertRaisesRegex(ValueError, 'exceeds'):
            pack.macos_minimum(legacy.replace('13.0.0', '13.0.1'))

    def test_paths_reject_traversal_and_windows_forms(self):
        for name in ['../identity.key', '/etc/passwd', 'C:/private', 'folder\\..\\secret']:
            with self.assertRaises(ValueError):
                verify.relative(name)
        self.assertEqual(str(verify.relative('目录/内容.txt')), '目录/内容.txt')

    def test_preflight_cannot_be_accepted_and_archive_corruption_is_detected(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            file = root / 'candidate.json'
            archive = root / 'package.zip'
            archive.write_bytes(b'actual archive bytes')
            data = {'candidate': False, 'source_state': 'dirty', 'archive': archive.name,
                    'archive_sha256': verify.sha(archive), 'archive_bytes': archive.stat().st_size}
            file.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, 'preflight'):
                verify.verify(file)
            data.update(candidate=True, source_state='clean')
            file.write_text(json.dumps(data))
            archive.write_bytes(b'corrupted archive bytes')
            with self.assertRaisesRegex(ValueError, 'checksum/size'):
                verify.verify(file)


if __name__ == '__main__':
    unittest.main()
