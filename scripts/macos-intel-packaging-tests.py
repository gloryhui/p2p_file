#!/usr/bin/env python3
"""Exercise Intel doctor/build prerequisite gates with an isolated fake toolchain."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parent.parent


@unittest.skipUnless(os.name == 'posix', 'Bash entrypoints require a POSIX host')
class IntelPrerequisites(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='p2p-intel-doctor-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        tools = self.root / 'tools'
        tools.mkdir()
        self.env = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ['PATH'],
                        P2P_FAKE_ROOT=str(self.root), P2P_FAKE_ARCH='x86_64',
                        P2P_FAKE_TRANSLATED='0', P2P_FAKE_HARDWARE_ARM='0',
                        P2P_FAKE_RUST_VERSION='1.85.0', P2P_FAKE_CARGO_VERSION='1.85.0')
        commands = {
            'uname': 'if [ "$1" = -s ]; then echo Darwin; else echo "$P2P_FAKE_ARCH"; fi',
            'sw_vers': 'echo 15.0',
            'sysctl': 'if [ "$2" = sysctl.proc_translated ]; then echo "$P2P_FAKE_TRANSLATED"; else echo "$P2P_FAKE_HARDWARE_ARM"; fi',
            'xcode-select': 'echo "$P2P_FAKE_ROOT"',
            'xcrun': 'echo "$P2P_FAKE_ROOT"',
            'clang': 'echo "Apple clang version 16.0.0"',
            'git': 'echo "git version 2.50.0"',
            'rustup': 'if [ "$1" = target ]; then echo x86_64-apple-darwin; else echo "rustup 1.28.0"; fi',
            'rustc': 'echo "rustc $P2P_FAKE_RUST_VERSION (fake)"',
            'cargo': 'if [ "$1" = --version ]; then echo "cargo $P2P_FAKE_CARGO_VERSION (fake)"; else touch "$P2P_FAKE_ROOT/cargo-started"; exit 99; fi',
            'codesign': 'echo "codesign fake utility"',
            'otool': 'echo "otool fake utility"',
        }
        for name, body in commands.items():
            file = tools / name
            file.write_text('#!/bin/sh\n' + body + '\n')
            file.chmod(0o755)

    def invoke(self, script, *args):
        return subprocess.run(['bash', str(REPO / 'packaging/macos-x86_64' / script), *args],
                              env=self.env, capture_output=True, text=True, timeout=30)

    def assert_build_blocked(self):
        output = self.root / 'package output'
        result = self.invoke('build.sh', '--output', str(output))
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('NOT READY', result.stdout)
        self.assertFalse((self.root / 'cargo-started').exists())
        self.assertFalse(output.exists())
        return result

    def test_native_intel_and_minimum_numeric_toolchain_are_ready(self):
        result = self.invoke('doctor.sh')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('\nREADY\n', result.stdout)
        self.assertIn('native architecture | detected: x86_64', result.stdout)
        self.assertFalse((self.root / 'cargo-started').exists())

    def test_arm_hardware_and_rosetta_never_reach_cargo_or_create_output(self):
        cases = [('arm64', '0', '1'), ('x86_64', '1', '1'), ('x86_64', '0', '1')]
        for machine, translated, hardware in cases:
            with self.subTest(machine=machine, translated=translated):
                self.env.update(P2P_FAKE_ARCH=machine, P2P_FAKE_TRANSLATED=translated,
                                P2P_FAKE_HARDWARE_ARM=hardware)
                result = self.assert_build_blocked()
                self.assertIn('FAIL | native architecture', result.stdout)

    def test_old_or_malformed_rust_and_cargo_never_reach_build(self):
        for variable in ['P2P_FAKE_RUST_VERSION', 'P2P_FAKE_CARGO_VERSION']:
            for version in ['1.84.1', 'unknown']:
                with self.subTest(variable=variable, version=version):
                    self.env[variable] = version
                    result = self.assert_build_blocked()
                    self.assertIn('>= 1.85.0', result.stdout)
                    self.env[variable] = '1.85.0'


if __name__ == '__main__':
    unittest.main()
