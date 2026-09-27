#!/usr/bin/env python3
"""Convert the approved PNG to native icon containers on macOS (sips/iconutil)."""
from pathlib import Path
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent / 'assets' / 'icons'


def resize(size, output):
    subprocess.run(['sips', '-z', str(size), str(size), str(ROOT / 'app-icon.png'),
                    '--out', str(output)], check=True, stdout=subprocess.DEVNULL)


def main():
    with tempfile.TemporaryDirectory(prefix='p2p-icons-') as temp:
        work = Path(temp)
        iconset = work / 'AppIcon.iconset'
        iconset.mkdir()
        for size in (16, 32, 128, 256, 512):
            resize(size, iconset / f'icon_{size}x{size}.png')
            resize(size * 2, iconset / f'icon_{size}x{size}@2x.png')
        subprocess.run(['iconutil', '-c', 'icns', str(iconset), '-o',
                        str(ROOT / 'app-icon.icns')], check=True)
        sizes = (16, 24, 32, 48, 64, 128, 256)
        entries, payload = [], []
        offset = 6 + 16 * len(sizes)
        for size in sizes:
            path = work / f'{size}.png'
            resize(size, path)
            data = path.read_bytes()
            entries.append(struct.pack('<BBBBHHII', size % 256, size % 256,
                                       0, 0, 1, 32, len(data), offset))
            payload.append(data)
            offset += len(data)
        (ROOT / 'app-icon.ico').write_bytes(
            struct.pack('<HHH', 0, 1, len(sizes)) + b''.join(entries + payload))
        resize(256, ROOT / 'app-icon-ui.png')


if __name__ == '__main__':
    main()
