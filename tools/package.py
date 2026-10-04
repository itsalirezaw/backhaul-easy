#!/usr/bin/env python3
"""Package only reviewed source files, never local state or downloaded binaries."""
import hashlib
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / 'dist'
DIST.mkdir(exist_ok=True)
NAMES = [
    'README.md', 'README.fa.md', 'VALIDATION.md', 'THIRD_PARTY.md', 'LICENSE', '.gitignore', '.gitattributes',
    '.github/workflows/ci.yml',
    'install.sh', 'install-header.sh', 'install-footer.sh', 'bootstrap.py',
    'backhaul_easy.py', 'panel_support.py', 'tools/build_installer.py', 'tools/package.py',
    'tests/test_backhaul_easy.py', 'tests/test_bootstrap.py', 'tests/test_panel_support.py',
    'tests/integration_backhaul.py',
]
destination = DIST / 'backhaul-easy-1.0.0-source.zip'
with zipfile.ZipFile(destination, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
    for name in sorted(NAMES):
        info = zipfile.ZipInfo('backhaul-easy/' + name, date_time=(2026, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o100644 << 16
        archive.writestr(info, (ROOT / name).read_bytes())
lines = [hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + path.name for path in (ROOT / 'install.sh', destination)]
(DIST / 'SHA256SUMS').write_text('\n'.join(lines) + '\n', encoding='ascii', newline='\n')
print(destination)
