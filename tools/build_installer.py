#!/usr/bin/env python3
"""Build a deterministic standalone installer; no network or dependencies."""
import base64
import io
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]
FILES = ('bootstrap.py', 'backhaul_easy.py', 'panel_support.py', 'install-header.sh', 'install-footer.sh')
buffer = io.BytesIO()
with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
    for name in FILES:
        text = ROOT.joinpath(name).read_text(encoding='utf-8').replace('\r\n', '\n')
        if name.endswith('.py'):
            compile(text, name, 'exec')
        info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
        info.create_system = 3  # Keep ZIP metadata identical on Windows and Linux.
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o100600 << 16
        archive.writestr(info, text.encode('utf-8'))
encoded = base64.b64encode(buffer.getvalue()).decode()
script = ROOT.joinpath('install-header.sh').read_text() + "\nBUNDLE='" + encoded + "'\n" + ROOT.joinpath('install-footer.sh').read_text()
ROOT.joinpath('install.sh').write_text(script, encoding='utf-8', newline='\n')
print('Built standalone install.sh')
