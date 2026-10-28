"""Only in the marked disposable rehearsal: copy its generated test certificate."""
import grp
import os
from pathlib import Path
import shutil


if not Path('/etc/dazzle-handoff-isolated-container').exists() or not Path('/.dockerenv').exists():
    raise SystemExit('Disposable marked container required')
target=Path('/etc/dazzle-vps/web-tls')
if target.exists():
    for name in ('cert.pem','key.pem'):
        shutil.copyfile(Path('/etc/dazzle-vps/tls')/name,target/name)
        os.chown(target/name,0,grp.getgrnam('dazzle-web').gr_gid)
        os.chmod(target/name,0o640)
