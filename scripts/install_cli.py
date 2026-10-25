#!/usr/bin/env python3
"""Install a source-bundled CLI into ~/.local; no production configuration."""
import argparse
import os
from pathlib import Path
import shutil
import sys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--prefix", type=Path, default=Path.home()/".local")
args = parser.parse_args()
repo = Path(__file__).resolve().parents[1]
source = repo/"backend"/"dazzle"
if not (source/"__main__.py").is_file():raise SystemExit("Backend sources missing")
bin_dir = args.prefix.expanduser().resolve()/"bin"
resource = args.prefix.expanduser().resolve()/"share"/"dazzle-vps"
bin_dir.mkdir(parents=True,exist_ok=True)
resource.mkdir(parents=True,exist_ok=True)
next_source=resource/"dazzle.new"
if next_source.exists():shutil.rmtree(next_source)
shutil.copytree(source,next_source,ignore=shutil.ignore_patterns("__pycache__","*.pyc"))
target=resource/"dazzle"
if target.exists():shutil.rmtree(target)
next_source.rename(target)
wrapper = bin_dir/"dazzle-vps"
if wrapper.is_symlink():raise SystemExit("Refusing to overwrite a symlink")
# No shell interpolation and no credential arguments in this wrapper.
wrapper.write_text("#!"+sys.executable+"\nimport sys\nsys.dont_write_bytecode=True\nsys.path.insert(0,"+repr(str(resource))+ ")\nfrom dazzle.__main__ import main\nraise SystemExit(main())\n")
wrapper.chmod(0o755)
print(wrapper)
