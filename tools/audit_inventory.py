#!/usr/bin/env python3
"""Generate or verify the GitHub source-package file inventory.

This is not an automated source-code correctness proof. Only checks membership
and file contents; compile coverage is reported separately.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import io
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / 'reports' / 'audit_inventory.csv'


def classify(relative: str) -> str:
    name = relative.split('/')[0]
    suffix = Path(relative).suffix
    if suffix in ('.c', '.h', '.go') and name not in ('tests', 'tools'):
        return 'src'
    if suffix == '.md':
        return 'docs'
    if name == 'tests' or 'test' in relative or relative.startswith('tools/compat-oracle/'):
        return 'tests'
    if name == 'web':
        return 'web'
    if suffix in ('.yml', '.cmake', '.csv', '.defaults') or Path(relative).name in ('CMakeLists.txt','Kconfig.projbuild'):
        return 'build'
    return 'other'


def generate() -> str:
    rows = []
    for f in sorted(ROOT.rglob('*')):
        if not f.is_file() or f == MANIFEST:
            continue
        if any(part.startswith('build') or part == '__pycache__' for part in f.relative_to(ROOT).parts):
            continue
        if f.suffix in ('.pyc','.o','.elf','.bin'):
            continue
        rel = f.relative_to(ROOT).as_posix()
        rows.append((rel,classify(rel),str(f.stat().st_size),hashlib.sha256(f.read_bytes()).hexdigest(),
                     '纳入静态审查清单；动态执行覆盖仅由覆盖率报告证明'))
    output = io.StringIO()
    writer = csv.writer(output,lineterminator='\n')
    writer.writerow(('path','category','bytes','sha256','audit_scope_note'))
    writer.writerows(rows)
    return output.getvalue()


def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument('--write',action='store_true',help='regenerate reports/audit_inventory.csv')
    args=ap.parse_args()
    result=generate()
    if args.write:
        MANIFEST.parent.mkdir(exist_ok=True)
        MANIFEST.write_text(result)
        print(f'Wrote {len(result.splitlines())-1} file records')
        return 0
    current=MANIFEST.read_text() if MANIFEST.is_file() else ''
    if current != result:
        print('Inventory differs. Run python3 tools/audit_inventory.py --write')
        return 1
    print(f'Inventory OK: {len(result.splitlines())-1} files')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
