#!/usr/bin/env python3
"""Offline repository Markdown link and fence validator. Zero firmware footprint.

Usage: python3 tools/check_docs.py
"""
from __future__ import annotations
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
FILES = sorted(ROOT.rglob('*.md'))
LINK = re.compile(r'(?<!!)\[[^]]+\]\(([^)]+)\)')
errors = []
nlinks = 0
for path in FILES:
    txt = path.read_text(encoding='utf-8')
    in_fence = False
    for no, line in enumerate(txt.splitlines(), 1):
        st = line.lstrip()
        if st.startswith('```'):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        for match in LINK.finditer(line):
            name = match.group(1).split('#', 1)[0].strip()
            if not name or name.startswith(('https://', 'http://', 'mailto:', 'data:', 'sandbox:', '/')):
                continue
            nlinks += 1
            dest = (path.parent / name).resolve()
            if not dest.is_relative_to(ROOT) or not dest.is_file():
                errors.append(f'{path.relative_to(ROOT)}:{no}: dead local link: {name}')
    if in_fence:
        errors.append(f'{path.relative_to(ROOT)}: unclosed fenced code block')
print(f'Markdown files: {len(FILES)}, local links: {nlinks}, errors: {len(errors)}')
for e in errors: print(e, file=sys.stderr)
sys.exit(1 if errors else 0)
