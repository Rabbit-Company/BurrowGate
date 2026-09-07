#!/usr/bin/env python3
"""Bundle the TRMNL plugin into an importable ZIP, using only Python stdlib.

The archive mirrors the sources: settings.yml, shared.liquid, and four layouts that are each
a single render tag. TRMNL prepends shared markup to every layout before rendering. Pass
--inline to do that prepending here instead, producing self-contained layouts for an import
path that drops shared.liquid.
"""
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

root = Path(__file__).resolve().parent
layouts = ["full.liquid", "half_horizontal.liquid", "half_vertical.liquid", "quadrant.liquid"]
inline = "--inline" in sys.argv[1:]
shared = (root / "shared.liquid").read_text()
archive_path = root / "burrowgate.zip"
with ZipFile(archive_path, "w", ZIP_DEFLATED) as archive:
    archive.write(root / "settings.yml", "settings.yml")
    if not inline:
        archive.write(root / "shared.liquid", "shared.liquid")
    for name in layouts:
        markup = (root / name).read_text()
        archive.writestr(name, shared + markup if inline else markup)
print(f"Built {archive_path}{' with shared markup inlined' if inline else ''}")
