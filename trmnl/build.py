#!/usr/bin/env python3
"""Generate standalone TRMNL layouts and an importable ZIP, using only Python stdlib."""
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

root = Path(__file__).resolve().parent
source = (root / "screen.liquid").read_text()
files = ["settings.yml"]
for layout, stats, rows in [("full", 3, 6), ("half_horizontal", 3, 3), ("half_vertical", 2, 6), ("quadrant", 2, 3)]:
    name = f"{layout}.liquid"
    rendered = source.replace("__LAYOUT__", layout).replace("__STAT_LIMIT__", str(stats)).replace("__ROW_LIMIT__", str(rows))
    rendered = rendered.replace("__TICKS__", "100,50,0" if layout in ("half_horizontal", "quadrant") else "100,75,50,25,0")
    (root / name).write_text(rendered)
    files.append(name)
with ZipFile(root / "burrowgate.zip", "w", ZIP_DEFLATED) as archive:
    for name in files:
        archive.write(root / name, name)
print(f"Built {root / 'burrowgate.zip'}")
