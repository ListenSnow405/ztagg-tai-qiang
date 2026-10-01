#!/usr/bin/env python3
"""Rebuild the mobile APK with the touch-control web assets."""

from __future__ import annotations

import argparse
import shutil
import zipfile
from pathlib import Path


ASSET_REPLACEMENTS = {
    "assets/www/game/src/core/dom.js": "game/src/core/dom.js",
    "assets/www/game/src/i18n.js": "game/src/i18n.js",
    "assets/www/game/src/modes/rpg.js": "game/src/modes/rpg.js",
    "assets/www/game/src/modes/walk.js": "game/src/modes/walk.js",
    "assets/www/game/styles/chapter1.css": "game/styles/chapter1.css",
    "assets/www/game/styles/prologue.css": "game/styles/prologue.css",
    "assets/www/game/minigames/photo-rhythm/index.html": (
        "game/minigames/photo-rhythm/index.html"
    ),
}


def replacement_bytes(project_dir: Path, archive_name: str) -> bytes:
    source_path = project_dir / ASSET_REPLACEMENTS[archive_name]
    data = source_path.read_bytes()
    if archive_name.endswith("/walk.js"):
        data = data.replace(b"../sign&log/", b"../sign-log/")
    return data


def rebuild_apk(source_apk: Path, output_apk: Path, project_dir: Path) -> None:
    output_apk.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(source_apk, "r") as source, zipfile.ZipFile(
        output_apk, "w", allowZip64=True
    ) as output:
        archive_names = set(source.namelist())
        missing = set(ASSET_REPLACEMENTS) - archive_names
        if missing:
            raise RuntimeError(f"APK is missing expected entries: {sorted(missing)}")

        for info in source.infolist():
            if info.filename.upper().startswith("META-INF/"):
                continue

            if info.filename in ASSET_REPLACEMENTS:
                output.writestr(
                    info,
                    replacement_bytes(project_dir, info.filename),
                    compress_type=info.compress_type,
                    compresslevel=9,
                )
                continue

            with source.open(info, "r") as source_file, output.open(info, "w") as output_file:
                shutil.copyfileobj(source_file, output_file, length=1024 * 1024)


def main() -> None:
    project_dir = Path(__file__).resolve().parents[1]
    workspace_dir = project_dir.parent
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source",
        type=Path,
        default=workspace_dir / "I.L.Y-final.apk",
        help="Original signed APK",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=workspace_dir / "I.L.Y-mobile-unsigned.apk",
        help="Unsigned rebuilt APK",
    )
    parser.add_argument(
        "--preserve-assets",
        action="store_true",
        help="Copy the source APK's web assets byte-for-byte; useful when signing an already-final build",
    )
    args = parser.parse_args()

    if args.preserve_assets:
        ASSET_REPLACEMENTS.clear()
    rebuild_apk(args.source.resolve(), args.output.resolve(), project_dir)
    print(args.output.resolve())


if __name__ == "__main__":
    main()
