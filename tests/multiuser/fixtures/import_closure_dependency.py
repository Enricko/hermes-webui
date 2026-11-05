"""Synthetic sibling dependency used to detect unsnapshotted imports."""

import os
from pathlib import Path

Path(os.environ["F02_SYNTHETIC_IMPORT_MARKER"]).write_text(
    "sibling import reached", encoding="utf-8"
)
