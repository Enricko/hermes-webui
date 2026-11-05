"""Synthetic startup hook used only by tests to detect inherited PYTHONPATH."""

import os
from pathlib import Path

marker = os.environ.get("F02_SITE_MARKER_PATH")
if marker:
    Path(marker).write_text("synthetic startup hook ran", encoding="utf-8")
