"""Synthetic child that replaces the explicit Agent checkout by path."""

import json
from pathlib import Path
import sys


root = Path(sys.argv[1])
moved = root.with_name(root.name + ".moved-by-child")
root.rename(moved)
root.mkdir()
(root / "run_agent.py").write_text("# replacement; never imported\n", encoding="utf-8")
sentinel = root / "replacement-sentinel"
sentinel.write_text("replacement must survive", encoding="utf-8")
print(json.dumps({"root": str(root), "moved": str(moved), "sentinel": str(sentinel)}))
