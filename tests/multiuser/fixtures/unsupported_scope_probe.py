"""Synthetic-only probe for unsupported browser and credential access paths."""

import sys
from pathlib import Path
from urllib.request import ProxyHandler, build_opener


if sys.argv[1] == "credential-reader":
    # This stands in for a credential-reader import. It never calls an OS API.
    Path(sys.argv[2]).write_text("synthetic reader reached", encoding="utf-8")
elif sys.argv[1].startswith("http://"):
    opener = build_opener(ProxyHandler({}))
    with opener.open(sys.argv[1], timeout=2) as response:
        response.read()
else:
    raise SystemExit(64)
