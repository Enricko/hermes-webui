"""Child pytest assertion that root conftest and Agent discovery did not run."""

import sys
from pathlib import Path


def test_no_root_conftest_or_product_agent_imported():
    root_conftest = Path(__file__).resolve().parents[2] / "conftest.py"
    imported_files = {
        Path(getattr(module, "__file__", "")).resolve()
        for module in tuple(sys.modules.values())
        if getattr(module, "__file__", None)
    }
    assert root_conftest.resolve() not in imported_files
    assert "run_agent" not in sys.modules
    assert "api.startup" not in sys.modules
    assert not any(name.startswith("hermes_agent") for name in sys.modules)
