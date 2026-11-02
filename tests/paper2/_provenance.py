"""One actual git snapshot per unit-test module, unchanged throughout that module.

No model files or Git state change during the suite. Source/input checksums
remain freshly computed by every run; CLI subprocesses keep normal provenance.
"""

from unittest.mock import patch
from src.paper2.model.engine import _git_state

_patcher = None


def setUpModule():
    global _patcher
    actual = _git_state()
    _patcher = patch("src.paper2.model.engine._git_state", return_value=actual)
    _patcher.start()


def tearDownModule():
    _patcher.stop()
