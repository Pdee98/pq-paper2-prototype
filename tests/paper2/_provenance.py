"""One actual git snapshot per unit-test module, unchanged throughout that module.

No model files or Git state change during the suite. Source/input checksums
remain freshly computed by every run; CLI subprocesses keep normal provenance.
"""

from unittest.mock import patch
from src.paper2.model.engine import _git_state

_patcher = None
_memory_patcher = None


def setUpModule():
    global _patcher, _memory_patcher
    actual = _git_state()
    _patcher = patch("src.paper2.model.engine._git_state", return_value=actual)
    _patcher.start()
    # Functional test fixtures do not depend on the developer host's current
    # free RAM. Production never uses this stub; threshold tests override it.
    import os
    def memory(pids=()):
        return dict(parent_pid=os.getpid(),rss_bytes={str(pid):100*1024**2 for pid in [os.getpid(),*pids]},
                    available_bytes=8*1024**3,total_bytes=32*1024**3)
    _memory_patcher=patch('src.paper2.prototype.gc_control.memory_snapshot',side_effect=memory)
    _memory_patcher.start()


def tearDownModule():
    _memory_patcher.stop()
    _patcher.stop()
