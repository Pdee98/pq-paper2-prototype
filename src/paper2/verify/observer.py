"""Optional progress observation; contains no checker or simulator decisions."""
from contextvars import ContextVar
OBSERVER = ContextVar("paper2_checker_observer", default=None)

def emit(stage, **counts):
    callback = OBSERVER.get()
    if callback is not None:
        callback(stage, **counts)
