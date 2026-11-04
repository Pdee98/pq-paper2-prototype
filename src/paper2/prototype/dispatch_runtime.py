"""Prototype-only completion transactions and interruptible dispatcher slices.

Model selection/state methods, worker processes and Pipe payloads are unchanged.
Rows capture immutable state before selection, but buffer/progress commits and
append-only evidence are deferred until all newly selected jobs have been sent.
"""

import heapq

from src.paper2.state import SignatureCache


class EvidenceList(list):
    """No scheduling/state consumer reads these append-only evidence lists."""
    def __init__(self,owner,values):super().__init__(values);self.owner=owner
    def append(self,value):
        if self.owner.completion_evidence is not None:
            self.owner.completion_evidence.append(("append",self,value))
        else:super().append(value)


class SlicedCache(SignatureCache):
    def _maintenance(self,now,context):
        owner=self.owner
        # Completion transitions stay atomic through successor selection. A
        # context change likewise cannot expose a partially reset namespace.
        if owner.completion_evidence is not None or (self.context is not None and context!=self.context):
            return super()._maintenance(now,context)
        self.context=context
        while self.expiry and self.expiry[0][0]<=max(now,owner.t):
            _,key,version=heapq.heappop(self.expiry)
            entry=self.entries.get(key)
            if entry is not None and entry["version"]==version:
                del self.entries[key]
                # Publish this removal before yielding: a completion can insert
                # the identical key, and a late eviction row would erase it in
                # the independent checker. No removal is emitted twice.
                job,kind=owner.maintenance_context
                owner._log("cache_evict",job,cache_key=key,detail=kind+":ttl")
            owner._checkpoint("cache_ttl")
        return []
