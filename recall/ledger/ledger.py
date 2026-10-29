"""Append-only, hash-chained action ledger: the recovery engine's source of truth."""

import copy
import hashlib
import json
import threading

ACTION_UPDATES = {"hold_released", "hold_rejected"}


class LedgerError(Exception):
    pass


def _digest(body: dict) -> str:
    return hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()


class Ledger:
    def __init__(self, path=None):
        self._entries = []
        self.path = path
        self._lock = threading.Lock()  # drafts may be appended from a background thread

    def append(self, entry_type: str, ts: int, **fields) -> dict:
        with self._lock:
            prev = self._entries[-1]["hash"] if self._entries else "0" * 64
            body = {"seq": len(self._entries), "type": entry_type, "ts": ts, **copy.deepcopy(fields), "prev": prev}
            body["hash"] = _digest(body)
            self._entries.append(body)
            if self.path:
                with open(self.path, "a") as fh:
                    fh.write(json.dumps(body, sort_keys=True, default=str) + "\n")
            return copy.deepcopy(body)

    def entries(self, entry_type=None):
        return [copy.deepcopy(e) for e in self._entries if entry_type is None or e["type"] == entry_type]

    def __len__(self):
        return len(self._entries)

    def next_action_id(self) -> str:
        return f"A-{sum(1 for e in self._entries if e['type'] == 'action') + 1:04d}"

    def get_action(self, action_id):
        """The action as currently known: the original record with later hold decisions applied."""
        merged = None
        for e in self._entries:
            if e.get("action_id") != action_id:
                continue
            if e["type"] == "action":
                merged = copy.deepcopy(e)
            elif e["type"] in ACTION_UPDATES and merged is not None:
                for k in ("status", "resources", "executed_at", "approved_by", "rejected_by", "reason"):
                    if k in e:
                        merged[k] = copy.deepcopy(e[k])
        return merged

    def verify(self) -> bool:
        prev = "0" * 64
        for i, e in enumerate(self._entries):
            body = {k: v for k, v in e.items() if k != "hash"}
            if e["seq"] != i or e["prev"] != prev or _digest(body) != e["hash"]:
                raise LedgerError(f"ledger chain broken at seq {i}")
            prev = e["hash"]
        return True
