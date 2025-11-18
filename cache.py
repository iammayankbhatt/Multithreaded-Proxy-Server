"""
Thread-safe LRU cache for storing HTTP responses.
Stores value as a dict: {'status':int, 'headers':list_of_tuples, 'body':bytes}
Eviction by total bytes of bodies + approximate header overhead.
"""

import threading
from collections import OrderedDict
import time

class CacheEntry:
    def __init__(self, value, size_bytes, expiry_ts: float | None):
        self.value = value
        self.size_bytes = size_bytes
        self.expiry_ts = expiry_ts

class ThreadSafeLRUCache:
    def __init__(self, max_bytes=20 * 1024 * 1024):
        self.lock = threading.RLock()
        self.max_bytes = max_bytes
        self.map = OrderedDict()  # key -> CacheEntry
        self.total_bytes = 0

    def _evict_if_needed(self):
        # assume lock already held
        while self.total_bytes > self.max_bytes and self.map:
            k, entry = self.map.popitem(last=False)
            self.total_bytes -= entry.size_bytes

    def _is_expired(self, entry: CacheEntry):
        return entry.expiry_ts is not None and time.time() > entry.expiry_ts

    def get(self, key: str):
        with self.lock:
            entry = self.map.get(key)
            if not entry:
                return None
            if self._is_expired(entry):
                # remove expired
                del self.map[key]
                self.total_bytes -= entry.size_bytes
                return None
            # promote
            self.map.move_to_end(key)
            return entry.value

    def put(self, key: str, value, ttl: int | None):
        # value expected: dict with headers, status, body (bytes)
        size = len(value.get('body', b'')) + 256  # approximate header overhead
        expiry = time.time() + ttl if ttl else None
        with self.lock:
            if key in self.map:
                old = self.map.pop(key)
                self.total_bytes -= old.size_bytes
            entry = CacheEntry(value, size, expiry)
            self.map[key] = entry
            self.total_bytes += size
            self.map.move_to_end(key)
            self._evict_if_needed()

    def flush(self):
        with self.lock:
            self.map.clear()
            self.total_bytes = 0

    def stats(self):
        with self.lock:
            return {
                'items': len(self.map),
                'total_bytes': self.total_bytes,
                'max_bytes': self.max_bytes,
                'keys': list(self.map.keys())[:50]  # show first 50 keys (for safety)
            }
