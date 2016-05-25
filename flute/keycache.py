class RoomMessageKeyCache(object):
    """Holds room message keys for a flute room."""
    def __init__(self, n_max_keys):
        """Dictionary: { <keyid> : <cached key> }"""
        self.cached_keys = {}
        self.n_max_keys = n_max_keys

    def submit_key(self, key):
        """Submit new room message key to the cache."""
        if self.is_empty():
            current_keyid = 1
        else:
            current_keyid = self.get_current_keyid()
            current_keyid += 1

        self.cached_keys[current_keyid] = key

        self.cleanup_old_keys()

    def is_empty(self):
        """Return True if the key cache is empty."""
        return len(self.cached_keys) == 0

    def cleanup_old_keys(self):
        while len(self.cached_keys) > self.n_max_keys:
            oldest_keyid = self.get_oldest_keyid()
            self.cached_keys.pop(oldest_keyid)

    def message_key_iterator(self):
        # Iterate through all keys.  We sort the dict in reverse key order, so
        # that we first try the keys with the latest keyid.
        for key in sorted(self.cached_keys, reverse=True):
            yield self.cached_keys[key]

    def get_current_key(self):
        """Get latest key."""
        if self.is_empty():
            return None # XXX or throw exception?

        current_keyid = self.get_current_keyid()
        return self.cached_keys[current_keyid]

    def get_current_keyid(self):
        """Get latest keyid."""
        if self.is_empty():
            raise EmptyKeyCache

        return max(self.cached_keys.keys())

    def get_oldest_keyid(self):
        if self.is_empty():
            raise EmptyKeyCache

        return min(self.cached_keys.keys())

class EmptyKeyCache(Exception): pass
