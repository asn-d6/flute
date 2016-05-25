import unittest

import viola.keycache

class KeyCacheTest(unittest.TestCase):
    def test_keycache(self):
        """
        We test the key cache by adding some keys and then fetching them.  We also
        test the cleanup procedure for old keys.
        """
        key_cache = viola.keycache.RoomMessageKeyCache(n_max_keys=5)

        # Test key submission
        key_cache.submit_key("123")
        key_cache.submit_key("456")
        key_cache.submit_key("789")

        # Test key retrieval
        key = key_cache.get_current_key()
        self.assertEqual(key, "789")
        current_key = key_cache.get_current_key()
        self.assertEqual(key, current_key)
        current_keyid = key_cache.get_current_keyid()
        self.assertEqual(current_keyid, 3)

        # Submit some more keys
        key_cache.submit_key("abc")
        key_cache.submit_key("def")

        # Test key retrieval again
        key = key_cache.get_current_key()
        self.assertEqual(key, "def")
        oldest_keyid = key_cache.get_oldest_keyid()
        self.assertEqual(oldest_keyid, 1)

        # Submit more keys to test key cache cleanup: We should already have
        # registered 5 keys, so adding extra keys should force the key cache to
        # clean up the oldest keys.
        key_cache.submit_key("!@#")
        key = key_cache.get_current_key()
        self.assertEqual(key, "!@#")

        oldest_keyid = key_cache.get_oldest_keyid()
        self.assertEqual(oldest_keyid, 2)

        # Test cleanup some more
        key_cache.submit_key("$%^")
        key_cache.submit_key("&*(")
        oldest_keyid = key_cache.get_oldest_keyid()
        self.assertEqual(oldest_keyid, 4)

    def test_key_iterator(self):
        key_cache = viola.keycache.RoomMessageKeyCache(n_max_keys=5)
        i = 0

        self.assertEqual(key_cache.is_empty(), True)

        # Test key submission
        key_cache.submit_key("buena")
        key_cache.submit_key("vista")
        key_cache.submit_key("social")
        key_cache.submit_key("club")

        self.assertEqual(key_cache.is_empty(), False)

        for key in key_cache.message_key_iterator():
            i += 1
            if i == 1:
                self.assertEqual(key, "club")
            elif i == 2:
                self.assertEqual(key, "social")
            elif i == 3:
                self.assertEqual(key, "vista")
            elif i == 4:
                self.assertEqual(key, "buena")
            else: # should never get here
                self.assertFalse(True)

if __name__ == '__main__':
    unittest.main()

