""" room.py : Code that manages Viola rooms and their members """

import crypto
import util
import viola
import keycache
import weechat

class RoomMember(object):
    """Represents the member of a Viola room."""
    def __init__(self, nickname, identity_pubkey, room_pubkey):
        self.nickname = nickname
        self.identity_pubkey = identity_pubkey
        self.room_pubkey = room_pubkey

    def get_message_key_ciphertext(self,
                                   captain_room_participant_privkey,
                                   room_message_key):
        return crypto.get_message_key_ciphertext(captain_room_participant_privkey,
                                                 room_message_key, self.room_pubkey)

    def change_nickname(self, old_nick, new_nick):
        """Update the nickname of this room member."""
        assert(old_nick == self.nickname)
        self.nickname = new_nick

    def get_identity_pubkey(self):
        return self.identity_pubkey

# Rekey room every N minutes
ROOM_REKEY_PERIOD = 10 * 60 * 1000 # 10 minutes (in milliseconds)

# Max number of room message keys we should cache
MAX_CACHED_ROOM_MESSAGE_KEYS = 10

def schedule_periodic_room_rekey(channel, server):
    util.debug("Scheduling rekey on %s!" % channel)
    weechat.hook_timer(ROOM_REKEY_PERIOD, 0, 0,
                       "rekey_timer_cb",
                       channel + ',' + server)

class ViolaRoom(object):
    """Represents a Viola room"""
    def __init__(self, channel_name, server, buf, i_am_captain):
        self.name = channel_name
        self.server = server
        self.i_am_captain = i_am_captain

        # Dict of members { nickname : RoomMember}
        # Does not include ourselves.
        self.members = {}

        # Generate personal ephemeral room key used for KEY_TRANSPORT.
        self.participant_priv_key = None
        self.generate_room_key()

        # This is the cache that holds the room keys
        self.key_cache = keycache.RoomMessageKeyCache(MAX_CACHED_ROOM_MESSAGE_KEYS)

        # A pointer to the weechat IRC buffer this room is in. XXX terrible abstraction
        self.buf = buf

        # Room status. Used to figure out whether to send encrypted messages or not.
        self.status = "bootstrapping"  # XXX hack. figure out proper FSM

        self.key_transport_counter = 0

        if self.i_am_captain:
            # If we are captain we need to rekey room every N minutes.
            schedule_periodic_room_rekey(self.name, self.server)

        # XXX make sure these things get cleaned when room/channel gets closed.

    def generate_room_key(self):
        self.participant_priv_key = crypto.gen_privkey()
        util.debug("Generated room participant key %s" % crypto.get_hexed_key(bytes(self.participant_priv_key.public_key)))

    def get_room_participant_pubkey(self):
        """Return our 'room participant public key'."""
        return bytes(self.participant_priv_key.public_key)

    def get_room_participant_privkey(self):
        """Return our 'room participant private key'."""
        return self.participant_priv_key

    def set_room_message_key(self, room_message_key, captain_key_counter):
        """Set the latest room message key, and the key transport counter."""
        self.key_cache.submit_key(room_message_key)
        self.key_transport_counter = captain_key_counter

    def get_current_room_message_key(self):
        return self.key_cache.get_current_key()

    def key_transport_is_replay(self, new_key_counter):
        if new_key_counter <= self.key_transport_counter:
            util.viola_channel_msg(self.buf,
                                   "Received replayed KEY_TRANSPORT packet (%d / %d)" % \
                                   (new_key_counter, self.key_transport_counter),
                                   color="red")
            return True

        return False

    def add_member(self, nickname, identity_pubkey, room_pubkey):
        """Add member to viola room."""
        new_member = RoomMember(nickname, identity_pubkey, room_pubkey)
        self.members[nickname] = new_member
        util.debug("Adding new room member %s (members: %s)" % (nickname, str(self.members.keys())))

    def remove_member_and_rekey(self, nickname):
        """Remove member from viola room and send a new KEY_TRANSPORT if required."""
        if not nickname in self.members:
            raise NoSuchMember

        util.debug("Removing %s from room %s (members: %s)." % (nickname, self.name, self.members.keys()))

        # Remove member
        self.members.pop(nickname)

        # If we are captains and there are still people in the channel, rekey:
        if self.i_am_captain and self.members:
                viola.send_key_transport_packet(self) # XXX dirty calling viola.py

    def rekey(self):
        if not self.i_am_captain:
            util.debug("Tried to rekey while i am not captain..." )
            return
        if not self.members:
            util.debug("Not rekeying empty room...")
            return

        util.debug("Rekeying for room %s ." % self.name)
        viola.send_key_transport_packet(self)

    def get_member(self, nick):
        if nick not in self.members:
            raise NoSuchMember
        return self.members[nick]

    def get_message_key_array_and_counter(self):
        """
        As the captain, we need to generate a new room message key, encrypt it, put
        it in the message key array and pass it to all the room members.
        Return the message key array and the new message key counter.
        """

        assert(self.i_am_captain)
        fresh_room_message_key = crypto.gen_symmetric_key()
        new_key_counter = self.key_transport_counter + 1
        self.set_room_message_key(fresh_room_message_key, new_key_counter)

        util.debug("Generated new room message key for %s: %s" %
                   (self.name, crypto.get_hexed_key(self.key_cache.get_current_key())))

        message_key_array = []

        for member in self.members.values():
            # Encrypt the room message key for each member.
            key_ciphertext = member.get_message_key_ciphertext(self.participant_priv_key,
                                                               self.key_cache.get_current_key())
            assert(len(key_ciphertext) == 32 + 40) # XXX
            message_key_array.append(key_ciphertext)

        # Concatenate all bytes and return
        message_key_array_str = "".join(message_key_array)
        return message_key_array_str, new_key_counter

    def decrypt_room_message(self, message_ciphertext):
        """
        Figure out the right "room message key" and try to decrypt the room message
        ciphertext.
        """
        plaintext = None

        # Dont even try decrypting if we don't know the current room message key...
        if self.key_cache.is_empty():
            util.debug("Received ROOM_MESSAGE in %s but no message key. Ignoring." % self.name)
            util.viola_channel_msg(self.buf,
                                   "[You hear a viola screeching... Please do '/viola join-room' to join the session.]",
                                   "grey")
            return ""

        # Loop over all keys and try to decrypt packet.
        for potential_room_message_key in self.key_cache.message_key_iterator():
            try:
                plaintext = crypto.decrypt_room_message(potential_room_message_key, message_ciphertext)
                break
            except crypto.DecryptFail:
                util.debug("Hm, that key did not work. Trying next one...")
                continue

        # Did we get a plaintext? If yes, return it!!
        if plaintext:
            return plaintext

        # If we are here, all keys failed to decrypt and we can't do anything else...
        util.debug("All keys failed to decrypt ROOM_MESSAGE packet...")
        raise MessageDecryptFail

    def user_changed_nick(self, old_nick, new_nick):
        """
        A user changed their nickname. See if their old nickname is in this room,
        and if so update the user data.
        """
        if old_nick in self.members:
            # Swap the old nick with the new nick.
            room_member = self.members.pop(old_nick)
            room_member.change_nickname(old_nick, new_nick)
            self.members[new_nick] = room_member
            util.debug("Changed nickname of %s in %s to %s" % (old_nick, self.name, new_nick))

    def is_active(self):
        """Return True if this channel has been initialized and is active."""
        return bool(self.key_cache.get_current_key()) # XXX use the FSM of the room

class NoMessageKey(Exception): pass
class NoSuchMember(Exception): pass
class MessageDecryptFail(Exception): pass
