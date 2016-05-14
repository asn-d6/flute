""" room.py : Code that manages Viola rooms and their members """

import crypto
import util
import viola

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

        # This is the key to actually encrypt messages. We don't know it yet.
        self.room_message_key = None

        # A pointer to the weechat IRC buffer this room is in. XXX terrible abstraction
        self.buf = buf

        # Room status. Used to figure out whether to send encrypted messages or not.
        self.status = "bootstrapping"  # XXX hack. figure out proper FSM

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

    def set_room_message_key(self, room_message_key):
        """We got the room message key! Set it!"""
        self.room_message_key = room_message_key

    def get_room_message_key(self):
        if not self.room_message_key:
            raise NoMessageKey()
        return self.room_message_key

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

    def get_member(self, nick):
        if nick not in self.members:
            raise NoSuchMember
        return self.members[nick]

    def get_message_key_array(self):
        """
        As the captain, we need to generate a new room message key, encrypt it, put
        it in the message key array and pass it to all the room members.
        """

        assert(self.i_am_captain)
        self.room_message_key = crypto.gen_symmetric_key() # XXX

        util.debug("Generated new room message key for %s: %s" %
                   (self.name, crypto.get_hexed_key(self.room_message_key)))

        message_key_array = []

        for member in self.members.values():
            # Encrypt the room message key for each member.
            key_ciphertext = member.get_message_key_ciphertext(self.participant_priv_key,
                                                               self.room_message_key)
            assert(len(key_ciphertext) == 32 + 40) # XXX
            message_key_array.append(key_ciphertext)

        # Concatenate all bytes and return
        return "".join(message_key_array)

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
        return self.room_message_key # XXX use the FSM of the room

class NoMessageKey(Exception): pass
class NoSuchMember(Exception): pass
