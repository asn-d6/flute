""" accounts.py: Flute user account management """

import os
import util
import crypto
import json
import room
import otrlib

# TODO Only one flute account for now per weechat  :)
ACCOUNT = None
def init_accounts(flute_dir):
    global ACCOUNT
    ACCOUNT = Account(flute_dir)

def get_my_account():
    return ACCOUNT

"""Represents a Flute user account.
   TODO: In the glorious future, a user should be able to have multiple Flute accounts.
"""
class Account(object):
    def __init__(self, flute_dir):
        # Flute home dir
        self.flute_dir = flute_dir

        # Filenames of disk state
        self.identity_privkey = None
        self.identity_privkey_fname = self.get_identity_privkey_fname("flute_account") # XXX put account name
        self.friends_db_fname = self.get_friends_db_fname("flute_account")

        # Dictionary of active flute rooms.
        # e.g. { "#social" : FluteRoom1 ; "#skateboarding" : FluteRoom2 }
        self.active_flute_rooms = {}

        # Initialize crypto!
        self.init_crypto()

    def get_friends_db_fname(self, account_name):
        return os.path.join(self.flute_dir, '{}.friends'.format(account_name))

    def get_identity_privkey_fname(self, account_name):
        """Return the private key file path for an account."""
        return os.path.join(self.flute_dir, '{}.priv_key'.format(account_name))

    def print_friend_list(self):
        if not os.path.exists(self.friends_db_fname):
            util.control_msg("Friend list file does not exist.")
            return

        with open(self.friends_db_fname, 'r+') as friends_file:
            friends_dict = json.load(friends_file)
            util.control_msg("Current state of friend list:\n%s" % json.dumps(friends_dict, indent=2))

    def print_fingerprint(self):
        identity_key = self.get_identity_pubkey()
        hexed_key = crypto.get_hexed_key(identity_key)
        util.control_msg("Our identity key is:")
        util.control_msg("\t%s" % otrlib.colorize(hexed_key, "green"))
        util.control_msg("A friend can trust it using the '/flute trust-key' command.")

    def init_crypto(self):
        """Initialize per-account crypto: Create an identity keypair."""
        try:
            self.identity_privkey = crypto.load_identity_privkey_from_disk(self.identity_privkey_fname)
        except IOError: # file not found (?)
            self.identity_privkey = crypto.gen_signing_privkey()
            util.debug("Generated identity keypair. Storing in '%s'." % self.identity_privkey_fname)
            crypto.store_identity_privkey_to_disk(self.identity_privkey, self.identity_privkey_fname)
        except ValueError:
            util.debug("Could not parse privkey.")

        util.debug("Using identity public key: %s" % crypto.get_hexed_key(self.identity_privkey.verify_key))

    def register_flute_room(self, channel, server, buf, i_am_captain=False):
        """
        Register flute room on this account. If a room under this channel name
        already exists, be careful about overwriting it.
        """
        old_room = None

        # If this room already exists and is active, don't register it again.
        if channel in self.active_flute_rooms:
            old_room = self.active_flute_rooms[channel]
            if old_room.is_active():
                util.flute_channel_msg(buf, "Channel %s is already a flute room" % channel) # XXX fix!
                raise FluteCommandError

        # If there used to be a room with this name but we are not overwriting
        # it, remove the old one.
        if old_room:
            self.active_flute_rooms.pop(channel) # XXX more cleanup?

        # Create the room
        flute_room = room.FluteRoom(channel, server, buf, i_am_captain)
        # and register it.
        self.active_flute_rooms[channel] = flute_room

        return flute_room

    def trust_key(self, nickname, hexed_key):
        """Register trusted key 'hexed_key' under 'nickname'."""
        util.debug("Trusting key by %s" % nickname)

        try:
            crypto.store_friends_pubkey_to_disk(nickname, hexed_key, self.friends_db_fname)
        except crypto.NickAlreadyRegistered:
            util.control_msg(otrlib.colorize("Nick %s is already registered." % nickname, "red"))
            return
        except crypto.KeyAlreadyRegistered:
            util.control_msg(otrlib.colorize("Key %s is already registered." % hexed_key, "red"))
            return

        # Print current version of the friend list
        self.print_friend_list()

    def get_flute_room(self, channel, server):
        """Get flute room based on channel/server"""
        if channel not in self.active_flute_rooms:
            raise NoSuchRoom

        return self.active_flute_rooms[channel]

    def sign_msg_with_identity_key(self, msg):
        return self.identity_privkey.sign(msg)

    def get_identity_pubkey(self):
        return bytes(self.identity_privkey.verify_key)

    def get_friend_from_identity_key(self, identity_pubkey):
        """
        If this key is in our friend list, return the friend's nickname. if this key
        is unknown, raise IdentityKeyNotTrusted.
        """
        if not os.path.exists(self.friends_db_fname):
            raise IdentityKeyNotTrusted # XXX initialize file

        with open(self.friends_db_fname, 'r+') as friends_file:
            try:
                friends_dict = json.load(friends_file)
            except ValueError, msg:
                util.debug("Could not load friends db: %s" % msg)
                friends_dict = {}

        # Check if nick or key are already registered.
        hexed_identity_pubkey = crypto.get_hexed_key(identity_pubkey)
        if hexed_identity_pubkey in friends_dict:
            return friends_dict[hexed_identity_pubkey]

        raise IdentityKeyNotTrusted

    def user_changed_nick(self, old_nick, new_nick):
        """
        A user changed their nickname. Walk over all the active flute rooms and do
        this change.
        """
        # XXX Here we assume that ALL nicks are in one server.
        util.debug("User %s changed nickname to %s. Updating rooms." % (old_nick, new_nick))
        for room in self.active_flute_rooms.values():
            room.user_changed_nick(old_nick, new_nick)

    def user_quit_irc(self, nick):
        """A user quit IRC. Remove them from all active channels."""
        for flute_room in self.active_flute_rooms.values():
            try:
                flute_room.remove_member_and_rekey(nick)
            except room.NoSuchMember:
                continue


class IdentityKeyNotTrusted(Exception): pass
class NoSuchRoom(Exception): pass
