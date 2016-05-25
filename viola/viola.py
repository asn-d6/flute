""" flute.py : Handles and sends flute packets """

import crypto
import json # for saving state to disk
import os
import struct

import util
import otrlib
import json
import base64
import room
import transport
import introduction
import accounts

FLUTE_TAG = b'?VLA,'

INTRODUCTION_OPCODE = "00"
ROOM_JOIN_OPCODE = "01"
KEY_TRANSPORT_OPCODE = "02"
ROOM_MESSAGE_OPCODE = "03"

IRC_MAXIMUM_MESSAGE_SIZE = 399 # XXX figure out the right size here.

SIG_LEN = 64 # bytes per ed25519 sig
PUBKEY_LEN = 32 # bytes per ed25519/curve25519 key
SYMMETRIC_KEY_LEN = 32 # bytes per symmetric Box() key
MESSAGE_KEY_ARRAY_CELL_LEN = 72 # bytes: 32 bytes symmetric key + 40 bytes of nacl overhead
KEY_ID_LEN = 4 # bytes

#XXX need to verify ROOM_MESSAGE packets with long-term secret!!!
#XXX what happens if a user does join-room multiple times without leaving the channel
#XXX kill weechat logging wtf

def handle_room_message_packet(packet_payload, parsed, server):
    sender_host = parsed['from']
    sender_nick = parsed['from_nick']
    channel = parsed['to_channel']
    account = accounts.get_my_account()

    if not channel: # XXX functionify
        util.debug("Received ROOM_MESSAGE not in channel from %s. Ignoring." % sender_host)
        return ""

    # Is this channel a flute room for us?
    # XXX Code duplication
    try:
        flute_room = account.get_flute_room(channel, server)
    except accounts.NoSuchRoom:
        util.debug("Received ROOM_MESSAGE in a regular channel (%s). Ignoring." % channel)
        buf = util.get_current_buffer() # XXX weechat API shouldn't polute flute.py
        util.flute_channel_msg(buf,
                               "[You hear a flute screeching... Please do '/flute join-room' to join the session.]",
                               "lightcyan")
        return ""


    payload = base64.b64decode(packet_payload)

    if len(payload) <= 64:
        raise IncompletePacket

    util.debug("Attempting to decrypt ROOM_MESSAGE in %s" % channel)

    # Get packet fields
    signature = payload[:SIG_LEN]
    message_ciphertext = payload[SIG_LEN:]

    # Decrypt ciphertext
    try:
        plaintext = flute_room.decrypt_room_message(message_ciphertext)
    except room.MessageDecryptFail:
        util.flute_channel_msg(flute_room.buf,
                               "Could not decrypt message sent in room. Maybe old key. Try rejoining the channel.",
                               color="red")
        return ""

    if not plaintext:
        return ""

    msg = "[ENCRYPTED] %s" % plaintext
    msg_in = otrlib.build_privmsg_in(sender_host, channel, msg)
    return msg_in


MINIMUM_KEY_TRANSPORT_PAYLOAD_LEN = SIG_LEN + PUBKEY_LEN*2 + MESSAGE_KEY_ARRAY_CELL_LEN

def handle_key_transport_packet(packet_payload, parsed, server):
    sender = parsed['from_nick']
    channel = parsed['to_channel']
    account = accounts.get_my_account()

    if not channel: # XXX functionify
        util.debug("Received KEY_TRANSPORT not in channel from %s. Ignoring." % sender)
        return ""

    # Is this channel a flute room for us?
    # XXX Code duplication
    try:
        flute_room = account.get_flute_room(channel, server)
    except accounts.NoSuchRoom:
        util.debug("Received KEY_TRANSPORT in a regular channel (%s). Ignoring." % channel)
        return ""

    payload = base64.b64decode(packet_payload)

    if len(payload) < MINIMUM_KEY_TRANSPORT_PAYLOAD_LEN:
        raise IncompletePacket

    if flute_room.i_am_captain:
        util.debug("Received KEY_TRANSPORT in %s by %s but I am captain! Ignoring." % (channel, sender))
        return ""

    util.debug("Received KEY_TRANSPORT in %s! Handling it." % channel)

    # Start parsing the packet
    signature = payload[:SIG_LEN]

    captain_identity_pubkey = payload[SIG_LEN:SIG_LEN+PUBKEY_LEN]
    captain_identity_pubkey = crypto.parse_signing_pubkey(captain_identity_pubkey)

    captain_transport_pubkey = payload[SIG_LEN+PUBKEY_LEN : SIG_LEN+PUBKEY_LEN+PUBKEY_LEN]
    captain_transport_pubkey = crypto.parse_pub_key(captain_transport_pubkey)

    new_key_counter, = struct.unpack('>I',payload[SIG_LEN + PUBKEY_LEN + PUBKEY_LEN: SIG_LEN + PUBKEY_LEN + PUBKEY_LEN + KEY_ID_LEN])

    encrypted_message_key_array = payload[SIG_LEN+PUBKEY_LEN+PUBKEY_LEN + KEY_ID_LEN:]

    # Check if we trust the captain.
    try:
        captain_friend_name = account.get_friend_from_identity_key(captain_identity_pubkey)
    except accounts.IdentityKeyNotTrusted:
        hexed_captain_key = crypto.get_hexed_key(captain_identity_pubkey)
        buf = flute_room.buf
        util.flute_channel_msg(buf, "Untrusted nickname %s is the captain of this channel with key: %s" % (sender, hexed_captain_key),
                               color="red")
        util.flute_channel_msg(buf, "Ignoring KEY_TRANSPORT by untrusted captain. If you trust that key and "
                               "you want to join the channel, please issue the following command and rejoin:\n"
                               "\t /flute trust-key <name> %s\n"
                               "where <name> is the nickname you want to assign to the key."  % hexed_captain_key,
                               color="red")
        util.flute_channel_msg(buf, "Example: /flute trust-key alice %s" % hexed_captain_key,
                               color="red")
        return ""

    # Verify captain signature
    captain_identity_pubkey.verify(payload)    # XXX catch exception

    # Check for replays using KEY_TRANSPORT counter
    if new_key_counter < 1:
        util.debug("Corrupted key counter %d" % new_key_counter)
        return ""
    if flute_room.key_transport_is_replay(new_key_counter):
        return ""

    # Try to decrypt the message key array
    try:
        room_message_key = crypto.decrypt_room_message_key(encrypted_message_key_array,
                                                           captain_transport_pubkey,
                                                           flute_room.get_room_participant_privkey())
    except crypto.NoKeyFound:
        util.debug("Received KEY_TRANSPORT but did not find my key. Fuck.")
        return ""

    # We got the room message key!
    flute_room.set_room_message_key(room_message_key, new_key_counter)
    flute_room.status = "done"

    # We found our captain. Add them to the room!
    # XXX careful not to double-add the captain in case of rekey
    flute_room.add_member(sender, captain_identity_pubkey, captain_transport_pubkey)

    # Print some messages to the user
    buf = util.flute_channel_msg(flute_room.buf, "Got room key for %s with captain %s!" % (channel, sender))
    util.debug("Got a new room message key from captain %s: %s" % \
               (sender, crypto.get_hexed_key(room_message_key)))

    return ""

ROOM_JOIN_PAYLOAD_LEN = SIG_LEN + PUBKEY_LEN*2

def handle_room_join_packet(packet_payload, parsed, server):
    sender_nick = parsed['from_nick']
    channel = parsed['to_channel']
    account = accounts.get_my_account()

    if not parsed['to_channel']: # XXX functionify
        util.debug("Received ROOM_JOIN not in channel from %s. Ignoring." % sender_nick)
        return ""

    # Is this channel a flute room for us?
    try:
        flute_room = account.get_flute_room(channel, server)
    except accounts.NoSuchRoom:
        util.debug("Received ROOM_JOIN in a regular channel (%s). Ignoring." % channel)
        return ""

    payload = base64.b64decode(packet_payload)

    if len(payload) < ROOM_JOIN_PAYLOAD_LEN:
        raise IncompletePacket

    signature = payload[:SIG_LEN]
    identity_pubkey = crypto.parse_signing_pubkey(payload[SIG_LEN:SIG_LEN+PUBKEY_LEN])
    room_pubkey = crypto.parse_pub_key(payload[SIG_LEN+PUBKEY_LEN:SIG_LEN+PUBKEY_LEN+PUBKEY_LEN])

    # Verify signature
    # XXX is this the right logic for this particular packet?
    # XXX catch exception
    identity_pubkey.verify(payload)

    # XXX should we add all members even if we don't know them?
    flute_room.add_member(sender_nick, identity_pubkey, room_pubkey)

    # No need to do anything more if we are not captain in this channel.
    if not flute_room.i_am_captain:
        util.debug("Received ROOM_JOIN in %s but not captain. Ignoring." % channel)
        return ""

    util.debug("Received ROOM_JOIN in %s. Sending KEY_TRANSPORT (%d members)!" % (channel, len(flute_room.members)))

    # We are the captain. Check if we trust this key. Reject member otherwise.
    try:
        joining_friend_name = account.get_friend_from_identity_key(identity_pubkey)
    except accounts.IdentityKeyNotTrusted:
        buf = flute_room.buf
        util.flute_channel_msg(buf, "%s nickname %s is trying to join the channel with key %s." %
                               (otrlib.colorize("Untrusted", "red"), sender_nick,
                                crypto.get_hexed_key(identity_pubkey)), "red")
        util.flute_channel_msg(buf, "If you trust that key and you want them to join the channel, "
                               "please issue the following command and ask them to rejoin the channel:\n"
                               "\t /flute trust-key <name> %s\n"
                               "where <name> is the nickname you want to assign to the key."  %
                               crypto.get_hexed_key(identity_pubkey), "red")

        util.flute_channel_msg(buf, "Example: /flute trust-key alice %s" % crypto.get_hexed_key(identity_pubkey), "red")
        return ""

    # XXX Security: Maybe we should ask the captain before autoadding them!
    buf = flute_room.buf
    util.flute_channel_msg(buf, "Friend '%s' was added to the flute room!" % joining_friend_name)

    # We are captains in the channel. Act like it!
    # There is a new room member! Refresh and send new key!
    send_key_transport_packet(flute_room)
    return ""


def handle_flute_packet(packet, parsed, server):
    """
    Handle a generic flute packet. Parse its opcode and call the correct
    function for this specific type of packet.
    """

    util.debug("Parsing flute packet.")

    # XXX terrible functionify
    opcode = packet[:2]
    packet_payload = packet[2:]

    if opcode == "00":
        msg = introduction.handle_introduction_packet(packet_payload, parsed)
    elif opcode == "01":
        msg = handle_room_join_packet(packet_payload, parsed, server)
    elif opcode == "02":
        msg = handle_key_transport_packet(packet_payload, parsed, server)
    elif opcode == "03":
        msg = handle_room_message_packet(packet_payload, parsed, server)
    else:
        util.debug("Received flute packet with opcode: %s" % opcode)
        raise NotImplementedError("wtf")

    return msg

def forward_received_unencrypted_msg_to_user(parsed, server):
    """We received a regular IRC message that has nothing to do with Flute.
    Mark as unencrypted and forward to user"""
    sender = parsed['from']
    channel = parsed['to_channel']

    if channel:
        target = channel
    else:
        target = parsed['to_nick']

    msg = "[UNENCRYPTED] %s" % parsed['text'] # XXX need better indicator (use status bar, etc.)
    msg_in = otrlib.build_privmsg_in(sender, channel, msg)
    return msg_in

def received_irc_msg_cb(irc_msg, server):
    """Received IRC message 'msg'. Decode and return the message."""

    parsed = otrlib.parse_irc_privmsg(irc_msg, server)

    # Check whether the received message is a flute message
    msg = parsed['text']
    try:
        msg.index(FLUTE_TAG)
    except ValueError: # Not a flute message. Treat as plaintext and forward.
        return forward_received_unencrypted_msg_to_user(parsed, server)

    complete_packet = transport.accumulate_flute_fragment(msg, parsed, server)
    if not complete_packet: # Need to collect more fragments!
        return ""

    # We reconstructed a fragmented flute message! Handle it!
    return handle_flute_packet(complete_packet, parsed, server)

def handle_outgoing_irc_msg_to_channel(parsed, server):
    """We are about to send 'parsed' to a channel. If the channel is a flute room
    where the room message key is known, encrypt the message and send it
    directly. Otherwise if no Flute session is going on, return the plaintext
    string that should be output to the channel."""
    channel = parsed['to_channel']
    msg = parsed['text']
    account = accounts.get_my_account()

    try:
        flute_room = account.get_flute_room(channel, server)
    except accounts.NoSuchRoom:
        util.debug("No flute room at %s. Sending plaintext." % channel)
        return msg

    try:
        room_message_key = flute_room.get_current_room_message_key()
    except room.NoMessageKey:
        util.debug("No message key at %s. Sending plaintext." % channel) # XXX ???
        return msg

    if not flute_room.status == "done":
        util.debug("Room %s not setup yet. Sending plaintext." % channel) # XXX ???
        return msg

    util.debug("Sending encrypted msg to %s" % channel)

    # OK we are in a flute room and we even know the key!
    # Send a ROOM_MESSAGE!
    # XXX functionify
    ciphertext = crypto.get_room_message_ciphertext(room_message_key, msg)
    packet_signed = account.sign_msg_with_identity_key(ciphertext)

    payload_b64 = base64.b64encode(packet_signed)

    msg = ROOM_MESSAGE_OPCODE + payload_b64
    transport.send_flute_privmsg(server, channel, msg)

    return ""

def handle_outgoing_irc_msg_to_user(parsed):
    """We are about to send 'parsed' to a user. Just send plaintext."""
    return parsed['text']

def send_irc_msg_cb(msg, server):
    """Sending IRC message 'msg'. Return the bytes we should send to the network."""
    parsed = otrlib.parse_irc_privmsg(msg, server)

    if parsed['to_channel']:
        target = parsed['to_channel']
        msg = handle_outgoing_irc_msg_to_channel(parsed, server)
    else:
        target = parsed['to_nick']
        msg = handle_outgoing_irc_msg_to_user(parsed)

    if msg:
        msg_out = otrlib.build_privmsg_out(target, msg)
        return msg_out
    else:
        return ""

def send_key_transport_packet(flute_room):
    util.debug("I'm captain in %s: Membership changed. Refreshing message key." % flute_room.name)

    account = accounts.get_my_account()
    channel = flute_room.name
    server = flute_room.server

    assert(flute_room.i_am_captain) # Only captains should be here!

    # Prepare necessary packet fields.
    captain_identity_key = account.get_identity_pubkey()
    captain_transport_key = flute_room.get_room_participant_pubkey() # XXX maybe special func for captain's key?

    # XXX get_message_key_array also *generates* a new key. rename.
    message_key_array, key_transport_counter = flute_room.get_message_key_array_and_counter()
    # our array must be a multiple of 72 bytes
    assert(len(message_key_array) % MESSAGE_KEY_ARRAY_CELL_LEN == 0)
    # Encode new key id as big endian unsigned integer
    new_message_key_counter = struct.pack('>I', key_transport_counter)

    # Format the packet and sign it.
    packet_fields = captain_identity_key + captain_transport_key + new_message_key_counter + \
                    message_key_array
    packet_signed = account.sign_msg_with_identity_key(packet_fields)

    payload_b64 = base64.b64encode(packet_signed)

    flute_room.status = "bootstrapping"
    util.debug("Sending KEY_TRANSPORT in %s!" % channel)

    msg_type = KEY_TRANSPORT_OPCODE
    msg = msg_type + payload_b64
    transport.send_flute_privmsg(server, channel, msg)

    flute_room.status = "done"

def send_room_join(channel, server, buf):
    """Send ROOM_JOIN message."""
    account = accounts.get_my_account()

    # Don't send ROOM_JOIN to empty channel. No one to handle it.
    if util.irc_channel_is_empty(channel, server):
        util.flute_channel_msg(buf, "Can't 'join-room' in an empty channel!", "red")
        util.flute_channel_msg(buf, "Do '/flute start-room' if you want to start a new flute room instead.", "red")
        return

    # First of all, register this new room.
    flute_room = account.register_flute_room(channel, server, buf)

    # Get the keys to be placed in the packet
    my_pub_key = account.get_identity_pubkey()
    my_room_key = flute_room.get_room_participant_pubkey()

    # Sign them
    packet_fields = my_pub_key + my_room_key
    packet_signed = account.sign_msg_with_identity_key(packet_fields)

    payload_b64 = base64.b64encode(packet_signed)

    msg = ROOM_JOIN_OPCODE + payload_b64
    transport.send_flute_privmsg(server, channel, msg)

    util.flute_channel_msg(buf, "Requested to join room %s..." % channel)

def start_flute_room(channel, server, buf):
    """Start a Flute room in 'channel'@'server' on weechat buffer 'buf'."""
    account = accounts.get_my_account()
    util.debug("Starting a flute session in %s." % channel)

    # Make sure we are the only nick in the channel otherwise someone else
    # might already be captaining.
    if not util.irc_channel_is_empty(channel, server):
        util.flute_channel_msg(buf, "Can only start flute session in empty channel!", "red")
        util.flute_channel_msg(buf, "Try '/flute join-room' in this channel instead.", "red")
        return

    account.register_flute_room(channel, server, buf, i_am_captain=True)

    util.flute_channel_msg(buf, "We are now the captain in room %s!" % channel)

def user_left_channel(irc_msg, server):
    """A user left a channel we are in. Remove them from the channel if we are captain."""
    account = accounts.get_my_account()

    parsed = util.parse_irc_quit_kick_part(irc_msg, server)

    nick = parsed['from_nick']
    channel = parsed['channel']
    command = parsed['command']

    assert(command.upper() == "PART")

    util.debug("Received %s from %s in channel %s." % (command, nick, channel))

    try:
        flute_room = account.get_flute_room(channel, server)
    except accounts.NoSuchRoom:
        util.debug("No flute room at %s. Sending plaintext." % channel)
        return

    try:
        flute_room.remove_member_and_rekey(nick)
    except room.NoSuchMember:
        util.control_msg("A non-existent nick left the room. WTF.") # XXX i think this also catches ourselves
        return

def user_got_kicked(irc_msg, server):
    """A user got kicked from a channel we are in. Remove them from the member list."""
    account = accounts.get_my_account()

    parsed = util.parse_irc_quit_kick_part(irc_msg, server)

    nick = parsed['from_nick']
    channel = parsed['channel']
    command = parsed['command']
    target = parsed['target']

    assert(command.upper() == "KICK")

    util.debug("%s got kicked from %s by %s." % (target, channel, nick))

    try:
        flute_room = account.get_flute_room(channel, server)
    except accounts.NoSuchRoom:
        util.debug("No flute room at %s. Sending plaintext." % channel)
        return

    try:
        flute_room.remove_member_and_rekey(target)
    except room.NoSuchMember:
        util.control_msg("A non-existent nick left the room. WTF.") # XXX i think this also catches ourselves

def user_quit_irc(irc_msg, server):
    """A user quit IRC. Remove them form the member list of any channel they are in."""
    account = accounts.get_my_account()

    parsed = util.parse_irc_quit_kick_part(irc_msg, server)

    nick = parsed['from_nick']
    command = parsed['command']

    assert(command.upper() == "QUIT")

    account.user_quit_irc(nick)

def user_changed_irc_nick(old_nick, new_nick):
    """User changed nickname. Track the change."""
    account = accounts.get_my_account()
    # A user changed nick: we need to update the flute rooms.
    account.user_changed_nick(old_nick, new_nick)

def rekey_room(metadata):
    """Extract channel/server from metadata and rekey flute room."""

    # Get channel/server from metadata
    splited_room_id = metadata.split(',')
    room = splited_room_id[0]
    server = splited_room_id[1]

    util.debug("Attempting to rekey room %s..." % room)

    # Find the right flute room
    account = accounts.get_my_account()
    try:
        flute_room = account.get_flute_room(room, server)
    except accounts.NoSuchRoom:
        util.debug("Tried to rekey unknown room %s..." % room)
        return

    # Rekey room!
    flute_room.rekey()

class FluteCommandError(Exception): pass
class IncompletePacket(Exception): pass
