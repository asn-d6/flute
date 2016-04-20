""" introduction.py Handles and sends INTRODUCTION packets. """

import viola
import util
import base64
import crypto
import otrlib
import transport

import nacl.exceptions # XXX dirty

INTRODUCTION_PAYLOAD_LEN = 64 + 32

def handle_introduction_packet(packet_payload, parsed):
    util.debug("Parsing introduction packet")

    payload = base64.b64decode(packet_payload)

    if len(payload) < INTRODUCTION_PAYLOAD_LEN:
        raise IncompletePacket

    # Get packet fields
    signature = payload[:64]
    rcvd_pubkey = crypto.parse_signing_pubkey(payload[64:64+32])

    # Verify signature
    try:
        rcvd_pubkey.verify(payload)
    except nacl.exceptions.BadSignatureError:
        util.control_msg("Could not verify signature of INTRODUCTION packet.")
        return ""

    hexed_key = crypto.get_hexed_key(rcvd_pubkey)
    irc_nick = parsed['from_nick']
    util.control_msg("You received an introduction from %s with identity key:" % irc_nick)
    util.control_msg("\t%s" % otrlib.colorize(hexed_key, "green"))
    util.control_msg("If you trust that key, please type:")
    util.control_msg("\t /viola trust-key <name> %s" % hexed_key)
    util.control_msg("where <name> is the nickname you want to assign to the key.")
    util.control_msg("Example: /viola trust-key alice %s" % hexed_key)
    util.control_msg("-" * 100)

    return ""

def send_introduction(account, parsed_args, buf):
    """Build msg that introduces ourselves ('account') to another person."""

    # Validate args and print error otherwise XXX

    # Prepare the metadata
    nickname = parsed_args[1]
    server = util.get_local_server(buf) # XXX

    # Prepare the introduction message to be sent
    my_pub_key = account.get_identity_pubkey()
    packet_signed = account.sign_msg_with_identity_key(my_pub_key)

    payload_b64 = base64.b64encode(packet_signed)

    msg = viola.INTRODUCTION_OPCODE + payload_b64
    transport.send_viola_privmsg(server, nickname, msg)
