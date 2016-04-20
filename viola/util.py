""" util.py : General viola utility functions """

import re

import otrlib

import weechat

# The viola utility buffers
global VIOLA_DEBUG_BUFFER
VIOLA_DEBUG_BUFFER = None
global VIOLA_CONTROL_BUFFER
VIOLA_CONTROL_BUFFER = None

def get_local_server(buf):
    return otrlib.buffer_get_string(buf, 'localvar_server')

def get_local_nick(buf):
    return otrlib.buffer_get_string(buf, 'localvar_nick')

def get_local_channel(buf):
    return otrlib.buffer_get_string(buf, 'localvar_channel')

def get_current_buffer():
    return weechat.current_buffer()

def prnt(buf, message):
    """Wrap weechat.prnt() with utf-8 encode."""
    weechat.prnt(buf, str(message))

def viola_channel_msg(buf, msg, color="green"):
    """
    Insert a colorized viola message to the buffer 'buf'.
    This is used for informative viola messages inlined in the room bufer.
    """
    msg = "[Viola] %s" % msg
    prnt(buf, otrlib.colorize(msg, color))

def setup_viola_weechat_buffers():
    """Initialize the viola control panel and debug buffers."""
    global VIOLA_DEBUG_BUFFER
    global VIOLA_CONTROL_BUFFER

    if not VIOLA_CONTROL_BUFFER:
        VIOLA_CONTROL_BUFFER = weechat.buffer_new(otrlib.colorize("Viola Control Panel", "yellow"),
                                                                  "", "",
                                                                  "debug_buffer_close_cb", "")

        weechat.buffer_set(VIOLA_CONTROL_BUFFER, 'title', 'Viola Control Messages')

        weechat.buffer_set(VIOLA_CONTROL_BUFFER, 'localvar_set_no_log', '1')

    if not VIOLA_DEBUG_BUFFER:
        VIOLA_DEBUG_BUFFER = weechat.buffer_new("Viola Debug", "", "",
                                              "debug_buffer_close_cb", "")
        weechat.buffer_set(VIOLA_DEBUG_BUFFER, 'title', 'Viola Debug')
        weechat.buffer_set(VIOLA_DEBUG_BUFFER, 'localvar_set_no_log', '1')

def debug(msg):
    """Send a debug message to the viola debug buffer."""
    global VIOLA_DEBUG_BUFFER
    assert(VIOLA_DEBUG_BUFFER)

    prnt(VIOLA_DEBUG_BUFFER, ('{script} DEBUG\t{text}'.format(
        script="Viola",
        text=unicode(msg)
    )))

def control_msg(msg):
    """Send a message to the viola control panel"""
    global VIOLA_CONTROL_BUFFER
    assert(VIOLA_CONTROL_BUFFER)

    header = "Viola control panel"

    prnt(VIOLA_CONTROL_BUFFER, "%s\t%s" % (otrlib.colorize(header, "yellow"), unicode(msg)))

def irc_channel_is_empty(channel, server):
    """Return True if we are the only nick in the channel."""

    infolist = weechat.infolist_get('irc_nick', '', "%s,%s" % (server, channel))
    n_members = 0

    # Count users
    if infolist:
        while weechat.infolist_next(infolist):
            n_members += 1

        weechat.infolist_free(infolist)

    # At least another person is in the channel.
    if n_members > 1:
        return False

    return True

def parse_irc_quit_kick_part(message, server):
    """Parse an QUIT/KICK/PART IRC message."""
    weechat_result = weechat.info_get_hashtable(
        'irc_message_parse', dict(message=message))

    if weechat_result['command'].upper() not in ("QUIT", "KICK", "PART"):
        raise PrivmsgParseException(message)

    result = {
        'from': weechat_result['host'],
        'from_nick': weechat_result['nick'],
        'command': weechat_result['command'],
        'channel': weechat_result['channel']
    }

    if weechat_result['command'].upper() == "KICK":
        result['target'] = weechat_result['text'].split(" ")[0] # XXX ugly

    return result

def is_hex(s):
    """Return true if string 's' is hex."""
    hex_digits = set("0123456789abcdef")
    for char in s:
        if not (char in hex_digits):
            return False
    return True
