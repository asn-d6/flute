# Code stolen from weechat_otr.py. Lightly modified and salted.

import weechat
import flute


IRC_SANITIZE_TABLE = dict((ord(char), None) for char in '\n\r\x00')
def irc_sanitize(msg):
    """Remove NUL, CR and LF characters from msg.
    The (utf-8 encoded version of a) string returned from this function
    should be safe to use as an argument in an irc command."""
    utf_msg = unicode(msg, 'utf8')
    return utf_msg.translate(IRC_SANITIZE_TABLE)

def buffer_get_string(buf, prop):
    """Wrap weechat.buffer_get_string() with utf-8 encode/decode."""
    if buf is not None:
        encoded_buf = str(buf)
    else:
        encoded_buf = None

    return weechat.buffer_get_string(encoded_buf, str(prop))

def buffer_is_private(buf):
    """Return True if a buffer is private."""
    return buffer_get_string(buf, 'localvar_type') == 'private'

def default_peer_args(args, buf):
    """Get the nick and server of a remote peer from command arguments or
    a buffer.

    args is the [nick, server] slice of arguments from a command.
    If these are present, return them. If args is empty and the buffer buf
    is private, return the remote nick and server of buf."""
    result = None, None

    if len(args) == 2:
        result = tuple(args)
    else:
        if buffer_is_private(buf):
            result = (
                buffer_get_string(buf, 'localvar_channel'),
                buffer_get_string(buf, 'localvar_server'))

    return result

def isupport_value(server, feature):
    """Get the value of an IRC server feature."""
    args = '{server},{feature}'.format(server=server, feature=feature)
    return info_get('irc_server_isupport_value', args)

def is_a_channel(channel, server):
    """Return true if a string has an IRC channel prefix."""
    prefixes = \
        tuple(isupport_value(server, 'CHANTYPES')) + \
        tuple(isupport_value(server, 'STATUSMSG'))

    # If the server returns nothing for CHANTYPES and STATUSMSG use
    # default prefixes.
    if not prefixes:
        prefixes = ('#', '&', '+', '!', '@')

    return channel.startswith(prefixes)

# Ripped from weechat_otr.py
def command(buf, command_str):
    """Wrap weechat.command() with utf-8 encode."""
    weechat.prnt("", command_str)
    weechat.command(buf, str(command_str))

# Ripped from weechat_otr.py .
def build_privmsg_out(target, msg):
    """Build outbound IRC PRIVMSG command(s)."""
    cmd = []
    for line in msg.splitlines():
        target=irc_sanitize(target)
        line = irc_sanitize(line)
        cmd.append("PRIVMSG %s :%s" % (target, line))
    return '\r\n'.join(cmd)

def build_privmsg_in(fromm, target, msg):
    """Build inbound IRC PRIVMSG command."""
    user=irc_sanitize(fromm)
    target=irc_sanitize(target)
    msg=irc_sanitize(msg)
    return ":%s PRIVMSG %s :%s" % (user, target, msg)

# Ripped from weechat_otr.py
# XXX unittest see tests in weechat-otr.py
def parse_irc_privmsg(message, server):
    """Parse an IRC PRIVMSG/QUIT/KICK/PART command and return a dictionary.

    Either the to_channel key or the to_nick key will be set depending on
    whether the message is to a nick or a channel. The other will be None.

    Example input:

    :nick!user@host PRIVMSG #weechat :message here

    Output:

    {'from': 'nick!user@host',
    'from_nick': 'nick',
    'to': '#weechat',
    'to_channel': '#weechat',
    'to_nick': None,
    'text': 'message here'}
    """

    weechat_result = weechat.info_get_hashtable(
        'irc_message_parse', dict(message=message))

    if weechat_result['command'].upper() == "PRIVMSG":
        target, text = weechat_result['arguments'].split(' ', 1)
        if text.startswith(':'):
            text = text[1:]

        result = {
            'from': weechat_result['host'],
            'to' : target,
            'text': text,
            }

        if weechat_result['host']:
            result['from_nick'] = weechat_result['nick']
        else:
            result['from_nick'] = ''

        if is_a_channel(target, server):
            result['to_channel'] = target
            result['to_nick'] = None
        else:
            result['to_channel'] = None
            result['to_nick'] = target

        return result
    else:
        raise PrivmsgParseException(message)

def weechat_version_ok():
    """Check if the WeeChat version is compatible with this script.

    If WeeChat version < 0.4.2 log an error to the core buffer and return
    False. Otherwise return True.
    """
    weechat_version = weechat.info_get('version_number', '') or 0
    if int(weechat_version) < 0x00040200:
        error_message = (
            '{script_name} requires WeeChat version >= 0.4.2. The current '
            'version is {current_version}.').format(
            script_name=SCRIPT_NAME,
            current_version=weechat.info_get('version', ''))
        weechat.prnt('', error_message)
        return False
    else:
        return True

def info_get(info_name, arguments):
    """Wrap weechat.info_get() _without_ utf-8 encode/decode."""
    return weechat.info_get(info_name, arguments)


def colorize(msg, color):
    """Colorize each line of msg using color."""
    result = []

    for line in msg.splitlines():
        result.append('{colorstr}{msg}'.format(
            colorstr=weechat.color(color),
            msg=line))

    return '\r\n'.join(result)

def buffer_is_private(buf):
    """Return True if a buffer is private."""
    return buffer_get_string(buf, 'localvar_type') == 'private'
