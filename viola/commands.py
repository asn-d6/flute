"""commands.py: Functions that handle the weechat "/viola" commands"""

import util
import otrlib
import introduction
import viola
import accounts

def start_room_cmd(parsed_args, buf):
    """Become the channel of this room."""
    channel = util.get_local_channel(buf)
    server  = util.get_local_server(buf)

    # Become leader of channel
    viola.start_viola_room(channel, server, buf)

def introduction_cmd(parsed_args, buf):
    account = accounts.get_my_account()

    # Prepare the metadata
    server = util.get_local_server(buf)

    # If a nick is provided, introduce to that nick. Otherwise, check if we are
    # currently having a private conversation with another nick, and if so
    # introduce to that nick.
    if len(parsed_args) >= 2:
        target_nick = parsed_args[1]
    else:
        if otrlib.buffer_is_private(buf):
            target_nick = util.get_local_channel(buf)
        else:
            util.control_msg("Bad introduction command! Can't introduce yourself to a channel!")
            raise viola.ViolaCommandError

    introduction.send_introduction(account, target_nick, server, buf)

    util.viola_channel_msg(buf,
                           "[Introduced ourselves to %s.]" % target_nick,
                           color="green")

def join_room_cmd(parsed_args, buf):
    """Prepare for sending ROOM_JOIN message."""
    channel = util.get_local_channel(buf)
    server  = util.get_local_server(buf)

    viola.send_room_join(channel, server, buf)

def list_friends_cmd():
    account = accounts.get_my_account()
    account.print_friend_list()

def trust_key_cmd(parsed_args, buf):
    nickname = parsed_args[1]
    hexed_key = parsed_args[2]

    # Check for illegal nickname chars
    if not nickname.isalnum():
        util.control_msg("Invalid nickname: %s" % nickname)
        raise viola.ViolaCommandError

    if len(hexed_key) != 64 or not util.is_hex(hexed_key):
        util.control_msg("Invalid key value: %s" % hexed_key)
        raise viola.ViolaCommandError

    account = accounts.get_my_account()
    account.trust_key(nickname, hexed_key)

