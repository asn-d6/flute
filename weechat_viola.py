"""Integrating weechat with viola"""

SCRIPT_AUTHOR = 'wont'
SCRIPT_LICENCE = 'GPL3'
SCRIPT_VERSION = '0.0.1'

SCRIPT_NAME = 'viola'
SCRIPT_DESC = 'One always plays the viola while they drink and chatter...'
SCRIPT_HELP = """VIOLA IS EXPERIMENTAL SOFTWARE PLEASE USE RESPONSIBLY!!!

Introduce yourself to an IRC user: /viola introduction <user>
Trust a friend's viola key: /viola trust-key <nick> <key>
List friends: /viola list-friends

Start a viola room in an IRC channel: /viola start-room
Join an active viola room in an IRC channel: /viola join-room
"""

import os, sys
import shlex # needed for /viola cmd parsing

import weechat

import viola.viola as viola
import viola.otrlib as otrlib
import viola.util as util
import viola.crypto as crypto
import viola.commands as commands
import viola.accounts as accounts

VIOLA_DIR_NAME = 'viola'


def create_viola_dir(dirname):
    """Create the OTR subdirectory in the WeeChat config directory if it does
    not exist."""
    if not os.path.exists(viola_dir):
        weechat.mkdir_home(VIOLA_DIR_NAME, 0o700)

def message_in_cb(data, modifier, modifier_data, string):
    """Incoming message callback"""
    return viola.received_irc_msg_cb(string, modifier_data)

def message_out_cb(data, modifier, modifier_data, string):
    """Outgoing message callback"""
    return viola.send_irc_msg_cb(string, modifier_data)

def viola_command_cb(data, buf, args):
    """Parse and dispatch /viola commands by the user"""
    retval =  weechat.WEECHAT_RC_OK

    try:
        parsed_args = [arg for arg in shlex.split(args)]
    except:
        util.debug("Command parsing error.")
        return retval

    util.debug("Received viola command: %s" % str(parsed_args))

    if not parsed_args:
        return retval

    # Parse all the /viola commands!!!
    if parsed_args[0] == 'introduction':
        try:
            commands.introduction_cmd(parsed_args, buf)
        except viola.ViolaCommandError:
            return weechat.WEECHAT_RC_ERROR
    elif parsed_args[0] == 'trust-key':
        try:
            commands.trust_key_cmd(parsed_args, buf)
        except viola.ViolaCommandError:
            return weechat.WEECHAT_RC_ERROR
    elif parsed_args[0] == 'join-room':
        commands.join_room_cmd(parsed_args, buf)
    elif parsed_args[0] == 'start-room':
        commands.start_room_cmd(parsed_args, buf)
    elif parsed_args[0] == 'list-friends':
        commands.list_friends_cmd()
    else:
        util.control_msg("Unknown viola command: %s" % parsed_args[0])
        return weechat.WEECHAT_RC_ERROR

    return retval

"""
stdout/stderr: Data:
stdout/stderr: Signal: irc_in_PART
stdout/stderr: type data: test
stdout/stderr: stirng: :test1!f@i.love.debian.org PART #test
"""
def user_left_channel_cb(data, modifier, modifier_data, string):
    viola.user_left_channel(string, modifier_data)
    return string

def user_got_kicked_cb(data, modifier, modifier_data, string):
    viola.user_got_kicked(string, modifier_data)
    return string

def user_quit_irc_cb(data, modifier, modifier_data, string):
    viola.user_quit_irc(string, modifier_data)
    return string

"""
16:53:06 weechat     | python: stdout/stderr: Data:
16:53:06 weechat     | python: stdout/stderr: Signal: test,irc_in_NICK
16:53:06 weechat     | python: stdout/stderr: sd: :rofl!f@i.love.debian.org NICK :DRE
"""
def new_nick_cb(data, signal, signal_data):
    # XXX terrible code
    old_nick = signal_data[1:signal_data.find("!")]
    new_nick = signal_data[signal_data.rfind(' ') + 2:]
    viola.user_changed_irc_nick(old_nick, new_nick)
    return weechat.WEECHAT_RC_OK

def rekey_timer_cb(data, remaining_calls):
    viola.rekey_room(data)
    return weechat.WEECHAT_RC_OK

def rekey_timer_operation(room_server):
    weechat.prnt("", " starting timer for room %s." % room_server)
    weechat.hook_timer(60 * 1000, 60, 0, "rekey_timer_cb", room_server)

################################################################################

application_operations = {
        "rekey_timer" : rekey_timer_operation
        }

# Register the plugin with Weechat.

reg = weechat.register(SCRIPT_NAME, SCRIPT_AUTHOR,
                     SCRIPT_VERSION, SCRIPT_LICENCE, SCRIPT_DESC,
                     'shutdown', '')
if reg:
    if otrlib.weechat_version_ok():
        # Initialize logging buffers
        util.setup_viola_weechat_buffers()
        util.control_msg(otrlib.colorize("This is the control panel buffer for important messages!", "yellow"))
        util.control_msg(otrlib.colorize("-"*100, "yellow"))

        # Initialize user accounts
        viola_dir = os.path.join(otrlib.info_get('weechat_dir', ''), VIOLA_DIR_NAME)
        create_viola_dir(viola_dir)
        accounts.init_accounts(viola_dir, application_operations)

        # Celebrate and setup callbacks
        weechat.prnt("", otrlib.colorize("[Viola squeaks]", "green"))

        # Catch incoming messages
        weechat.hook_modifier('irc_in_privmsg', 'message_in_cb', '')
        # Catch outgoing messages
        weechat.hook_modifier('irc_out_privmsg', 'message_out_cb', '')

        # Catch users leaving channels
        weechat.hook_modifier('irc_in_quit', 'user_quit_irc_cb', '')
        weechat.hook_modifier('irc_in_part', 'user_left_channel_cb', '')
        weechat.hook_modifier('irc_in_kick', 'user_got_kicked_cb', '')

        # Catch users changing nicks
        weechat.hook_signal('*,irc_in_nick', 'new_nick_cb', '')

        # Now also hook the central /viola command and its subcommands.
        weechat.hook_command(SCRIPT_NAME, SCRIPT_HELP,
                             "introduction [NICK] || "
                             "trust-key [NICK KEY] || "
                             "list-friends || "
                             "start-room || "
                             "join-room",
                             "",
                             "introduction %(nick) %-||"
                             "trust-key %-||"
                             "list-friends %-||"
                             "start-room %-||"
                             "join-room %-||",
                             "viola_command_cb",
                             "")

