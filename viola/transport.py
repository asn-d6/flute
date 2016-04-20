""" transport.py: Handles the Viola transport format. Fragmentation and stuff."""

import viola
import otrlib
import util

def get_fragments_from_msg(msg):
    """Chunk 'msg' in viola fragments to be sent to the network."""
    fragments = []

    fms = viola.IRC_MAXIMUM_MESSAGE_SIZE - 19 # XXX
    msg_len = len(msg)

    chunks = [ msg[i:i+fms] for i in range(0, msg_len, fms) ]
    n_total_chunks = len(chunks)

    if n_total_chunks > 65535:
        raise OverflowError('too many fragments')

    # Iterate over fragments. Prepare them and send them over.
    for n_chunk, chunk in enumerate(chunks, start=1):
        # XXX Dont' use %d. Header must be constant length!!!
        header = "?VLA,%d,%d!" % (n_chunk, n_total_chunks)
        msg = header + chunk
        fragments.append(msg)

    return fragments

def send_viola_privmsg(server, nick, message):
    """
    Send a message to a nick or a channel. Split it to viola fragments first,
    and then send it over.
    """
    for line in message.splitlines():
        fragments = get_fragments_from_msg(line)

        for fragment in fragments:
            otrlib.command('', '/quote -server {server} PRIVMSG {nick} :{fragment}'.format(
                server=otrlib.irc_sanitize(server),
                nick=otrlib.irc_sanitize(nick),
                fragment=otrlib.irc_sanitize(fragment)))


def get_fragment_payload(fragment):
    """Return the payload part of this fragment."""
    header, payload = fragment.split("!")
    return payload

class IncompleteMessage(object):
    """
    Represents a message by a peer that is still not completely received. We
    need more message fragments to assemble it.
    """
    def __init__(self, peer_sid, first_fragment, n_total_fragments):
        """Add incomplete message by 'peer_sid'."""
        fragment_payload = get_fragment_payload(first_fragment)
        self.collected_payloads = []
        self.collected_payloads.append(fragment_payload)

        self.peer_sid = peer_sid

        self.n_total_fragments = n_total_fragments
        self.n_current_fragment = 1

        util.debug("New incomplete message by %s (%d)" % (peer_sid, n_total_fragments))

    def submit_new_message_fragment(self, new_fragment, n_current_fragment, n_total_fragments):
        """
        Submit new message fragment:
          If the message is finally complete, return it.
          If message is still pending, return None.
        Can also raise FragmentationError if corrupted format.
        """
        if n_total_fragments != self.n_total_fragments:
            raise FragmentationError("New fragment piece has different parameters!")

        if n_current_fragment != (self.n_current_fragment + 1):
            raise FragmentationError("Received fragment piece in wrong order (%d/%d)!",
                                     n_current_fragment, (self.n_current_fragment + 1))

        util.debug("Submitting new fragment (%d/%d) for %s" % (n_current_fragment, n_total_fragments, self.peer_sid))

        # Increase fragment counter
        self.n_current_fragment += 1
        # Submit new payload
        fragment_payload = get_fragment_payload(new_fragment)
        self.collected_payloads.append(fragment_payload)

        # If message is complete, return it. Otherwise return None.
        if self.n_current_fragment == self.n_total_fragments:
            print "LOL: %s" % str(self.collected_payloads)
            return "".join(self.collected_payloads)
        else:
            return None

"""
Collects any received Viola fragments, pieces them together and returns
them when they are completed.
"""
class FragmentAssembler(object):
    def __init__(self):
        # Dictionary of { peer_sid : IncompleteMessage }
        self.active_incomplete_msgs = {} # XXX reset every N mins?

    def get_fragment_details(self, fragment):
        """
        Parse a transport header like "?VLA,37,38!<OPCODE><MSG>" and return the
        fragment information. In that case it would return (37, 38).

        Can raise BadTransportFormat
        """

        header, the_rest = fragment.split("!")

        if not header.startswith("?VLA,"):
            raise BadTransportFormat # XXX also remove msg from active_incomplete_msgs

        fragment_details = header[5:]
        n_current_fragment, n_total_fragments = fragment_details.split(",")

        # Some basic checks on the fragment format:
        if n_current_fragment == 0 or n_total_fragments == 0 or n_current_fragment > n_total_fragments:
            raise BadTransportFormat

        # Parse strings as integers
        try:
            n_current_fragment = int(n_current_fragment)
            n_total_fragments = int(n_total_fragments)
        except ValueError:
            raise BadTransportFormat

        return n_current_fragment, n_total_fragments

    def register_new_incomplete_msg(self, peer_sid, incomplete_msg):
        self.active_incomplete_msgs[peer_sid] = incomplete_msg

    def submit_fragment(self, fragment, sender, server, target):
        """
        Submit fragment for assembling. If this fragment completes the packet, then
        return the packet payload.
        """
        peer_sid = "%s:%s:%s" % (sender, server, target)

        n_current_fragment, n_total_fragments = self.get_fragment_details(fragment)

        if n_current_fragment == n_total_fragments == 1:
            # Message was only one fragment long. Return it immediately.
            return get_fragment_payload(fragment)

        # Check if this is the beginning of a new fragmented message.
        if peer_sid not in self.active_incomplete_msgs:
            if n_current_fragment != 1:
                util.debug("Received fragment %d from unknown peer. Ignoring." % n_current_fragment)
                return None

            incomplete_msg = IncompleteMessage(peer_sid, fragment, n_total_fragments)
            self.register_new_incomplete_msg(peer_sid, incomplete_msg)
            return None

        # This is an old fragmented message. Submit newly found fragments.
        incomplete_msg = self.active_incomplete_msgs[peer_sid]
        complete_msg = incomplete_msg.submit_new_message_fragment(fragment, n_current_fragment, n_total_fragments)

        # Check if we just completed this message and if so, return the full
        # thing to our caller.  Also clean up.
        if complete_msg:
            self.active_incomplete_msgs.pop(peer_sid) # cleanup
            util.debug("Completed fragmented message (%d)! Returning!" % n_total_fragments)
            return complete_msg
        else:
            return None

"""
Our global fragment assembler
XXX Attach to accounts.py singleton .
"""
FRAGMENT_ASSEMBLER = FragmentAssembler()

def accumulate_viola_fragment(fragment, parsed, server):
    """
    We just received a new fragment. Submit it for assembly.
    If it completes a message, return the message. Otherwise None.
    """
    sender = parsed['from'] # XXX indexing with 'from' / what happens when nick changes?
    channel = parsed['to_channel']

    # XXX code dup
    if channel:
        target = channel
    else:
        target = parsed['to_nick']

    complete_message_payload = FRAGMENT_ASSEMBLER.submit_fragment(fragment, sender, server, target)
    # complete_message might be None or the actual complete message now
    return complete_message_payload

class BadTransportFormat(Exception): pass
class FragmentationError(Exception): pass
