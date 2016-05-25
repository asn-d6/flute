""" crypto.py : Some flute-specific crypto """

import binascii
import json
import util
import os

try:
    import nacl.exceptions
    import nacl.signing
    import nacl.encoding
    import nacl.secret
    import nacl.utils
    from nacl.public import PrivateKey, PublicKey, Box
except nacl.exceptions.CryptoError, msg: # Catch any errors
    print("!!! Failed to import PyNaCl: '%s'" % msg)
    print("!!! Might be caused by https://github.com/pyca/pynacl/issues/186")
    print("!!! Ignoring error, but no guarantees that flute will work... :(")

# XXX pull in more crypto code in here.

def get_random_bytes(n_bytes):
    return nacl.utils.random(n_bytes)

def gen_symmetric_key():
    return nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)

def gen_privkey():
    return PrivateKey.generate()

def gen_signing_privkey():
    return nacl.signing.SigningKey.generate()

def parse_signing_pubkey(msg):
    return nacl.signing.VerifyKey(msg)

def parse_pub_key(msg): # XXX rename
    return PublicKey(msg)

def load_identity_privkey_from_disk(privkey_fname):
    with open(privkey_fname, 'r') as keyfile:
        json_privkey = json.load(keyfile)
        hexed_privkey = json_privkey['privkey']
        return nacl.signing.SigningKey(binascii.unhexlify(hexed_privkey))

def store_identity_privkey_to_disk(privkey, privkey_fname):
    """Store 'privkey' in file 'privkey_fname' using a simple json format."""

    privkey_hex = get_hexed_key(privkey)
    with open(privkey_fname, 'w') as keyfile:
        json.dump({'privkey' : (privkey_hex)},
                  keyfile)

# XXX move to accounts
def store_friends_pubkey_to_disk(nickname, hexed_key, friends_db_fname):
    # Create friends db file if it doesn't exist.
    if not os.path.exists(friends_db_fname):
        util.debug("Creating friend database at %s." % friends_db_fname)
        open(friends_db_fname, 'a').close()

    with open(friends_db_fname, 'r+') as friends_file:
        try:
            friends_dict = json.load(friends_file)
        except ValueError, msg:
            util.debug("Could not load friends db: %s" % msg)
            friends_dict = {}

    # Check if nick or key are already registered.
    if hexed_key in friends_dict:
        raise KeyAlreadyRegistered()
    if nickname in friends_dict.values():
        raise NickAlreadyRegistered()

    # Prepare entry for new friend
    new_friend = {hexed_key : nickname}
    friends_dict.update(new_friend)

    # Update database
    with open(friends_db_fname, 'w') as friends_file:
        json.dump(friends_dict, friends_file)

    util.control_msg("Success. %s added to friend list." % nickname)

def array_chunk_generator(array, chunk_size):
    """Yield successive n-sized chunks from l."""
    for i in xrange(0, len(array), chunk_size):
        yield array[i : i+chunk_size]

def decrypt_room_message_key(message_key_array, captain_transport_pubkey, my_room_privkey):
    """
    Parse the message key array, do the trial decryption, and try to retrieve
    the room message key.  Return it if found, otherwise raise NoKeyFound.
    """
    # The array length needs to be a multiple of 72 bytes.
    if len(message_key_array) % 72 != 0:
        util.debug("Received message key array of length %d" % len(message_key_array))
        raise NoKeyFound

    # Build our decryption box.
    decryption_box = Box(my_room_privkey, captain_transport_pubkey)

    chunks = array_chunk_generator(message_key_array, 72)

    # Start walking over the message key array and trial decrypt every
    # ciphertext till we get our key. If we finish array and still haven't
    # found anything, bail with NoKeyFound exception.
    while True:
        try:
            chunk = chunks.next()
        except StopIteration: # no more chunks
            util.debug("Walked over the whole KEY_TRANSPORT packet!")
            raise NoKeyFound

        try:
            room_message_key = decryption_box.decrypt(chunk)
            break
        except nacl.exceptions.CryptoError:
            util.debug("Walking KEY_TRANSPORT: Not our key!")
            # if we didn't find key in first chunk, move to next one.
            continue

    return room_message_key

def get_room_message_ciphertext(room_message_key, message):
    """Encrypt message symmetrically using 'room_message_key'."""
    box = nacl.secret.SecretBox(room_message_key)
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    ciphertext = box.encrypt(message, nonce)
    return ciphertext

def get_message_key_ciphertext(captain_room_participant_privkey, room_message_key, member_pubkey):
    """
    As the captain, encrypt the room_message_key for this particular room member
    with key 'member_pubkey'.
    """
    encryption_box = Box(captain_room_participant_privkey, member_pubkey)
    message = room_message_key
    nonce = get_random_bytes(Box.NONCE_SIZE)

    ciphertext = encryption_box.encrypt(message, nonce) # XXX move to crypto.py
    return ciphertext

def decrypt_room_message(room_message_key, ciphertext):
    """Decrypt ciphertext using room message key."""
    box = nacl.secret.SecretBox(room_message_key)
    try:
        return box.decrypt(ciphertext)
    except nacl.exceptions.CryptoError:
        raise DecryptFail

def get_hexed_key(key):
    """Hex crypto key and return hex string."""
    return binascii.hexlify(bytes(key))

class NickAlreadyRegistered(Exception): pass
class KeyAlreadyRegistered(Exception): pass
class NoKeyFound(Exception): pass
class DecryptFail(Exception): pass
