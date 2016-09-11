"""
Connection to hardware authentication device.

It is used for getting SSH public keys and ECDSA signing of server requests.
"""
import binascii
import io
import logging
import re
import struct

from onlykey import OnlyKey, Message

from . import factory, formats, util
import ed25519
import time

log = logging.getLogger(__name__)

class Client(object):
    """Client wrapper for SSH authentication device."""

    def __init__(self, loader=factory.load, curve=formats.CURVE_ED25519):
        """Connect to hardware device."""
        self.device_name =  'OnlyKey'
        self.ok = OnlyKey()
        self.curve = curve

    def __enter__(self):
        """Start a session, and test connection."""
        return self

    def __exit__(self, *args):
        """Forget PIN, shutdown screen and disconnect."""
        log.info('disconnected from %s', self.device_name)
        self.ok.close()

    def get_identity(self, label, index=0):
        """Parse label string into Identity protobuf."""
        identity = string_to_identity(label)
        identity['proto'] = 'ssh'
        identity['index'] = index
        print 'identity', identity
        return identity

    def get_public_key(self, label):
        """Get SSH public key corresponding to specified by label."""
        print 'pk label', label
        identity = self.get_identity(label=label)
        # label = identity_to_string(identity)  # canonize key label
        log.info('getting "%s" public key (%s) from %s...',
                 label, self.curve, self.device_name)
        self.ok.send_message(msg=Message.OKGETSSHPUBKEY)
        vk = ed25519.VerifyingKey(self.ok.read_bytes(32, to_str=True))
        return formats.export_public_key(vk=vk, label=label)

    def sign_ssh_challenge(self, label, blob):
        """Sign given blob using a private key, specified by the label."""
        identity = self.get_identity(label=label)
        msg = _parse_ssh_blob(blob)
        log.debug('%s: user %r via %r (%r)',
                  msg['conn'], msg['user'], msg['auth'], msg['key_type'])
        log.debug('nonce: %s', binascii.hexlify(msg['nonce']))
        log.debug('fingerprint: %s', msg['public_key']['fingerprint'])
        log.debug('hidden challenge size: %d bytes', len(blob))

        log.info('please confirm user "%s" login to "%s" using %s...',
                 msg['user'], label, self.device_name)

        log.debug('blob len=%d', len(blob))

        self.ok.send_large_message(payload=blob, msg=Message.OKSIGNSSHCHALLENGE)
        raw_input('push button')
        time.sleep(0.2)
        for _ in xrange(3):
            self.ok.send_large_message(payload=blob, msg=Message.OKSIGNSSHCHALLENGE)
            for _ in xrange(50):
                result = self.ok.read_string(timeout_ms=250)
                log.debug('result from device = %s', result)
                if len(result) == 64:
                    return result

        raise Exception('failed to sign challenge')

_identity_regexp = re.compile(''.join([
    '^'
    r'(?:(?P<proto>.*)://)?',
    r'(?:(?P<user>.*)@)?',
    r'(?P<host>.*?)',
    r'(?::(?P<port>\w*))?',
    r'(?P<path>/.*)?',
    '$'
]))


def string_to_identity(s, identity_type=dict):
    """Parse string into Identity protobuf."""
    m = _identity_regexp.match(s)
    result = m.groupdict()
    log.debug('parsed identity: %s', result)
    kwargs = {k: v for k, v in result.items() if v}
    return identity_type(**kwargs)


def identity_to_string(identity):
    """Dump Identity protobuf into its string representation."""
    print identity
    return ''
    # result = []
    # if identity.proto:
    #     result.append(identity.proto + '://')
    # if identity.user:
    #     result.append(identity.user + '@')
    # result.append(identity.host)
    # if identity.port:
    #     result.append(':' + identity.port)
    # if identity.path:
    #     result.append(identity.path)
    # return ''.join(result)


def get_address(identity, ecdh=False):
    """Compute BIP32 derivation address according to SLIP-0013/0017."""
    index = struct.pack('<L', identity.index)
    addr = index + identity_to_string(identity).encode('ascii')
    log.debug('address string: %r', addr)
    digest = formats.hashfunc(addr).digest()
    s = io.BytesIO(bytearray(digest))

    hardened = 0x80000000
    addr_0 = [13, 17][bool(ecdh)]
    address_n = [addr_0] + list(util.recv(s, '<LLLL'))
    return [(hardened | value) for value in address_n]


def _parse_ssh_blob(data):
    res = {}
    i = io.BytesIO(data)
    res['nonce'] = util.read_frame(i)
    i.read(1)  # SSH2_MSG_USERAUTH_REQUEST == 50 (from ssh2.h, line 108)
    res['user'] = util.read_frame(i)
    res['conn'] = util.read_frame(i)
    res['auth'] = util.read_frame(i)
    i.read(1)  # have_sig == 1 (from sshconnect2.c, line 1056)
    res['key_type'] = util.read_frame(i)
    public_key = util.read_frame(i)
    res['public_key'] = formats.parse_pubkey(public_key)
    assert not i.read()
    return res
