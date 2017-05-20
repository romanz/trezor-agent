"""GPG-agent utilities."""
import binascii
import logging

from . import client, decode, keyring, protocol
from .. import util

log = logging.getLogger(__name__)


def yield_connections(sock):
    """Run a server on the specified socket."""
    while True:
        log.debug('waiting for connection on %s', sock.getsockname())
        try:
            conn, _ = sock.accept()
        except KeyboardInterrupt:
            return
        conn.settimeout(None)
        log.debug('accepted connection on %s', sock.getsockname())
        yield conn


def serialize(data):
    """Serialize data according to ASSUAN protocol."""
    for c in [b'%', b'\n', b'\r']:
        escaped = '%{:02X}'.format(ord(c)).encode('ascii')
        data = data.replace(c, escaped)
    return data


def sig_encode(r, s):
    """Serialize ECDSA signature data into GPG S-expression."""
    r = serialize(util.num2bytes(r, 32))
    s = serialize(util.num2bytes(s, 32))
    return b'(7:sig-val(5:ecdsa(1:r32:' + r + b')(1:s32:' + s + b')))'


def _serialize_point(data):
    prefix = '{}:'.format(len(data)).encode('ascii')
    # https://www.gnupg.org/documentation/manuals/assuan/Server-responses.html
    return b'(5:value' + serialize(prefix + data) + b')'


def parse_ecdh(line):
    """Parse ECDH request and return remote public key."""
    prefix, line = line.split(b' ', 1)
    assert prefix == b'D'
    exp, leftover = keyring.parse(keyring.unescape(line))
    log.debug('ECDH s-exp: %r', exp)
    assert not leftover
    label, exp = exp
    assert label == b'enc-val'
    assert exp[0] == b'ecdh'
    items = exp[1:]
    log.debug('ECDH parameters: %r', items)
    return dict(items)[b'e']


class AgentError(Exception):
    """GnuPG agent-related error."""


class AgentStop(Exception):
    """Raised to close the agent."""


class Handler(object):
    """GPG agent requests' handler."""

    def __init__(self, device):
        """C-tor."""
        self.device = device
        self.client = client.Client(device=device)
        # Cache ASSUAN commands' arguments between commands
        self.keygrip = None
        self.digest = None
        self.algo = None
        # Cache public keys from GnuPG
        self.pubkey_bytes = keyring.export_public_keys()
        # "Clone" existing GPG version
        version = keyring.gpg_version()

        self.handlers = {
            b'RESET': None,
            b'OPTION': None,
            b'SETKEYDESC': None,
            b'GETINFO': lambda conn, _: keyring.sendline(conn, b'D ' + version),
            b'AGENT_ID': lambda conn, _: keyring.sendline(conn, b'D TREZOR'),  # "Fake" agent ID
            b'SIGKEY': lambda _, args: self.set_key(*args),
            b'SETKEY': lambda _, args: self.set_key(*args),
            b'SETHASH': lambda _, args: self.set_hash(*args),
            b'PKSIGN': lambda conn, _: self.pksign(conn),
            b'PKDECRYPT': lambda conn, _: self.pkdecrypt(conn),
            b'HAVEKEY': lambda _, args: self.have_key(*args),
            b'KEYINFO': lambda conn, _: self.key_info(conn)
        }

    @util.memoize
    def get_identity(self, keygrip):
        """
        Returns device.interface.Identity that matches specified keygrip.

        In case of missing keygrip, KeyError will be raised.
        """
        keygrip_bytes = binascii.unhexlify(keygrip)
        pubkey_dict, user_ids = decode.load_by_keygrip(
            pubkey_bytes=self.pubkey_bytes, keygrip=keygrip_bytes)
        # We assume the first user ID is used to generate TREZOR-based GPG keys.
        user_id = user_ids[0]['value'].decode('ascii')
        curve_name = protocol.get_curve_name_by_oid(pubkey_dict['curve_oid'])
        ecdh = (pubkey_dict['algo'] == protocol.ECDH_ALGO_ID)

        identity = client.create_identity(user_id=user_id, curve_name=curve_name)
        verifying_key = self.client.pubkey(identity=identity, ecdh=ecdh)
        pubkey = protocol.PublicKey(
            curve_name=curve_name, created=pubkey_dict['created'],
            verifying_key=verifying_key, ecdh=ecdh)
        assert pubkey.key_id() == pubkey_dict['key_id']
        assert pubkey.keygrip() == keygrip_bytes
        return identity

    def pksign(self, conn):
        """Sign a message digest using a private EC key."""
        log.debug('signing %r digest (algo #%s)', self.digest, self.algo)
        identity = self.get_identity(keygrip=self.keygrip)
        r, s = self.client.sign(identity=identity,
                                digest=binascii.unhexlify(self.digest))
        result = sig_encode(r, s)
        log.debug('result: %r', result)
        keyring.sendline(conn, b'D ' + result)

    def pkdecrypt(self, conn):
        """Handle decryption using ECDH."""
        for msg in [b'S INQUIRE_MAXLEN 4096', b'INQUIRE CIPHERTEXT']:
            keyring.sendline(conn, msg)

        line = keyring.recvline(conn)
        assert keyring.recvline(conn) == b'END'
        remote_pubkey = parse_ecdh(line)

        identity = self.get_identity(keygrip=self.keygrip)
        ec_point = self.client.ecdh(identity=identity, pubkey=remote_pubkey)
        keyring.sendline(conn, b'D ' + _serialize_point(ec_point))

    @util.memoize
    def have_key(self, *keygrips):
        """Check if current keygrip correspond to a TREZOR-based key."""
        try:
            self.get_identity(keygrip=keygrips[0])
        except KeyError as e:
            log.warning('HAVEKEY(%s) failed: %s', keygrips, e)
            raise AgentError(b'ERR 67108881 No secret key <GPG Agent>')

    def key_info(self, conn):
        """
        Dummy reply (mainly for 'gpg --edit' to succeed).

        For details, see GnuPG agent KEYINFO command help.
        https://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg.git;a=blob;f=agent/command.c;h=c8b34e9882076b1b724346787781f657cac75499;hb=refs/heads/master#l1082
        """
        fmt = 'S KEYINFO {0} X - - - - - - -'
        keyring.sendline(conn, fmt.format(self.keygrip).encode('ascii'))

    def set_key(self, keygrip):
        """Set hexadecimal keygrip for next operation."""
        self.keygrip = keygrip

    def set_hash(self, algo, digest):
        """Set algorithm ID and hexadecimal digest for next operation."""
        self.algo = algo
        self.digest = digest

    def handle(self, conn):
        """Handle connection from GPG binary using the ASSUAN protocol."""
        keyring.sendline(conn, b'OK')
        for line in keyring.iterlines(conn):
            parts = line.split(b' ')
            command = parts[0]
            args = parts[1:]

            if command == b'BYE':
                return
            elif command == b'KILLAGENT':
                keyring.sendline(conn, b'OK')
                raise AgentStop()

            if command not in self.handlers:
                log.error('unknown request: %r', line)
                continue

            handler = self.handlers[command]
            if handler:
                try:
                    handler(conn, args)
                except AgentError as e:
                    msg, = e.args
                    keyring.sendline(conn, msg)
                    continue
            keyring.sendline(conn, b'OK')
