"""GPG-agent utilities."""
import binascii
import logging

from .. import util
from . import client, keyring, keystore

log = logging.getLogger(__name__)


def sig_encode(r, s):
    """Serialize ECDSA signature data into GPG S-expression."""
    r = util.assuan_serialize(util.num2bytes(r, 32))
    s = util.assuan_serialize(util.num2bytes(s, 32))
    return b'(7:sig-val(5:ecdsa(1:r32:' + r + b')(1:s32:' + s + b')))'


def _serialize_point(data):
    prefix = '{}:'.format(len(data)).encode('ascii')
    # https://www.gnupg.org/documentation/manuals/assuan/Server-responses.html
    return b'(5:value' + util.assuan_serialize(prefix + data) + b')'


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


# pylint: disable=too-many-instance-attributes
class Handler:
    """GPG agent requests' handler."""

    def _get_options(self):
        return self.options

    def __init__(self, ui, homedir):
        """C-tor."""
        self.keygrip = None
        self.digest = None
        self.algo = None
        self.options = []
        self.ui = ui
        self.client = client.Client(ui=ui, options_getter=self._get_options)
        self.homedir = homedir

        self.handlers = {
            b'RESET': self.reset,
            b'OPTION': self.handle_option,
            b'SETKEYDESC': None,
            b'NOP': None,
            b'GETINFO': self.handle_getinfo,
            b'AGENT_ID': self.handle_agent_id,
            b'SIGKEY': self.set_key,
            b'SETKEY': self.set_key,
            b'SETHASH': self.set_hash,
            b'PKSIGN': self.pksign,
            b'PKDECRYPT': self.pkdecrypt,
            b'HAVEKEY': self.have_key,
            b'DELETE_KEY': self.delete_key,
            b'KEYINFO': self.key_info,
            b'SCD': self.handle_scd,
            b'GET_PASSPHRASE': self.handle_get_passphrase,
        }

    @util.memoize_method
    async def get_version(self):
        """Clone existing GPG version."""
        return await keyring.gpg_version()

    async def reset(self, *_):
        """Reset agent's state variables."""
        self.keygrip = None
        self.digest = None
        self.algo = None

    async def handle_option(self, _conn, opt, *_):
        """Store GPG agent-related options (e.g. for pinentry)."""
        self.options.append(opt)
        log.debug('options: %s', self.options)

    async def handle_get_passphrase(self, conn, *_):
        """Allow simple GPG symmetric encryption (using a passphrase)."""
        p1 = await self.ui.get_passphrase('Symmetric encryption:')
        p2 = await self.ui.get_passphrase('Re-enter encryption:')
        if p1 == p2:
            result = b'D ' + util.assuan_serialize(p1.encode('ascii'))
            await keyring.sendline(conn, result, confidential=True)
        else:
            log.warning('Passphrase does not match!')

    async def handle_agent_id(self, conn, *_):
        """Send fake agent ID."""
        await keyring.sendline(conn, b'D TREZOR')

    async def handle_getinfo(self, conn, cmd, *_):
        """Handle some of the GETINFO messages."""
        result = None
        if cmd == b'version':
            result = await self.get_version()
        elif cmd == b's2k_count':
            # Use highest number of S2K iterations.
            # https://www.gnupg.org/documentation/manuals/gnupg/OpenPGP-Options.html
            # https://tools.ietf.org/html/rfc4880#section-3.7.1.3
            result = '{}'.format(64 << 20).encode('ascii')
        else:
            log.warning('Unknown GETINFO command: %s', cmd)

        if result:
            await keyring.sendline(conn, b'D ' + result)

    async def handle_scd(self, conn, *args):
        """No support for smart-card device protocol."""
        reply = {
            (b'GETINFO', b'version'): await self.get_version(),
        }.get(args)
        if reply is None:
            raise AgentError(b'ERR 100696144 No such device <SCD>')
        await keyring.sendline(conn, b'D ' + reply)

    async def get_identity(self, keygrip):
        """
        Returns device.interface.Identity that matches specified keygrip.

        In case of missing keygrip, KeyError will be raised.
        """
        key = await keystore.load_key(self.client, binascii.unhexlify(keygrip), self.homedir)
        return key['identity']

    async def pksign(self, conn, *_):
        """Sign a message digest using a private EC key."""
        log.debug('signing %r digest (algo #%s)', self.digest, self.algo)
        identity = await self.get_identity(self.keygrip)
        r, s = await self.client.sign(identity=identity,
                                      digest=binascii.unhexlify(self.digest))
        result = sig_encode(r, s)
        log.debug('result: %r', result)
        await keyring.sendline(conn, b'D ' + result)

    async def pkdecrypt(self, conn, *_):
        """Handle decryption using ECDH."""
        for msg in [b'S INQUIRE_MAXLEN 4096', b'INQUIRE CIPHERTEXT']:
            await keyring.sendline(conn, msg)

        line = await keyring.recvline(conn)
        assert await keyring.recvline(conn) == b'END'
        remote_pubkey = parse_ecdh(line)

        identity = await self.get_identity(self.keygrip)
        ec_point = await self.client.ecdh(identity=identity, pubkey=remote_pubkey)
        await keyring.sendline(conn, b'D ' + _serialize_point(ec_point))

    async def have_key(self, conn, *keygrips):
        """Check if any keygrip corresponds to a TREZOR-based key."""
        if len(keygrips) == 1 and keygrips[0].startswith(b"--list="):
            keygrips = await keystore.list_keys(self.client, self.homedir)
            log.debug('keygrips: %r', keygrips)
            await keyring.sendline(conn, b'D ' + util.assuan_serialize(b''.join(keygrips)))
            return

        for keygrip in keygrips:
            try:
                await self.get_identity(keygrip=keygrip)
                break
            except KeyError as e:
                log.warning('HAVEKEY(%s) failed: %s', keygrip, e)
        else:
            raise AgentError(b'ERR 67108881 No secret key <GPG Agent>')

    async def delete_key(self, _, *keygrips):
        """Remove the specified keys from the key database."""
        for keygrip in keygrips:
            try:
                if keygrip in ('--force', '--stub'):
                    continue
                await keystore.delete_key(binascii.unhexlify(keygrip), self.homedir)
            except IOError as e:
                log.warning('DELETE_KEY(%s) failed: %s', keygrip, e)

    async def key_info(self, conn, keygrip, *_):
        """
        Dummy reply (mainly for 'gpg --edit' to succeed).

        For details, see GnuPG agent KEYINFO command help.
        https://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg.git;a=blob;f=agent/command.c;h=c8b34e9882076b1b724346787781f657cac75499;hb=refs/heads/master#l1082
        """
        try:
            await self.get_identity(keygrip=keygrip)
        except KeyError as e:
            raise AgentError(b'ERR 67108891 Not found <GPG Agent>') from e
        fmt = 'S KEYINFO {0} X - - - - - - -'
        await keyring.sendline(conn, fmt.format(keygrip.decode('ascii')).encode('ascii'))

    async def set_key(self, _conn, keygrip, *_):
        """Set hexadecimal keygrip for next operation."""
        self.keygrip = keygrip

    async def set_hash(self, _conn, algo, digest, *_):
        """Set algorithm ID and hexadecimal digest for next operation."""
        self.algo = algo
        self.digest = digest

    async def handle(self, conn):
        """Handle connection from GPG binary using the ASSUAN protocol."""
        await keyring.sendline(conn, b'OK')
        async for line in keyring.iterlines(conn):
            parts = line.split(b' ')
            command = parts[0]
            args = tuple(parts[1:])

            if command == b'BYE':
                await keyring.sendline(conn, b'OK closing connection')
                return
            elif command == b'KILLAGENT':
                await keyring.sendline(conn, b'OK closing connection')
                raise AgentStop()

            if command not in self.handlers:
                await keyring.sendline(conn, b'ERR 67109139 Unknown IPC command <GPG Agent>')
                log.error('unknown request: %r', line)
                continue

            handler = self.handlers[command]
            if handler:
                try:
                    await handler(conn, *args)
                except AgentError as e:
                    msg, = e.args
                    await keyring.sendline(conn, msg)
                    continue
            await keyring.sendline(conn, b'OK')
