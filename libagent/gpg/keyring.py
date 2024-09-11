"""Tools for doing signature using gpg-agent."""
from __future__ import absolute_import, print_function, unicode_literals

import binascii
import io
import logging
import os
import re
import socket
import sys
import urllib.parse

import trio

from .. import util

if sys.platform == 'win32':
    from .. import win_server

log = logging.getLogger(__name__)


async def check_output(args, env=None, run_process=trio.run_process):
    """Call an external binary and return its stdout."""
    log.debug('calling %s with env %s', args, env)
    info = await run_process(args, env=env, capture_stdout=True, capture_stderr=True)
    log.debug('output: %r', info.stdout)
    if info.stderr:
        log.debug('error: %r', info.stderr)
    return info.stdout


async def get_agent_sock_path(env=None, run_process=trio.run_process):
    """Parse gpgconf output to find out GPG agent UNIX socket path."""
    args = [await util.which('gpgconf'), '--list-dirs', 'agent-socket']
    return (await check_output(args=args, env=env, run_process=run_process)).strip()


async def connect_to_agent(env=None, run_process=trio.run_process):
    """Connect to GPG agent's UNIX socket."""
    sock_path = get_agent_sock_path(run_process=run_process, env=env)
    # This forces the gpg-agent configured for this environment to run.
    await check_output(args=gpg_command(['--list-secret-keys']), run_process=run_process, env=env)
    if sys.platform == 'win32':
        sock = await win_server.Client.open(sock_path)
    else:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        await sock.connect(sock_path)
    return sock


async def communicate(sock, msg):
    """Send a message and receive a single line."""
    await sendline(sock, msg.encode('ascii'))
    return await recvline(sock)


async def sendline(sock, msg, confidential=False):
    """Send a binary message, followed by EOL."""
    log.debug('<- %r', ('<snip>' if confidential else msg))
    await util.send(sock, msg + b'\n')


async def recvline(sock):
    """Receive a single line from the socket."""
    reply = io.BytesIO()

    while True:
        c = await sock.recv(1)
        if not c:
            return None  # socket is closed

        if c == b'\n':
            break
        reply.write(c)

    result = reply.getvalue()
    log.debug('-> %r', result)
    return result


async def iterlines(conn):
    """Iterate over input, split by lines."""
    while True:
        line = await recvline(conn)
        if line is None:
            break
        yield line


def unescape(s):
    """Unescape ASSUAN message (0xAB <-> '%AB')."""
    s = bytearray(s)
    i = 0
    while i < len(s):
        if s[i] == ord('%'):
            hex_bytes = bytes(s[i+1:i+3])
            value = int(hex_bytes.decode('ascii'), 16)
            s[i:i+3] = [value]
        i += 1
    return bytes(s)


def parse_term(s):
    """Parse single s-expr term from bytes."""
    size, s = s.split(b':', 1)
    size = int(size)
    return s[:size], s[size:]


def parse(s):
    """Parse full s-expr from bytes."""
    if s.startswith(b'('):
        s = s[1:]
        name, s = parse_term(s)
        values = [name]
        while not s.startswith(b')'):
            value, s = parse(s)
            values.append(value)
        return values, s[1:]

    return parse_term(s)


def _parse_ecdsa_sig(args):
    (r, sig_r), (s, sig_s) = args
    assert r == b'r'
    assert s == b's'
    return (util.bytes2num(sig_r),
            util.bytes2num(sig_s))


# DSA and EDDSA happen to have the same structure as ECDSA signatures
_parse_dsa_sig = _parse_ecdsa_sig
_parse_eddsa_sig = _parse_ecdsa_sig


def _parse_rsa_sig(args):
    (s, sig_s), = args
    assert s == b's'
    return (util.bytes2num(sig_s),)


def parse_sig(sig):
    """Parse signature integer values from s-expr."""
    label, sig = sig
    assert label == b'sig-val'
    algo_name = sig[0]
    parser = {b'rsa': _parse_rsa_sig,
              b'ecdsa': _parse_ecdsa_sig,
              b'eddsa': _parse_eddsa_sig,
              b'dsa': _parse_dsa_sig}[algo_name]
    return parser(args=sig[1:])


async def sign_digest(sock, keygrip, digest, run_process=trio.run_process, environ=None):
    """Sign a digest using specified key using GPG agent."""
    hash_algo = 8  # SHA256
    assert len(digest) == 32

    assert (await communicate(sock, 'RESET')).startswith(b'OK')

    ttyname = (await check_output(args=['tty'], run_process=run_process)).strip()
    options = ['ttyname={}'.format(ttyname)]  # set TTY for passphrase entry

    display = (environ or os.environ).get('DISPLAY')
    if display is not None:
        options.append('display={}'.format(display))

    for opt in options:
        assert await communicate(sock, 'OPTION {}'.format(opt)) == b'OK'

    assert await communicate(sock, 'SIGKEY {}'.format(keygrip)) == b'OK'
    hex_digest = binascii.hexlify(digest).upper().decode('ascii')
    assert await communicate(sock, 'SETHASH {} {}'.format(hash_algo,
                                                          hex_digest)) == b'OK'

    assert await communicate(sock, 'SETKEYDESC '
                             'Sign+a+new+TREZOR-based+subkey') == b'OK'
    assert await communicate(sock, 'PKSIGN') == b'OK'
    while True:
        line = (await recvline(sock)).strip()
        if not line.startswith(b'S PROGRESS'):
            break
    line = unescape(line)
    log.debug('unescaped: %r', line)
    prefix, sig = line.split(b' ', 1)
    if prefix != b'D':
        raise ValueError(prefix)

    sig, leftover = parse(sig)
    assert not leftover, leftover
    return parse_sig(sig)


async def get_gnupg_components(run_process=trio.run_process):
    """Parse GnuPG components' paths."""
    args = [await util.which('gpgconf'), '--list-components']
    output = await check_output(args=args, run_process=run_process)
    components = {k: urllib.parse.unquote(v) for k, v in re.findall(
                  r'(?<!:)([^\n\r:]*):[^\n\r:]*:([^\n\r:]*)(?!:)', output.decode('utf-8'))}
    log.debug('gpgconf --list-components: %s', components)
    return components


@util.memoize
async def get_gnupg_binary(run_process=trio.run_process, neopg_binary=None):
    """Starting GnuPG 2.2.x, the default installation uses `gpg`."""
    if neopg_binary:
        return neopg_binary
    return (await get_gnupg_components(run_process=run_process))['gpg']


@util.memoize
async def get_pinentry_binary(run_process=trio.run_process):
    """Returns the exact path to `pinentry` if GPG is installed."""
    try:
        return (await get_gnupg_components(run_process=run_process))['pinentry']
    except Exception:  # pylint: disable=broad-except
        return 'pinentry'


async def gpg_command(args, env=None):
    """Prepare common GPG command line arguments."""
    if env is None:
        env = os.environ
    cmd = await get_gnupg_binary(neopg_binary=env.get('NEOPG_BINARY'))
    return [cmd] + args


async def gpg_version(run_process=trio.run_process):
    """Get a keygrip of the primary GPG key of the specified user."""
    args = await gpg_command(['--version'])
    output = await check_output(args=args, run_process=run_process)
    line = re.split('[\n\r]+', output.decode('utf-8'))[0]  # b'gpg (GnuPG) 2.1.11'
    line = line.split(' ')[-1]  # b'2.1.11'
    line = line.split('-')[0]  # remove trailing version parts
    return line.split('v')[-1].encode()  # remove 'v' prefix


async def export_public_key(user_id, env=None, run_process=trio.run_process):
    """Export GPG public key for specified `user_id`."""
    args = await gpg_command(['--export', '--export-filter', 'select=uid=' + user_id])
    result = await check_output(args=args, env=env, run_process=run_process)
    if not result:
        log.error('could not find public key %r in local GPG keyring', user_id)
        raise KeyError(user_id)
    return result


async def export_public_keys(env=None, run_process=trio.run_process):
    """Export all GPG public keys."""
    args = await gpg_command(['--export'])
    result = await check_output(args=args, env=env, run_process=run_process)
    if not result:
        raise KeyError('No GPG public keys found at env: {!r}'.format(env))
    return result


async def delete_public_key(key_id, env=None, run_process=trio.run_process):
    """Export all GPG public keys."""
    args = await gpg_command(['--delete-keys', '--expert', '--batch', '--yes', key_id])
    await check_output(args=args, env=env, run_process=run_process)


async def create_agent_signer(keygrip, env):
    """Sign digest with existing GPG keys using gpg-agent tool."""
    sock = await connect_to_agent(env=env)

    async def sign(digest):
        """Sign the digest and return an ECDSA/RSA/DSA signature."""
        return await sign_digest(sock=sock, keygrip=keygrip, digest=digest)

    return sign
