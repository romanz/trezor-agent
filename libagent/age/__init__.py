"""
TREZOR support for ECDSA GPG signatures.

See these links for more details:
 - https://www.gnupg.org/faq/whats-new-in-2.1.html
 - https://tools.ietf.org/html/rfc4880
 - https://tools.ietf.org/html/rfc6637
 - https://tools.ietf.org/html/draft-irtf-cfrg-eddsa-05
"""

import argparse
import contextlib
import datetime
import logging
import sys

import bech32
import donna25519

import pkg_resources
import semver


from . import client
from .. import device, formats, server, util

log = logging.getLogger(__name__)

def decode_pubkey(pubkey):
    prefix, data = bech32.bech32_decode(pubkey)
    assert prefix == "age"
    pubkey_bytes = bytes(bech32.convertbits(data, 5, 8))
    return donna25519.PublicKey(pubkey_bytes[:32])

def encode_pubkey(pubkey):
    return bech32.bech32_encode("age", bech32.convertbits(pubkey.public, 8, 5))

def decode_privkey(privkey):
    prefix, data = bech32.bech32_decode(privkey.lower())
    assert prefix == "age-secret-key-"
    privkey_bytes = bytes(bech32.convertbits(data, 5, 8))
    return donna25519.PrivateKey(privkey_bytes[:32])

def encode_privkey(privkey):
    return bech32.bech32_encode("age-secret-key-", bech32.convertbits(privkey.private, 8, 5)).upper()


def check_output(args):
    """Runs command and returns the output as string."""
    log.debug('run: %s', args)
    out = subprocess.check_output(args=args).decode('utf-8')
    log.debug('out: %r', out)
    return out


def check_call(args, stdin=None, env=None):
    """Runs command and verifies its success."""
    log.debug('run: %s%s', args, ' {}'.format(env) if env else '')
    subprocess.check_call(args=args, stdin=stdin, env=env)

def run_pubkey(device_type, args):
    """Initialize hardware-based GnuPG identity."""
    util.setup_logging(verbosity=args.verbose)
    log.warning('This AGE tool is still in EXPERIMENTAL mode, '
                'so please note that the API and features may '
                'change without backwards compatibility!')

    c = client.Client(device=device_type())
    pubkey = c.pubkey(identity=args.identity, ecdh=True)
    print(encode_pubkey(donna25519.PublicKey(pubkey)))

def run_decrypt(device_type, args):
    """Unlock hardware device (for future interaction)."""
    util.setup_logging(verbosity=args.verbose)

    peer_pubkey = b"\x40" + args.peer_pubkey.public
    c = client.Client(device=device_type())
    shared_key = c.ecdh(identity=args.identity, pubkey=peer_pubkey)
    sys.stdout.buffer.write(bytes(shared_key))


def main(device_type):
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser()

    agent_package = device_type.package_name()
    resources_map = {r.key: r for r in pkg_resources.require(agent_package)}
    resources = [resources_map[agent_package], resources_map['libagent']]
    versions = '\n'.join('{}={}'.format(r.key, r.version) for r in resources)
    parser.add_argument('--version', help='print the version info',
                        action='version', version=versions)

    subparsers = parser.add_subparsers(title='Action', dest='action')
    subparsers.required = True

    p = subparsers.add_parser('pubkey', help='export age public key')
    p.add_argument('-v', '--verbose', default=0, action='count')
    p.add_argument('-i', '--identity', type=client.create_identity)
    p.set_defaults(func=run_pubkey)

    p = subparsers.add_parser('decrypt', help='decrypt age file')
    p.add_argument('-v', '--verbose', default=0, action='count')
    p.add_argument('-i', '--identity', type=client.create_identity)
    p.add_argument('peer_pubkey', type=decode_pubkey)
    p.set_defaults(func=run_decrypt)

    args = parser.parse_args()
    device_type.ui = device.ui.UI(device_type=device_type, config=vars(args))

    return args.func(device_type=device_type, args=args)
