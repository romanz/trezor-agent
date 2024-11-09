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
import functools
import logging
import os
import re
import stat
import sys

import trio

try:
    # Not supported on Windows. Should be manually installed as a service instead.
    import daemon
except ImportError:
    daemon = None
import pkg_resources
import semver

from .. import device, formats, server, util
from . import agent, client, decode, encode, keyring, keystore, protocol

log = logging.getLogger(__name__)


async def export_public_key(device_type, homedir, args):
    """Generate a new pubkey for a new/existing GPG identity."""
    # pylint: disable=too-many-branches
    log.warning('NOTE: in order to re-generate the exact same GPG key later, '
                'run this command with "--time=%d" commandline flag (to set '
                'the timestamp of the GPG key manually).', args.time)
    async with await device.ui.UI.create(device_type=device_type, config=vars(args)) as ui:
        c = client.Client(ui=ui)
        if args.derivation_path:
            user_id = args.derivation_path
        else:
            user_id = args.user_id
        fingerprints = []

        result = None
        if args.subkey:  # add as subkey
            sign_identity = None
            try:
                if args.primary_homedir is None:
                    result = await keyring.export_public_key(args.user_id)
                    # Check if the key was generated with this device
                    sign_identity = await decode.identity_for_key(c, result,
                                                                  os.environ['GNUPGHOME'])
                else:
                    result = await keyring.export_public_key(args.user_id,
                                                             env={'GNUPGHOME':
                                                                  args.primary_homedir})
                    # Check if the key was generated with this device
                    sign_identity = await decode.identity_for_key(c, result, args.primary_homedir)
                if sign_identity is None:
                    if args.primary_homedir is None:
                        signer_func = await keyring.create_agent_signer(
                            next(decode.iter_keygrips(result)),
                            env=os.environ)
                    else:
                        signer_func = await keyring.create_agent_signer(
                            next(decode.iter_keygrips(result)),
                            env={'GNUPGHOME': args.primary_homedir})
                else:
                    signer_func = functools.partial(c.sign, identity=sign_identity)
            except Exception:  # pylint: disable=broad-except
                log.warning('Could not find a primary key matching the specified user id. '
                            'Creating a new primary key instead of a subkey')

        if result is None:
            identity = client.create_identity(user_id=user_id,
                                              curve_name=args.ecdsa_curve_name)
            # No external
            signer_func = functools.partial(c.sign, identity=identity)

        if result is None or not args.no_sign:  # Signing or certification key
            pubkey = await keystore.store_key(c, user_id, args.ecdsa_curve_name,
                                              False, args.time, homedir)
            fingerprints.append(util.hexlify(pubkey.fingerprint()))
            if result is None:
                result = await encode.create_primary(user_id=args.user_id,
                                                     pubkey=pubkey,
                                                     signer_func=signer_func,
                                                     flags=1 if args.no_sign else 3)
            else:
                result = await encode.create_subkey(primary_bytes=result,
                                                    subkey=pubkey,
                                                    signer_func=signer_func,
                                                    flags=2)

        if args.encrypt != 'none':  # Encryption key
            if args.encrypt == 'communications':
                flags = 4
            elif args.encrypt == 'storage':
                flags = 8
            else:
                flags = 12
            pubkey = await keystore.store_key(c, user_id,
                                              formats.get_ecdh_curve_name(args.ecdsa_curve_name),
                                              True, args.time, homedir)
            fingerprints.append(util.hexlify(pubkey.fingerprint()))
            assert result is not None
            result = await encode.create_subkey(primary_bytes=result,
                                                subkey=pubkey,
                                                signer_func=signer_func,
                                                flags=flags)

        return (fingerprints, protocol.armor(result, 'PUBLIC KEY BLOCK'))


async def verify_gpg_version():
    """Make sure that the installed GnuPG is not too old."""
    existing_gpg = (await keyring.gpg_version()).decode('ascii')
    required_gpg = '>=2.1.11'
    msg = 'Existing GnuPG has version "{}" ({} required)'.format(existing_gpg,
                                                                 required_gpg)
    if not semver.match(existing_gpg, required_gpg):
        log.error(msg)


async def check_call(args, input_bytes=b'', env=None):
    """Runs command and verifies its success."""
    log.debug('run: %s%s', args, ' {}'.format(env) if env else '')
    await trio.run_process(args, stdin=input_bytes, env=env, check=True)


async def run_init(device_type, args):
    """Initialize hardware-based GnuPG identity."""
    util.setup_logging(verbosity=args.verbose)
    log.warning('This GPG tool is still in EXPERIMENTAL mode, '
                'so please note that the API and features may '
                'change without backwards compatibility!')

    await verify_gpg_version()

    # Prepare new GPG home directory for hardware-based identity
    device_name = device_type.package_name().rsplit('-', 1)[0]
    log.info('device name: %s', device_name)
    homedir = args.homedir
    if not homedir:
        homedir = os.path.expanduser('~/.gnupg/{}'.format(device_name))

    log.info('GPG home directory: %s', homedir)

    if await trio.Path(homedir).exists():
        log.error('GPG home directory %s exists, '
                  'remove it manually if required', homedir)
        sys.exit(1)

    await trio.Path(homedir).mkdir(mode=0o700, parents=True, exist_ok=True)

    agent_path = await util.which('{}-gpg-agent'.format(device_name))

    # Prepare GPG agent invocation script (to pass the PATH from environment).
    async with await trio.open_file(os.path.join(homedir, ('run-agent.sh'
                                                           if sys.platform != 'win32' else
                                                           'run-agent.bat')), 'w') as f:
        if sys.platform != 'win32':
            await f.write(r"""#!/bin/sh
export PATH="{0}"
""".format(util.escape_cmd_quotes(os.environ['PATH'])))
        else:
            await f.write(r"""@echo off
set PATH={0}
""".format(util.escape_cmd_win(os.environ['PATH'])))
        await f.write('"{0}" -vv'.format(util.escape_cmd_quotes(agent_path)))
        for arg in ['pin_entry_binary', 'passphrase_entry_binary', 'cache_expiry_seconds']:
            if hasattr(args, arg):
                await f.write(' "--{0}={1}"'.format(arg.replace('_', '-'),
                                                    util.escape_cmd_quotes(getattr(args, arg))))
        if sys.platform != 'win32':
            await f.write(' $*\n')
        else:
            await f.write(' %*\n')
    await trio.Path(f.name).chmod(0o700)
    run_agent_script = f.name

    # Prepare GPG configuration file
    async with await trio.open_file(os.path.join(homedir, 'gpg.conf'), 'w') as f:
        # Do not bother escaping or quoting config parameters.
        # _gpgrt_argparse simply reads until EOL.
        await f.write("""# Hardware-based GPG configuration
agent-program {0}
personal-digest-preferences SHA512
""".format(run_agent_script))

    # Prepare a helper script for setting up the new identity
    async with await trio.open_file(os.path.join(homedir, 'env'), 'w') as f:
        await f.write("""#!/bin/bash
set -eu
export GNUPGHOME={0}
COMMAND=$*
if [ -z "${{COMMAND}}" ]
then
    ${{SHELL}}
else
    ${{COMMAND}}
fi
""".format(homedir))
    await trio.Path(f.name).chmod(0o700)


async def run_add(device_type, args):
    """Initialize hardware-based GnuPG identity."""
    util.setup_logging(verbosity=args.verbose)
    log.warning('This GPG tool is still in EXPERIMENTAL mode, '
                'so please note that the API and features may '
                'change without backwards compatibility!')

    await verify_gpg_version()

    # Add a new hardware-based identity to the GPG home directory
    device_name = device_type.package_name().rsplit('-', 1)[0]
    log.info('device name: %s', device_name)
    homedir = args.homedir
    if not homedir:
        homedir = os.path.expanduser('~/.gnupg/{}'.format(device_name))

    log.info('GPG home directory: %s', homedir)

    if not os.path.exists(homedir):
        log.error('GPG home directory %s is missing, '
                  'use %s-gpg init first', homedir, device_name)
        sys.exit(1)

    # Prepare the keys
    fingerprints, public_key_bytes = await export_public_key(device_type, homedir, args)

    if not fingerprints:
        log.warning('No keys created')
        sys.exit(1)

    # Generate new GPG identity and import into GPG keyring
    verbosity = ('-' + ('v' * args.verbose)) if args.verbose else '--quiet'
    await check_call(await keyring.gpg_command(['--homedir', homedir, verbosity,
                                                '--import']),
                     input_bytes=public_key_bytes.encode())

    # Make new GPG identity with "ultimate" trust (via its fingerprint)
    await check_call(await keyring.gpg_command(['--homedir', homedir,
                                                '--import-ownertrust']),
                     input_bytes=(fingerprints[0] + ':6\n').encode())

    if args.default:
        # Make new key the default key
        await check_call([await util.which('gpgconf'), '--homedir', homedir,
                          '--change-options', 'gpg'],
                         input_bytes=('default-key:0:"' + fingerprints[0]).encode())


async def run_unlock(device_type, args):
    """Unlock hardware device (for future interaction)."""
    util.setup_logging(verbosity=args.verbose)
    async with await device.ui.UI.create(device_type=device_type, config=vars(args)) as ui:
        async with ui.device():
            log.info('unlocked %s device', ui.get_device_name())


async def _server_from_assuan_fd(env):
    fd = env.get('_assuan_connection_fd')
    if fd is None:
        return None
    log.info('using fd=%r for UNIX socket server', fd)
    return server.unix_domain_socket_server_from_fd(int(fd))


async def _server_from_sock_path(env):
    sock_path = await keyring.get_agent_sock_path(env=env)
    return server.unix_domain_socket_server(sock_path)


def run_agent(device_type):
    """Run a simple GPG-agent server."""
    p = argparse.ArgumentParser()
    p.add_argument('--homedir', default=os.environ.get('GNUPGHOME'))
    p.add_argument('-v', '--verbose', default=0, action='count')
    if daemon:
        p.add_argument('--daemon', default=False, action='store_true',
                       help='daemonize the agent')

    p.add_argument('--pin-entry-binary', type=str, default=argparse.SUPPRESS,
                   help='path to PIN entry UI helper')
    p.add_argument('--passphrase-entry-binary', type=str, default=argparse.SUPPRESS,
                   help='path to passphrase entry UI helper')
    p.add_argument('--cache-expiry-seconds', type=float, default=argparse.SUPPRESS,
                   help='expire passphrase from cache after this duration')

    args, _ = p.parse_known_args()

    if daemon and args.daemon:
        with daemon.DaemonContext():
            trio.run(run_agent_internal, args, device_type)
    else:
        trio.run(run_agent_internal, args, device_type)


async def handle_connection(conn, ui, homedir, quit_event):
    """Handle a single connection to the agent."""
    try:
        await agent.Handler(ui=ui, homedir=homedir).handle(conn)
    except agent.AgentStop:
        log.info('stopping gpg-agent')
        quit_event.set()
        return
    except IOError as e:
        log.info('connection closed: %s', e)
        return
    except Exception as e:  # pylint: disable=broad-except
        log.exception('handler failed: %s', e)


async def run_agent_internal(args, device_type):
    """Actually run the server."""
    assert args.homedir

    log_file = os.path.join(args.homedir, 'gpg-agent.log')
    util.setup_logging(verbosity=args.verbose, filename=log_file)

    log.debug('sys.argv: %s', sys.argv)
    log.debug('os.environ: %s', os.environ)
    log.debug('pid: %d, parent pid: %d', os.getpid(), os.getppid())
    try:
        env = {'GNUPGHOME': args.homedir, 'PATH': os.environ['PATH']}
        async with await device.ui.UI.create(device_type=device_type, config=vars(args)) as ui:
            sock_server = await _server_from_assuan_fd(os.environ)
            if sock_server is None:
                sock_server = await _server_from_sock_path(env)

            async with sock_server as sock:
                quit_event = trio.Event()
                handle_conn = functools.partial(handle_connection,
                                                ui=ui,
                                                homedir=args.homedir,
                                                quit_event=quit_event)
                try:
                    await server.server_thread(sock, handle_conn, quit_event)
                finally:
                    log.debug('closing server')
                    quit_event.set()

    except Exception as e:  # pylint: disable=broad-except
        log.exception('gpg-agent failed: %s', e)


def main(device_type):
    """Parse command-line arguments."""
    epilog = ('See https://github.com/romanz/trezor-agent/blob/master/'
              'doc/README-GPG.md for usage examples.')
    parser = argparse.ArgumentParser(epilog=epilog)

    agent_package = device_type.package_name()
    resources_map = {r.key: r for r in pkg_resources.require(agent_package)}
    resources = [resources_map[agent_package], resources_map['libagent']]
    versions = '\n'.join('{}={}'.format(r.key, r.version) for r in resources)
    parser.add_argument('--version', help='print the version info',
                        action='version', version=versions)

    subparsers = parser.add_subparsers(title='Action', dest='action')
    subparsers.required = True

    p = subparsers.add_parser('init',
                              help='initialize a hardware-based GnuPG home directory')
    p.add_argument('-v', '--verbose', default=0, action='count')

    p.add_argument('--homedir', type=str, default=os.environ.get('GNUPGHOME'),
                   help='GnuPG home directory to create')

    p.add_argument('--pin-entry-binary', type=str, default=argparse.SUPPRESS,
                   help='path to PIN entry UI helper')
    p.add_argument('--passphrase-entry-binary', type=str, default=argparse.SUPPRESS,
                   help='path to passphrase entry UI helper')
    p.add_argument('--cache-expiry-seconds', type=float, default=argparse.SUPPRESS,
                   help='expire passphrase from cache after this duration')

    p.set_defaults(func=run_init)

    p = subparsers.add_parser('add',
                              help='add a hardware-based GnuPG identity or subkey to the profile')
    p.add_argument('user_id')
    p.add_argument('-e', '--ecdsa-curve-name', default='nist256p1',
                   choices=sorted(formats.SUPPORTED_CURVES),
                   help='specify curve name')
    p.add_argument('-t', '--time', type=int, default=0,
                   help='set key creation time. This will modify the key\'s fingerprint, '
                        'but not the associated private key')
    p.add_argument('-v', '--verbose', default=0, action='count')
    p.add_argument('-d', '--default', default=False, action='store_true',
                   help='sets the newly created key as the default key for the profile')
    p.add_argument('--derivation-path', default=None,
                   help='custom derivation path for the key. If not specified, '
                        'the user id is used')
    p.add_argument('-s', '--subkey', default=False, action='store_true',
                   help='create a subkey instead of a primary key')
    p.add_argument('--primary-homedir', default=None,
                   help='home directory in which the primary is stored, if creating a subkey. '
                        'Useful for keeping subkey and primary in separate profiles')
    p.add_argument('--no-sign', default=False, action='store_true',
                   help='do not create a signing key. '
                        'If creating a primary key, it will be set to certify-only')
    p.add_argument('--encrypt', default='any', choices=['none', 'any', 'communications', 'storage'],
                   help='select allowed encryption usage for the key. '
                        'If set to none, an encryption key will not be created')

    p.add_argument('--homedir', type=str, default=os.environ.get('GNUPGHOME'),
                   help='customize GnuPG home directory for the new identity')

    p.set_defaults(func=run_add)

    p = subparsers.add_parser('unlock', help='unlock the hardware device')
    p.add_argument('-v', '--verbose', default=0, action='count')
    p.set_defaults(func=run_unlock)

    args = parser.parse_args()

    return trio.run(args.func, device_type, args)
