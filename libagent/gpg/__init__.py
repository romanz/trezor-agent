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
import shlex
import stat
import subprocess
import sys
import textwrap

try:
    # TODO: Not supported on Windows. Use daemoniker instead?
    import daemon
except ImportError:
    daemon = None
import pkg_resources
import semver

from .. import device, formats, server, util
from . import agent, client, encode, keyring, protocol

log = logging.getLogger(__name__)


def export_public_key(device_type, args):
    """Generate a new pubkey for a new/existing GPG identity."""
    log.warning('NOTE: in order to re-generate the exact same GPG key later, '
                'run this command with "--time=%d" commandline flag (to set '
                'the timestamp of the GPG key manually).', args.time)
    c = client.Client(device=device_type())
    identity = client.create_identity(user_id=args.user_id,
                                      curve_name=args.ecdsa_curve)
    verifying_key = c.pubkey(identity=identity, ecdh=False)
    decryption_key = c.pubkey(identity=identity, ecdh=True)
    signer_func = functools.partial(c.sign, identity=identity)
    fingerprints = []

    if args.subkey:  # add as subkey
        log.info('adding %s GPG subkey for "%s" to existing key',
                 args.ecdsa_curve, args.user_id)
        # subkey for signing
        signing_key = protocol.PublicKey(
            curve_name=args.ecdsa_curve, created=args.time,
            verifying_key=verifying_key, ecdh=False)
        fingerprints.append(util.hexlify(signing_key.fingerprint()))
        # subkey for encryption
        encryption_key = protocol.PublicKey(
            curve_name=formats.get_ecdh_curve_name(args.ecdsa_curve),
            created=args.time, verifying_key=decryption_key, ecdh=True)
        fingerprints.append(util.hexlify(encryption_key.fingerprint()))
        primary_bytes = keyring.export_public_key(args.user_id)
        result = encode.create_subkey(primary_bytes=primary_bytes,
                                      subkey=signing_key,
                                      signer_func=signer_func)
        result = encode.create_subkey(primary_bytes=result,
                                      subkey=encryption_key,
                                      signer_func=signer_func)
    else:  # add as primary
        log.info('creating new %s GPG primary key for "%s"',
                 args.ecdsa_curve, args.user_id)
        # primary key for signing
        primary = protocol.PublicKey(
            curve_name=args.ecdsa_curve, created=args.time,
            verifying_key=verifying_key, ecdh=False)
        fingerprints.append(util.hexlify(primary.fingerprint()))
        # subkey for encryption
        subkey = protocol.PublicKey(
            curve_name=formats.get_ecdh_curve_name(args.ecdsa_curve),
            created=args.time, verifying_key=decryption_key, ecdh=True)
        fingerprints.append(util.hexlify(subkey.fingerprint()))

        result = encode.create_primary(user_id=args.user_id,
                                       pubkey=primary,
                                       signer_func=signer_func)
        result = encode.create_subkey(primary_bytes=result,
                                      subkey=subkey,
                                      signer_func=signer_func)

    return (fingerprints, protocol.armor(result, 'PUBLIC KEY BLOCK'))


def verify_gpg_version():
    """Make sure that the installed GnuPG is not too old."""
    existing_gpg = keyring.gpg_version().decode('ascii')
    required_gpg = '>=2.1.11'
    msg = 'Existing GnuPG has version "{}" ({} required)'.format(existing_gpg,
                                                                 required_gpg)
    if not semver.match(existing_gpg, required_gpg):
        log.error(msg)


def check_output(args):
    """Runs command and returns the output as string."""
    log.debug('run: %s', args)
    out = subprocess.check_output(args=args).decode('utf-8')
    log.debug('out: %r', out)
    return out


def check_call(args, stdin=None, input_bytes=None, env=None):
    """Runs command and verifies its success."""
    log.debug('run: %s%s', args, ' {}'.format(env) if env else '')
    subprocess.run(args=args, stdin=stdin, input=input_bytes, env=env, check=True)


def write_file(path, data):
    """Writes data to specified path."""
    with open(path, 'w') as f:
        log.debug('setting %s contents:\n%s', path, data)
        f.write(data)
    return f


def run_init(device_type, args):
    """Initialize hardware-based GnuPG identity."""
    util.setup_logging(verbosity=args.verbose)
    log.warning('This GPG tool is still in EXPERIMENTAL mode, '
                'so please note that the API and features may '
                'change without backwards compatibility!')

    verify_gpg_version()

    # Prepare new GPG home directory for hardware-based identity
    device_name = device_type.package_name().rsplit('-', 1)[0]
    log.info('device name: %s', device_name)
    homedir = args.homedir
    if not homedir:
        homedir = os.path.expanduser('~/.gnupg/{}'.format(device_name))

    log.info('GPG home directory: %s', homedir)

    if os.path.exists(homedir):
        log.error('GPG home directory %s exists, '
                  'remove it manually if required', homedir)
        sys.exit(1)

    # Prepare the key before making any changes
    fingerprints, public_key_bytes = export_public_key(device_type, args)

    os.makedirs(homedir, mode=0o700)

    agent_path = util.which('{}-gpg-agent'.format(device_name))

    # Prepare GPG agent invocation script (to pass the PATH from environment).
    extra_options = {}
    for arg in ['pin_entry_binary', 'passphrase_entry_binary', 'cache_expiry_seconds']:
        if hasattr(args, arg):
            extra_options[arg.replace('_', '-')] = getattr(args, arg)
    with open(os.path.join(homedir, ('run-agent.sh'
                                     if sys.platform != 'win32' else
                                     'run-agent.bat')), 'w') as f:
        if sys.platform != 'win32':
            quoted_extra_args = shlex.join(
                f"--{name}={value}" for name, value in extra_options.items()
            )
            f.write(textwrap.dedent(rf"""
                #!/bin/sh
                export PATH={shlex.quote(os.environ['PATH'])}
                exec {shlex.quote(agent_path)} -vv {quoted_extra_args} "$@"
                """
            ).lstrip())
        else:
            quoted_extra_args = " ".join(
                f"--{name}={util.escape_cmd_quotes(str(value))}"
                for name, value in extra_options.items()
            )
            f.write(textwrap.dedent(rf"""
                @echo off
                set PATH={util.escape_cmd_win(os.environ['PATH'])}
                {util.escape_cmd_quotes(agent_path)} -vv {quoted_extra_args} %*
            """).lstrip())
    os.chmod(f.name, 0o700)
    run_agent_script = f.name

    # Prepare GPG configuration file
    with open(os.path.join(homedir, 'gpg.conf'), 'w') as f:
        f.write("""# Hardware-based GPG configuration
agent-program "{0}"
personal-digest-preferences SHA512
default-key {1}
""".format(util.escape_cmd_quotes(run_agent_script), fingerprints[0]))

    # Prepare a helper script for setting up the new identity
    with open(os.path.join(homedir, 'env'), 'w') as f:
        f.write("""#!/bin/sh
set -eu
GNUPGHOME={0}
export GNUPGHOME
if [ -z "$*" ]
then
    exec "$SHELL"
else
    exec "$@"
fi
""".format(shlex.quote(homedir)))
    os.chmod(f.name, 0o700)

    # Generate new GPG identity and import into GPG keyring
    verbosity = ('-' + ('v' * args.verbose)) if args.verbose else '--quiet'
    check_call(keyring.gpg_command(['--homedir', homedir, verbosity,
                                    '--import']),
               input_bytes=public_key_bytes.encode())

    # Make new GPG identity with "ultimate" trust (via its fingerprint)
    check_call(keyring.gpg_command(['--homedir', homedir,
                                    '--import-ownertrust']),
               input_bytes=(fingerprints[0] + ':6\n').encode())

    # Load agent and make sure it responds with the new identity
    check_call(keyring.gpg_command(['--homedir', homedir,
                                    '--list-secret-keys', args.user_id]))


def run_unlock(device_type, args):
    """Unlock hardware device (for future interaction)."""
    util.setup_logging(verbosity=args.verbose)
    with device_type() as d:
        log.info('unlocked %s device', d)


def _server_from_assuan_fd(env):
    fd = env.get('_assuan_connection_fd')
    if fd is None:
        return None
    log.info('using fd=%r for UNIX socket server', fd)
    return server.unix_domain_socket_server_from_fd(int(fd))


def _server_from_sock_path(env):
    sock_path = keyring.get_agent_sock_path(env=env)
    return server.unix_domain_socket_server(sock_path)


def run_agent(device_type):
    """Run a simple GPG-agent server."""
    p = argparse.ArgumentParser()
    p.add_argument('--homedir', default=os.environ.get('GNUPGHOME'))
    p.add_argument('-v', '--verbose', default=0, action='count')
    p.add_argument('--server', default=False, action='store_true',
                   help='Use stdin/stdout for communication with GPG.')
    if daemon:
        p.add_argument('--daemon', default=False, action='store_true',
                       help='Daemonize the agent.')

    p.add_argument('--pin-entry-binary', type=str, default='pinentry',
                   help='Path to PIN entry UI helper.')
    p.add_argument('--passphrase-entry-binary', type=str, default='pinentry',
                   help='Path to passphrase entry UI helper.')
    p.add_argument('--cache-expiry-seconds', type=float, default=float('inf'),
                   help='Expire passphrase from cache after this duration.')

    args, _ = p.parse_known_args()

    if daemon and args.daemon:
        with daemon.DaemonContext():
            run_agent_internal(args, device_type)
    else:
        run_agent_internal(args, device_type)


def run_agent_internal(args, device_type):
    """Actually run the server."""
    assert args.homedir

    log_file = os.path.join(args.homedir, 'gpg-agent.log')
    util.setup_logging(verbosity=args.verbose, filename=log_file)

    log.debug('sys.argv: %s', sys.argv)
    log.debug('os.environ: %s', os.environ)
    log.debug('pid: %d, parent pid: %d', os.getpid(), os.getppid())
    try:
        env = {'GNUPGHOME': args.homedir, 'PATH': os.environ['PATH']}
        pubkey_bytes = keyring.export_public_keys(env=env)
        device_type.ui = device.ui.UI(device_type=device_type,
                                      config=vars(args))
        handler = agent.Handler(device=device_type(),
                                pubkey_bytes=pubkey_bytes)

        sock_server = _server_from_assuan_fd(os.environ)
        if sock_server is None:
            sock_server = _server_from_sock_path(env)

        with sock_server as sock:
            for conn in agent.yield_connections(sock):
                with contextlib.closing(conn):
                    try:
                        handler.handle(conn)
                    except agent.AgentStop:
                        log.info('stopping gpg-agent')
                        return
                    except IOError as e:
                        log.info('connection closed: %s', e)
                        return
                    except Exception as e:  # pylint: disable=broad-except
                        log.exception('handler failed: %s', e)

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
                              help='initialize hardware-based GnuPG identity')
    p.add_argument('user_id')
    p.add_argument('-e', '--ecdsa-curve', default='nist256p1')
    p.add_argument('-t', '--time', type=int, default=0)
    p.add_argument('-v', '--verbose', default=0, action='count')
    p.add_argument('-s', '--subkey', default=False, action='store_true')

    p.add_argument('--homedir', type=str, default=os.environ.get('GNUPGHOME'),
                   help='Customize GnuPG home directory for the new identity.')

    p.add_argument('--pin-entry-binary', type=str, default=argparse.SUPPRESS,
                   help='Path to PIN entry UI helper.')
    p.add_argument('--passphrase-entry-binary', type=str, default=argparse.SUPPRESS,
                   help='Path to passphrase entry UI helper.')
    p.add_argument('--cache-expiry-seconds', type=float, default=argparse.SUPPRESS,
                   help='Expire passphrase from cache after this duration.')

    p.set_defaults(func=run_init)

    p = subparsers.add_parser('unlock', help='unlock the hardware device')
    p.add_argument('-v', '--verbose', default=0, action='count')
    p.set_defaults(func=run_unlock)

    args = parser.parse_args()
    device_type.ui = device.ui.UI(device_type=device_type, config=vars(args))

    return args.func(device_type=device_type, args=args)
