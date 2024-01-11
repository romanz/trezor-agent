"""SSH-agent implementation using hardware authentication devices."""
import argparse
import contextlib
import functools
import io
import logging
import os
import random
import re
import signal
import string
import subprocess
import sys
import tempfile

import configargparse
import trio
import trio_util

try:
    # TODO: Not supported on Windows. Use daemoniker instead?
    import daemon
except ImportError:
    daemon = None
import pkg_resources

from .. import device, formats, server, util
from . import client, protocol

log = logging.getLogger(__name__)

SOCK_TYPE = 'Windows named pipe' if sys.platform == 'win32' else 'UNIX domain socket'
SOCK_TYPE_PATH = 'Windows named pipe path' if sys.platform == 'win32' else 'UNIX socket path'
FILE_PREFIX = 'file:'


@contextlib.asynccontextmanager
async def ssh_args(previous, conn):
    """Create SSH command for connecting specified server."""
    I, = conn.identities
    identity = I.identity_dict

    args = []
    if 'port' in identity:
        args += ['-p', identity['port']]
    if 'user' in identity:
        args += ['-l', identity['user']]

    async with conn.public_keys_as_file() as pubkey_tempfile_name:
        args += ['-o', 'IdentityFile={}'.format(pubkey_tempfile_name)]
        args += ['-o', 'IdentitiesOnly=true']
        async with previous(conn) as command:
            yield ['ssh'] + args + [identity['host']] + command


@contextlib.asynccontextmanager
async def mosh_args(previous, conn):
    """Create SSH command for connecting specified server."""
    I, = conn.identities
    identity = I.identity_dict

    args = []
    if 'port' in identity:
        args += ['-p', identity['port']]
    if 'user' in identity:
        args += [identity['user']+'@'+identity['host']]
    else:
        args += [identity['host']]

    async with previous(conn) as command:
        yield ['mosh'] + args + command


def _to_unicode(s):
    try:
        return unicode(s, 'utf-8')
    except NameError:
        return s


def create_agent_parser(device_type):
    """Create an ArgumentParser for this tool."""
    epilog = ('See https://github.com/romanz/trezor-agent/blob/master/'
              'doc/README-SSH.md for usage examples.')
    p = configargparse.ArgParser(default_config_files=['~/.ssh/agent.config'],
                                 epilog=epilog)
    p.add_argument('-v', '--verbose', default=0, action='count')

    agent_package = device_type.package_name()
    resources_map = {r.key: r for r in pkg_resources.require(agent_package)}
    resources = [resources_map[agent_package], resources_map['libagent']]
    versions = '\n'.join('{}={}'.format(r.key, r.version) for r in resources)
    p.add_argument('--version', help='print the version info',
                   action='version', version=versions)

    curve_names = ', '.join(sorted(formats.SUPPORTED_CURVES))
    p.add_argument('-e', '--ecdsa-curve-name', metavar='CURVE',
                   default=formats.CURVE_NIST256,
                   help='specify ECDSA curve name: ' + curve_names)
    p.add_argument('--debug', default=False, action='store_true',
                   help='log SSH protocol messages for debugging.')
    p.add_argument('--log-file', type=str,
                   help='Path to the log file (to be written by the agent).')
    p.add_argument('--sock-path', type=str,
                   help='Path to the ' + SOCK_TYPE + ' of the agent.')

    p.add_argument('--pin-entry-binary', type=str, default=argparse.SUPPRESS,
                   help='Path to PIN entry UI helper.')
    p.add_argument('--passphrase-entry-binary', type=str, default=argparse.SUPPRESS,
                   help='Path to passphrase entry UI helper.')
    p.add_argument('--cache-expiry-seconds', type=float, default=argparse.SUPPRESS,
                   help='Expire passphrase from cache after this duration.')

    g = p.add_mutually_exclusive_group()
    if daemon:
        g.add_argument('-d', '--daemonize', default=False, action='store_true',
                       help='Daemonize the agent and print its ' + SOCK_TYPE_PATH)
    g.add_argument('-f', '--foreground', default=False, action='store_true',
                   help='Run agent in foreground with specified ' + SOCK_TYPE_PATH)
    g.add_argument('-s', '--shell', default=False, action='store_true',
                   help=('run ${SHELL} as subprocess under SSH agent, allowing '
                         'regular SSH-based tools to be used in the shell'))
    g.add_argument('-c', '--connect', default=False, action='store_true',
                   help='connect to specified host via SSH')
    # Windows doesn't have native mosh
    if sys.platform != 'win32':
        g.add_argument('--mosh', default=False, action='store_true',
                       help='connect to specified host via using Mosh')

    p.add_argument('identity', type=_to_unicode, default=None,
                   help='proto://[user@]host[:port][/path]')
    p.add_argument('command', type=str, nargs='*', metavar='ARGUMENT',
                   help='command to run under the SSH agent')
    return p


@contextlib.asynccontextmanager
async def serve(handler, sock_path):
    """Start the ssh-agent server on a UNIX-domain socket."""
    ssh_version = subprocess.check_output(['ssh', '-V'],
                                          stderr=subprocess.STDOUT)
    log.debug('local SSH version: %r', ssh_version)
    environ = {'SSH_AUTH_SOCK': sock_path, 'SSH_AGENT_PID': str(os.getpid())}
    async with server.unix_domain_socket_server(sock_path) as sock:
        quit_event = trio.Event()
        handle_conn = functools.partial(server.handle_connection,
                                        handler=handler)
        async with trio_util.move_on_when(server.server_thread, sock, handle_conn, quit_event):
            try:
                yield environ
            finally:
                log.debug('closing server')
                quit_event.set()


async def run_server(conn_context, command_context, sock_path, debug):
    """Run the SSH agent. Optionally execute a command while the agent is running."""
    ret = 0
    try:
        # override default PIN/passphrase entry tools (relevant for TREZOR/Keepkey):
        async with conn_context as conn:
            handler = protocol.Handler(conn=conn, debug=debug)
            async with serve(handler=handler, sock_path=sock_path) as env:
                async with command_context(conn) as command:
                    if command:
                        ret = await server.run_process(command=command, environ=env)
                    else:
                        await trio.sleep_forever()  # Wait until the server has stopped
    finally:
        log.info('server stopped')
    return ret


async def show_public_keys(conn_context):
    """Command for showing public keys associated with the provided identities."""
    async with conn_context as conn:
        for pk in await conn.public_keys():
            sys.stdout.write(pk)
        return 0  # success exit code


def handle_connection_error(func):
    """Fail with non-zero exit code."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except device.interface.NotFoundError as e:
            log.error('Connection error (try unplugging and replugging your device): %s', e)
            return 1
    return wrapper


def parse_config(contents):
    """Parse config file into a list of Identity objects."""
    for identity_str, curve_name in re.findall(r'\<(.*?)\|(.*?)\>', contents):
        yield device.interface.Identity(identity_str=identity_str,
                                        curve_name=curve_name)


def import_public_keys(contents):
    """Load (previously exported) SSH public keys from a file's contents."""
    for line in io.StringIO(contents):
        # Verify this line represents valid SSH public key
        formats.import_public_key(line)
        yield line


class JustInTimeConnection:
    """Connect to the device just before the needed operation."""

    def __init__(self, conn, identities, public_keys=None):
        """Create a JIT connection object."""
        self.conn = conn
        self.identities = identities
        self.public_keys_cache = public_keys

    async def public_keys(self):
        """Return a list of SSH public keys (in textual format)."""
        if not self.public_keys_cache:
            self.public_keys_cache = await self.conn.export_public_keys(self.identities)
        return self.public_keys_cache

    async def parse_public_keys(self):
        """Parse SSH public keys into dictionaries."""
        public_keys = [formats.import_public_key(pk)
                       for pk in await self.public_keys()]
        for pk, identity in zip(public_keys, self.identities):
            pk['identity'] = identity
        return public_keys

    @contextlib.asynccontextmanager
    async def public_keys_as_file(self):
        """Store public keys as temporary SSH identity files."""
        tf = tempfile.NamedTemporaryFile(prefix='trezor-ssh-pubkey-', mode='w', delete=False)
        try:
            async with trio.wrap_file(tf) as f:
                for pk in await self.public_keys():
                    await f.write(pk)
                    await f.write('\n')

            yield tf.name
        finally:
            try:
                await trio.Path(tf.name).unlink()
            except OSError:
                log.warning("Failed to delete temporary file: %s", tf.name)

    async def sign(self, blob, identity):
        """Sign a given blob using the specified identity on the device."""
        return await self.conn.sign_ssh_challenge(blob=blob, identity=identity)


@contextlib.contextmanager
def _dummy_context():
    yield


def _get_sock_path(args):
    sock_path = args.sock_path
    if sock_path:
        return sock_path
    elif args.foreground:
        log.error('running in foreground mode requires specifying %s', SOCK_TYPE_PATH)
        sys.exit(1)
    elif sys.platform == 'win32':
        return '\\\\.\\pipe\\trezor-ssh-agent-' + os.urandom(10).hex()
    else:
        return tempfile.mktemp(prefix='trezor-ssh-agent-')


@contextlib.asynccontextmanager
async def _command_context_constant(command, *_):
    yield command


@contextlib.asynccontextmanager
async def _just_in_time_conection(device_type, config, identities, public_keys):
    # override default PIN/passphrase entry tools (relevant for TREZOR/Keepkey):
    async with await device.ui.UI.create(device_type=device_type, config=config) as ui:
        conn = JustInTimeConnection(
            conn=client.Client(ui),
            identities=identities, public_keys=public_keys)
        yield conn


@handle_connection_error
def main(device_type):
    """Run ssh-agent using given hardware client factory."""
    args = create_agent_parser(device_type=device_type).parse_intermixed_args()
    util.setup_logging(verbosity=args.verbose, filename=args.log_file)

    public_keys = None
    filename = None
    if args.identity.startswith('/') or args.identity.startswith(FILE_PREFIX):
        filename = (args.identity[len(FILE_PREFIX):]
                    if args.identity.startswith(FILE_PREFIX)
                    else args.identity)
        contents = open(filename, 'rb').read().decode('utf-8')
        # Allow loading previously exported SSH public keys
        if filename.endswith('.pub'):
            public_keys = list(import_public_keys(contents))
        identities = list(parse_config(contents))
    else:
        identities = [device.interface.Identity(
            identity_str=args.identity, curve_name=args.ecdsa_curve_name)]
    for index, identity in enumerate(identities):
        identity.identity_dict['proto'] = 'ssh'
        log.info('identity #%d: %s', index, identity.to_string())

    conn_context = _just_in_time_conection(device_type, vars(args), identities, public_keys)

    sock_path = _get_sock_path(args)
    command_context = functools.partial(_command_context_constant, args.command)
    show_pks = not args.command
    context = _dummy_context()
    if args.connect:
        show_pks = False
        command_context = functools.partial(ssh_args, command_context)
    elif sys.platform != 'win32' and args.mosh:
        show_pks = False
        command_context = functools.partial(mosh_args, command_context)
    elif daemon and args.daemonize:
        show_pks = False
        out = 'SSH_AUTH_SOCK={0}; export SSH_AUTH_SOCK;\n'.format(sock_path)
        sys.stdout.write(out)
        sys.stdout.flush()
        context = daemon.DaemonContext()
        log.info('running the agent as a daemon on %s', sock_path)
    elif args.foreground:
        show_pks = False
        log.info('running the agent on %s', sock_path)

    use_shell = bool(args.shell)
    if use_shell:
        show_pks = False
        command_context = functools.partial(_command_context_constant, [os.environ['SHELL']])
        sys.stdin.close()

    if not show_pks:
        with context:
            return trio.run(run_server, conn_context, command_context, sock_path, args.debug)
    else:
        return trio.run(show_public_keys, conn_context)
