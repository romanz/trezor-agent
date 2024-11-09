"""UNIX-domain socket server and related utility functions."""
import contextlib
import functools
import logging
import os
import signal
import socket
import sys

import trio
import trio.lowlevel
import trio.socket
import trio_util

from . import util

if sys.platform == 'win32':
    from . import win_server

log = logging.getLogger(__name__)


async def remove_file(path, trio_path=trio.Path):
    """Remove file, and raise OSError if still exists."""
    try:
        await trio_path(path).unlink()
    except OSError:
        if await trio_path(path).exists():
            raise


@contextlib.asynccontextmanager
async def unix_domain_socket_server(sock_path):
    """
    Create UNIX-domain socket on specified path.

    Listen on it, and delete it after the generated context is over.
    """
    log.debug('serving on %s', sock_path)
    if sys.platform == 'win32':
        # Return a named pipe emulating a socket server interface
        with await win_server.Server.open(sock_path) as server:
            yield server
        return

    await remove_file(sock_path)

    with trio.socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        await server.bind(sock_path)
        server.listen(1)
        try:
            yield server
        finally:
            await remove_file(sock_path)


class FDServer:
    """File-descriptor based server (for NeoPG)."""

    def __init__(self, fd):
        """C-tor."""
        self.fd = fd
        self.sock = trio.socket.fromfd(fd, socket.AF_UNIX, socket.SOCK_STREAM)

    def __enter__(self):
        """Context manager support."""
        return self

    def __exit__(self, *args):
        """Context manager support."""
        return self.sock.__exit__(*args)

    def accept(self):
        """Use the same socket for I/O."""
        return self, None

    async def recv(self, n):
        """Forward to underlying socket."""
        return await self.sock.recv(n)

    async def send(self, data):
        """Forward to underlying socket."""
        return await self.sock.send(data)

    def close(self):
        """Close the duplicated file descriptor."""
        return self.sock.close()

    def getsockname(self):
        """Simple representation."""
        return '<fd: {}>'.format(self.fd)


@contextlib.asynccontextmanager
async def unix_domain_socket_server_from_fd(fd):
    """Build UDS-based socket server from a file descriptor."""
    yield FDServer(fd)


async def handle_connection(conn, handler):
    """
    Handle a single connection using the specified protocol handler in a loop.

    Exit when EOFError is raised.
    All other exceptions are logged as warnings.
    """
    try:
        log.debug('welcome agent')
        with conn:
            while True:
                msg = await util.read_frame_async(conn)
                reply = await handler.handle(msg=msg)
                await util.send(conn, reply)
    except EOFError:
        log.debug('goodbye agent')
    except Exception as e:  # pylint: disable=broad-except
        log.warning('error: %s', e, exc_info=True)


async def server_thread(sock, handle_conn, quit_event):
    """Run a server on the specified socket."""
    log.debug('server thread started')

    async def handle(conn):
        with conn:
            await handle_conn(conn)
        return conn

    try:
        signals = [getattr(signal, attr)
                   for attr in ['SIGINT', 'SIGBREAK', 'SIGABRT'] if hasattr(signal, attr)]
        with trio.open_signal_receiver(*signals) as signal_waiter:
            async with trio_util.move_on_when(signal_waiter.__anext__):
                async with trio_util.move_on_when(quit_event.wait):
                    async with trio.open_nursery() as nursery:
                        while True:
                            log.debug('waiting for connection on %s', sock.getsockname())
                            conn, _ = await sock.accept()
                            nursery.start_soon(handle, conn)
    finally:
        log.debug('server thread stopped')


async def run_process(command, environ):
    """
    Run the specified process and wait until it finishes.

    Use environ dict for environment variables.
    """
    async with trio.open_nursery() as nursery:
        log.info('running %r with %r', command, environ)
        env = dict(os.environ)
        env.update(environ)
        try:
            p = await nursery.start(functools.partial(trio.run_process, command, env=env,
                                                      check=False, stdin=None))
        except OSError as e:
            raise OSError('cannot run %r: %s' % (command, e)) from e
        log.debug('subprocess %d is running', p.pid)
        ret = await p.wait()
        log.debug('subprocess %d exited: %d', p.pid, ret)
        return ret
