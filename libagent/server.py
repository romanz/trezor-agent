"""UNIX-domain socket server for ssh-agent implementation."""
import contextlib
import logging
import os
import socket
import subprocess
import sys
import threading

from . import util

if sys.platform == 'win32':
    from . import win_server

log = logging.getLogger(__name__)

# The first file descriptor passed by systemd socket activation (SD_LISTEN_FDS_START).
SD_LISTEN_FDS_START = 3


def remove_file(path, remove=os.remove, exists=os.path.exists):
    """Remove file, and raise OSError if still exists."""
    try:
        remove(path)
    except OSError:
        if exists(path):
            raise


@contextlib.contextmanager
def unix_domain_socket_server(sock_path):
    """
    Create UNIX-domain socket on specified path.

    Listen on it, and delete it after the generated context is over.
    """
    log.debug('serving on %s', sock_path)
    if sys.platform == 'win32':
        # Return a named pipe emulating a socket server interface
        yield win_server.Server(sock_path)
        return
    remove_file(sock_path)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(sock_path)
    server.listen(1)
    try:
        yield server
    finally:
        remove_file(sock_path)


class FDServer:
    """File-descriptor based server (for NeoPG)."""

    def __init__(self, fd):
        """C-tor."""
        self.fd = fd
        self.sock = socket.fromfd(fd, socket.AF_UNIX, socket.SOCK_STREAM)

    def accept(self):
        """Use the same socket for I/O."""
        return self, None

    def recv(self, n):
        """Forward to underlying socket."""
        return self.sock.recv(n)

    def sendall(self, data):
        """Forward to underlying socket."""
        return self.sock.sendall(data)

    def close(self):
        """Not needed."""

    def settimeout(self, _):
        """Not needed."""

    def getsockname(self):
        """Simple representation."""
        return '<fd: {}>'.format(self.fd)


@contextlib.contextmanager
def unix_domain_socket_server_from_fd(fd):
    """Build UDS-based socket server from a file descriptor."""
    yield FDServer(fd)


def socket_activation_fd(environ=None, pid=None):
    """Return the listening fd passed by systemd socket activation, else None.

    Implements the ``sd_listen_fds(3)`` protocol: activation is honored only when
    ``LISTEN_PID`` names this process and ``LISTEN_FDS`` passes at least one
    socket; the first one is ``SD_LISTEN_FDS_START``. The activation variables
    are removed from the environment (as with ``unset_environment=1``) so that
    any subprocess the agent later spawns does not re-interpret them.
    """
    if environ is None:
        environ = os.environ
    if pid is None:
        pid = os.getpid()

    listen_pid = environ.get('LISTEN_PID')
    listen_fds = environ.get('LISTEN_FDS')
    if listen_pid is None or listen_fds is None:
        return None

    # Consume the activation variables regardless of validity.
    for var in ('LISTEN_PID', 'LISTEN_FDS', 'LISTEN_FDNAMES'):
        environ.pop(var, None)

    if listen_pid != str(pid):
        log.warning('LISTEN_PID=%s does not match our pid %d; '
                    'ignoring socket activation', listen_pid, pid)
        return None
    try:
        count = int(listen_fds)
    except ValueError:
        log.warning('LISTEN_FDS=%r is not an integer; ignoring', listen_fds)
        return None
    if count < 1:
        log.warning('LISTEN_FDS=%d passed no sockets; ignoring', count)
        return None
    if count > 1:
        log.warning('LISTEN_FDS=%d: only the first passed socket is used', count)
    return SD_LISTEN_FDS_START


@contextlib.contextmanager
def unix_domain_socket_server_from_systemd(fd):
    """Adopt a systemd-activated *listening* UNIX-domain socket.

    Unlike :func:`unix_domain_socket_server`, the socket is already bound and
    listening (systemd owns it), so it is neither bound nor unlinked here: the
    socket file's lifetime belongs to the ``.socket`` unit.
    """
    log.debug('adopting systemd-activated socket on fd %d', fd)
    # Don't leak the inherited fd into any subprocess the agent spawns.
    os.set_inheritable(fd, False)
    server = socket.fromfd(fd, socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        yield server
    finally:
        server.close()


def handle_connection(conn, handler, mutex):
    """
    Handle a single connection using the specified protocol handler in a loop.

    Since this function may be called concurrently from server_thread,
    the specified mutex is used to synchronize the device handling.

    Exit when EOFError is raised.
    All other exceptions are logged as warnings.
    """
    try:
        log.debug('welcome agent')
        with contextlib.closing(conn):
            while True:
                msg = util.read_frame(conn)
                with mutex:
                    reply = handler.handle(msg=msg)
                util.send(conn, reply)
    except EOFError:
        log.debug('goodbye agent')
    except Exception as e:  # pylint: disable=broad-except
        log.warning('error: %s', e, exc_info=True)


def retry(func, exception_type, quit_event):
    """
    Run the function, retrying when the specified exception_type occurs.

    Poll quit_event on each iteration, to be responsive to an external
    exit request.
    """
    while True:
        if quit_event.is_set():
            raise StopIteration
        try:
            return func()
        except exception_type:
            pass


def server_thread(sock, handle_conn, quit_event):
    """Run a server on the specified socket."""
    log.debug('server thread started')

    def accept_connection():
        conn, _ = sock.accept()
        conn.settimeout(None)
        return conn

    while True:
        log.debug('waiting for connection on %s', sock.getsockname())
        try:
            conn = retry(accept_connection, socket.timeout, quit_event)
        except StopIteration:
            log.debug('server stopped')
            break
        # Handle connections from SSH concurrently.
        threading.Thread(target=handle_conn,
                         kwargs={'conn': conn}).start()
    log.debug('server thread stopped')


@contextlib.contextmanager
def spawn(func, kwargs):
    """Spawn a thread, and join it after the context is over."""
    t = threading.Thread(target=func, kwargs=kwargs)
    t.start()
    yield
    t.join()


def run_process(command, environ):
    """
    Run the specified process and wait until it finishes.

    Use environ dict for environment variables.
    """
    log.info('running %r with %r', command, environ)
    env = dict(os.environ)
    env.update(environ)
    try:
        p = subprocess.Popen(args=command, env=env)
    except OSError as e:
        raise OSError('cannot run %r: %s' % (command, e)) from e
    log.debug('subprocess %d is running', p.pid)
    ret = p.wait()
    log.debug('subprocess %d exited: %d', p.pid, ret)
    return ret
