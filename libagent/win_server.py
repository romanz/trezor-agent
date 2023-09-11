"""Windows named pipe server simulating a UNIX socket."""
import contextlib
import ctypes
import io
import os
import socket

import win32api
import win32event
import win32file
import win32pipe
import winerror

from . import util

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

PIPE_BUFFER_SIZE = 64 * 1024
CTRL_C_EVENT = 0
THREAD_SET_CONTEXT = 0x0010


# Workaround for Ctrl+C not stopping IO on Windows
# See https://github.com/python/cpython/issues/85609
@contextlib.contextmanager
def ctrl_cancel_async_io(file_handle):
    """Listen for SIGINT and translate it to interrupting IO on the specified file handle."""
    @ctypes.WINFUNCTYPE(ctypes.c_uint, ctypes.c_uint)
    def ctrl_handler(ctrl_event):
        if ctrl_event == CTRL_C_EVENT:
            kernel32.CancelIoEx(file_handle, None)
        return False

    try:
        kernel32.SetConsoleCtrlHandler(ctrl_handler, True)
        yield
    finally:
        kernel32.SetConsoleCtrlHandler(ctrl_handler, False)


# Based loosely on https://docs.microsoft.com/en-us/windows/win32/ipc/multithreaded-pipe-server
class NamedPipe:
    """A Windows named pipe.

    Can act both as a listener waiting for and processing connections,
    or as a client connecting to a listener.
    """

    @staticmethod
    def __close(handle, disconnect):
        """Closes a named pipe handle."""
        if handle == win32file.INVALID_HANDLE_VALUE:
            return
        win32file.FlushFileBuffers(handle)
        if disconnect:
            win32pipe.DisconnectNamedPipe(handle)
        win32api.CloseHandle(handle)

    @staticmethod
    def create(name):
        """Opens a named pipe server for receiving connections."""
        handle = win32pipe.CreateNamedPipe(
            name,
            win32pipe.PIPE_ACCESS_DUPLEX | win32file.FILE_FLAG_OVERLAPPED,
            win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
            win32pipe.PIPE_UNLIMITED_INSTANCES,
            PIPE_BUFFER_SIZE,
            PIPE_BUFFER_SIZE,
            0,
            None)

        if handle == win32file.INVALID_HANDLE_VALUE:
            raise IOError('CreateNamedPipe failed ({0})'.format(win32api.GetLastError()))

        try:
            pending_io = False
            overlapped = win32file.OVERLAPPED()
            overlapped.hEvent = win32event.CreateEvent(None, True, True, None)
            error_code = win32pipe.ConnectNamedPipe(handle, overlapped)
            if error_code == winerror.ERROR_IO_PENDING:
                pending_io = True
            else:
                win32event.SetEvent(overlapped.hEvent)
                if error_code != winerror.ERROR_PIPE_CONNECTED:
                    raise IOError('ConnectNamedPipe failed ({0})'.format(error_code))
            ret = NamedPipe(name, handle, overlapped, pending_io, True)
            handle = win32file.INVALID_HANDLE_VALUE
            return ret
        finally:
            NamedPipe.__close(handle, True)

    @staticmethod
    def open(name):
        """Opens a named pipe server for receiving connections."""
        handle = win32file.CreateFile(
            name,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0,
            None,
            win32file.OPEN_EXISTING,
            win32file.FILE_FLAG_OVERLAPPED,
            None)

        if handle == win32file.INVALID_HANDLE_VALUE:
            raise IOError('CreateFile failed ({0})'.format(win32api.GetLastError()))

        try:
            overlapped = win32file.OVERLAPPED()
            overlapped.hEvent = win32event.CreateEvent(None, True, True, None)
            win32pipe.SetNamedPipeHandleState(handle, win32pipe.PIPE_READMODE_BYTE, None, None)
            ret = NamedPipe(name, handle, overlapped, False, False)
            handle = win32file.INVALID_HANDLE_VALUE
            return ret
        finally:
            NamedPipe.__close(handle, False)

    def __init__(self, name, handle, overlapped, pending_io, created):
        """Should not be called directly.

        Use ``NamedPipe.create`` or ``NamedPipe.open`` instead.
        """
        # pylint: disable=too-many-arguments
        self.name = name
        self.handle = handle
        self.overlapped = overlapped
        self.pending_io = pending_io
        self.created = created
        self.retain_buf = bytes()
        self.timeout = win32event.INFINITE

    def __del__(self):
        """Close the named pipe."""
        self.close()

    def settimeout(self, timeout):
        """Sets the timeout for IO operations on the named pipe in milliseconds."""
        self.timeout = win32event.INFINITE if timeout is None else int(timeout * 1000)

    def close(self):
        """Close the named pipe."""
        NamedPipe.__close(self.handle, self.created)
        self.handle = win32file.INVALID_HANDLE_VALUE

    def connect(self):
        """Connect to a named pipe with the specified timeout."""
        with ctrl_cancel_async_io(self.handle):
            waitHandle = win32event.WaitForSingleObject(self.overlapped.hEvent, self.timeout)
        if waitHandle == win32event.WAIT_TIMEOUT:
            raise TimeoutError('Timed out waiting for client on pipe {0}'.format(self.name))
        if not self.pending_io:
            return
        win32pipe.GetOverlappedResult(
            self.handle,
            self.overlapped,
            False)
        error_code = win32api.GetLastError()
        if error_code == winerror.NO_ERROR:
            return
        raise IOError('Connection to named pipe {0} failed ({1})'.format(self.name, error_code))

    def recv(self, size):
        """Read data from the pipe."""
        rbuf = win32file.AllocateReadBuffer(min(size, PIPE_BUFFER_SIZE))
        try:
            error_code, _ = win32file.ReadFile(self.handle, rbuf, self.overlapped)
            if error_code not in (winerror.NO_ERROR,
                                  winerror.ERROR_IO_PENDING,
                                  winerror.ERROR_MORE_DATA):
                raise IOError('ReadFile failed ({0})'.format(error_code))
        except win32api.error as e:
            if e.winerror == winerror.ERROR_NO_DATA:
                return None
            raise
        with ctrl_cancel_async_io(self.handle):
            win32event.WaitForSingleObject(self.overlapped.hEvent, self.timeout)
        try:
            chunk_size = win32pipe.GetOverlappedResult(self.handle, self.overlapped, False)
            error_code = win32api.GetLastError()
            if error_code != winerror.NO_ERROR:
                raise IOError('ReadFile failed ({0})'.format(error_code))
            return rbuf[:chunk_size] if chunk_size > 0 else None
        except win32api.error as e:
            if e.winerror == winerror.ERROR_BROKEN_PIPE:
                return None
            raise

    def send(self, data):
        """Write from the specified buffer to the pipe."""
        error_code, _ = win32file.WriteFile(self.handle, data, self.overlapped)
        if error_code not in (winerror.NO_ERROR,
                              winerror.ERROR_IO_PENDING,
                              winerror.ERROR_MORE_DATA):
            raise IOError('WriteFile failed ({0})'.format(error_code))
        with ctrl_cancel_async_io(self.handle):
            win32event.WaitForSingleObject(self.overlapped.hEvent, self.timeout)
        written = win32pipe.GetOverlappedResult(self.handle, self.overlapped, False)
        error_code = win32api.GetLastError()
        if error_code != winerror.NO_ERROR:
            raise IOError('WriteFile failed ({0})'.format(error_code))
        return written

    def sendall(self, data):
        """Send the specified reply to the pipe."""
        while len(data) > 0:
            written = self.send(data)
            data = data[written:]


class InterruptibleSocket:
    """A wrapper for sockets which allows IO operations to be interrupted by SIGINT."""

    def __init__(self, sock):
        """Wraps the socket object ``sock``."""
        self.sock = sock

    def __del__(self):
        """Close the wrapped socket. It should not outlive the wrapper."""
        self.close()

    def settimeout(self, timeout):
        """Forward to underlying socket."""
        self.sock.settimeout(timeout)

    def recv(self, size):
        """Forward to underlying socket, while monitoring for SIGINT."""
        try:
            with ctrl_cancel_async_io(self.sock.fileno()):
                return self.sock.recv(size)
        except OSError as e:
            if e.winerror == 10054:
                # Convert socket close to end of file
                return None
            raise

    def sendall(self, reply):
        """Forward to underlying socket, while monitoring for SIGINT."""
        with ctrl_cancel_async_io(self.sock.fileno()):
            return self.sock.sendall(reply)

    def close(self):
        """Forward to underlying socket."""
        return self.sock.close()

    def getsockname(self):
        """Forward to underlying socket."""
        return self.sock.getsockname()


class Server:
    """Listend on an emulated AF_UNIX socket on Windows.

    Supports both Gpg4win-style AF_UNIX emulation and OpenSSH-style AF_UNIX emulation
    """

    def __init__(self, pipe_name):
        """Opens a socket or named pipe.

        If ``pipe_name`` is a byte string, it is interpreted as a Gpg4win-style socket.
        The string contains the name of a file which must contain information needed to connect to
        a TCP socket listening on localhost emulating an AF_UNIX socket.
        Both the file and listening socket are created.

        If it is a string, it is interpreted as an OpenSSH-style socket.
        The string contains the name of a Windows named pipe.
        """
        self.timeout = None
        self.pipe_name = pipe_name
        self.sock = None
        self.pipe = None
        if not isinstance(self.pipe_name, str):
            # GPG simulated socket via localhost socket
            self.key = os.urandom(16)
            self.sock = socket.socket()
            self.sock.bind(('127.0.0.1', 0))
            _, port = self.sock.getsockname()
            self.sock.listen(1)
            # Write key to file
            with open(self.pipe_name, 'wb') as f:
                with ctrl_cancel_async_io(f.fileno()):
                    f.write(str(port).encode())
                    f.write(b'\n')
                    f.write(self.key)

    def __del__(self):
        """Close the underlying socket or pipe."""
        if self.pipe is not None:
            self.pipe.close()
        self.pipe = None
        if self.sock is not None:
            self.sock.close()
        self.sock = None

    def settimeout(self, timeout):
        """Set the timeout in seconds."""
        if self.sock:
            self.sock.settimeout(timeout)
        self.timeout = timeout

    def getsockname(self):
        """Return the file path or pipe name used for creating this named pipe."""
        return self.pipe_name

    def accept(self):
        """Listens for incoming connections on the socket.

        Returns a pair ``(pipe, address)`` where ``pipe`` is a connected socket-like object
        representing a client, and ``address`` is some string representing the client's address.

        When a named pipe is used, the client's address is the same as the pipe name.
        """
        if self.sock:
            with ctrl_cancel_async_io(self.sock.fileno()):
                sock, addr = self.sock.accept()
            sock = InterruptibleSocket(sock)
            sock.settimeout(self.timeout)
            if self.key != util.recv(sock, 16):
                sock.close()
                # Simulate timeout on failed connection to allow the caller to retry
                raise TimeoutError('Illegitimate client tried to connect to pipe {0}'
                                   .format(self.pipe_name))
            sock.settimeout(None)
            return (sock, addr)
        else:
            # Named pipe based server
            if self.pipe is None:
                self.pipe = NamedPipe.create(self.pipe_name)
            self.pipe.settimeout(self.timeout)
            self.pipe.connect()
            self.pipe.settimeout(None)
            # A named pipe can only accept a single connection
            # It must be recreated if a new connection is to be made
            pipe = self.pipe
            self.pipe = None
            return (pipe, self.pipe_name)


class Client:
    """Connects to an emulated AF_UNIX socket on Windows.

    Supports both Gpg4win-style AF_UNIX emulation and OpenSSH-style AF_UNIX emulation
    """

    def __init__(self, pipe_name):
        """Connects to a socket or named pipe.

        If ``pipe_name`` is a byte string, it is interpreted as a Gpg4win-style socket.
        The string contains the name of a file which contains information needed to connect to
        a TCP socket listening on localhost emulating an AF_UNIX socket.

        If it is a string, it is interpreted as an OpenSSH-style socket.
        The string contains the name of a Windows named pipe.
        """
        self.pipe_name = pipe_name
        self.sock = None
        self.pipe = None
        if not isinstance(self.pipe_name, str):
            # Read key from file
            with open(self.pipe_name, 'rb') as f:
                with ctrl_cancel_async_io(f.fileno()):
                    port = io.BytesIO()
                    while True:
                        c = f.read(1)
                        if not c:
                            raise OSError('Could not read port for socket {0}'.format(pipe_name))
                        if c == b'\n':
                            break
                        if c < b'0' or c > b'9':
                            raise OSError('Could not read port for socket {0}'.format(pipe_name))
                        port.write(c)
                    port = int(port.getvalue())
                    key_len = 0
                    key = io.BytesIO()
                    while key:
                        c = f.read(16-key_len)
                        if not c:
                            raise OSError('Could not read nonce for socket {0}'.format(pipe_name))
                        key.write(c)
                        key_len += len(c)
                    key = key.getvalue()
                    # Verify end of file
                    c = f.read(1)
                    if c:
                        raise OSError('Corrupt socket {0}'.format(pipe_name))
            # GPG simulated socket via localhost socket
            sock = socket.socket()
            sock.connect(('127.0.0.1', port))
            self.sock = InterruptibleSocket(sock)
            self.sock.sendall(key)
        else:
            self.pipe = NamedPipe.open(pipe_name)

    def __del__(self):
        """Close the underlying socket or named pipe."""
        if self.pipe is not None:
            self.pipe.close()
        self.pipe = None
        if self.sock is not None:
            self.sock.close()
        self.sock = None

    def settimeout(self, timeout):
        """Forward to underlying socket or named pipe."""
        if self.sock:
            self.sock.settimeout(timeout)
        if self.pipe:
            self.pipe.settimeout(timeout)

    def getsockname(self):
        """Return the file path or pipe name used for connecting to this named pipe."""
        return self.pipe_name

    def recv(self, size):
        """Forward to underlying socket or named pipe."""
        if self.sock is not None:
            return self.sock.recv(size)
        return self.pipe.recv(size)

    def sendall(self, reply):
        """Forward to underlying socket or named pipe."""
        if self.sock is not None:
            return self.sock.sendall(reply)
        return self.pipe.sendall(reply)
