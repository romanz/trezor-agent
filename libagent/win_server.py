"""Windows named pipe server simulating a UNIX socket."""
import io
import os

import trio
import trio.lowlevel
import trio.socket
import win32api
import win32event
import win32file
import win32pipe
import winerror

from . import util

PIPE_BUFFER_SIZE = 64 * 1024
CTRL_C_EVENT = 0
THREAD_SET_CONTEXT = 0x0010


# Based loosely on https://docs.microsoft.com/en-us/windows/win32/ipc/multithreaded-pipe-server
class NamedPipe:
    """A Windows named pipe.

    Can act both as a listener waiting for and processing connections,
    or as a client connecting to a listener.
    """

    @classmethod
    def __close(cls, handle, disconnect):
        """Closes a named pipe handle."""
        if handle == win32file.INVALID_HANDLE_VALUE:
            return
        win32file.FlushFileBuffers(handle)
        if disconnect:
            win32pipe.DisconnectNamedPipe(handle)
        win32api.CloseHandle(handle)

    @classmethod
    def create(cls, name):
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
            ret = cls(name, handle, overlapped, pending_io, True)
            handle = win32file.INVALID_HANDLE_VALUE
            return ret
        finally:
            NamedPipe.__close(handle, True)

    @classmethod
    def open(cls, name):
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
            ret = cls(name, handle, overlapped, False, False)
            handle = win32file.INVALID_HANDLE_VALUE
            return ret
        finally:
            NamedPipe.__close(handle, False)

    def __enter__(self):
        """Context manager support."""
        return self

    def __exit__(self, *_):
        """Context manager support."""
        self.close()

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

    def __del__(self):
        """Close the named pipe."""
        self.close()

    def close(self):
        """Close the named pipe."""
        NamedPipe.__close(self.handle, self.created)
        self.handle = win32file.INVALID_HANDLE_VALUE

    async def connect(self):
        """Connect to a named pipe."""
        await trio.lowlevel.WaitForSingleObject(int(self.overlapped.hEvent))
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

    async def recv(self, size):
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
        await trio.lowlevel.WaitForSingleObject(int(self.overlapped.hEvent))
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

    async def send(self, data):
        """Write from the specified buffer to the pipe."""
        error_code, _ = win32file.WriteFile(self.handle, data, self.overlapped)
        if error_code not in (winerror.NO_ERROR,
                              winerror.ERROR_IO_PENDING,
                              winerror.ERROR_MORE_DATA):
            raise IOError('WriteFile failed ({0})'.format(error_code))
        await trio.lowlevel.WaitForSingleObject(int(self.overlapped.hEvent))
        written = win32pipe.GetOverlappedResult(self.handle, self.overlapped, False)
        error_code = win32api.GetLastError()
        if error_code != winerror.NO_ERROR:
            raise IOError('WriteFile failed ({0})'.format(error_code))
        return written


class Server:
    """Listend on an emulated AF_UNIX socket on Windows.

    Supports both Gpg4win-style AF_UNIX emulation and OpenSSH-style AF_UNIX emulation
    """

    @classmethod
    async def open(cls, pipe_name):
        """Opens a socket or named pipe.

        If ``pipe_name`` is a byte string, it is interpreted as a Gpg4win-style socket.
        The string contains the name of a file which must contain information needed to connect to
        a TCP socket listening on localhost emulating an AF_UNIX socket.
        Both the file and listening socket are created.

        If it is a string, it is interpreted as an OpenSSH-style socket.
        The string contains the name of a Windows named pipe.
        """
        if isinstance(pipe_name, str):
            return Server(pipe_name, None, None)
        # GPG simulated socket via localhost socket
        key = os.urandom(16)
        sock_close = sock = trio.socket.socket()
        try:
            await sock.bind(('127.0.0.1', 0))
            _, port = sock.getsockname()
            sock.listen(1)
            # Write key to file
            async with await trio.open_file(pipe_name, 'wb') as f:
                await f.write(str(port).encode())
                await f.write(b'\n')
                await f.write(key)
            sock_close = None
            return Server(pipe_name, sock, key)
        finally:
            if sock_close:
                sock_close.close()

    def __enter__(self):
        """Context manager support."""
        return self

    def __exit__(self, *_):
        """Context manager support."""
        self.close()

    def __init__(self, pipe_name, sock, key):
        """Should not be called directly.

        Use ``Server.open`` instead.
        """
        self.pipe_name = pipe_name
        self.sock = sock
        self.key = key

    def __del__(self):
        """Close the underlying socket or pipe."""
        self.close()

    def close(self):
        """Close the underlying socket or pipe."""
        if self.sock is not None:
            self.sock.close()
        self.sock = None

    def getsockname(self):
        """Return the file path or pipe name used for creating this named pipe."""
        return self.pipe_name

    async def accept(self, retry_invalid_client=True):
        """Listens for incoming connections on the socket.

        Returns a pair ``(pipe, address)`` where ``pipe`` is a connected socket-like object
        representing a client, and ``address`` is some string representing the client's address.

        When a named pipe is used, the client's address is the same as the pipe name.
        """
        if self.sock:
            while True:
                sock, addr = await self.sock.accept()
                if self.key == await util.recv_async(sock, 16):
                    break
                sock.close()
                if not retry_invalid_client:
                    raise IOError('Illegitimate client tried to connect to pipe {0}'
                                  .format(self.pipe_name))
            return (sock, addr)
        else:
            # Named pipe based server
            pipe = NamedPipe.create(self.pipe_name)
            await pipe.connect()
            return (pipe, self.pipe_name)


class Client:
    """Connects to an emulated AF_UNIX socket on Windows.

    Supports both Gpg4win-style AF_UNIX emulation and OpenSSH-style AF_UNIX emulation
    """

    @classmethod
    async def open(cls, pipe_name):
        """Connects to a socket or named pipe.

        If ``pipe_name`` is a byte string, it is interpreted as a Gpg4win-style socket.
        The string contains the name of a file which contains information needed to connect to
        a TCP socket listening on localhost emulating an AF_UNIX socket.

        If it is a string, it is interpreted as an OpenSSH-style socket.
        The string contains the name of a Windows named pipe.
        """
        if isinstance(pipe_name, str):
            return Client(pipe_name, None, NamedPipe.open(pipe_name))
        # Read key from file
        async with await trio.open_file(pipe_name, 'rb') as f:
            port = io.BytesIO()
            while True:
                c = await f.read(1)
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
            while key_len < 16:
                c = await f.read(16-key_len)
                if not c:
                    raise OSError('Could not read nonce for socket {0}'.format(pipe_name))
                key.write(c)
                key_len += len(c)
            key = key.getvalue()
            # Verify end of file
            c = await f.read(1)
            if c:
                raise OSError('Corrupt socket {0}'.format(pipe_name))
        # GPG simulated socket via localhost socket
        sock_close = sock = trio.socket.socket()
        try:
            await sock.connect(('127.0.0.1', port))
            await util.send(sock, key)
            sock_close = None
            return Client(pipe_name, sock, None)
        finally:
            if sock_close:
                sock_close.close()

    def __enter__(self):
        """Context manager support."""
        return self

    def __exit__(self, *_):
        """Context manager support."""
        self.close()

    def __init__(self, pipe_name, sock, pipe):
        """Should not be called directly.

        Use ``Client.open`` instead.
        """
        self.pipe_name = pipe_name
        self.sock = sock
        self.pipe = pipe

    def __del__(self):
        """Close the underlying socket or named pipe."""
        self.close()

    def close(self):
        """Close the underlying socket or named pipe."""
        if self.pipe is not None:
            self.pipe.close()
        self.pipe = None
        if self.sock is not None:
            self.sock.close()
        self.sock = None

    def getsockname(self):
        """Return the file path or pipe name used for connecting to this named pipe."""
        return self.pipe_name

    async def recv(self, size):
        """Forward to underlying socket or named pipe."""
        if self.sock is not None:
            return await self.sock.recv(size)
        return await self.pipe.recv(size)

    async def send(self, reply):
        """Forward to underlying socket or named pipe."""
        if self.sock is not None:
            return await self.sock.send(reply)
        return await self.pipe.send(reply)
