"""Windows named pipe server for ssh-agent implementation."""
import logging
import pywintypes
import struct
import threading
import win32api
import win32event
import win32pipe
import win32file
import winerror

from . import util

log = logging.getLogger(__name__)

PIPE_BUFFER_SIZE = 64 * 1024

# Make MemoryView look like a buffer to reuse util.recv
class MvBuffer:
    def __init__(self, mv):
        self.mv = mv
    def read(self, n):
        return self.mv[0:n]

# Based loosely on https://docs.microsoft.com/en-us/windows/win32/ipc/multithreaded-pipe-server
class NamedPipe:
    __frame_size_size = struct.calcsize('>L')

    def __close(handle):
        """Closes a named pipe handle."""
        if handle == win32file.INVALID_HANDLE_VALUE:
            return
        win32file.FlushFileBuffers(handle)
        win32pipe.DisconnectNamedPipe(handle)
        win32api.CloseHandle(handle)

    def open(name):
        """Opens a named pipe server for receiving connections."""
        handle = win32pipe.CreateNamedPipe(
            name,
            win32pipe.PIPE_ACCESS_DUPLEX | win32file.FILE_FLAG_OVERLAPPED,
            win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
            win32pipe.PIPE_UNLIMITED_INSTANCES,
            PIPE_BUFFER_SIZE,
            PIPE_BUFFER_SIZE,
            0,
            None) # Default security attributes

        if handle == win32file.INVALID_HANDLE_VALUE:
            log.error("CreateNamedPipe failed (%d)", win32api.GetLastError())
            return None
        
        try:
            pending_io = False
            overlapped = win32file.OVERLAPPED()
            overlapped.hEvent = win32event.CreateEvent(None, True, True, None)
            error_code = win32pipe.ConnectNamedPipe(handle, overlapped)
            if error_code == winerror.ERROR_IO_PENDING:
                pending_io = True
            elif error_code != winerror.ERROR_PIPE_CONNECTED or not win32event.SetEvent(overlapped.hEvent):
                log.error('ConnectNamedPipe failed (%d)', error_code)
                return None
            log.debug('waiting for connection on %s', name)
            return NamedPipe(name, handle, overlapped, pending_io)
        except:
            NamedPipe.__close(handle)
            raise

    def __init__(self, name, handle, overlapped, pending_io):
        self.name = name
        self.handle = handle
        self.overlapped = overlapped
        self.pending_io = pending_io

    def close(self):
        """Close the named pipe."""
        NamedPipe.__close(self.handle)

    def connect(self, timeout):
        """Connect to an SSH client with the specified timeout."""
        waitHandle = win32event.WaitForSingleObject(
            self.overlapped.hEvent,
            timeout)
        if waitHandle == win32event.WAIT_TIMEOUT:
            return False
        if not self.pending_io:
            return True
        win32pipe.GetOverlappedResult(
            self.handle,
            self.overlapped,
            False)
        error_code = win32api.GetLastError()
        if error_code == winerror.NO_ERROR:
            return True
        log.error('GetOverlappedResult failed (%d)', error_code)
        return False

    def read_frame(self, quit_event):
        """Read the request frame from the SSH client."""
        request_size = None
        remaining = None
        buf = MvBuffer(win32file.AllocateReadBuffer(PIPE_BUFFER_SIZE))
        while True:
            if quit_event.is_set():
                return None
            error_code, _ = win32file.ReadFile(self.handle, buf.mv, self.overlapped)
            if error_code not in (winerror.NO_ERROR, winerror.ERROR_IO_PENDING, winerror.ERROR_MORE_DATA):
                log.error('ReadFile failed (%d)', error_code)
                return None
            win32event.WaitForSingleObject(self.overlapped.hEvent, win32event.INFINITE)
            chunk_size = win32pipe.GetOverlappedResult(self.handle, self.overlapped, False)
            error_code = win32api.GetLastError()
            if error_code != winerror.NO_ERROR:
                log.error('GetOverlappedResult failed (%d)', error_code)
                return None
            if request_size:
                remaining -= chunk_size
            else:
                request_size, = util.recv(buf, '>L')
                remaining = request_size - (chunk_size - NamedPipe.__frame_size_size)
            if remaining <= 0:
                break
        return util.recv(buf, request_size)

    def send(self, reply):
        """Send the specified reply to the SSH client."""
        error_code, _ = win32file.WriteFile(self.handle, reply)
        if error_code == winerror.NO_ERROR:
            return True
        log.error('WriteFile failed (%d)', error_code)
        return False


def handle_connection(pipe, handler, mutex, quit_event):
    """
    Handle a single connection using the specified protocol handler in a loop.

    Since this function may be called concurrently from server_thread,
    the specified mutex is used to synchronize the device handling.
    """
    log.debug('welcome agent')

    try:
        while True:
            if quit_event.is_set():
                return
            msg = pipe.read_frame(quit_event)
            if not msg:
                return
            with mutex:
                reply = handler.handle(msg=msg)
            if not pipe.send(reply):
                return
    except pywintypes.error as e:
        # Surface errors that aren't related to the client disconnecting
        if e.args[0] == winerror.ERROR_BROKEN_PIPE:
            log.debug('goodbye agent')
        else:
            raise
    except Exception as e:  # pylint: disable=broad-except
        log.warning('error: %s', e, exc_info=True)
    finally:
        pipe.close()


def server_thread(pipe_name, handle_conn, quit_event, timeout):
    """Run a Windows server on the specified pipe."""
    log.debug('server thread started')

    while True:
        if quit_event.is_set():
            break
        # A new pipe instance is necessary for each client
        pipe = NamedPipe.open(pipe_name)
        if not pipe:
            break
        try:
            # Poll for a new client connection
            while True:
                if quit_event.is_set():
                    break
                if pipe.connect(timeout * 1000):
                    # Handle connections from SSH concurrently.
                    threading.Thread(target=handle_conn,
                                     kwargs=dict(pipe=pipe)).start()
                    break
        except:
            pipe.close()
            raise

    log.debug('server thread stopped')
