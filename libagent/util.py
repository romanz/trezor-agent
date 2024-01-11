"""Various I/O and serialization utilities."""
import binascii
import contextlib
import functools
import io
import logging
import struct
import sys
import threading

import trio

log = logging.getLogger(__name__)


async def send(conn, data):
    """Send data blob to connection socket."""
    while len(data) > 0:
        sent = await conn.send(data)
        if not sent:
            raise IOError('Socket refused data')
        data = data[sent:]


async def recv_async(conn, size):
    """
    Receive bytes from connection socket.

    If size is struct.calcsize()-compatible format, use it to unpack the data.
    Otherwise, return the plain blob as bytes.
    """
    try:
        fmt = size
        size = struct.calcsize(fmt)
    except TypeError:
        fmt = None
    try:
        _read = conn.recv
    except AttributeError:
        _read = conn.read

    res = io.BytesIO()
    while size > 0:
        buf = await _read(size)
        if not buf:
            raise EOFError
        size = size - len(buf)
        res.write(buf)
    res = res.getvalue()
    if fmt:
        return struct.unpack(fmt, res)
    else:
        return res


def recv(conn, size):
    """
    Receive bytes from in-memory stream.

    If size is struct.calcsize()-compatible format, use it to unpack the data.
    Otherwise, return the plain blob as bytes.
    """
    try:
        fmt = size
        size = struct.calcsize(fmt)
    except TypeError:
        fmt = None
    try:
        _read = conn.recv
    except AttributeError:
        _read = conn.read

    res = io.BytesIO()
    while size > 0:
        buf = _read(size)
        if not buf:
            raise EOFError
        size = size - len(buf)
        res.write(buf)
    res = res.getvalue()
    if fmt:
        return struct.unpack(fmt, res)
    else:
        return res


async def read_frame_async(conn):
    """Read size-prefixed frame from connection."""
    size, = await recv_async(conn, '>L')
    return await recv_async(conn, size)


def read_frame(conn):
    """Read size-prefixed frame from in-memory stream."""
    size, = recv(conn, '>L')
    return recv(conn, size)


def bytes2num(s):
    """Convert MSB-first bytes to an unsigned integer."""
    res = 0
    for i, c in enumerate(reversed(bytearray(s))):
        res += c << (i * 8)
    return res


def num2bytes(value, size):
    """Convert an unsigned integer to MSB-first bytes with specified size."""
    res = []
    for _ in range(size):
        res.append(value & 0xFF)
        value = value >> 8
    assert value == 0
    return bytes(bytearray(list(reversed(res))))


def pack(fmt, *args):
    """Serialize MSB-first message."""
    return struct.pack('>' + fmt, *args)


def frame(*msgs):
    """Serialize MSB-first length-prefixed frame."""
    res = io.BytesIO()
    for msg in msgs:
        res.write(msg)
    msg = res.getvalue()
    return pack('L', len(msg)) + msg


def crc24(blob):
    """See https://tools.ietf.org/html/rfc4880#section-6.1 for details."""
    CRC24_INIT = 0x0B704CE
    CRC24_POLY = 0x1864CFB

    crc = CRC24_INIT
    for octet in bytearray(blob):
        crc ^= (octet << 16)
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= CRC24_POLY
    assert 0 <= crc < 0x1000000
    crc_bytes = struct.pack('>L', crc)
    assert crc_bytes[:1] == b'\x00'
    return crc_bytes[1:]


def bit(value, i):
    """Extract the i-th bit out of value."""
    return 1 if value & (1 << i) else 0


def low_bits(value, n):
    """Extract the lowest n bits out of value."""
    return value & ((1 << n) - 1)


def split_bits(value, *bits):
    """
    Split integer value into list of ints, according to `bits` list.

    For example, split_bits(0x1234, 4, 8, 4) == [0x1, 0x23, 0x4]
    """
    result = []
    for b in reversed(bits):
        mask = (1 << b) - 1
        result.append(value & mask)
        value = value >> b
    assert value == 0

    result.reverse()
    return result


def readfmt(stream, fmt):
    """Read and unpack an object from stream, using a struct format string."""
    size = struct.calcsize(fmt)
    blob = stream.read(size)
    return struct.unpack(fmt, blob)


def prefix_len(fmt, blob):
    """Prefix `blob` with its size, serialized using `fmt` format."""
    return struct.pack(fmt, len(blob)) + blob


def hexlify(blob):
    """Utility for consistent hexadecimal formatting."""
    return binascii.hexlify(blob).decode('ascii').upper()


class Reader:
    """Read basic type objects out of given stream."""

    def __init__(self, stream):
        """Create a non-capturing reader."""
        self.s = stream
        self._captured = None

    def readfmt(self, fmt):
        """Read a specified object, using a struct format string."""
        size = struct.calcsize(fmt)
        blob = self.read(size)
        obj, = struct.unpack(fmt, blob)
        return obj

    def read(self, size=None):
        """Read `size` bytes from stream."""
        blob = self.s.read(size)
        if size is not None and len(blob) < size:
            raise EOFError
        if self._captured:
            self._captured.write(blob)
        return blob

    @contextlib.contextmanager
    def capture(self, stream):
        """Capture all data read during this context."""
        self._captured = stream
        try:
            yield
        finally:
            self._captured = None


def setup_logging(verbosity, filename=None):
    """Configure logging for this tool."""
    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    level = levels[min(verbosity, len(levels) - 1)]
    logging.root.setLevel(level)

    fmt = logging.Formatter('%(asctime)s %(levelname)-12s %(message)-100s '
                            '[%(filename)s:%(lineno)d]')
    hdlr = logging.StreamHandler()  # stderr
    hdlr.setFormatter(fmt)
    logging.root.addHandler(hdlr)

    if filename:
        hdlr = logging.FileHandler(filename, 'a')
        hdlr.setFormatter(fmt)
        logging.root.addHandler(hdlr)


def memoize(func):
    """Simple caching decorator."""
    cache = {}

    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        """Caching wrapper."""
        key = (args, tuple(sorted(kwargs.items())))
        if key in cache:
            return cache[key]
        else:
            result = await func(*args, **kwargs)
            cache[key] = result
            return result

    return wrapper


def memoize_method(method):
    """Simple caching decorator."""
    cache = {}

    @functools.wraps(method)
    async def wrapper(self, *args, **kwargs):
        """Caching wrapper."""
        key = (args, tuple(sorted(kwargs.items())))
        if key in cache:
            return cache[key]
        else:
            result = await method(self, *args, **kwargs)
            cache[key] = result
            return result

    return wrapper


@memoize
async def which(cmd):
    """Return full path to specified command, or raise OSError if missing."""
    try:
        # For Python 3
        from shutil import which as _which
    except ImportError:
        # For Python 2
        from backports.shutil_which import which as _which
    full_path = await trio.to_thread.run_sync(_which, cmd)
    if full_path is None:
        raise OSError('Cannot find {!r} in $PATH'.format(cmd))
    log.debug('which %r => %r', cmd, full_path)
    return full_path


def assuan_serialize(data):
    """Serialize data according to ASSUAN protocol (for GPG daemon communication)."""
    for c in [b'%', b'\n', b'\r']:
        escaped = '%{:02X}'.format(ord(c)).encode('ascii')
        data = data.replace(c, escaped)
    return data


def escape_cmd_quotes(in_str):
    """
    Escape a string for use as a command line argument inside quotes.

    Does not add quotes. This allows appending multiple strings inside the quotes.
    """
    if sys.platform == 'win32':
        return in_str.translate(str.maketrans({'%': '%%', '\"': '\"\"'}))
    else:
        return in_str.translate(str.maketrans({'\"': '\\\"', '\'': '\\\'', '\\': '\\\\'}))


def escape_cmd_win(in_str):
    """Escape a string for Windows batch files in a context where quotes cannot be used."""
    return in_str.translate(str.maketrans({'\"': '^\"',
                                           '%': '%%',
                                           '&': '^&',
                                           '\'': '^\'',
                                           '<': '^<',
                                           '>': '^>',
                                           '^': '^^',
                                           '|': '^|'}))


class ExpiringCache:
    """Simple cache with a deadline."""

    def __init__(self, seconds, timer=trio.current_time):
        """C-tor."""
        self.duration = seconds
        self.timer = timer
        self.values = {}

    def get(self, key):
        """Returns existing value, or None if deadline has expired."""
        curtime = self.timer()
        self.values = {k: v for k, v in self.values.items() if curtime <= v[0]}
        return self.values.get(key, (None, None))[1]

    def set(self, key, value):
        """Set new value and reset the deadline for expiration."""
        self.values[key] = (
            self.timer() + self.duration,
            value
        )


@contextlib.asynccontextmanager
async def run_on_thread():
    """Allows running blocking commands from asynchronous context on a single thread."""
    # pylint: disable=too-many-statements
    command_condition = threading.Condition()
    command_value = ()
    command_in_progress = False
    thread_is_running = True

    def before_resolve():
        nonlocal command_condition, command_in_progress
        with command_condition:
            command_in_progress = False

    async def run_command(command, *args, **kwargs):
        nonlocal command_condition, command_value, thread_is_running
        assert thread_is_running
        res = _ResultFromThread(before_resolve)
        with command_condition:
            assert not command_value
            command_value = (res, command, args, kwargs)
            command_condition.notify()
        return await res.wait()

    async def run_command_immediate(command, *args, **kwargs):
        nonlocal command_condition, command_value, command_in_progress, thread_is_running
        assert thread_is_running
        res = _ResultFromThread(before_resolve)
        bypass_thread = False
        with command_condition:
            if not command_value and not command_in_progress:
                command_value = (res, command, args, kwargs)
                command_condition.notify()
            else:
                bypass_thread = True
        if bypass_thread:
            def run_func():
                nonlocal command, args, kwargs
                command(*args, **kwargs)
            return await trio.to_thread.run_sync(run_func)
        else:
            return await res.wait()

    def thread_func():
        nonlocal command_condition, command_value, command_in_progress
        while True:
            with command_condition:
                while not command_value:
                    command_condition.wait()
                command = command_value
                command_value = ()
                command_in_progress = True
            res, func, args, kwargs = command
            if res is None:
                break
            with res:
                res.resolve(func(*args, **kwargs))

    async with trio.open_nursery() as nursery:
        nursery.start_soon(trio.to_thread.run_sync, thread_func)
        try:
            yield run_command, run_command_immediate
        finally:
            thread_is_running = False
            with command_condition:
                # Abort any in-flight commands, as closing the thread is the highest priority
                if command_value:
                    res, = command_value
                    if res is not None:
                        res.reject(trio.Cancelled('Thread closed'))
                command_value = (None, None, None, None)
                command_condition.notify()


class _ResultFromThread:
    def __init__(self, before_resolve):
        self.event = trio.Event()
        self.retval = None
        self.retiserr = False
        self.done = False
        self.before_resolve = before_resolve

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            trio.from_thread.run_sync(self.reject, exc_val)
        else:
            # Last chance to resolve
            trio.from_thread.run_sync(self._resolve, None)
        return True

    def resolve(self, retval):
        trio.from_thread.run_sync(self._resolve, retval)

    def _resolve(self, retval):
        if self.done:
            return
        self.done = True
        self.before_resolve()
        self.retval = retval
        self.retiserr = False
        self.event.set()

    def reject(self, retval):
        if self.done:
            return
        self.done = True
        self.before_resolve()
        self.retval = retval
        self.retiserr = True
        self.event.set()

    async def wait(self):
        await self.event.wait()
        if self.retiserr:
            raise self.retval
        return self.retval
