"""Various I/O and serialization utilities."""
import binascii
import contextlib
import functools
import io
import logging
import struct
import sys
import time

log = logging.getLogger(__name__)


def send(conn, data):
    """Send data blob to connection socket."""
    conn.sendall(data)


def recv(conn, size):
    """
    Receive bytes from connection socket or stream.

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


def read_frame(conn):
    """Read size-prefixed frame from connection."""
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
    def wrapper(*args, **kwargs):
        """Caching wrapper."""
        key = (args, tuple(sorted(kwargs.items())))
        if key in cache:
            return cache[key]
        else:
            result = func(*args, **kwargs)
            cache[key] = result
            return result

    return wrapper


def memoize_method(method):
    """Simple caching decorator."""
    cache = {}

    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        """Caching wrapper."""
        key = (args, tuple(sorted(kwargs.items())))
        if key in cache:
            return cache[key]
        else:
            result = method(self, *args, **kwargs)
            cache[key] = result
            return result

    return wrapper


@memoize
def which(cmd):
    """Return full path to specified command, or raise OSError if missing."""
    try:
        # For Python 3
        from shutil import which as _which
    except ImportError:
        # For Python 2
        from backports.shutil_which import which as _which
    full_path = _which(cmd)
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

    def __init__(self, seconds, timer=time.time):
        """C-tor."""
        self.duration = seconds
        self.timer = timer
        self.value = None
        self.set(None)

    def get(self):
        """Returns existing value, or None if deadline has expired."""
        if self.timer() > self.deadline:
            self.value = None
        return self.value

    def set(self, value):
        """Set new value and reset the deadline for expiration."""
        self.deadline = self.timer() + self.duration
        self.value = value


class Base58Error(Exception):
    """Base class for all base-58 errors."""


class Base58TypeError(Base58Error):
    """Raised when a type error occurs."""


class Base58ValidationError(Base58Error):
    """Raised when base-58 validation fails."""


class Base58:
    """
    A class for base-58 encoding and decoding operations.

    Taken from https://github.com/jim-schilling/splurge-base58

    Base-58 is a binary-to-text encoding scheme that uses 58 characters
    to represent binary data. It's commonly used in cryptocurrency
    applications and other systems where binary data needs to be
    represented in a human-readable format.

    This implementation uses the Bitcoin alphabet:
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    """

    DIGITS = '123456789'
    ALPHA_UPPER = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
    ALPHA_LOWER = 'abcdefghijkmnopqrstuvwxyz'
    ALPHABET = DIGITS + ALPHA_UPPER + ALPHA_LOWER
    _BASE = len(ALPHABET)

    @classmethod
    def encode(cls, data: bytes) -> str:
        """
        Encode binary data to base-58 string.

        Args:
            data: Binary data to encode

        Returns:
            Base-58 encoded string

        Raises:
            Base58TypeError: If input is not bytes
            Base58ValidationError: If input data is empty or invalid
        """
        if not isinstance(data, bytes):
            raise Base58TypeError("Input must be bytes")

        if not data:
            raise Base58ValidationError("Cannot encode empty data")

        # Convert bytes to integer
        num = int.from_bytes(data, byteorder="big")

        # Handle zero case
        if num == 0:
            return cls.ALPHABET[0] * len(data)

        # Convert to base-58
        result = ""
        while num > 0:
            num, remainder = divmod(num, cls._BASE)
            result = cls.ALPHABET[remainder] + result

        # Add leading zeros for each leading zero byte in original data
        for byte in data:
            if byte == 0:
                result = cls.ALPHABET[0] + result
            else:
                break

        return result

    @classmethod
    def decode(cls, base58_data: str) -> bytes:
        """
        Decode base-58 string to binary data.

        Args:
            base58_data: Base-58 encoded string

        Returns:
            Decoded binary data

        Raises:
            Base58TypeError: If input is not a string
            Base58ValidationError: If input string is empty or contains invalid characters
        """
        if not isinstance(base58_data, str):
            raise Base58TypeError("Input must be a string")

        if not base58_data:
            raise Base58ValidationError("Cannot decode empty string")

        if not cls.is_valid(base58_data):
            raise Base58ValidationError("Invalid base-58 string")

        # Count leading '1' characters
        leading_ones = 0
        for char in base58_data:
            if char == cls.ALPHABET[0]:
                leading_ones += 1
            else:
                break

        # If all characters are '1', return the appropriate number of zero bytes
        if leading_ones == len(base58_data):
            return b"\x00" * leading_ones

        # Convert base-58 to integer (skip leading ones)
        num = 0
        for char in base58_data[leading_ones:]:
            num = num * cls._BASE + cls.ALPHABET.index(char)

        # Handle case where num is 0 (all remaining chars were '1')
        if num == 0:
            result = b""
        else:
            # Calculate minimum byte length
            byte_length = (num.bit_length() + 7) // 8
            result = num.to_bytes(byte_length, byteorder="big")

        # Add leading zeros for each leading '1' character
        return b"\x00" * leading_ones + result

    @classmethod
    def is_valid(cls, base58_data: str) -> bool:
        """
        Check if a string is valid base-58.

        Args:
            base58_data: String to validate

        Returns:
            True if valid base-58, False otherwise
        """
        if not isinstance(base58_data, str):
            return False

        if not base58_data:
            return False

        try:
            return all(char in cls.ALPHABET for char in base58_data)
        except Exception:
            return False
