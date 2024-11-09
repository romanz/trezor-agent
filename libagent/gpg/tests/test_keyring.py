import io
import subprocess

import pytest

from .. import keyring


def test_unescape_short():
    assert keyring.unescape(b'abc%0AX%0D %25;.-+()') == b'abc\nX\r %;.-+()'


def test_unescape_long():
    escaped = (b'D (7:sig-val(3:dsa(1:r32:\x1d\x15.\x12\xe8h\x19\xd9O\xeb\x06'
               b'yD?a:/\xae\xdb\xac\x93\xa6\x86\xcbs\xb8\x03\xf1\xcb\x89\xc7'
               b'\x1f)(1:s32:%25\xb5\x04\x94\xc7\xc4X\xc7\xe0%0D\x08\xbb%0DuN'
               b'\x9c6}[\xc2=t\x8c\xfdD\x81\xe8\xdd\x86=\xe2\xa9)))')
    unescaped = (b'D (7:sig-val(3:dsa(1:r32:\x1d\x15.\x12\xe8h\x19\xd9O\xeb'
                 b'\x06yD?a:/\xae\xdb\xac\x93\xa6\x86\xcbs\xb8\x03\xf1\xcb\x89'
                 b'\xc7\x1f)(1:s32:%\xb5\x04\x94\xc7\xc4X\xc7\xe0\r\x08\xbb\ru'
                 b'N\x9c6}[\xc2=t\x8c\xfdD\x81\xe8\xdd\x86=\xe2\xa9)))')
    assert keyring.unescape(escaped) == unescaped


def test_parse_term():
    assert keyring.parse(b'4:abcdXXX') == (b'abcd', b'XXX')


def test_parse_ecdsa():
    sig, rest = keyring.parse(b'(7:sig-val(5:ecdsa'
                              b'(1:r2:\x01\x02)(1:s2:\x03\x04)))')
    values = [[b'r', b'\x01\x02'], [b's', b'\x03\x04']]
    assert sig == [b'sig-val', [b'ecdsa'] + values]
    assert rest == b''
    assert keyring.parse_sig(sig) == (0x102, 0x304)


def test_parse_rsa():
    sig, rest = keyring.parse(b'(7:sig-val(3:rsa(1:s4:\x01\x02\x03\x04)))')
    assert sig == [b'sig-val', [b'rsa', [b's', b'\x01\x02\x03\x04']]]
    assert rest == b''
    assert keyring.parse_sig(sig) == (0x1020304,)


class FakeSocket:
    def __init__(self):
        self.rx = io.BytesIO()
        self.tx = io.BytesIO()

    async def recv(self, n):
        return self.rx.read(n)

    async def send(self, data):
        self.tx.write(data)
        return len(data)


def mock_run_process(output, error=b''):
    async def run_process(args, **_):
        return subprocess.CompletedProcess(args, returncode=0, stdout=output, stderr=error)
    return run_process


@pytest.mark.trio
async def test_sign_digest():
    sock = FakeSocket()
    sock.rx.write(b'OK Pleased to meet you, process XYZ\n')
    sock.rx.write(b'OK\n' * 6)
    sock.rx.write(b'D (7:sig-val(3:rsa(1:s16:0123456789ABCDEF)))\n')
    sock.rx.seek(0)
    keygrip = '1234'
    digest = b'A' * 32
    sig = await keyring.sign_digest(sock=sock, keygrip=keygrip,
                                    digest=digest, run_process=mock_run_process('/dev/pts/0'),
                                    environ={'DISPLAY': ':0'})
    assert sig == (0x30313233343536373839414243444546,)
    assert sock.tx.getvalue() == b'''RESET
OPTION ttyname=/dev/pts/0
OPTION display=:0
SIGKEY 1234
SETHASH 8 4141414141414141414141414141414141414141414141414141414141414141
SETKEYDESC Sign+a+new+TREZOR-based+subkey
PKSIGN
'''


@pytest.mark.trio
async def test_iterlines():
    sock = FakeSocket()
    sock.rx.write(b'foo\nbar\nxyz')
    sock.rx.seek(0)
    assert [line async for line in keyring.iterlines(sock)] == [b'foo', b'bar']


@pytest.mark.trio
async def test_get_agent_sock_path():
    expected_prefix = b'/run/user/'
    expected_suffix = b'/gnupg/S.gpg-agent'
    expected_infix = b'0123456789'
    expected_if_root = b'/root/.gnupg/S.gpg-agent'  # Use in case tox was executed as root
    value = await keyring.get_agent_sock_path()
    if value == expected_if_root:
        return
    assert value.startswith(expected_prefix)
    assert value.endswith(expected_suffix)
    value = value[len(expected_prefix):-len(expected_suffix)]
    assert value.strip(expected_infix) == b''
