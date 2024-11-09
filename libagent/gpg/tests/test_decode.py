import io
import pathlib

import pytest

from ... import util
from .. import decode, protocol


def test_subpackets():
    s = io.BytesIO(b'\x00\x05\x02\xAB\xCD\x01\xEF')
    assert decode.parse_subpackets(util.Reader(s)) == [b'\xAB\xCD', b'\xEF']


def test_subpackets_prefix():
    for n in [0, 1, 2, 4, 5, 10, 191, 192, 193,
              255, 256, 257, 8383, 8384, 65530]:
        item = b'?' * n  # create dummy subpacket
        prefixed = protocol.subpackets(item)
        result = decode.parse_subpackets(util.Reader(io.BytesIO(prefixed)))
        assert [item] == result


def test_mpi():
    s = io.BytesIO(b'\x00\x09\x01\x23')
    assert decode.parse_mpi(util.Reader(s)) == 0x123

    s = io.BytesIO(b'\x00\x09\x01\x23\x00\x03\x05')
    assert decode.parse_mpis(util.Reader(s), n=2) == [0x123, 5]


cwd = pathlib.Path(__file__).parent
input_files = cwd.glob('*.gpg')


@pytest.fixture(params=input_files)
def public_key_path(request):
    return request.param


def test_gpg_files(public_key_path):  # pylint: disable=redefined-outer-name
    with open(public_key_path, 'rb') as f:
        assert list(decode.parse_packets(f))
