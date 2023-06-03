import binascii
import glob
import io
import pathlib
import os

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


def test_has_custom_subpacket():
    sig = {'unhashed_subpackets': []}
    assert not decode.has_custom_subpacket(sig)

    custom_markers = [
        protocol.CUSTOM_SUBPACKET,
        protocol.subpacket(10, protocol.CUSTOM_KEY_LABEL),
    ]
    for marker in custom_markers:
        sig = {'unhashed_subpackets': [marker]}
        assert decode.has_custom_subpacket(sig)


def test_load_by_keygrip_missing():
    with pytest.raises(KeyError):
        decode.load_by_keygrip(pubkey_bytes=b'', keygrip=b'')

def test_load_by_keygrip():
    # contrib/trezor_agent_recover.py --identity "test@example.com" --timestamp 0 --mnemonic "all all all all all all all all all all all all"
    with open(os.path.join(cwd, "49717CC09A348E5DAAF345903784A7264F609C5F.gpg"), 'rb') as f:

        # Primary Key
        p_kg = binascii.unhexlify("930E34F72D88B9BF4FA5372D7ED493D0DC738DAD")
        data, uids, keyflag = decode.load_by_keygrip(f.read(), p_kg)
        f.seek(0)

        assert data['keygrip'] == p_kg
        assert keyflag == 1

        # Signing Subkey
        s_kg = binascii.unhexlify("94F380990548D9644271F149D4FDF0D808F54127")
        data, uids, keyflag = decode.load_by_keygrip(f.read(), s_kg)
        f.seek(0)

        assert data['keygrip'] == s_kg
        assert keyflag == 2

        # Authentication Subkey
        a_kg = binascii.unhexlify("4D2EB4C79914B876AAFA941C7FB51B72E4D348BD")
        data, uids, keyflag = decode.load_by_keygrip(f.read(), a_kg)
        f.seek(0)

        assert data['keygrip'] == a_kg
        assert keyflag == 32 # 0x20

        # Encryption Subkey
        e_kg = binascii.unhexlify("CCAB28DB355C0993CF6E6F994066B08A7F873127")
        data, uids, keyflag = decode.load_by_keygrip(f.read(), e_kg)
        f.seek(0)

        assert data['keygrip'] == e_kg
        assert keyflag == 12 # 0x4 | 0x8


def test_keygrips():
    pubkey_bytes = (cwd / "romanz-pubkey.gpg").open("rb").read()
    keygrips = list(decode.iter_keygrips(pubkey_bytes))
    assert [k.hex() for k in keygrips] == [
        '7b2497258d76bc6539ed88d018cd1c739e2dbb6c',
        '30ae97f3d8e0e34c5ed80e1715fd442ca24c0a8e',
    ]

    for keygrip in keygrips:
        pubkey_dict, user_ids, keyflag = decode.load_by_keygrip(pubkey_bytes, keygrip)
        assert pubkey_dict['keygrip'] == keygrip
        assert [u['value'] for u in user_ids] == [
            b'Roman Zeyde <roman.zeyde@gmail.com>',
            b'Roman Zeyde <me@romanzey.de>',
        ]
