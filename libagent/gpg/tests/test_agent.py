import functools
import os
from unittest import mock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ... import formats, util
from ...device import fake_device, interface
from .. import agent, client, decode, encode, keyring, protocol


def test_sig_encode():
    SIG = (
        b'(7:sig-val(5:ecdsa(1:r32:\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x0c)(1:s32:\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00")))')
    assert agent.sig_encode(12, 34) == SIG


def test_pksign_wrong_key(monkeypatch, caplog):
    monkeypatch.setattr(keyring, 'gpg_version', lambda: b'2.4.7')
    device = fake_device.FakeDevice()
    device.ui = mock.Mock()
    path = os.path.join(os.path.dirname(__file__), 'A4EB142E5FC2C898BAEC2C9B2BA8930D2B320C62.gpg')
    with open(path, 'rb') as f:
        handler = agent.Handler(device=device, pubkey_bytes=f.read())

    keygrip = next(decode.iter_keygrips(handler.pubkey_bytes))
    handler.set_key(util.hexlify(keygrip).encode('ascii'))
    with pytest.raises(agent.AgentError) as e:
        handler.pksign(conn=None)
    assert e.value.args == (b'ERR 67108881 No secret key <GPG Agent>',)
    assert '"nist256p-test" (nist256p1) - wrong passphrase' in caplog.text


@pytest.mark.parametrize('error, reply', [
    (interface.NotFoundError('not found'), b'ERR 67108976 Card not present <GPG Agent>'),
    (interface.DeviceError('broken pipe'), b'ERR 67108972 Card error <GPG Agent>'),
])
def test_device_error(monkeypatch, error, reply):
    monkeypatch.setattr(keyring, 'gpg_version', lambda: b'2.4.7')
    device = fake_device.FakeDevice()
    device.ui = mock.Mock()
    handler = agent.Handler(device=device, pubkey_bytes=b'')

    def fail(*_):
        raise error
    handler.handlers[b'PKSIGN'] = fail
    sent = []
    monkeypatch.setattr(keyring, 'iterlines', lambda conn: iter([b'PKSIGN']))
    monkeypatch.setattr(keyring, 'sendline', lambda conn, msg, **_: sent.append(msg))
    handler.handle(conn=None)
    assert sent == [b'OK', reply]


def test_pksign_after_device_key_changed(monkeypatch):
    """Simulates a reconnect with a different passphrase (i.e. wallet)."""
    monkeypatch.setattr(keyring, 'gpg_version', lambda: b'2.4.7')
    monkeypatch.setattr(keyring, 'sendline', lambda conn, msg, **_: None)
    device = fake_device.FakeDevice()
    device.ui = mock.Mock()
    gpg_client = client.Client(device)
    identity = client.create_identity('test', formats.CURVE_NIST256)
    pubkey = protocol.PublicKey(curve_name=formats.CURVE_NIST256, created=1,
                                verifying_key=gpg_client.pubkey(identity), ecdh=False)
    pubkey_bytes = encode.create_primary(
        'test', pubkey, signer_func=functools.partial(gpg_client.sign, identity=identity))
    handler = agent.Handler(device=device, pubkey_bytes=pubkey_bytes)
    handler.set_key(util.hexlify(pubkey.keygrip()).encode('ascii'))
    handler.set_hash(b'8', b'00' * 32)
    handler.pksign(conn=None)  # matching key

    other = ec.derive_private_key(2, ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
    other_key = formats.decompress_pubkey(pubkey=other, curve_name=formats.CURVE_NIST256)
    monkeypatch.setattr(device, 'pubkey', lambda identity, ecdh=False: other_key)
    with pytest.raises(agent.AgentError) as e:
        handler.pksign(conn=None)
    assert e.value.args == (b'ERR 67108881 No secret key <GPG Agent>',)
