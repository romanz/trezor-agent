import os
from unittest import mock

import pytest

from ... import util
from ...device import fake_device
from .. import agent, decode, keyring


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
