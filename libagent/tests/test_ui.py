import io
from unittest import mock

import pytest

from ..device import interface, ui


def pinentry(line):
    p = mock.Mock()
    p.stdout = io.BytesIO(line)
    return p


def test_expect():
    assert ui.expect(pinentry(b'D 1234\n'), [b'OK', b'D ']) == b'1234\n'


def test_expect_cancelled():
    p = pinentry(b'ERR 83886179 Operation cancelled <Pinentry>\n')
    with pytest.raises(interface.CancelledError):
        ui.expect(p, [b'OK', b'D '])


def test_expect_unexpected():
    with pytest.raises(ui.UnexpectedError):
        ui.expect(pinentry(b'ERR 83886254 Not implemented <Pinentry>\n'), [b'OK'])
