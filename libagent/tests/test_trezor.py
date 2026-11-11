# pylint: disable=protected-access,redefined-outer-name
from unittest import mock

import pytest
from trezorlib.transport import TransportException

from ..device import interface, trezor


@pytest.fixture
def device(monkeypatch):
    monkeypatch.setattr(trezor.Trezor, '_session', None)
    result = trezor.Trezor()
    result.ui = mock.Mock()
    return result


def test_not_found(device, monkeypatch):
    def get_default_client(**_):
        raise TransportException('No Trezor device found')
    monkeypatch.setattr(trezor, 'get_default_client', get_default_client)
    with pytest.raises(interface.NotFoundError):
        device._call(mock.Mock())
    assert trezor.Trezor._session is None


def test_reconnect_after_failure(device):
    old_session, new_session = mock.Mock(), mock.Mock()
    trezor.Trezor._session = old_session
    func = mock.Mock(side_effect=OSError('broken pipe'))
    with pytest.raises(interface.DeviceError):
        device._call(func, n=[1])
    func.assert_called_once_with(old_session, n=[1])
    assert trezor.Trezor._session is None  # next call will reconnect

    trezor.Trezor._session = new_session
    func = mock.Mock(return_value='ok')
    assert device._call(func, n=[1]) == 'ok'
    func.assert_called_once_with(new_session, n=[1])


def test_keep_session_on_device_failure(device):
    session = mock.Mock()
    trezor.Trezor._session = session
    func = mock.Mock(side_effect=trezor.TrezorFailure(mock.Mock()))
    with pytest.raises(trezor.TrezorFailure):
        device._call(func)
    assert trezor.Trezor._session is session
