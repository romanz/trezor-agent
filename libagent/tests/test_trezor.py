# pylint: disable=protected-access,redefined-outer-name
from unittest import mock

import pytest
from trezorlib.messages import Failure, FailureType
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


def mock_reconnect(monkeypatch, new_session=None, error=None):
    def get_default_client(**_):
        if error:
            raise error
        client = mock.Mock()
        client.features.passphrase_protection = False
        client.get_session.return_value = new_session
        return client
    monkeypatch.setattr(trezor, 'get_default_client', get_default_client)


def test_reconnect(device, monkeypatch):
    old_session, new_session = mock.Mock(), mock.Mock()
    trezor.Trezor._session = old_session
    mock_reconnect(monkeypatch, new_session=new_session)
    func = mock.Mock(side_effect=[OSError('no device'), 'ok'])
    assert device._call(func, retry=True, n=[1]) == 'ok'
    assert func.call_args_list == [mock.call(old_session, n=[1]), mock.call(new_session, n=[1])]
    assert trezor.Trezor._session is new_session


def test_reconnect_not_found(device, monkeypatch):
    trezor.Trezor._session = mock.Mock()
    mock_reconnect(monkeypatch, error=TransportException('No Trezor device found'))
    with pytest.raises(interface.NotFoundError):
        device._call(mock.Mock(side_effect=OSError('no device')), retry=True)
    assert trezor.Trezor._session is None


def test_retry_only_once(device, monkeypatch):
    trezor.Trezor._session = mock.Mock()
    mock_reconnect(monkeypatch, new_session=mock.Mock())
    func = mock.Mock(side_effect=OSError('no device'))
    with pytest.raises(interface.DeviceError):
        device._call(func, retry=True)
    assert func.call_count == 2
    assert trezor.Trezor._session is None


@pytest.mark.parametrize('error', [
    trezor.Cancelled(),
    interface.CancelledError('PIN entry cancelled'),
])
def test_no_retry_on_cancel(device, error):
    trezor.Trezor._session = mock.Mock()
    func = mock.Mock(side_effect=error)
    with pytest.raises(interface.CancelledError):
        device._call(func, retry=True)
    assert func.call_count == 1
    assert trezor.Trezor._session is None  # ask again for the passphrase


def test_cancel_on_device(device):
    session = mock.Mock()
    trezor.Trezor._session = session
    failure = trezor.TrezorFailure(Failure(code=FailureType.ActionCancelled, message='Cancelled'))
    with pytest.raises(interface.CancelledError):
        device._call(mock.Mock(side_effect=failure), retry=True)
    assert trezor.Trezor._session is session


def test_no_retry_for_signing(device):
    trezor.Trezor._session = mock.Mock()
    func = mock.Mock(side_effect=OSError('no device'))
    with pytest.raises(interface.DeviceError):
        device._call(func)
    assert func.call_count == 1
    assert trezor.Trezor._session is None  # but reconnect on the next call


def test_keep_session_on_device_failure(device):
    session = mock.Mock()
    trezor.Trezor._session = session
    failure = trezor.TrezorFailure(Failure(code=FailureType.ProcessError, message='oops'))
    with pytest.raises(interface.DeviceError):
        device._call(mock.Mock(side_effect=failure), retry=True)
    assert trezor.Trezor._session is session
