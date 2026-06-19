# pylint: disable=protected-access
import mock
import pytest

try:
    from ..device import trezor
except ImportError:  # trezorlib is an optional dependency of libagent
    trezor = None

pytestmark = pytest.mark.skipif(trezor is None, reason='requires trezorlib')


@pytest.fixture(autouse=True)
def reset_session_cache():
    """Reset the per-class session cache around each test."""
    if trezor is None:
        yield
        return
    cls = trezor.Trezor
    cls._session = cls._client = cls._idle_timer = None
    cls._idle_gen = 0
    cls.close_after_idle = None
    cls.ui = mock.Mock()
    yield
    if cls._idle_timer is not None:
        cls._idle_timer.cancel()
    cls._session = cls._client = cls._idle_timer = None
    cls.close_after_idle = None


def fake_client():
    client = mock.Mock()
    session = mock.Mock()
    session.get_root_fingerprint.return_value = b'\xab\xcd\xef\x01'
    client.get_session.return_value = session
    return client, session


def test_session_is_kept_by_default():
    trezor.Trezor.close_after_idle = None
    client, session = fake_client()
    with mock.patch.object(trezor, 'get_default_client', return_value=client) as get:
        device = trezor.Trezor()
        with device:
            assert device.session is session
        with device:  # a second operation reuses the cached session
            assert device.session is session
    assert get.call_count == 1
    assert trezor.Trezor._session is session
    assert not session.close.called
    assert not client.transport.close.called


def test_release_after_each_operation():
    trezor.Trezor.close_after_idle = 0
    client, session = fake_client()
    with mock.patch.object(trezor, 'get_default_client', return_value=client):
        device = trezor.Trezor()
        with device:
            assert device.session is session
    assert trezor.Trezor._session is None
    assert trezor.Trezor._client is None
    assert session.close.called
    assert client.transport.close.called


def test_release_survives_failures_when_closing():
    trezor.Trezor.close_after_idle = 0
    client, session = fake_client()
    session.close.side_effect = RuntimeError('boom')
    client.transport.close.side_effect = RuntimeError('boom')
    with mock.patch.object(trezor, 'get_default_client', return_value=client):
        device = trezor.Trezor()
        with device:
            assert device.session is session
    # even if the device errors while closing, the cache is cleared
    assert trezor.Trezor._session is None
    assert trezor.Trezor._client is None


def test_idle_timer_is_armed_then_cancelled_by_next_operation():
    trezor.Trezor.close_after_idle = 100
    client, session = fake_client()
    with mock.patch.object(trezor, 'get_default_client', return_value=client):
        device = trezor.Trezor()
        with device:
            assert device.session is session
        # close() armed a release but kept the session for now
        assert trezor.Trezor._idle_timer is not None
        assert trezor.Trezor._session is session
        # the next operation cancels the pending release
        device.connect()
        assert trezor.Trezor._idle_timer is None
        assert trezor.Trezor._session is session
    assert not client.transport.close.called


def test_idle_timeout_releases_the_session():
    trezor.Trezor.close_after_idle = 100
    client, session = fake_client()
    with mock.patch.object(trezor, 'get_default_client', return_value=client):
        device = trezor.Trezor()
        with device:
            assert device.session is session
        gen = trezor.Trezor._idle_gen
        trezor.Trezor._idle_timer.cancel()  # fire deterministically below
        trezor.Trezor._idle_timeout(gen)
    assert trezor.Trezor._session is None
    assert session.close.called
    assert client.transport.close.called


def test_stale_idle_timeout_is_ignored():
    trezor.Trezor.close_after_idle = 100
    client, session = fake_client()
    with mock.patch.object(trezor, 'get_default_client', return_value=client):
        device = trezor.Trezor()
        with device:
            assert device.session is session
        stale_gen = trezor.Trezor._idle_gen
        device.connect()  # cancels and bumps the generation
        # a timer that fired just before connect() must not release the session
        trezor.Trezor._idle_timeout(stale_gen)
    assert trezor.Trezor._session is session
    assert not session.close.called
