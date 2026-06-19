"""TREZOR-related code (see http://bitcointrezor.com/)."""

import logging
import threading

from trezorlib.btc import get_public_node
from trezorlib.client import PassphraseSetting, get_default_client
from trezorlib.exceptions import TrezorFailure
from trezorlib.messages import IdentityType
from trezorlib.misc import get_ecdh_session_key, sign_identity

from .. import formats
from . import interface

log = logging.getLogger(__name__)


class Trezor(interface.Device):
    """Connection to TREZOR device."""

    @classmethod
    def package_name(cls):
        """Python package name (at PyPI)."""
        return 'trezor-agent'

    required_version = '>=1.4.0'

    ui = None  # can be overridden by device's users
    _session = None  # cache one session per agent process
    _client = None  # the owning TrezorClient (holds the USB transport)
    _lock = threading.RLock()  # guards the cached session/client and the timer
    _idle_timer = None  # threading.Timer that releases the session when idle
    _idle_gen = 0  # bumped on every (re)arm/cancel to invalidate stale timers

    @property
    def session(self):
        """Return cached session, or connect and pair if needed."""
        return self._get_session()

    @classmethod
    def _get_session(cls):
        with cls._lock:
            if cls._session is None:
                assert cls.ui is not None
                client = get_default_client(
                    app_name="trezor-agent",
                    pin_callback=cls.ui.get_pin,
                    code_entry_callback=cls.ui.get_pairing_code,
                )
                session = client.get_session(passphrase=PassphraseSetting.AUTO)
                log.info("%s @ fpr=%s", session, session.get_root_fingerprint().hex())
                cls._client = client
                cls._session = session

            return cls._session

    def connect(self):
        """Reuse the cached session, cancelling any pending idle release."""
        self._cancel_idle_timer()
        return self

    def close(self):
        """Release the cached session, immediately or after an idle delay.

        Controlled by ``close_after_idle`` (see ``interface.Device``):
        ``None`` keeps the session for the whole process (the default and the
        historical behavior), ``0`` releases it after every operation, and
        ``N > 0`` releases it after ``N`` seconds of inactivity. Releasing the
        session frees the device for other applications between operations.
        """
        idle = self.close_after_idle
        if idle is None:
            return
        if idle <= 0:
            self._release_session()
        else:
            self._arm_idle_timer(idle)

    @classmethod
    def _cancel_idle_timer(cls):
        with cls._lock:
            cls._idle_gen += 1
            if cls._idle_timer is not None:
                cls._idle_timer.cancel()
                cls._idle_timer = None

    @classmethod
    def _arm_idle_timer(cls, idle):
        with cls._lock:
            cls._idle_gen += 1
            gen = cls._idle_gen
            if cls._idle_timer is not None:
                cls._idle_timer.cancel()
            timer = threading.Timer(idle, cls._idle_timeout, args=(gen,))
            timer.daemon = True
            cls._idle_timer = timer
            timer.start()

    @classmethod
    def _idle_timeout(cls, gen):
        with cls._lock:
            # A new operation may have cancelled/re-armed us after the timer
            # fired but before it took the lock: only act if still current.
            if gen != cls._idle_gen:
                return
            cls._idle_timer = None
            cls._release_session()

    @classmethod
    def _release_session(cls):
        """Close the cached session and release the USB transport, if any."""
        with cls._lock:
            cls._idle_gen += 1
            if cls._idle_timer is not None:
                cls._idle_timer.cancel()
                cls._idle_timer = None
            session, client = cls._session, cls._client
            cls._session = None
            cls._client = None
            if session is None and client is None:
                return
            if session is not None:
                try:
                    session.close()
                except Exception as e:  # pylint: disable=broad-except
                    log.debug("ending device session failed: %s", e)
            if client is not None:
                try:
                    client.transport.close()
                except Exception as e:  # pylint: disable=broad-except
                    log.debug("closing device transport failed: %s", e)
            log.info("released cached device session")

    def pubkey(self, identity, ecdh=False):
        """Return public key."""
        curve_name = identity.get_curve_name(ecdh=ecdh)
        log.debug('"%s" getting public key (%s) from %s',
                  identity.to_string(), curve_name, self)
        addr = identity.get_bip32_address(ecdh=ecdh)
        result = get_public_node(
            self.session,
            n=addr,
            ecdsa_curve_name=curve_name)
        log.debug('result: %s', result)
        pubkey = bytes(result.node.public_key)
        return formats.decompress_pubkey(pubkey=pubkey, curve_name=identity.curve_name)

    def _identity_proto(self, identity):
        result = IdentityType()
        for name, value in identity.items():
            setattr(result, name, value)
        return result

    def sign(self, identity, blob):
        """Sign given blob and return the signature (as bytes)."""
        sig, _ = self.sign_with_pubkey(identity, blob)
        return sig

    def sign_with_pubkey(self, identity, blob):
        """Sign given blob and return the signature (as bytes)."""
        curve_name = identity.get_curve_name(ecdh=False)
        log.debug('"%s" signing %r (%s) on %s',
                  identity.to_string(), blob, curve_name, self)
        try:
            result = sign_identity(
                self.session,
                identity=self._identity_proto(identity),
                challenge_hidden=blob,
                challenge_visual='',
                ecdsa_curve_name=curve_name)
            log.debug('result: %s', result)
            assert len(result.signature) == 65
            assert result.signature[:1] == b'\x00'
            return bytes(result.signature[1:]), bytes(result.public_key)
        except TrezorFailure as e:
            msg = '{} error: {}'.format(self, e)
            log.debug(msg, exc_info=True)
            raise interface.DeviceError(msg)

    def ecdh(self, identity, pubkey):
        """Get shared session key using Elliptic Curve Diffie-Hellman."""
        session_key, _ = self.ecdh_with_pubkey(identity, pubkey)
        return session_key

    def ecdh_with_pubkey(self, identity, pubkey):
        """Get shared session key using Elliptic Curve Diffie-Hellman & self public key."""
        curve_name = identity.get_curve_name(ecdh=True)
        log.debug('"%s" shared session key (%s) for %r from %s',
                  identity.to_string(), curve_name, pubkey, self)
        try:
            result = get_ecdh_session_key(
                self.session,
                identity=self._identity_proto(identity),
                peer_public_key=pubkey,
                ecdsa_curve_name=curve_name)
            log.debug('result: %s', result)
            assert len(result.session_key) in {65, 33}  # NIST256 or Curve25519
            assert result.session_key[:1] == b'\x04'
            self_pubkey = result.public_key
            if self_pubkey:
                self_pubkey = bytes(self_pubkey[1:])

            return bytes(result.session_key), self_pubkey
        except TrezorFailure as e:
            msg = '{} error: {}'.format(self, e)
            log.debug(msg, exc_info=True)
            raise interface.DeviceError(msg)
