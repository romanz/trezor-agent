"""TREZOR-related code (see https://trezor.io/)."""

import logging

from trezorlib.btc import get_public_node
from trezorlib.client import PassphraseSetting, get_default_client
from trezorlib.exceptions import (InvalidSessionError, TrezorException,
                                  TrezorFailure)
from trezorlib.messages import Capability, IdentityType
from trezorlib.misc import get_ecdh_session_key, sign_identity
from trezorlib.transport import TransportException

from .. import formats
from . import interface

log = logging.getLogger(__name__)


def _is_connection_error(e):
    """Errors of a stale session (e.g. USB errors), unlike PIN or cancellation errors."""
    if isinstance(e, TrezorException):
        return isinstance(e, (TransportException, InvalidSessionError))
    return True


class Trezor(interface.Device):
    """Connection to TREZOR device."""

    @classmethod
    def package_name(cls):
        """Python package name (at PyPI)."""
        return 'trezor-agent'

    required_version = '>=1.4.0'

    ui = None  # can be overridden by device's users
    _session = None  # cache one session per agent process

    @property
    def session(self):
        """Return cached session, or connect and pair if needed."""
        if self.__class__._session is None:
            assert self.ui is not None
            client = get_default_client(
                app_name="trezor-agent",
                pin_callback=self.ui.get_pin,
                code_entry_callback=self.ui.get_pairing_code,
            )
            if not client.features.unlocked:
                # Otherwise, some features are not available.
                client.ensure_unlocked()

            # If passphrase is enabled, allow entering it on the host.
            # If the entered passphrase is empty, enter it on the device (if supported).
            # Otherwise, open the default wallet with no passphrase.
            passphrase = PassphraseSetting.AUTO

            features = client.features
            if features.passphrase_protection:
                on_device = Capability.PassphraseEntry in features.capabilities
                if entered := self.ui.get_passphrase(on_device=on_device):
                    passphrase = entered

            session = client.get_session(passphrase=passphrase)
            log.info("%s @ fpr=%s", session, session.get_root_fingerprint().hex())
            self.__class__._session = session

        return self.__class__._session

    def connect(self):
        """One session is cached."""
        return self

    def close(self):
        """One session is cached."""
        pass

    def _call(self, func, retry=False, **kwargs):
        """Call trezorlib function with the cached session.

        On connection errors (e.g. after the device was re-plugged), the session is dropped.
        If `retry` is set, the call is retried once with a new session (asking again for PIN
        and passphrase).  Only use it for public keys: the new session may use a different
        passphrase, so its keys must be checked (by the caller) before signing.
        """
        had_session = self.__class__._session is not None
        try:
            return func(self.session, **kwargs)
        except TrezorFailure:
            raise  # the device has responded, so the session is still usable
        except Exception as e:
            self.__class__._session = None
            if retry and had_session and _is_connection_error(e):
                log.warning('%s connection lost (%r), reconnecting', self, e)
                return self._call(func, **kwargs)  # without session, so no further retry
            if isinstance(e, TransportException) and not had_session:
                raise interface.NotFoundError('{} not found: {}'.format(self, e)) from e
            raise interface.DeviceError('{} error: {!r}'.format(self, e)) from e

    def pubkey(self, identity, ecdh=False):
        """Return public key."""
        curve_name = identity.get_curve_name(ecdh=ecdh)
        log.debug('"%s" getting public key (%s) from %s',
                  identity.to_string(), curve_name, self)
        addr = identity.get_bip32_address(ecdh=ecdh)
        result = self._call(
            get_public_node,
            retry=True,
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
            result = self._call(
                sign_identity,
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
            result = self._call(
                get_ecdh_session_key,
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
