"""Simulator for a hardware wallet device."""

import hashlib
import hmac
import logging

import ecdsa
import ecdsa.ecdh
import nacl.bindings
import nacl.public
import nacl.signing
from mnemonic import Mnemonic

from .. import formats, util
from . import interface

log = logging.getLogger(__name__)


class _CurveNist256p1:
    @classmethod
    def get_seed(cls):
        return b'Nist256p1 seed'

    @classmethod
    def get_order(cls):
        return ecdsa.curves.NIST256p.order

    def __init__(self, key_bytes):
        self.signing_key = ecdsa.SigningKey.from_string(
            key_bytes,
            curve=ecdsa.curves.NIST256p,
            hashfunc=hashlib.sha256
        )

    def get_public_key(self):
        return self.PublicKey(self.signing_key.verifying_key)

    def sign(self, data):
        return self.signing_key.sign_digest_deterministic(digest=data,
                                                          hashfunc=hashlib.sha256)

    def ecdh(self, public_key):
        peer = formats.decompress_pubkey(public_key, formats.CURVE_NIST256)
        return b'\x04' + (
            peer.pubkey.point
            * self.signing_key.privkey.secret_multiplier
        ).to_bytes('raw')

    class PublicKey:
        def __init__(self, verifying_key):
            self.verifying_key = verifying_key

        def get_bytes(self):
            return self.verifying_key.to_string('compressed')

        def get_raw(self):
            return self.verifying_key


class _Ed25519:
    @classmethod
    def get_seed(cls):
        return b'ed25519 seed'

    @classmethod
    def get_order(cls):
        return None

    def __init__(self, key_bytes):
        self.signing_key = nacl.signing.SigningKey(key_bytes)

    def get_public_key(self):
        return self.PublicKey(self.signing_key.verify_key)

    def sign(self, data):
        return self.signing_key.sign(data).signature

    def ecdh(self, public_key):
        assert len(public_key) == 33
        return b'\x04' + nacl.bindings.crypto_scalarmult(
            bytes(self.signing_key.to_curve25519_private_key()), public_key)

    class PublicKey:
        def __init__(self, verify_key):
            self.verify_key = verify_key

        def get_bytes(self):
            return bytes(self.verify_key)

        def get_raw(self):
            return self.verify_key


class _Curve25519:
    @classmethod
    def get_seed(cls):
        return b'curve25519 seed'

    @classmethod
    def get_order(cls):
        return None

    def __init__(self, key_bytes):
        self.private_key = nacl.public.PrivateKey(key_bytes)

    def get_public_key(self):
        return self.PublicKey(nacl.signing.VerifyKey(bytes(self.private_key.public_key)))

    def sign(self, data):
        # Signing not supported
        raise NotImplementedError()

    def ecdh(self, public_key):
        assert len(public_key) == 33
        return b'\x04' + nacl.bindings.crypto_scalarmult(bytes(self.private_key), public_key[1:])

    class PublicKey:
        def __init__(self, verify_key):
            self.verify_key = verify_key

        def get_bytes(self):
            return bytes(self.verify_key)

        def get_raw(self):
            return self.verify_key


SUPPORTED_CURVES = {
    formats.CURVE_NIST256: _CurveNist256p1,
    formats.CURVE_ED25519: _Ed25519,
    formats.ECDH_CURVE25519: _Curve25519,
}


def _derive_key(seed, identity, ecdh):
    curve = SUPPORTED_CURVES[identity.get_curve_name(ecdh)]
    curve_order = curve.get_order()
    curve_seed = curve.get_seed()
    address = identity.get_bip32_address(ecdh)

    digest = hmac.new(curve_seed, seed, hashlib.sha512).digest()
    privkey_bytes = digest[:32]
    privkey = util.bytes2num(privkey_bytes)
    if curve_order is not None:
        while privkey == 0 or privkey >= curve_order:
            digest = hmac.new(curve_seed, digest, hashlib.sha512).digest()
            privkey = util.bytes2num(digest[:32])
    chain = digest[32:]

    for index in address:
        index_bytes = index.to_bytes(4, 'big')
        if index >= 0x80000000:
            data = b'\x00' + privkey_bytes
        else:
            data = curve(privkey_bytes).get_public_key().get_bytes()
        if curve_order is None:
            data += index_bytes
            digest = hmac.new(chain, data, hashlib.sha512).digest()
            privkey_bytes = digest[:32]
            privkey = util.bytes2num(privkey_bytes)
            chain = digest[32:]
        else:
            while True:
                data += index_bytes
                digest = hmac.new(chain, data, hashlib.sha512).digest()

                child_privkey = util.bytes2num(digest[:32])
                if child_privkey < curve_order:
                    child_privkey = (child_privkey + privkey) % curve_order
                    if child_privkey != 0:
                        privkey = child_privkey
                        privkey_bytes = util.num2bytes(privkey, size=32)
                        chain = digest[32:]
                        break

                data = b'\x01' + digest[32:]

    return curve(privkey_bytes)


class Simulator(interface.Device):
    """Simulator for a hardware wallet device."""

    @classmethod
    def package_name(cls):
        """Python package name."""
        return 'simulator-agent'

    @classmethod
    def setup_arg_parser(cls, parser):
        """Add device-specific parameters to the argument parser."""
        log.critical('This simulator is NOT a replacement for a real hardware device.')
        log.critical('There are a thousand ways a hacker could steal the mnemonic you enter.')
        log.critical('Only use for testing, or for assets you can afford to lose.')
        parser.add_argument('--mnemonic', default=None,
                            help='the mnemonic phrase to generate the master seed')
        parser.add_argument('--passphrase', default=None,
                            help='the passphrase to a hidden wallet')
        parser.add_argument('--no-passphrase', default=False, action='store_true',
                            help='use a blank passphrase')

    ui = None  # can be overridden by device's users

    def __init__(self, args):
        """C-tor."""
        super().__init__(args)
        self.seed = None

    def connect(self):
        """Request mnemonic from user, after giving ample warning."""
        mnemonic = self.args.mnemonic
        passphrase = self.args.passphrase
        if mnemonic is None:
            mnemonic = self.ui.get_passphrase('Enter your mnemonic:',
                                              description='WARNING: Do NOT use the '
                                              'simulator with a real '
                                              'wallet\'s mnemonic!\n'
                                              'It is NOT secure, and your '
                                              'mnemonic WILL be stolen!\n')
        if passphrase is None and self.args.no_passphrase:
            passphrase = ''
        if passphrase is None:
            passphrase = (self.ui.get_passphrase('Enter your passphrase',
                                                 description='Leave blank for the default wallet'))

        self.seed = Mnemonic.to_seed(mnemonic, passphrase)

    def close(self):
        """Close the device."""

    def pubkey(self, identity, ecdh=False):
        """Get public key (as bytes)."""
        return _derive_key(self.seed, identity, ecdh).get_public_key().get_raw()

    def sign(self, identity, blob):
        """Sign given blob and return the signature (as bytes)."""
        if identity.identity_dict['proto'] in {'ssh'}:
            digest = hashlib.sha256(blob).digest()
        else:
            digest = blob
        return _derive_key(self.seed, identity, False).sign(digest)

    def ecdh(self, identity, pubkey):
        """Get shared session key using Elliptic Curve Diffie-Hellman."""
        return _derive_key(self.seed, identity, True).ecdh(pubkey)
