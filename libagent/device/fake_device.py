"""Fake device - ONLY FOR TESTS!!! (NEVER USE WITH REAL DATA)."""

import hashlib
import logging

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from .. import formats, util
from . import interface

log = logging.getLogger(__name__)


def _verify_support(identity):
    """Make sure the device supports given configuration."""
    if identity.curve_name not in {formats.CURVE_NIST256}:
        raise NotImplementedError(
            'Unsupported elliptic curve: {}'.format(identity.curve_name))


class FakeDevice(interface.Device):
    """Connection to TREZOR device."""

    @classmethod
    def package_name(cls):
        """Python package name."""
        return 'fake-device-agent'

    def connect(self):
        """Return "dummy" connection."""
        log.critical('NEVER USE THIS CODE FOR REAL-LIFE USE-CASES!!!')
        log.critical('ONLY FOR DEBUGGING AND TESTING!!!')
        # The code below uses HARD-CODED secret key - and should be used ONLY
        # for GnuPG integration tests (e.g. when no real device is available).
        # pylint: disable=attribute-defined-outside-init
        self.sk = ec.derive_private_key(1, ec.SECP256R1())
        self.vk = self.sk.public_key()
        return self

    def close(self):
        """Close the device."""

    def pubkey(self, identity, ecdh=False):
        """Return public key."""
        _verify_support(identity)
        pubkey = self.vk.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.CompressedPoint,
        )
        return formats.decompress_pubkey(pubkey=pubkey, curve_name=identity.curve_name)

    def sign(self, identity, blob):
        """Sign given blob and return the signature (as bytes)."""
        if identity.identity_dict['proto'] in {'ssh'}:
            digest = hashlib.sha256(blob).digest()
        else:
            digest = blob
        signature = self.sk.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        r, s = utils.decode_dss_signature(signature)
        return util.num2bytes(r, size=32) + util.num2bytes(s, size=32)

    def ecdh(self, identity, pubkey):
        """Get shared session key using Elliptic Curve Diffie-Hellman."""
        assert pubkey[:1] == b'\x04'
        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pubkey)
        # The fixed fake private scalar is one, so the shared point equals the peer point.
        return peer.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )[1:]
