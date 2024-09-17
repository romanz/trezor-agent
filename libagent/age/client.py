"""Device abstraction layer for AGE operations."""

import logging

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..device import interface

log = logging.getLogger(__name__)


def create_identity(user_id):
    """Create AGE identity for hardware device."""
    result = interface.Identity(identity_str='age://', curve_name="ed25519")
    result.identity_dict['host'] = user_id
    return result


class Client:
    """Sign messages and get public keys from a hardware device."""

    def __init__(self, ui):
        """C-tor."""
        self.ui = ui

    async def pubkey(self, identity, ecdh=False):
        """Return public key as VerifyingKey object."""
        async with self.ui.device() as device:
            pubkey = bytes(await device.pubkey(ecdh=ecdh, identity=identity))
            assert len(pubkey) == 32
            return pubkey

    async def ecdh(self, identity, peer_pubkey):
        """Derive shared secret using ECDH from peer public key."""
        log.info('please confirm AGE decryption on %s for "%s"...',
                 self.ui.get_device_name(), identity.to_string())
        async with self.ui.device() as device:
            assert len(peer_pubkey) == 32
            result, self_pubkey = await device.ecdh_with_pubkey(
                pubkey=(b"\x40" + peer_pubkey), identity=identity)
            assert result[:1] == b"\x04"
            hkdf = HKDF(
                 algorithm=hashes.SHA256(),
                 length=32,
                 salt=((peer_pubkey + self_pubkey)),
                 info=b"age-encryption.org/v1/X25519")
            return hkdf.derive(result[1:])
