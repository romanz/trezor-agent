"""Device abstraction layer for AGE operations."""

import logging

from .. import formats, util
from ..device import interface

log = logging.getLogger(__name__)


def create_identity(user_id):
    """Create AGE identity for hardware device."""
    result = interface.Identity(identity_str='age://', curve_name="ed25519")
    result.identity_dict['host'] = user_id
    return result


class Client:
    """Sign messages and get public keys from a hardware device."""

    def __init__(self, device):
        """C-tor."""
        self.device = device

    def pubkey(self, identity, ecdh=False):
        """Return public key as VerifyingKey object."""
        with self.device:
            pubkey = self.device.pubkey(ecdh=ecdh, identity=identity)
            return bytes(pubkey)

    def ecdh(self, identity, pubkey):
        """Derive shared secret using ECDH from remote public key."""
        log.info('please confirm GPG decryption on %s for "%s"...',
                 self.device, identity.to_string())
        with self.device:
            result = self.device.ecdh(pubkey=pubkey, identity=identity)
            assert result[:1] == b"\x04"
            return result[1:]
