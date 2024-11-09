"""Device abstraction layer for GPG operations."""

import logging

from .. import formats, util
from ..device import interface

log = logging.getLogger(__name__)


def create_identity(user_id, curve_name):
    """Create GPG identity for hardware device."""
    result = interface.Identity(identity_str='gpg://', curve_name=curve_name)
    result.identity_dict['host'] = user_id
    return result


class Client:
    """Sign messages and get public keys from a hardware device."""

    def __init__(self, ui, options_getter=None):
        """C-tor."""
        self.ui = ui
        self.options_getter = options_getter

    async def pubkey(self, identity, ecdh=False):
        """Return public key as VerifyingKey object."""
        async with self.ui.device(self.options_getter) as device:
            return await device.pubkey(ecdh=ecdh, identity=identity)

    async def sign(self, identity, digest):
        """Sign the digest and return a serialized signature."""
        log.info('please confirm GPG signature on %s for "%s"...',
                 self.ui.get_device_name(), identity.to_string())
        if identity.curve_name == formats.CURVE_NIST256:
            digest = digest[:32]  # sign the first 256 bits
        log.debug('signing digest: %s', util.hexlify(digest))
        async with self.ui.device(self.options_getter) as device:
            sig = await device.sign(blob=digest, identity=identity)
        return (util.bytes2num(sig[:32]), util.bytes2num(sig[32:]))

    async def ecdh(self, identity, pubkey):
        """Derive shared secret using ECDH from remote public key."""
        log.info('please confirm GPG decryption on %s for "%s"...',
                 self.ui.get_device_name(), identity.to_string())
        async with self.ui.device(self.options_getter) as device:
            return await device.ecdh(pubkey=pubkey, identity=identity)
