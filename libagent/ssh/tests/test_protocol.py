import pytest

from .. import device, formats, protocol

# pylint: disable=line-too-long

NIST256_KEY = 'ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEUksojS/qRlTKBKLQO7CBX7a7oqFkysuFn1nJ6gzlR3wNuQXEgd7qb2bjmiiBHsjNxyWvH5SxVi3+fghrqODWo= ssh://localhost'  # nopep8
NIST256_BLOB = b'\x00\x00\x00 !S^\xe7\xf8\x1cKN\xde\xcbo\x0c\x83\x9e\xc48\r\xac\xeb,]"\xc1\x9bA\x0eit\xc1\x81\xd4E2\x00\x00\x00\x05roman\x00\x00\x00\x0essh-connection\x00\x00\x00\tpublickey\x01\x00\x00\x00\x13ecdsa-sha2-nistp256\x00\x00\x00h\x00\x00\x00\x13ecdsa-sha2-nistp256\x00\x00\x00\x08nistp256\x00\x00\x00A\x04E$\xb2\x88\xd2\xfe\xa4eL\xa0J-\x03\xbb\x08\x15\xfbk\xba*\x16L\xac\xb8Y\xf5\x9c\x9e\xa0\xceTw\xc0\xdb\x90\\H\x1d\xee\xa6\xf6n9\xa2\x88\x11\xec\x8c\xdcrZ\xf1\xf9K\x15b\xdf\xe7\xe0\x86\xba\x8e\rj'  # nopep8
NIST256_SIG = b'\x88G!\x0c\n\x16:\xbeF\xbe\xb9\xd2\xa9&e\x89\xad\xc4}\x10\xf8\xbc\xdc\xef\x0e\x8d_\x8a6.\xb6\x1fq\xf0\x16>,\x9a\xde\xe7(\xd6\xd7\x93\x1f\xed\xf9\x94ddw\xfe\xbdq\x13\xbb\xfc\xa9K\xea\x9dC\xa1\xe9'  # nopep8

LIST_MSG = b'\x0b'
LIST_NIST256_REPLY = b'\x00\x00\x00\x84\x0c\x00\x00\x00\x01\x00\x00\x00h\x00\x00\x00\x13ecdsa-sha2-nistp256\x00\x00\x00\x08nistp256\x00\x00\x00A\x04E$\xb2\x88\xd2\xfe\xa4eL\xa0J-\x03\xbb\x08\x15\xfbk\xba*\x16L\xac\xb8Y\xf5\x9c\x9e\xa0\xceTw\xc0\xdb\x90\\H\x1d\xee\xa6\xf6n9\xa2\x88\x11\xec\x8c\xdcrZ\xf1\xf9K\x15b\xdf\xe7\xe0\x86\xba\x8e\rj\x00\x00\x00\x0fssh://localhost'  # nopep8

NIST256_SIGN_MSG = b'\r\x00\x00\x00h\x00\x00\x00\x13ecdsa-sha2-nistp256\x00\x00\x00\x08nistp256\x00\x00\x00A\x04E$\xb2\x88\xd2\xfe\xa4eL\xa0J-\x03\xbb\x08\x15\xfbk\xba*\x16L\xac\xb8Y\xf5\x9c\x9e\xa0\xceTw\xc0\xdb\x90\\H\x1d\xee\xa6\xf6n9\xa2\x88\x11\xec\x8c\xdcrZ\xf1\xf9K\x15b\xdf\xe7\xe0\x86\xba\x8e\rj\x00\x00\x00\xd1\x00\x00\x00 !S^\xe7\xf8\x1cKN\xde\xcbo\x0c\x83\x9e\xc48\r\xac\xeb,]"\xc1\x9bA\x0eit\xc1\x81\xd4E2\x00\x00\x00\x05roman\x00\x00\x00\x0essh-connection\x00\x00\x00\tpublickey\x01\x00\x00\x00\x13ecdsa-sha2-nistp256\x00\x00\x00h\x00\x00\x00\x13ecdsa-sha2-nistp256\x00\x00\x00\x08nistp256\x00\x00\x00A\x04E$\xb2\x88\xd2\xfe\xa4eL\xa0J-\x03\xbb\x08\x15\xfbk\xba*\x16L\xac\xb8Y\xf5\x9c\x9e\xa0\xceTw\xc0\xdb\x90\\H\x1d\xee\xa6\xf6n9\xa2\x88\x11\xec\x8c\xdcrZ\xf1\xf9K\x15b\xdf\xe7\xe0\x86\xba\x8e\rj\x00\x00\x00\x00'  # nopep8
NIST256_SIGN_REPLY = b'\x00\x00\x00j\x0e\x00\x00\x00e\x00\x00\x00\x13ecdsa-sha2-nistp256\x00\x00\x00J\x00\x00\x00!\x00\x88G!\x0c\n\x16:\xbeF\xbe\xb9\xd2\xa9&e\x89\xad\xc4}\x10\xf8\xbc\xdc\xef\x0e\x8d_\x8a6.\xb6\x1f\x00\x00\x00!\x00q\xf0\x16>,\x9a\xde\xe7(\xd6\xd7\x93\x1f\xed\xf9\x94ddw\xfe\xbdq\x13\xbb\xfc\xa9K\xea\x9dC\xa1\xe9'  # nopep8


class FakeConnection:
    def __init__(self, keys, signer):
        self.keys = keys
        self.signer = signer

    async def parse_public_keys(self):
        return self.keys

    async def sign(self, blob, identity):
        if self.signer:
            return self.signer(blob=blob, identity=identity)
        return b''


@pytest.mark.trio
async def test_list():
    key = formats.import_public_key(NIST256_KEY)
    key['identity'] = device.interface.Identity('ssh://localhost', 'nist256p1')
    h = protocol.Handler(FakeConnection(keys=[key], signer=None))
    reply = await h.handle(LIST_MSG)
    assert reply == LIST_NIST256_REPLY


@pytest.mark.trio
async def test_list_legacy_pubs_with_suffix():
    h = protocol.Handler(FakeConnection(keys=[], signer=None))
    suffix = b'\x00\x00\x00\x06foobar'
    reply = await h.handle(b'\x01' + suffix)
    assert reply == b'\x00\x00\x00\x05\x02\x00\x00\x00\x00'  # no legacy keys


@pytest.mark.trio
async def test_unsupported():
    h = protocol.Handler(FakeConnection(keys=[], signer=None))
    reply = await h.handle(b'\x09')
    assert reply == b'\x00\x00\x00\x01\x05'


def ecdsa_signer(identity, blob):
    assert identity.to_string() == '<ssh://localhost|nist256p1>'
    assert blob == NIST256_BLOB
    return NIST256_SIG


@pytest.mark.trio
async def test_ecdsa_sign():
    key = formats.import_public_key(NIST256_KEY)
    key['identity'] = device.interface.Identity('ssh://localhost', 'nist256p1')
    h = protocol.Handler(FakeConnection(keys=[key], signer=ecdsa_signer))
    reply = await h.handle(NIST256_SIGN_MSG)
    assert reply == NIST256_SIGN_REPLY


@pytest.mark.trio
async def test_sign_missing():
    h = protocol.Handler(FakeConnection(keys=[], signer=ecdsa_signer))
    with pytest.raises(KeyError):
        await h.handle(NIST256_SIGN_MSG)


@pytest.mark.trio
async def test_sign_wrong():
    def wrong_signature(identity, blob):
        assert identity.to_string() == '<ssh://localhost|nist256p1>'
        assert blob == NIST256_BLOB
        return b'\x00' * 64

    key = formats.import_public_key(NIST256_KEY)
    key['identity'] = device.interface.Identity('ssh://localhost', 'nist256p1')
    h = protocol.Handler(FakeConnection(keys=[key], signer=wrong_signature))
    with pytest.raises(ValueError):
        await h.handle(NIST256_SIGN_MSG)


@pytest.mark.trio
async def test_sign_cancel():
    def cancel_signature(identity, blob):  # pylint: disable=unused-argument
        raise IOError()

    key = formats.import_public_key(NIST256_KEY)
    key['identity'] = device.interface.Identity('ssh://localhost', 'nist256p1')
    h = protocol.Handler(FakeConnection(keys=[key], signer=cancel_signature))
    assert await h.handle(NIST256_SIGN_MSG) == protocol.failure()


ED25519_KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFBdF2tjfSO8nLIi736is+f0erq28RTc7CkM11NZtTKR ssh://localhost'  # nopep8
ED25519_SIGN_MSG = b'''\r\x00\x00\x003\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 P]\x17kc}#\xbc\x9c\xb2"\xef~\xa2\xb3\xe7\xf4z\xba\xb6\xf1\x14\xdc\xec)\x0c\xd7SY\xb52\x91\x00\x00\x00\x94\x00\x00\x00 i3\xae}yk\\\xa1L\xb9\xe1\xbf\xbc\x8e\x87\r\x0e\xc0\x9f\x97\x0fTC!\x80\x07\x91\xdb^8\xc1\xd62\x00\x00\x00\x05roman\x00\x00\x00\x0essh-connection\x00\x00\x00\tpublickey\x01\x00\x00\x00\x0bssh-ed25519\x00\x00\x003\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 P]\x17kc}#\xbc\x9c\xb2"\xef~\xa2\xb3\xe7\xf4z\xba\xb6\xf1\x14\xdc\xec)\x0c\xd7SY\xb52\x91\x00\x00\x00\x00'''  # nopep8
ED25519_SIGN_REPLY = b'''\x00\x00\x00X\x0e\x00\x00\x00S\x00\x00\x00\x0bssh-ed25519\x00\x00\x00@\x8eb)\xa6\xe9P\x83VE\xfbq\xc6\xbf\x1dV3\xe3<O\x11\xc0\xfa\xe4\xed\xb8\x81.\x81\xc8\xa6\xba\x10RA'a\xbc\xa9\xd3\xdb\x98\x07\xf0\x1a\x9c4\x84<\xaf\x99\xb7\xe5G\xeb\xf7$\xc1\r\x86f\x16\x8e\x08\x05'''  # nopep8

ED25519_BLOB = b'''\x00\x00\x00 i3\xae}yk\\\xa1L\xb9\xe1\xbf\xbc\x8e\x87\r\x0e\xc0\x9f\x97\x0fTC!\x80\x07\x91\xdb^8\xc1\xd62\x00\x00\x00\x05roman\x00\x00\x00\x0essh-connection\x00\x00\x00\tpublickey\x01\x00\x00\x00\x0bssh-ed25519\x00\x00\x003\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 P]\x17kc}#\xbc\x9c\xb2"\xef~\xa2\xb3\xe7\xf4z\xba\xb6\xf1\x14\xdc\xec)\x0c\xd7SY\xb52\x91'''  # nopep8
ED25519_SIG = b'''\x8eb)\xa6\xe9P\x83VE\xfbq\xc6\xbf\x1dV3\xe3<O\x11\xc0\xfa\xe4\xed\xb8\x81.\x81\xc8\xa6\xba\x10RA'a\xbc\xa9\xd3\xdb\x98\x07\xf0\x1a\x9c4\x84<\xaf\x99\xb7\xe5G\xeb\xf7$\xc1\r\x86f\x16\x8e\x08\x05'''  # nopep8


def ed25519_signer(identity, blob):
    assert identity.to_string() == '<ssh://localhost|ed25519>'
    assert blob == ED25519_BLOB
    return ED25519_SIG


@pytest.mark.trio
async def test_ed25519_sign():
    key = formats.import_public_key(ED25519_KEY)
    key['identity'] = device.interface.Identity('ssh://localhost', 'ed25519')
    h = protocol.Handler(FakeConnection(keys=[key], signer=ed25519_signer))
    reply = await h.handle(ED25519_SIGN_MSG)
    assert reply == ED25519_SIGN_REPLY
