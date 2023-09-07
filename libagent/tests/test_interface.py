from ..device import interface
from ..formats import KeyFlags


def test_unicode():
    i = interface.Identity('ko\u017eu\u0161\u010dek@host', 'ed25519', KeyFlags.CERTIFY)
    assert i.to_bytes() == b'kozuscek@host'
    assert sorted(i.items()) == [('host', 'host'), ('index', 0), ('user', 'kozuscek')]
