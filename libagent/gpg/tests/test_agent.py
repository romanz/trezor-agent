import hashlib

from cryptography.hazmat.primitives.keywrap import aes_key_wrap

from .. import agent


def test_sig_encode():
    SIG = (
        b'(7:sig-val(5:ecdsa(1:r32:\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x0c)(1:s32:\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00")))')
    assert agent.sig_encode(12, 34) == SIG


def test_parse_ecdh():
    assert agent.parse_ecdh(b'D (7:enc-val(4:ecdh(1:s1:S)(1:e1:E)))') == {b's': b'S', b'e': b'E'}
    assert agent.parse_ecdh(b'D (7:enc-val(3:ecc(1:c1:7)(1:e1:E)))') == {b'c': b'7', b'e': b'E'}


def test_kem_decrypt():
    shared_x = bytes(range(32))
    kdf_params = b'KDF-PARAMS'
    session_key = b'\x09' + (b'K' * 32) + b'\x00\x00' + (b'\x05' * 5)
    kek = hashlib.sha256(b'\x00\x00\x00\x01' + shared_x + kdf_params).digest()[:16]
    wrapped = aes_key_wrap(kek, session_key)
    params = {b'c': b'7', b'h': b'8', b'kdf-params': kdf_params,
              b's': bytes([len(wrapped)]) + wrapped}
    assert agent.kem_decrypt(params, b'\x04' + shared_x) == session_key  # Curve25519
    assert agent.kem_decrypt(params, b'\x04' + shared_x + (b'Y' * 32)) == session_key  # NIST256
