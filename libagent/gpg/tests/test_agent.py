from cryptography.hazmat.primitives.asymmetric import x25519

from ... import util
from .. import agent


def test_sig_encode():
    SIG = (
        b'(7:sig-val(5:ecdsa(1:r32:\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x0c)(1:s32:\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00")))')
    assert agent.sig_encode(12, 34) == SIG


def test_kem_unwrap():
    # Session key encrypted by GnuPG 2.4 to a Curve25519 subkey,
    # as requested by GnuPG 2.5 via "PKDECRYPT --kem=PGP".
    secret = bytes.fromhex('50a50132cfdd95058e6de4405be89cb6cc2eedec4e56368506635fc388f58a61')
    e = bytes.fromhex('4045aca2a1ac9ca06b0c9df0a41861941fb567095e359babed565e73148beed226')
    s = bytes.fromhex('300a4f6d7d85abb2a70c9d5676f3675f0e368b5168fd6068aca3baceb7c3b17b'
                      'ada87179c4d94c8fc4df73fae15b2d2eef')
    kdf_params = (b'\x0a\x2b\x06\x01\x04\x01\x97\x55\x01\x05\x01\x12\x03\x01\x08\x07'
                  b'Anonymous Sender    ' +
                  bytes.fromhex('DF18FE2FA6A5BBA6793900D6AA8B034929071D9E'))

    def item(name, value):
        return b'(%d:%s%d:%s)' % (len(name), name, len(value), value)

    request = (b'(7:enc-val(3:ecc' + item(b'c', b'7') + item(b'h', b'8') +
               item(b'e', e) + item(b's', s) + item(b'kdf-params', kdf_params) + b'))')
    params = agent.parse_ecdh(b'D ' + util.assuan_serialize(request))
    assert params[b'e'] == e

    sk = x25519.X25519PrivateKey.from_private_bytes(secret)
    shared = sk.exchange(x25519.X25519PublicKey.from_public_bytes(e[1:]))
    session_key = agent.kem_unwrap(b'\x04' + shared, params)
    # cipher algo (AES-256), session key, checksum, padding
    assert session_key == bytes.fromhex(
        '0983c2cc9b9c3e788bcd5c9ecd26f459d7498839e089b8c14831c92d4bd896dbd6122c0505050505')


def test_kem_unwrap_nist256():
    # Session key encrypted by GnuPG 2.4 to a NIST P-256 subkey with secret
    # scalar 1, so the device's ECDH result equals the ephemeral point `e`.
    e = bytes.fromhex('0491f912ba16861450b3d3e81648a5e3d2e8f2b1b9423b3d1a1dc69fbd1ce4b3b5'
                      '83169ede1fb05fb3b4dcdbf67eb036099a903b7fdda6b212535b285e38350734')
    s = bytes.fromhex('309acba0635f4c8d4d1b73531cd45154bfed99d2e7480d74fd6555cf871566f6'
                      '37eeb60b920e154acf33f01cf1fa0c27dd')
    kdf_params = (b'\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x12\x03\x01\x08\x07'
                  b'Anonymous Sender    ' +
                  bytes.fromhex('61CD4832F06BC8BB0E382F1AD05CD80398F7AA6D'))
    params = {b'c': b'7', b'h': b'8', b'e': e, b's': s, b'kdf-params': kdf_params}
    assert agent.kem_unwrap(e, params) == bytes.fromhex(
        '094189b83d3cf648d9c0eab2d3daf6847f2ac497856a293c47453c7eaf37a14b5310580505050505')
