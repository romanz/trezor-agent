"""Decoders for GPG v2 data structures."""
import base64
import functools
import hashlib
import io
import logging
import struct

import ecdsa
import nacl.signing

from .. import util
from . import keystore, protocol

log = logging.getLogger(__name__)


def parse_subpackets(s):
    """See https://tools.ietf.org/html/rfc4880#section-5.2.3.1 for details."""
    subpackets = []
    total_size = s.readfmt('>H')
    data = s.read(total_size)
    s = util.Reader(io.BytesIO(data))

    while True:
        try:
            first = s.readfmt('B')
        except EOFError:
            break

        if first < 192:
            subpacket_len = first
        elif first < 255:
            subpacket_len = ((first - 192) << 8) + s.readfmt('B') + 192
        else:  # first == 255
            subpacket_len = s.readfmt('>L')

        subpackets.append(s.read(subpacket_len))

    return subpackets


def parse_mpi(s):
    """See https://tools.ietf.org/html/rfc4880#section-3.2 for details."""
    bits = s.readfmt('>H')
    blob = bytearray(s.read(int((bits + 7) // 8)))
    return sum(v << (8 * i) for i, v in enumerate(reversed(blob)))


def parse_mpis(s, n):
    """Parse multiple MPIs from stream."""
    return [parse_mpi(s) for _ in range(n)]


def _parse_nist256p1_pubkey(mpi):
    prefix, x, y = util.split_bits(mpi, 4, 256, 256)
    if prefix != 4:
        raise ValueError('Invalid MPI prefix: {}'.format(prefix))
    point = ecdsa.ellipticcurve.Point(curve=ecdsa.NIST256p.curve,
                                      x=x, y=y)
    return ecdsa.VerifyingKey.from_public_point(
        point=point, curve=ecdsa.curves.NIST256p,
        hashfunc=hashlib.sha256)


def _parse_ed25519_pubkey(mpi):
    prefix, value = util.split_bits(mpi, 8, 256)
    if prefix != 0x40:
        raise ValueError('Invalid MPI prefix: {}'.format(prefix))
    vk = nacl.signing.VerifyKey(util.num2bytes(value, size=32), encoder=nacl.encoding.RawEncoder)
    return vk


SUPPORTED_CURVES = {
    b'\x2A\x86\x48\xCE\x3D\x03\x01\x07':
        (_parse_nist256p1_pubkey, protocol.keygrip_nist256),
    b'\x2B\x06\x01\x04\x01\xDA\x47\x0F\x01':
        (_parse_ed25519_pubkey, protocol.keygrip_ed25519),
    b'\x2B\x06\x01\x04\x01\x97\x55\x01\x05\x01':
        (_parse_ed25519_pubkey, protocol.keygrip_curve25519),
}

RSA_ALGO_IDS = {1, 2, 3}
ELGAMAL_ALGO_ID = 16
DSA_ALGO_ID = 17
ECDSA_ALGO_IDS = {18, 19, 22}  # {ecdsa, nist256, ed25519}


def _parse_embedded_signatures(subpackets):
    for packet in subpackets:
        data = bytearray(packet)
        if data[0] == 32:
            # https://tools.ietf.org/html/rfc4880#section-5.2.3.26
            stream = io.BytesIO(data[1:])
            yield _parse_signature(util.Reader(stream))


def _parse_signature(stream):
    """See https://tools.ietf.org/html/rfc4880#section-5.2 for details."""
    p = {'type': 'signature'}

    to_hash = io.BytesIO()
    with stream.capture(to_hash):
        p['version'] = stream.readfmt('B')
        p['sig_type'] = stream.readfmt('B')
        p['pubkey_alg'] = stream.readfmt('B')
        p['hash_alg'] = stream.readfmt('B')
        p['hashed_subpackets'] = parse_subpackets(stream)

    # https://tools.ietf.org/html/rfc4880#section-5.2.4
    tail_to_hash = b'\x04\xff' + struct.pack('>L', to_hash.tell())

    p['_to_hash'] = to_hash.getvalue() + tail_to_hash

    p['unhashed_subpackets'] = parse_subpackets(stream)
    embedded = list(_parse_embedded_signatures(p['unhashed_subpackets']))
    if embedded:
        log.debug('embedded sigs: %s', embedded)
        p['embedded'] = embedded

    p['hash_prefix'] = stream.readfmt('2s')
    if p['pubkey_alg'] in ECDSA_ALGO_IDS:
        p['sig'] = (parse_mpi(stream), parse_mpi(stream))
    elif p['pubkey_alg'] in RSA_ALGO_IDS:  # RSA
        p['sig'] = (parse_mpi(stream),)
    elif p['pubkey_alg'] == DSA_ALGO_ID:
        p['sig'] = (parse_mpi(stream), parse_mpi(stream))
    else:
        log.error('unsupported public key algo: %d', p['pubkey_alg'])

    assert not stream.read()
    return p


def _parse_pubkey(stream, packet_type='pubkey'):
    """See https://tools.ietf.org/html/rfc4880#section-5.5 for details."""
    p = {'type': packet_type}
    packet = io.BytesIO()
    with stream.capture(packet):
        p['version'] = stream.readfmt('B')
        p['created'] = stream.readfmt('>L')
        p['algo'] = stream.readfmt('B')
        if p['algo'] in ECDSA_ALGO_IDS:
            log.debug('parsing elliptic curve key')
            # https://tools.ietf.org/html/rfc6637#section-11
            oid_size = stream.readfmt('B')
            oid = stream.read(oid_size)
            assert oid in SUPPORTED_CURVES, util.hexlify(oid)
            p['curve_oid'] = oid

            mpi = parse_mpi(stream)
            log.debug('mpi: %x (%d bits)', mpi, mpi.bit_length())
            leftover = stream.read()
            if leftover:
                leftover = io.BytesIO(leftover)
                # https://tools.ietf.org/html/rfc6637#section-8
                # should be b'\x03\x01\x08\x07': SHA256 + AES128
                size, = util.readfmt(leftover, 'B')
                p['kdf'] = leftover.read(size)
                p['secret'] = leftover.read()

            parse_func, keygrip_func = SUPPORTED_CURVES[oid]
            p['verifying_key'] = parse_func(mpi)
            keygrip = keygrip_func(p['verifying_key'])
            log.debug('keygrip: %s', util.hexlify(keygrip))
            p['keygrip'] = keygrip

        elif p['algo'] == DSA_ALGO_ID:
            parse_mpis(stream, n=4)  # DSA keys are not supported
        elif p['algo'] == ELGAMAL_ALGO_ID:
            parse_mpis(stream, n=3)  # ElGamal keys are not supported
        else:  # assume RSA
            parse_mpis(stream, n=2)  # RSA keys are not supported
        assert not stream.read()

    # https://tools.ietf.org/html/rfc4880#section-12.2
    packet_data = packet.getvalue()
    data_to_hash = (b'\x99' + struct.pack('>H', len(packet_data)) +
                    packet_data)
    p['key_id'] = hashlib.sha1(data_to_hash).digest()[-8:]
    p['_to_hash'] = data_to_hash
    log.debug('key ID: %s', util.hexlify(p['key_id']))
    return p


_parse_subkey = functools.partial(_parse_pubkey, packet_type='subkey')


def _parse_user_id(stream, packet_type='user_id'):
    """See https://tools.ietf.org/html/rfc4880#section-5.11 for details."""
    value = stream.read()
    to_hash = b'\xb4' + util.prefix_len('>L', value)
    return {'type': packet_type, 'value': value, '_to_hash': to_hash}


# User attribute is handled as an opaque user ID
_parse_attribute = functools.partial(_parse_user_id,
                                     packet_type='user_attribute')

PACKET_TYPES = {
    2: _parse_signature,
    5: _parse_pubkey,
    6: _parse_pubkey,
    7: _parse_subkey,
    13: _parse_user_id,
    14: _parse_subkey,
    17: _parse_attribute,
}


def parse_packets(stream):
    """
    Support iterative parsing of available GPG packets.

    See https://tools.ietf.org/html/rfc4880#section-4.2 for details.
    """
    reader = util.Reader(stream)
    while True:
        try:
            value = reader.readfmt('B')
        except EOFError:
            return

        log.debug('prefix byte: %s', bin(value))
        assert util.bit(value, 7) == 1

        tag = util.low_bits(value, 6)
        if util.bit(value, 6) == 0:
            length_type = util.low_bits(tag, 2)
            tag = tag >> 2
            fmt = {0: '>B', 1: '>H', 2: '>L'}[length_type]
            packet_size = reader.readfmt(fmt)
        else:
            first = reader.readfmt('B')
            if first < 192:
                packet_size = first
            elif first < 224:
                packet_size = ((first - 192) << 8) + reader.readfmt('B') + 192
            elif first == 255:
                packet_size = reader.readfmt('>L')
            else:
                log.error('Partial Body Lengths unsupported')

        log.debug('packet length: %d', packet_size)
        packet_data = reader.read(packet_size)
        packet_type = PACKET_TYPES.get(tag)

        p = {'type': 'unknown', 'tag': tag, 'raw': packet_data}
        if packet_type is not None:
            try:
                p = packet_type(util.Reader(io.BytesIO(packet_data)))
                p['tag'] = tag
            except ValueError:
                log.exception('Skipping packet: %s', util.hexlify(packet_data))

        log.debug('packet "%s": %s', p['type'], p)
        yield p


def digest_packets(packets, hasher):
    """Compute digest on specified packets, according to '_to_hash' field."""
    data_to_hash = io.BytesIO()
    for p in packets:
        data_to_hash.write(p['_to_hash'])
    hasher.update(data_to_hash.getvalue())
    return hasher.digest()


HASH_ALGORITHMS = {
    1: 'md5',
    2: 'sha1',
    3: 'ripemd160',
    8: 'sha256',
    9: 'sha384',
    10: 'sha512',
    11: 'sha224',
}


def _parse_pubkey_packets(pubkey_bytes):
    stream = io.BytesIO(pubkey_bytes)
    packets_per_pubkey = []
    for p in parse_packets(stream):
        if p['type'] == 'pubkey':
            # Add a new packet list for each pubkey.
            packets_per_pubkey.append([])
        packets_per_pubkey[-1].append(p)
    return packets_per_pubkey


def iter_keygrips(pubkey_bytes):
    """Iterate over all keygrips in this pubkey."""
    for packets in _parse_pubkey_packets(pubkey_bytes):
        for p in packets:
            keygrip = p.get('keygrip')
            if keygrip:
                yield keygrip


async def identity_for_key(client, pubkey_bytes, homedir):
    """Returns the identity used to produce the associated primary key.

    If a key matching the specified public key is not found in the keystore, ``None`` is returned.
    """
    packets = parse_packets(io.BytesIO(pubkey_bytes))
    pubkey_dict = next(packets, None)
    if pubkey_dict is None or pubkey_dict['type'] != 'pubkey' or 'verifying_key' not in pubkey_dict:
        return None
    try:
        key = await keystore.load_key(client, pubkey_dict['keygrip'], homedir)
    except Exception:  # pylint: disable=broad-except
        return None
    # Check that it's the same key
    if key['pubkey'].data_to_hash() != pubkey_dict['_to_hash']:
        return None
    return key['identity']


def load_signature(stream, original_data):
    """Load signature from stream, and compute GPG digest for verification."""
    signature, = list(parse_packets((stream)))
    hash_alg = HASH_ALGORITHMS[signature['hash_alg']]
    digest = digest_packets([{'_to_hash': original_data}, signature],
                            hasher=hashlib.new(hash_alg))
    assert signature['hash_prefix'] == digest[:2]
    return signature, digest


def remove_armor(armored_data):
    """Decode armored data into its binary form."""
    stream = io.BytesIO(armored_data)
    lines = stream.readlines()[3:-1]
    payload = base64.b64decode(b''.join(lines[:-1]))
    checksum = base64.b64decode(lines[-1])
    assert util.crc24(payload) == checksum
    return payload
