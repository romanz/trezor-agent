#!/usr/bin/env python
'''Export secret GPG key using BIP13 derivation scheme.
IMPORTANT: Never run this code with your own mnemonic on a PC
with an internet connection or with any kind of persistent storage.
It may leak your mnemonic, exposing any secret key managed by the
TREZOR - which may result in Bitcoin loss!!!
'''

from __future__ import print_function

import sys
import logging
import argparse
import getpass
import hashlib
import hmac
import struct

from typing import Tuple

from mnemonic import Mnemonic  # type: ignore
from ecdsa import curves, SigningKey  # type: ignore
from libagent import util, formats  # type: ignore
from libagent.gpg import encode, protocol, client  # type: ignore
from libagent.formats import KeyFlags  # type: ignore

HARDENED_INDEX = 0x80000000
curve_name_to_curve = {"nist256p1": curves.NIST256p}
curve_name_to_seed = {"nist256p1": "Nist256p1 seed"}

logger = logging.getLogger("export_keys")


def get_curve(curve_name: str) -> curves.Curve:
    return curve_name_to_curve[curve_name]


def mnemonic_to_seed(mnemonic):
    return Mnemonic("english").to_seed(mnemonic)[:64]


def privkey_and_chaincode_from_seed(
    seed: bytes,
    curve_name: str
) -> Tuple[bytes, bytes]:
    """Return private key and chaincode from provided seed

    >>> test_seed = mnemonic_to_seed(test_mnemonic)
    >>> privkey_and_chaincode_from_seed(test_seed, "nist256p1")
    (b'\\x1e\\xa4\\\\\\x10\\xd3\\x1a\\xd4\\xb8...\\xc9#t\\xf8\\xcf\\xcb')
    """
    curve_secret = curve_name_to_seed[curve_name]
    secret = hmac.new(curve_secret.encode(), seed, hashlib.sha512).digest()

    return secret[:32], secret[32:]


def derive_private_child(
    curve_name: str,
    privkey: bytes,
    chaincode: bytes,
    index: int
) -> Tuple[bytes, bytes]:
    """Derives private child key and chaincode using parent child key,
    chaincode and index

    >>> test_seed = mnemonic_to_seed(test_mnemonic)
    >>> p, c = privkey_and_chaincode_from_seed(test_seed, "nist256p1")
    >>> derive_private_child("nist256p1", p, c, 2147483661)
    (b'(\\x9f\\xccH\\xd7\\x96yKEQ\\x83\\xde\\x11\\xfaW...\\xc9\\xc5\\x82W\\x01`')
    """
    curve = get_curve(curve_name)
    secexp = util.bytes2num(privkey)

    assert index & HARDENED_INDEX, "index not hardened"

    data = b'\x00' + privkey + index.to_bytes(4, "big")
    payload = hmac.new(chaincode, data, hashlib.sha512).digest()

    B = util.bytes2num(payload[:32])

    assert B < curve.order, "curve order too small"

    B += secexp
    B %= curve.order

    child_private = util.num2bytes(B, 32)

    return child_private, payload[32:]


def derive(seed, path, curve_name):
    """Derives gpg key from provided bip32 path

    >>> seed = mnemonic_to_seed(test_mnemonic)
    >>> sk = derive(seed,
    ...     [2147483661, 3641273873, 3222207101, 2735596413, 2741857293],
    ...     "nist256p1")
    >>> sk.verifying_key.to_string().hex()
    '32dd7bda4eb424e57ec2594bc2dad...eb1ca14a6f518c204e32b24c5f18b4'
    """
    logger.debug("seed: %s", seed.hex())

    privkey, chaincode = privkey_and_chaincode_from_seed(seed, curve_name)
    logger.debug("master privkey: %s", privkey.hex())
    logger.debug("master chaincode: %s", chaincode.hex())

    for i in path:
        privkey, chaincode = derive_private_child(
            curve_name, privkey, chaincode, i)

        logger.debug("ckd: %d -> %s %s", i, privkey.hex(), chaincode.hex())

    logger.debug("child privkey: %s", privkey.hex())

    secexp = util.bytes2num(privkey)

    curve = get_curve(curve_name)
    sk = SigningKey.from_secret_exponent(
        secexp=secexp,
        curve=curve,
        hashfunc=hashlib.sha256)

    return sk


def pack(sk):
    secexp = util.bytes2num(sk.to_string())
    mpi_bytes = protocol.mpi(secexp)
    checksum = sum(bytearray(mpi_bytes)) & 0xFFFF
    return b'\x00' + mpi_bytes + struct.pack('>H', checksum)


def sigencode(r, s, _):
    return (r, s)


def create_signer(signing_key):
    def signer(digest):
        return signing_key.sign_digest_deterministic(
            digest, hashfunc=hashlib.sha256, sigencode=sigencode)
    return signer


def append_subkeys(seed, signer_func, primary_bytes, user_id, curve_name, creation_time,
                   signing=True, encryption=True, authentication=False, private=False):

    if signing:
        identity = client.create_identity(user_id=user_id, curve_name=curve_name,
            keyflag=KeyFlags.SIGN)
        sk = derive(seed, identity.get_bip32_address(), curve_name)
        cross_signer_func = create_signer(sk)
        signing_subkey = protocol.PublicKey(curve_name=curve_name, created=creation_time,
            verifying_key=sk.verifying_key, keyflag=KeyFlags.SIGN)
        signing_bytes = encode.create_subkey(primary_bytes=primary_bytes, subkey=signing_subkey,
            signer_func=signer_func, cross_signer_func=cross_signer_func,
            secret_bytes=(pack(sk) if private else b''))
    else:
        signing_bytes = b''

    if encryption:
        identity = client.create_identity(user_id=user_id, curve_name=curve_name,
            keyflag=KeyFlags.ENCRYPT)
        sk = derive(seed, identity.get_bip32_address(), curve_name)
        encryption_curve_name = formats.get_ecdh_curve_name(curve_name)
        encryption_subkey = protocol.PublicKey(curve_name=encryption_curve_name,
            created=creation_time, verifying_key=sk.verifying_key, keyflag=KeyFlags.ENCRYPT)
        encryption_bytes = encode.create_subkey(primary_bytes=primary_bytes,
            subkey=encryption_subkey, signer_func=signer_func,
            secret_bytes=(pack(sk) if private else b''))
    else:
        encryption_bytes = b''

    if authentication:
        identity = client.create_identity(user_id=user_id, curve_name=curve_name,
            keyflag=KeyFlags.AUTHENTICATE)
        sk = derive(seed, identity.get_bip32_address(), curve_name)
        authentication_subkey = protocol.PublicKey(curve_name=curve_name, created=creation_time,
            verifying_key=sk.verifying_key, keyflag=KeyFlags.AUTHENTICATE)
        authentication_bytes = encode.create_subkey(primary_bytes=primary_bytes,
            subkey=authentication_subkey, signer_func=signer_func,
            secret_bytes=(pack(sk) if private else b''))
    else:
        authentication_bytes = b''

    return primary_bytes + signing_bytes + encryption_bytes + authentication_bytes

def export_key(user_id, curve_name,
    time=0, smartcard=True, private=False,
    seed=None, mnemonic=None):

    if seed is None:
        assert mnemonic is not None,  "seed or mnemonic not provided"
        seed = mnemonic_to_seed(mnemonic)

    if smartcard:
        certify = KeyFlags.CERTIFY
        signing = True
        encryption = True
        authentication = True
    else:
        certify = KeyFlags.CERTIFY_AND_SIGN
        signing = False
        encryption = True
        authentication = False

    # primary key for certification/signing
    certifying_identity = client.create_identity(user_id=user_id,
        curve_name=curve_name, keyflag=certify)

    sk = derive(seed, certifying_identity.get_bip32_address(), curve_name)
    certifying_signer_func = create_signer(sk)

    primary = protocol.PublicKey(
        curve_name=curve_name, created=time,
        verifying_key=sk.verifying_key, keyflag=certify)
    primary_bytes = encode.create_primary(user_id=user_id,
                                    pubkey=primary,
                                    signer_func=certifying_signer_func,
                                    secret_bytes=(pack(sk) if private else b''))

    # subkeys
    result = append_subkeys(seed, certifying_signer_func, primary_bytes, user_id, curve_name, time,
        signing=signing, encryption=encryption, authentication=authentication, private=private)

    if private:
        return protocol.armor(result, 'PRIVATE KEY BLOCK')
    else:
        return protocol.armor(result, 'PUBLIC KEY BLOCK')


def main():
    print(__doc__)

    test_mnemonic = "all all all all all all all all all all all all"
    example_seed = mnemonic_to_seed(test_mnemonic).hex()
    example_identity = "First Last <first_last@example.com>"

    parser = argparse.ArgumentParser(
        description="trezor-agent gpg key recovery tool",
        formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument(
        "--mnemonic", type=str, default=None,
        help="trezor mnemonic (example: {})".format(test_mnemonic))

    parser.add_argument(
        "--seed", type=str, default=None,
        help="trezor seed (example: {})".format(example_seed[:64] + "..."))

    parser.add_argument(
        "--identity", type=str, default=None,
        help="gpg key user identity (example: '{}')".format(example_identity))

    parser.add_argument(
        "--timestamp", type=int, default=0,
        help="timestamp to use (default: 0)")

    parser.add_argument(
        "--smartcard", type=bool, default=True,
        help="smartcard subkeys (default: true)"
    )

    parser.add_argument(
        "--debug", action="store_true",
        help="enable debugging")

    args = parser.parse_args()

    if not args.identity:
        user_id = input('Enter your identity (example: {}): '.format(example_identity))  # noqa
    else:
        user_id = args.identity

    if not (args.mnemonic or args.seed):
        mnemonic = getpass.getpass('Enter your mnemonic: ')
    else:
        mnemonic = args.mnemonic

    seed = bytes.fromhex(args.seed) if args.seed else None

    logging.basicConfig(
        stream=sys.stderr,
        level=logging.DEBUG if args.debug else logging.INFO)


    curve_name = 'nist256p1'
    public_key = export_key(user_id, curve_name, time=args.timestamp,
        seed=seed, mnemonic=mnemonic, smartcard=args.smartcard,
        private=False)

    private_key = export_key(user_id, curve_name, time=args.timestamp,
        seed=seed, mnemonic=mnemonic, smartcard=args.smartcard,
        private=True)

    print('Use "gpg2 --import" on the following GPG key blocks:\n')
    print(public_key)
    print(private_key)


if __name__ == '__main__':
    main()
