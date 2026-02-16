"""password-agent module."""
import argparse
import logging
from hashlib import sha256
from typing import Type

from .. import util
from ..device import interface, ui
from . import wordlist_tools

log = logging.getLogger(__name__)


DERIVATION_SCHEME_VERSION = 1


def _create_identity(context: str) -> interface.Identity:
    identity_str = "password://"
    result = interface.Identity(identity_str=identity_str, curve_name='ed25519')
    result.identity_dict['host'] = context
    return result


def _sign_context_string(device: interface.Device, context: str) -> bytes:
    """Signs a message containing the context string and returns the signature."""
    domain_seperator_context = f"PW:CONTEXT_STR:{str(DERIVATION_SCHEME_VERSION)}:"
    preimage = f"{domain_seperator_context}{context}".encode('utf-8')
    digest = sha256(preimage).digest()

    identity = _create_identity(context)

    log.info('please confirm password derivation on %s for "%s"...', device, context)
    log.debug('signing data: %s', util.hexlify(digest))
    with device:
        sig = device.sign(blob=digest, identity=identity)
        assert len(sig) == 64 and isinstance(sig, bytes), f"invalid sig: {sig=}"
        return sig


def _derive_entropy(device: interface.Device, context_str: str) -> bytes:
    """
    Derive 16 bytes of entropy from context string.

    Same context input always produces same output.
    """
    signature = _sign_context_string(device=device, context=context_str)
    domain_separator_sig = f"PW:SIG:{str(DERIVATION_SCHEME_VERSION)}:".encode('utf-8')
    derivation_output = sha256(domain_separator_sig + signature).digest()
    return derivation_output


def _calculate_required_words(wordlist_length: int, target_bits: int = 128) -> int:
    """
    Calculate number of words needed to achieve around target entropy bits.

    e.g. 1 word of eff_large_wordlist (7776 words) represents ~12.8 bits of entropy
    """
    assert wordlist_length > 1, "Invalid wordlist length!"
    words_needed = 1
    possible_combinations = wordlist_length  # represents total possible combinations
    target_combinations = 2 ** target_bits
    while possible_combinations < target_combinations:
        words_needed += 1
        possible_combinations *= wordlist_length
    return words_needed


def _format_password(entropy: bytes, args: argparse.Namespace) -> str:
    """Format derived entropy into requested password format."""
    assert isinstance(entropy, bytes) and len(entropy) == 32

    if args.raw:
        return entropy[:16].hex()  # 16 bytes are enough

    if args.base58:
        # append one exclamation mark as many services require this, otherwise the generated
        # password might not be usable for these service
        return util.Base58.encode(entropy[:16]) + '!'

    wordlist = wordlist_tools.load_wordlist(wordlist_path=args.wordlist)
    words_derived = wordlist_tools.bytes_to_words(entropy_bytes=entropy, vocabulary=wordlist)
    wordlist_length = len(wordlist)
    num_words_needed = _calculate_required_words(wordlist_length, target_bits=128)

    log.debug(f"{wordlist_length=}, {num_words_needed=}, available words: {len(words_derived)}")
    assert len(words_derived) >= num_words_needed, \
        f"not enough entropy, {len(words_derived)=} < {num_words_needed=}"

    return "-".join(words_derived[:num_words_needed])


def run_derivation(*, device_type: Type['interface.Device'], args: argparse.Namespace) -> str:
    """Entry point to the password derivation flow."""
    context_str = args.context
    assert isinstance(context_str, str) and len(context_str) > 0, \
        f"Invalid context string: {context_str=}"
    assert len(context_str) < 50, f"Use sane context string length (<50). {len(context_str)=}"

    device = device_type()
    derived_entropy = _derive_entropy(device, context_str)
    return _format_password(derived_entropy, args)


def main(device_type: Type['interface.Device']):
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='Deterministically derive a password for the given context',
    )

    parser.add_argument(
        'context',
        type=str,
        help='Context string, e.g. "gmail", "proton-2025" or "laptop-disk"',
    )
    parser.add_argument(
        '-b58',
        '--base58',
        default=False,
        action='store_true',
        help="Derive b58 encoded password",
    )
    parser.add_argument(
        '-w',
        '--wordlist',
        default=None,
        type=str,
        help="Path to custom wordlist",
    )
    parser.add_argument('-r', '--raw', default=False, action='store_true')
    parser.add_argument('-v', '--verbose', default=0, action='count')
    parser.set_defaults(func=run_derivation)

    args = parser.parse_args()
    assert not (args.raw and args.base58), \
        "Cannot return raw output and base58 simultaneously"
    assert not (args.wordlist and (args.raw or args.base58)), \
        "Cannot use wordlist with base58 or raw output"
    util.setup_logging(verbosity=args.verbose)

    device_type.ui = ui.UI(device_type=device_type, config=vars(args))
    device_type.ui.cached_passphrase_ack = util.ExpiringCache(seconds=float(60))

    password = args.func(device_type=device_type, args=args)
    print(password, end="" if args.raw else "\n")
