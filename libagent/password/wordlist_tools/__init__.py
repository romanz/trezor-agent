"""wordlist_tools contain utils to deterministically map bytes to words in a given wordlist."""
import os
from functools import lru_cache
from typing import List, Optional

# https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases
DEFAULT_WORDLIST_FILE = 'eff_large_wordlist_words_only.txt'


@lru_cache(maxsize=1)
def load_wordlist(wordlist_path: Optional[str] = None) -> List[str]:
    """Load and parse wordlist file at wordlist_path or default eff wordlist."""
    if wordlist_path is None:
        module_dir = os.path.dirname(os.path.abspath(__file__))
        wordlist_path = os.path.join(module_dir, DEFAULT_WORDLIST_FILE)

    wordlist: list[str] = []
    with open(wordlist_path, encoding='utf-8') as file:
        for word in file:
            assert word and len(word) > 2, f"Invalid word in wordlist: '{word}'!"
            wordlist.append(word.strip())

    assert len(wordlist) > 0, f"empty wordlist? {wordlist_path=}"
    return wordlist


def bytes_to_words(entropy_bytes: bytes, vocabulary: List[str]) -> List[str]:
    """
    Deterministically maps input entropy to words from a vocabulary using rejection sampling.

    Ensures a uniform distribution without modulo bias.
    """
    # input validation
    assert isinstance(vocabulary, list) and len(vocabulary) > 0, "Vocabulary cannot be empty."
    assert all(isinstance(word, str) for word in vocabulary), "Inconsistent vocabulary types"
    assert isinstance(entropy_bytes, bytes) and len(entropy_bytes) >= 16, \
        "Input bytes must be at least 16 bytes long."

    # Sort vocabulary to ensure map indices are deterministic regardless of input implementation
    sorted_vocab = sorted(vocabulary)
    vocab_size = len(sorted_vocab)

    # Calculate how many bytes we need to cover the vocabulary size.
    bits_per_index = vocab_size.bit_length()
    bytes_per_sample = (bits_per_index + 7) // 8

    # Calculate the sampling space size (e.g., 2 bytes = 65536 possibilities).
    sample_space_size = 1 << (bytes_per_sample * 8)

    # Calculate the Rejection Threshold (Limit).
    # To avoid modulo bias, we must reject values that fall in the "remainder" zone
    # at the top of the sample space.
    # Threshold is the largest multiple of vocab_size fitting within sample_space_size.
    remainder = sample_space_size % vocab_size
    rejection_threshold = sample_space_size - remainder

    mapped_words: list[str] = []
    byte_offset = 0
    total_bytes = len(entropy_bytes)

    while byte_offset + bytes_per_sample <= total_bytes:
        # Extract the slice of bytes
        byte_slice = entropy_bytes[byte_offset:byte_offset + bytes_per_sample]

        # Convert bytes to integer
        sample_value = int.from_bytes(byte_slice, byteorder='big')

        # Rejection Sampling Check:
        # If the value is above the threshold, mapping it would introduce bias
        # towards the beginning of the vocabulary.
        if sample_value < rejection_threshold:
            word_index = sample_value % vocab_size
            selected_word = sorted_vocab[word_index]

            # sanity checks
            assert isinstance(selected_word, str) and len(selected_word) > 0
            mapped_words.append(selected_word)

        # Move the cursor forward regardless of whether the sample was used or rejected
        byte_offset += bytes_per_sample

    assert len(mapped_words) > 0, "Insufficient entropy to generate any words."
    return mapped_words
