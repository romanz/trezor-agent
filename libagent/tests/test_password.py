import os
from unittest import TestCase
from unittest.mock import Mock

from ..password import (_calculate_required_words, _format_password,
                        wordlist_tools)


class PasswordAgentTests(TestCase):

    def test_wordlist_tool(self):
        eff_default_wordlist = wordlist_tools.load_wordlist()
        assert len(eff_default_wordlist) == 7776, len(eff_default_wordlist)
        valid_tests = [
            ("601edb571fc2c9235753396162e0bd240caf6ead6a010ddb5708be9d282ca9d0",
             ['contend', 'deputy', 'attendant', 'previous', 'tiptop',
              'tubular', 'dreary', 'devotion', 'herbicide',
              'quaintly', 'majesty', 'kelp', 'think', 'either', 'fastball', 'perch']),

            ("f6132e207695b769d8b447a0d17707ec3d916ef13a24575e759ae8e0320f1413",
             ['multiple', 'uncouple', 'armed', 'chunk', 'gallon',
              'umbrella', 'duct', 'animosity', 'ranch',
              'unfilled', 'traffic', 'tigress', 'reforest', 'rabid', 'reclaim']),

            ("7d5ab2e4de19897b78ea5776949ce985a17fbef80a5049e7c34629aedbdf571c",
             ['chatter', 'tug', 'expansive', 'napping', 'whoopee',
              'travesty', 'twelve', 'reshape', 'extruding',
              'endanger', 'flirt', 'immovable', 'idealist', 'glimmer', 'disloyal', 'thrive']),
        ]
        for input_hex, output_words in valid_tests:
            result = wordlist_tools.bytes_to_words(
                entropy_bytes=bytes.fromhex(input_hex),
                vocabulary=eff_default_wordlist,
            )
            self.assertEqual(result, output_words, f"{result=}, {output_words=}")

        with self.assertRaises(FileNotFoundError):
            wordlist_tools.load_wordlist('this_file_doesnt_exist123.txt')

        valid_entropy = b'\x00' * 16
        valid_vocab = ["word1", "word2", "word3"]
        short_entropy = b'\x00' * 15  # 15 bytes
        invalid_content_vocab = [123, "valid"]
        with self.assertRaisesRegex(AssertionError, "Vocabulary cannot be empty"):
            wordlist_tools.bytes_to_words(valid_entropy, [])

        with self.assertRaises(AssertionError):
            # Passing a string instead of a list of strings
            wordlist_tools.bytes_to_words(valid_entropy, "not a list")

        with self.assertRaisesRegex(AssertionError, "Input bytes must be at least 16 bytes long"):
            wordlist_tools.bytes_to_words(short_entropy, valid_vocab)

        with self.assertRaises(AssertionError):
            # Passing a string instead of bytes
            wordlist_tools.bytes_to_words("not bytes", valid_vocab)

        with self.assertRaises(AssertionError):
            wordlist_tools.bytes_to_words(valid_entropy, invalid_content_vocab)

        # Create a vocab of size 200
        vocab = [str(i) for i in range(200)]
        # 0xFF (255) is in the rejection zone for a vocab of size 200
        # We provide 16 bytes of rejection values.
        bad_entropy = b'\xff' * 16
        with self.assertRaisesRegex(AssertionError, "Insufficient entropy to generate any words"):
            wordlist_tools.bytes_to_words(bad_entropy, vocab)

    def test_calculate_required_words(self):
        self.assertEqual(_calculate_required_words(7776, 128), 10)
        self.assertEqual(_calculate_required_words(2048, 128), 12)
        self.assertEqual(_calculate_required_words(2048, 256), 24)
        self.assertEqual(_calculate_required_words(4, 4), 2)
        self.assertEqual(_calculate_required_words(2, 8), 8)
        self.assertEqual(_calculate_required_words(10, 4), 2)
        with self.assertRaises(AssertionError):
            _calculate_required_words(1, 128)
        with self.assertRaises(AssertionError):
            _calculate_required_words(0, 128)
        with self.assertRaises(AssertionError):
            _calculate_required_words(-10, 128)

    def test_format_password(self):
        args = Mock()
        args.raw = True
        entropy_hex = "f18d65d1d9c30346c7da32a14675036270fc724d45d0f8a2c302b873bb097c5c"
        self.assertEqual(
            _format_password(
                entropy=bytes.fromhex(entropy_hex),
                args=args,
            ), entropy_hex[:32])

        args = Mock()
        args.raw = False
        args.base58 = True
        output_base58 = "Wq26b2xZfQVPfH3ZW9EoUd!"
        self.assertEqual(
            _format_password(
                entropy=bytes.fromhex(entropy_hex),
                args=args,
            ),
            output_base58)

        random_output = _format_password(
                entropy=os.urandom(32),
                args=args,
        )
        self.assertTrue(random_output.endswith('!'))

        args.base58 = False
        args.wordlist = None
        output_passphrase = ("upstate-fresh-coroner-caption-partner"
                             "-reformat-fade-carnivore-sandal-silt")
        self.assertEqual(
            _format_password(
                entropy=bytes.fromhex(entropy_hex),
                args=args,
            ), output_passphrase)
