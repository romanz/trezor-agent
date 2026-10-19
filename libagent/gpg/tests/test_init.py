import sys

import mock

from ... import gpg


def test_run_agent_pinentry_no_default():
    # Regression test for #535: run_agent() must not set a literal default
    # for the pinentry binaries. Leaving them unset (argparse.SUPPRESS, as
    # main() does) lets device.ui.UI fall back to the path resolved by
    # keyring.get_pinentry_binary() via `gpgconf --list-components`.
    internal = mock.Mock()
    with mock.patch.object(gpg, 'run_agent_internal', internal), \
            mock.patch.object(sys, 'argv', ['trezor-gpg-agent']):
        gpg.run_agent(device_type=mock.Mock())
    args = internal.call_args[0][0]
    assert 'pin_entry_binary' not in vars(args)
    assert 'passphrase_entry_binary' not in vars(args)


def test_run_agent_pinentry_explicit():
    internal = mock.Mock()
    argv = ['trezor-gpg-agent',
            '--pin-entry-binary=/custom/pinentry',
            '--passphrase-entry-binary=/custom/pinentry-tty']
    with mock.patch.object(gpg, 'run_agent_internal', internal), \
            mock.patch.object(sys, 'argv', argv):
        gpg.run_agent(device_type=mock.Mock())
    args = internal.call_args[0][0]
    assert args.pin_entry_binary == '/custom/pinentry'
    assert args.passphrase_entry_binary == '/custom/pinentry-tty'
