import mock

from ... import formats
from .. import create_agent_parser


def _parser():
    device_type = mock.Mock()
    device_type.package_name.return_value = 'libagent'
    return create_agent_parser(device_type=device_type)


def test_default_curve_is_ed25519():
    args = _parser().parse_args(['ssh://localhost'])
    assert args.ecdsa_curve_name == formats.CURVE_ED25519


def test_curve_can_be_overridden():
    args = _parser().parse_args(['-e', formats.CURVE_NIST256, 'ssh://localhost'])
    assert args.ecdsa_curve_name == formats.CURVE_NIST256
