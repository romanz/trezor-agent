"""TREZOR-related definitions."""

# pylint: disable=unused-import,import-error
import os
import logging
import functools

from trezorlib.client import PinException
from trezorlib.tools import CallException
from trezorlib.client import TrezorClient
from trezorlib.messages import IdentityType, PassphraseAck, PinMatrixAck, PassphraseStateAck
from trezorlib.ui import ClickUI

Client = functools.partial(TrezorClient, ui=ClickUI)

try:
    from trezorlib.transport import get_transport
except ImportError:
    from trezorlib.device import TrezorDevice
    get_transport = TrezorDevice.find_by_path

log = logging.getLogger(__name__)


def find_device():
    """Selects a transport based on `TREZOR_PATH` environment variable.

    If unset, picks first connected device.
    """
    try:
        return get_transport(os.environ.get("TREZOR_PATH"))
    except Exception as e:  # pylint: disable=broad-except
        log.debug("Failed to find a Trezor device: %s", e)
