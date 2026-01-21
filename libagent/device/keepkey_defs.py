"""KeepKey-related definitions."""

# pylint: disable=unused-import,import-error

from keepkeylib.client import CallException
from keepkeylib.client import KeepKeyClient as Client
from keepkeylib.client import PinException
from keepkeylib.messages_pb2 import PassphraseAck, PinMatrixAck
from keepkeylib.transport_hid import HidTransport
from keepkeylib.transport_webusb import WebUsbTransport
from keepkeylib.types_pb2 import IdentityType

PASSPHRASE_TEST_PATH = Client.expand_path("-44/-1/0/0/0")
get_public_node = Client.get_public_node
get_address = Client.get_address
sign_identity = Client.sign_identity
Client.state = None
Client.session_id = None


def find_device():
    """Returns first WebUSB or HID transport."""
    for d in WebUsbTransport.enumerate():
        return WebUsbTransport(d)

    for d in HidTransport.enumerate():
        return HidTransport(d)
