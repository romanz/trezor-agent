"""UIs for PIN/passphrase entry."""

import contextlib
import functools
import io
import logging
import os
import subprocess
import sys

import trio
import trio_util

from .. import util
from ..gpg import keyring

try:
    from trezorlib.client import PASSPHRASE_ON_DEVICE
except ImportError:
    PASSPHRASE_ON_DEVICE = object()


log = logging.getLogger(__name__)


class _UISync:
    def __init__(self, ui, options_getter):
        self.ui = ui
        self.options_getter = options_getter

    def get_pin(self, code=None):
        return trio.from_thread.run(self.ui.get_pin, code, self.options_getter)

    def get_passphrase(self, prompt='Passphrase:', available_on_device=False):
        return trio.from_thread.run(self.ui.get_passphrase, prompt,
                                    available_on_device, self.options_getter)

    def button_request(self, br=None):
        return trio.from_thread.run(self.ui.button_request, br, self.options_getter)


class _DeviceOnThread:
    def __init__(self, runner, runner_immediate, proxy, button_scope):
        self.runner = runner
        self.runner_immediate = runner_immediate
        self.proxy = proxy
        self.button_scope = button_scope

    async def connect(self):
        return await self.runner(self.proxy.connect)

    async def close(self):
        return await self.runner(self.proxy.close)

    async def __aenter__(self):
        async with self.button_scope():  # May request a pin unlock
            await self.runner(self.proxy.__enter__)
        return self

    async def __aexit__(self, *args):
        # Try to close the device immediately
        # If a device request is in progress, this will prevent the program from being stuck
        return await self.runner_immediate(self.proxy.__exit__, *args)

    async def pubkey(self, identity, ecdh=False):
        async with self.button_scope():
            return await self.runner(self.proxy.pubkey, identity, ecdh)

    async def sign(self, identity, blob):
        async with self.button_scope():
            return await self.runner(self.proxy.sign, identity, blob)

    async def sign_with_pubkey(self, identity, blob):
        async with self.button_scope():
            return await self.runner(self.proxy.sign_with_pubkey, identity, blob)

    async def ecdh(self, identity, pubkey):
        async with self.button_scope():
            return await self.runner(self.proxy.ecdh, identity, pubkey)

    async def ecdh_with_pubkey(self, identity, pubkey):
        async with self.button_scope():
            return await self.runner(self.proxy.ecdh_with_pubkey, identity, pubkey)

    def __str__(self):
        return self.proxy.__str__()


# pylint: disable=too-many-instance-attributes
class UI:
    """UI for PIN/passphrase entry (for TREZOR devices)."""

    @classmethod
    async def create(cls, device_type, config=None):
        """Asynchronously create a UI object, fiilling in default options."""
        # by default, use GnuPG pinentry tool
        default_pinentry = await keyring.get_pinentry_binary()
        options_getter = await create_default_options_getter()
        return cls(device_type, default_pinentry, options_getter, config)

    def __init__(self, device_type, default_pinentry, options_getter, config=None):
        """C-tor."""
        self.run_on_thread = None
        self.run_command_on_thread = None
        self.run_command_on_thread_immediate = None
        self.quit_event = None
        self.button_nursery = None
        if config is None:
            config = {}
        self.pin_entry_binary = config.get('pin_entry_binary',
                                           default_pinentry)
        self.passphrase_entry_binary = config.get('passphrase_entry_binary',
                                                  default_pinentry)
        self.options_getter = options_getter
        self.device_lock = trio.Lock()
        self.device_type = device_type
        self.cached_passphrase_ack = util.ExpiringCache(
            seconds=float(config.get('cache_expiry_seconds', 'inf')))

    async def __aenter__(self):
        """Start a thread for accepting device commands."""
        assert self.run_on_thread is None
        self.run_on_thread = util.run_on_thread()
        self.quit_event = trio.Event()
        self.run_command_on_thread, self.run_command_on_thread_immediate = await (
            type(self.run_on_thread).__aenter__(self.run_on_thread))
        return self

    async def __aexit__(self, *args):
        """Close the thread and wait for it to complete."""
        if self.quit_event is not None:
            self.quit_event.set()
        if self.run_on_thread is not None:
            run_on_thread = self.run_on_thread
            self.run_on_thread = None
            return await type(run_on_thread).__aexit__(run_on_thread, *args)

    async def get_pin(self, _code=None, options_getter=None):
        """Ask the user for (scrambled) PIN."""
        assert self.quit_event is not None
        if options_getter is None:
            options_getter = self.options_getter
        async with trio_util.move_on_when(self.quit_event.wait):
            description = (
                'Use the numeric keypad to describe number positions.\n'
                'The layout is:\n'
                '    7 8 9\n'
                '    4 5 6\n'
                '    1 2 3')
            return await interact(
                title='{} PIN'.format(self.device_type.__name__),
                prompt='PIN:',
                description=description,
                binary=self.pin_entry_binary,
                options=self.options_getter())
        raise RuntimeError('UI scope exited')

    async def get_passphrase(self, prompt='Passphrase:',
                             available_on_device=False, options_getter=None):
        """Ask the user for passphrase."""
        assert self.quit_event is not None
        if options_getter is None:
            options_getter = self.options_getter
        async with trio_util.move_on_when(self.quit_event.wait):
            passphrase = None
            if self.cached_passphrase_ack:
                passphrase = self.cached_passphrase_ack.get(prompt)
            if passphrase is None:
                env_passphrase = os.environ.get("TREZOR_PASSPHRASE")
                if env_passphrase is not None:
                    passphrase = env_passphrase
                elif available_on_device:
                    passphrase = PASSPHRASE_ON_DEVICE
                else:
                    passphrase = await interact(
                        title='{} passphrase'.format(self.device_type.__name__),
                        prompt=prompt,
                        description=None,
                        binary=self.passphrase_entry_binary,
                        options=self.options_getter())
            if self.cached_passphrase_ack:
                self.cached_passphrase_ack.set(prompt, passphrase)
            return passphrase
        raise RuntimeError('UI scope exited')

    async def button_request(self, br=None, options_getter=None):
        """Called by TrezorClient when device interaction is required."""
        if self.button_nursery is None:
            # We don't have a clear scope for the operation
            # Better to show nothing than to show a window that would not automatically close
            return
        self.button_nursery.start_soon(self._button_request, br, options_getter)

    async def _button_request(self, _br=None, options_getter=None):
        try:
            if options_getter is None:
                options_getter = self.options_getter
            await interact(
                title='{} interact'.format(self.device_type.__name__),
                prompt=None,
                description='Please follow the instructions\n'
                'on your {} device\'s screen'.format(self.device_type.__name__),
                binary=self.passphrase_entry_binary,
                options=self.options_getter(),
                is_message=True)
        except Exception as e:  # pylint: disable=broad-except
            log.exception('Failed to show an interaction dialog: %s', e)

    def get_device_name(self):
        """Human-readable representation."""
        return self.device_type.__name__

    @contextlib.asynccontextmanager
    async def device(self, options_getter=None):
        """Acquire access to the device."""
        async with self.device_lock:  # Only allow one connection at a time
            async with _DeviceOnThread(self.run_command_on_thread,
                                       self.run_command_on_thread_immediate,
                                       self.device_type(_UISync(self, options_getter)),
                                       self._button_scope) as dot:
                yield dot

    @contextlib.asynccontextmanager
    async def _button_scope(self):
        async with trio.open_nursery() as nursery:
            self.button_nursery = nursery
            try:
                yield
            finally:
                if self.button_nursery == nursery:
                    self.button_nursery = None
                nursery.cancel_scope.cancel()


async def create_default_options_getter():
    """Return current TTY and DISPLAY settings for GnuPG pinentry."""
    options = []
    # Windows reports that it has a TTY but throws FileNotFoundError
    if sys.platform != 'win32' and sys.stdin.isatty():  # short-circuit calling `tty`
        try:
            ttyname = (await trio.run_process(['tty'], capture_stdout=True)).stdout.strip()
            options.append(b'ttyname=' + ttyname)
        except subprocess.CalledProcessError as e:
            log.warning('no TTY found: %s', e)

    display = os.environ.get('DISPLAY')
    if display is not None:
        options.append('display={}'.format(display).encode('ascii'))
    # Windows likely doesn't support this anyway
    elif sys.platform != 'win32':
        log.warning('DISPLAY not defined')

    log.info('using %s for pinentry options', options)
    return lambda: options


async def write(p, line):
    """Send a single line to the subprocess' stdin."""
    log.debug('%s <- %r', p.args, line)
    await p.stdin.send_all(line)


class UnexpectedError(Exception):
    """Unexpected response."""


async def expect(p, prefixes, confidential=False):
    """Read a line and return it without required prefix."""
    resp = io.BytesIO()
    while True:
        c = await p.stdout.receive_some(1)
        if not c:
            raise IOError('Program abruptly closed after receiving: ' + str(resp.getvalue()))
        if c == b'\n':
            break
        resp.write(c)
    resp = resp.getvalue()
    log.debug('%s -> %r', p.args, resp if not confidential else '********')
    for prefix in prefixes:
        if resp.startswith(prefix):
            return resp[len(prefix):]
    raise UnexpectedError(resp)


async def interact(title, description, prompt, binary, options, is_message=False):
    """Use GPG pinentry program to interact with the user."""
    # pylint: disable=too-many-arguments
    async with trio.open_nursery() as nursery:
        p = await nursery.start(functools.partial(trio.run_process, [binary],
                                                  stdin=subprocess.PIPE,
                                                  stdout=subprocess.PIPE,
                                                  env=os.environ))
        await expect(p, [b'OK'])

        title = util.assuan_serialize(title.encode('ascii'))
        await write(p, b'SETTITLE ' + title + b'\n')
        await expect(p, [b'OK'])

        if description:
            description = util.assuan_serialize(description.encode('ascii'))
            await write(p, b'SETDESC ' + description + b'\n')
            await expect(p, [b'OK'])

        if prompt:
            prompt = util.assuan_serialize(prompt.encode('ascii'))
            await write(p, b'SETPROMPT ' + prompt + b'\n')
            await expect(p, [b'OK'])

        log.debug('setting %d options', len(options))
        for opt in options:
            await write(p, b'OPTION ' + opt + b'\n')
            await expect(p, [b'OK', b'ERR'])

        if is_message:
            await write(p, b'MESSAGE\n')
        else:
            await write(p, b'GETPIN\n')
        pin = await expect(p, [b'OK', b'D '], confidential=True)

        # close stdin and wait for the process to exit
        await p.stdin.aclose()
        async for _ in p.stdout:
            pass
        exit_code = await p.wait()
        if exit_code:
            raise subprocess.CalledProcessError(exit_code, binary)

        return pin.decode('ascii').strip()
