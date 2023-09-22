import functools
import io
import os
import tempfile

import pytest
import trio

from .. import server, util
from ..ssh import protocol


@pytest.mark.trio
async def test_socket():
    path = tempfile.mktemp()
    async with server.unix_domain_socket_server(path):
        pass
    assert not os.path.isfile(path)


class FakeSocket:

    def __init__(self, data=b'', recv_raises=None):
        self.rx = io.BytesIO(data)
        self.tx = io.BytesIO()
        self.recv_raises = recv_raises

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    async def send(self, data):
        self.tx.write(data)
        return len(data)

    async def recv(self, size):
        if self.recv_raises:
            toraise = self.recv_raises[0]
            self.recv_raises = self.recv_raises[1:]
            raise toraise
        return self.rx.read(size)

    def close(self):
        pass


# pylint: disable=too-few-public-methods
class EmptyDevice:
    async def parse_public_keys(self):
        return []


@pytest.mark.trio
async def test_handle():
    handler = protocol.Handler(conn=EmptyDevice())
    conn = FakeSocket()
    await server.handle_connection(conn, handler)

    msg = bytearray([protocol.msg_code('SSH_AGENTC_REQUEST_RSA_IDENTITIES')])
    conn = FakeSocket(util.frame(msg))
    await server.handle_connection(conn, handler)
    assert conn.tx.getvalue() == b'\x00\x00\x00\x05\x02\x00\x00\x00\x00'

    msg = bytearray([protocol.msg_code('SSH2_AGENTC_REQUEST_IDENTITIES')])
    conn = FakeSocket(util.frame(msg))
    await server.handle_connection(conn, handler)
    assert conn.tx.getvalue() == b'\x00\x00\x00\x05\x0C\x00\x00\x00\x00'

    msg = bytearray([protocol.msg_code('SSH2_AGENTC_ADD_IDENTITY')])
    conn = FakeSocket(util.frame(msg))
    await server.handle_connection(conn, handler)
    conn.tx.seek(0)
    reply = util.read_frame(conn.tx)
    assert reply == util.pack('B', protocol.msg_code('SSH_AGENT_FAILURE'))

    conn = FakeSocket(recv_raises=[Exception(), EOFError()])
    await server.handle_connection(conn=conn, handler=None)


@pytest.mark.trio
async def test_server_thread():
    sock = FakeSocket()
    connections = [sock]
    quit_event = trio.Event()

    class FakeServer:
        async def accept(self):
            if not connections:
                await trio.sleep_forever()
            return connections.pop(), 'address'

        def getsockname(self):
            return 'fake_server'

    async def handle_conn(conn):
        assert conn is sock
        quit_event.set()

    await server.server_thread(sock=FakeServer(),
                               handle_conn=handle_conn,
                               quit_event=quit_event)


@pytest.mark.trio
async def test_run():
    assert await server.run_process(['true'], environ={}) == 0
    assert await server.run_process(['false'], environ={}) == 1
    assert await server.run_process(command=['bash', '-c', 'exit $X'],
                                    environ={'X': '42'}) == 42

    with pytest.raises(OSError):
        await server.run_process([''], environ={})


@pytest.mark.trio
async def test_remove():
    path = 'foo.bar'
    paths = set()
    force_exists_paths = set()

    class FakePath:
        def __init__(self, paths, force_exists_paths, path):
            self.path = path
            self.paths = paths
            self.force_exists_paths = force_exists_paths

        async def unlink(self):
            if self.path not in self.paths:
                raise OSError('boom')
            self.paths.remove(self.path)

        async def exists(self):
            return self.path in self.paths or self.path in self.force_exists_paths

    fake_path = functools.partial(FakePath, paths, force_exists_paths)
    paths.add(path)

    await server.remove_file(path, trio_path=fake_path)

    await server.remove_file(path, trio_path=fake_path)

    force_exists_paths.add(path)

    with pytest.raises(OSError):
        await server.remove_file(path, trio_path=fake_path)
