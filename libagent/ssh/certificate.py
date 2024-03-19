"""Utilities for signing ssh-certificates."""
import io

from . import formats, util


def _parse_stringlist(i):
    res = []
    length, = util.recv(i, '>L')
    while length >= 4:
        size, = util.recv(i, '>L')
        length -= 4
        size = min(size, length)
        if size == 0:
            continue
        res.append(util.recv(i, size).decode('utf8'))
        length -= size
    return res


def parse(blob):
    """Parses a data blob to a to-be-signed ssh-certificate."""
    # https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys
    res = {}
    i = io.BytesIO(blob)
    firstString = util.read_frame(i)
    if firstString.endswith(b'cert-v01@openssh.com'):
        res['isCertificate'] = True
        _certificate_key_type = firstString
        _nonce = util.read_frame(i)
        if (_certificate_key_type.startswith(b'ssh-rsa')):
            _pub_key = {}
            _pub_key['e'] = util.read_frame(i)
            _pub_key['n'] = util.read_frame(i)
        elif (_certificate_key_type.startswith(b'ssh-dsa')):
            _pub_key = {}
            _pub_key['p'] = util.read_frame(i)
            _pub_key['q'] = util.read_frame(i)
            _pub_key['g'] = util.read_frame(i)
            _pub_key['y'] = util.read_frame(i)
        elif (_certificate_key_type.startswith(b'ecdsa-sha2-nistp')):
            _curve = util.read_frame(i)
            _pub_key = util.read_frame(i)
        elif (_certificate_key_type.startswith(b'ssh-ed25519')):
            _pub_key = util.read_frame(i)
        else:
            raise ValueError('unknown certificate key type: '+_certificate_key_type.decode('utf8'))
        _serial_number,  = util.recv(i, '>Q')
        res['certificate_type'],  = util.recv(i, '>L')
        _key_id_ = util.read_frame(i)
        res['principals'] = _parse_stringlist(i)
        res['principals'] = ', '.join(res['principals'])
        _valid_after, = util.recv(i, '>Q')
        _valid_before, = util.recv(i, '>Q')
        _critical_options = _parse_stringlist(i)
        _extensions = _parse_stringlist(i)
        _reserved = util.read_frame(i)
        _signature_key = util.read_frame(i)
        assert not i.read()
        return res
    res['isCertificate'] = False
    i.close()
    return res


def format(certificate):
    """
    Makes certificate better human readable.

    Formats list properties to comma seperated strings and
    the signature key to human readable string.
    """
    certificate['principals'] = ', '.join(certificate['principals'])
    certificate['critical_options'] = ', '.join(certificate['critical_options'])
    certificate['extensions'] = ', '.join(certificate['extensions'])
    certificate['signature_key'] = formats.parse_pubkey(certificate['signature_key'])
