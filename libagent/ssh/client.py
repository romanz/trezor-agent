"""
Connection to hardware authentication device.

It is used for getting SSH public keys and ECDSA signing of server requests.
"""
import io
import logging

from . import formats, util

log = logging.getLogger(__name__)

SUPPORTED_CERT_TYPES = {
    formats.SSH_ED25519_CERT_TYPE,
    formats.SSH_NIST256_CERT_TYPE,
}


class Client:
    """Client wrapper for SSH authentication device."""

    def __init__(self, device):
        """Connect to hardware device."""
        self.device = device

    def export_public_keys(self, identities):
        """Export SSH public keys from the device."""
        pubkeys = []
        with self.device:
            for i in identities:
                vk = self.device.pubkey(identity=i)
                label = i.to_string()
                pubkey = formats.export_public_key(vk=vk, label=label)
                pubkeys.append(pubkey)
        return pubkeys

    def sign_ssh_challenge(self, blob, identity):
        """Sign given blob using a private key on the device."""
        log.debug('blob (%d bytes): %r', len(blob), blob)
        msg = parse_ssh_blob(blob)
        log.debug('parsed: %r', msg)

        identity_str = identity.to_string()
        if msg['sshsig']:
            log.info('please confirm "%s" signature for "%s" using %s...',
                     msg['namespace'], identity_str, self.device)
        else:
            log.info('please confirm "%s" signature for "%s" using %s...',
                     msg['key_type'].decode('ascii'), identity_str, self.device)

        with self.device:
            return self.device.sign(blob=blob, identity=identity)


def parse_ssh_blob(data):
    """Parse binary data into a dict."""
    res = {}
    if data.startswith(b'SSHSIG'):
        i = io.BytesIO(data[6:])
        # https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig
        res['sshsig'] = True
        res['namespace'] = util.read_frame(i)
        res['reserved'] = util.read_frame(i)
        res['hashalg'] = util.read_frame(i)
        res['message'] = util.read_frame(i)
    else:
        i = io.BytesIO(data)
        res['sshsig'] = False
        first_frame = util.read_frame(i)
        # https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys
        is_cert = first_frame in SUPPORTED_CERT_TYPES
        if is_cert:
            # see `sshkey_certify_custom()` for details:
            # https://github.com/openssh/openssh-portable/blob/master/sshkey.c
            res['key_type'] = first_frame
            res['nonce'] = util.read_frame(i)
            if first_frame == formats.SSH_NIST256_CERT_TYPE:
                res['curve'] = util.read_frame(i)
            res['pubkey'] = util.read_frame(i)
            res['serial_number'] = util.recv(i, '>Q')
            res['type'] = util.recv(i, '>L')
            res['key_id'] = util.read_frame(i)
            res['valid_principals'] = tuple(_iter_parse_list(util.read_frame(i)))
            res['valid_after'] = util.recv(i, '>Q')
            res['valid_before'] = util.recv(i, '>Q')
            res['critical_options'] = tuple(_iter_parse_list(util.read_frame(i)))
            res['extensions'] = tuple(_iter_parse_list(util.read_frame(i)))
            res['reserved'] = util.read_frame(i)
            res['signature_key'] = util.read_frame(i)
        else:
            res['nonce'] = first_frame
            i.read(1)  # SSH2_MSG_USERAUTH_REQUEST == 50 (from ssh2.h, line 108)
            res['user'] = util.read_frame(i)
            res['conn'] = util.read_frame(i)
            res['auth'] = util.read_frame(i)
            i.read(1)  # have_sig == 1 (from sshconnect2.c, line 1056)
            res['key_type'] = util.read_frame(i)
            public_key = util.read_frame(i)
            res['public_key'] = formats.parse_pubkey(public_key)
            if res['auth'] == b'publickey-hostbound-v00@openssh.com':
                res['server_host_key'] = formats.parse_pubkey(util.read_frame(i))

    unparsed = i.read()
    if unparsed:
        log.warning('unparsed blob: %r', unparsed)
    return res


def _iter_parse_list(blob):
    i = io.BytesIO(blob)
    while i.tell() < len(blob):
        yield util.read_frame(i)
