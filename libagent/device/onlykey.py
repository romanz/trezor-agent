"""OnlyKey-related code (see https://www.onlykey.io/)."""

import binascii
import base64
import io
import logging
import re
import hashlib
import codecs
import struct
import sys
import unidecode
import os.path
from os import path

from . import interface
from .. import formats, util
from ..gpg import keyring

import ecdsa
import nacl.signing
import time
#import pgpy
#from pgpy import PGPKey


log = logging.getLogger(__name__)

class OnlyKey(interface.Device):
    """Connection to OnlyKey device."""

    @classmethod
    def package_name(cls):
        """Python package name (at PyPI)."""
        return 'onlykey-agent'

    @property
    def _defs(self):
        from . import onlykey_defs
        return onlykey_defs

    def connect(self):
        """Enumerate and connect to the first USB HID interface."""
        try:
            self.device_name = 'OnlyKey'
            self.ok = self._defs.OnlyKey()
        except :
            raise interface.NotFoundError('{} not connected: "{}"')

    def set_skey(self, skey):
        self.skeyslot = skey
        log.debug('Setting skey slot = %s', skey)

    def set_dkey(self, dkey):
        self.dkeyslot = dkey
        log.debug('Setting dkey slot = %s', dkey)

    def import_pub(self, pubkey):
        self.import_pubkey = pubkey
        log.debug('Public key to import = %s', pubkey)
        #self.import_pubkey_obj, _ = pgpy.PGPKey.from_blob(pubkey)
        #self.import_pubkey_bytes = bytes(self.import_pubkey_obj)

    def get_sk_dk(self):
        fpath = keyring.get_agent_sock_path()
        fpath = fpath.decode()
        fpath = fpath.replace("S.gpg-agent", "run-agent.sh")
        log.debug('Path to run-agent.sh = %s', fpath)
        if path.exists(fpath):
            with open(fpath) as f:
                s = f.read()
                if '--skey-slot=' in s:
                    if s[s.find('--skey-slot=')+13:s.find('--skey-slot=')+14] == ' ':
                        self.set_skey(int(s[s.find('--skey-slot=')+12:s.find('--skey-slot=')+13]))
                    else:
                        self.set_skey(int(s[s.find('--skey-slot=')+12:s.find('--skey-slot=')+15]))
                if '--dkey-slot=' in s:
                    if s[s.find('--dkey-slot=')+13:s.find('--dkey-slot=')+14] == ' ':
                        self.set_dkey(int(s[s.find('--dkey-slot=')+12:s.find('--dkey-slot=')+13]))
                    else:
                        self.set_dkey(int(s[s.find('--dkey-slot=')+12:s.find('--dkey-slot=')+15]))
        else:
            self.set_skey(132)
            self.set_dkey(132)


    def sighash(self, sighash):
        if sighash == b'rsa-sha2-512' or sighash == b'rsa-sha2-256':
            self.sighash = sighash
            log.info('Setting RSA signature Hash Type =%s', sighash)

    def close(self):
        """Close connection."""
        log.info('disconnected from %s', self.device_name)
        self.ok.close()

    def pubkey(self, identity, ecdh=False):
        curve_name = identity.get_curve_name(ecdh=ecdh)
    
        if identity.identity_dict['proto'] != 'ssh' and hasattr('self', 'skeyslot') == False:
            self.get_sk_dk()
            
        if identity.identity_dict['proto'] != 'ssh' and self.dkeyslot < 132 and ecdh==True:
            this_slot_id=self.dkeyslot
            log.info('Key Slot =%s', this_slot_id)
        elif self.skeyslot < 132 and ecdh==False:
            this_slot_id=self.skeyslot
            log.info('Key Slot =%s', this_slot_id)
        else:
            this_slot_id=132

        log.info('Requesting public key from key slot =%s', this_slot_id)

        log.debug('"%s" getting public key (%s) from %s',
                  identity.to_string(), curve_name, self)

        # Calculate hash for key derivation input data
        if identity.identity_dict['proto'] == 'ssh':
            id_parts = unidecode.unidecode(identity.identity_dict['user'] + '@' + identity.identity_dict['host']).encode('ascii')
        else:
            id_parts = identity.to_bytes()
        log.info('Identity to hash =%s', id_parts)
        h1 = hashlib.sha256()
        h1.update(id_parts)
        data = h1.hexdigest()
        log.info('Identity hash =%s', data)

        if this_slot_id>100:
            if curve_name == 'curve25519':
                data = '04' + data
            elif curve_name == 'secp256k1':
                # Not currently supported by agent, for future use
                data = '03' + data
            elif curve_name == 'nist256p1':
                data = '02' + data
            elif curve_name == 'ed25519':
                data = '01'+ data
        else:
            data = '00'+ data

        self.ok.send_message(msg=self._defs.Message.OKGETPUBKEY, slot_id=this_slot_id, payload=data)
        log.info('curve name= %s', repr(curve_name))
        t_end = time.time() + 1.5
        if (curve_name != 'rsa'):
            while time.time() < t_end:
                try:
                    ok_pubkey = self.ok.read_bytes(timeout_ms=100)
                    if len(ok_pubkey) == 64 and len(set(ok_pubkey[0:63])) != 1:
                        break
                except Exception as e:
                    raise interface.DeviceError(e)
                    return

            log.info('received= %s', repr(ok_pubkey))
            if len(set(ok_pubkey[34:63])) == 1:
                if curve_name == 'nist256p1' or curve_name == 'secp256k1':
                    raise interface.DeviceError("Public key curve does not match requested type")
                ok_pubkey = bytearray(ok_pubkey[0:32])
                log.info('Received Public Key generated by OnlyKey= %s', repr(ok_pubkey.hex()))


                


                vk = nacl.signing.VerifyKey(bytes(ok_pubkey),
                                        encoder=nacl.encoding.RawEncoder)
                time.sleep(3)
                return vk
            elif len(ok_pubkey) == 64:
                ok_pubkey = bytearray(ok_pubkey[0:64])
                if curve_name == 'ed25519' or curve_name == 'curve25519':
                    raise interface.DeviceError("Public key curve does not match requested type")
                log.info('Received Public Key generated by OnlyKey= %s', repr(ok_pubkey))
                if identity.curve_name == 'nist256p1':
                    vk = ecdsa.VerifyingKey.from_string(ok_pubkey, curve=ecdsa.NIST256p)
                else:
                    vk = ecdsa.VerifyingKey.from_string(ok_pubkey, curve=ecdsa.SECP256k1)
                return vk
        else:
            ok_pubkey = []
            while time.time() < t_end:
                try:
                    ok_pub_part = self.ok.read_bytes(timeout_ms=100)
                    if len(ok_pub_part) == 64 and len(set(ok_pub_part[0:63])) != 1:
                        log.info('received part= %s', repr(ok_pub_part))
                        ok_pubkey += ok_pub_part
                        #Todo know RSA type to know how many packets
                except Exception as e:
                    raise interface.DeviceError(e)
                    return

            log.info('received= %s', repr(ok_pubkey))

            if len(ok_pubkey) == 256:
                # https://security.stackexchange.com/questions/42268/how-do-i-get-the-rsa-bit-length-with-the-pubkey-and-openssl
                ok_pubkey = b'\x00\x00\x00\x07' + b'\x73\x73\x68\x2d\x72\x73\x61' + b'\x00\x00\x00\x03' + b'\x01\x00\x01' + b'\x00\x00\x01\x01' + b'\x00' + bytes(ok_pubkey)
                #ok_pubkey = b'\x00\x00\x00\x07' + b'\x72\x73\x61\x2d\x73\x68\x61\x32\x2d\x32\x35\x36' + b'\x00\x00\x00\x03' + b'\x01\x00\x01' + b'\x00\x00\x01\x01' + b'\x00' + bytes(ok_pubkey)

            elif len(ok_pubkey) == 512:
                ok_pubkey = b'\x00\x00\x00\x07' + b'\x73\x73\x68\x2d\x72\x73\x61' + b'\x00\x00\x00\x03' + b'\x01\x00\x01' + b'\x00\x00\x02\x01' + b'\x00' + bytes(ok_pubkey)

            log.info('pubkey len = %s', len(ok_pubkey))
            return ok_pubkey

            raise interface.DeviceError("Error response length is not a valid public key")


    def sign(self, identity, blob):
        """Sign given blob and return the signature (as bytes)."""
        curve_name = identity.get_curve_name(ecdh=False)
        log.debug('"%s" signing %r (%s) on %s',
                  identity.to_string(), blob, curve_name, self)

        if identity.identity_dict['proto'] != 'ssh' and hasattr('self', 'skeyslot') == False:
            self.get_sk_dk()
        
        # Calculate hash for SSH signing
        if self.sighash == b'rsa-sha2-512':
            log.info('rsa-sha2-512')
            h1 = hashlib.sha512()
            h1.update(blob)
            data = h1.hexdigest()
            data = codecs.decode(data, 'hex_codec')
        elif self.sighash == b'rsa-sha2-256':
            log.info('rsa-sha2-256')
            h1 = hashlib.sha256()
            h1.update(blob)
            data = h1.hexdigest()
            data = codecs.decode(data, 'hex_codec')
        else:
            # Calculate hash for key derivation input data
            h1 = hashlib.sha256()
            if identity.identity_dict['proto'] == 'ssh':
                id_parts = unidecode.unidecode(identity.identity_dict['user'] + '@' + identity.identity_dict['host']).encode('ascii')
            else:
                id_parts = identity.to_bytes()
            h1.update(id_parts)
            data = h1.hexdigest()
            data = codecs.decode(data, 'hex_codec')
            log.info('Identity to hash =%s', id_parts)
            log.info('Identity hash =%s', data)

        # Determine type of key to derive on OnlyKey for signature
        # Slot 132 used for derived key, slots 101-116 used for stored ecc keys, slots 1-4 used for stored RSA keys
        if (self.skeyslot==132):
            if curve_name == 'ed25519':
                this_slot_id = 201
                log.info('Key type ed25519')
            elif curve_name == 'nist256p1':
                this_slot_id = 202
                log.info('Key type nistp256')
            else:
                this_slot_id = 203
                log.info('Key type secp256k1')
            # Send data and identity hash
            raw_message = blob + data
        else:
            this_slot_id = self.skeyslot
            # Send just data to sign
            raw_message = blob

        h2 = hashlib.sha256()
        h2.update(raw_message)
        d = h2.digest()

        assert len(d) == 32

        def get_button(byte):
            return byte % 6 + 1

        b1, b2, b3 = get_button(d[0]), get_button(d[15]), get_button(d[31])
        
        log.info('Key Slot =%s', this_slot_id)

        print ('Enter the 3 digit challenge code on OnlyKey to authorize ' + identity.to_string())
        print ('{} {} {}'.format(b1, b2, b3))

        t_end = time.time() + 22
        if (curve_name != 'rsa'):
            self.ok.send_large_message2(msg=self._defs.Message.OKSIGN, payload=raw_message, slot_id=this_slot_id)
            while time.time() < t_end:
                try:
                    result = self.ok.read_bytes(timeout_ms=100)
                    if len(result) == 64 and len(set(result[0:63])) != 1:
                        break
                except Exception as e:
                    raise interface.DeviceError(e)
                    return

            if len(result) >= 60:
                log.info('received= %s', repr(result))
                while len(result) < 64:
                    result.append(0)
                log.info('disconnected from %s', self.device_name)
                self.ok.close()
                return bytes(result)
        else:
            self.ok.send_large_message2(msg=self._defs.Message.OKSIGN, payload=data, slot_id=this_slot_id )
            result = []
            while time.time() < t_end:
                try:
                    sig_part = self.ok.read_bytes(timeout_ms=100)
                    if len(sig_part) == 64 and len(set(sig_part[0:63])) != 1:
                        log.info('received part= %s', repr(sig_part))
                        result += sig_part
                        t_end = time.time() + 1
                        #Todo know RSA type to know how many packets
                except Exception as e:
                    raise interface.DeviceError(e)
                    return

            log.info('received= %s', repr(result))
            return bytes(result)

        raise Exception('failed to sign challenge')


    def ecdh(self, identity, pubkey):
        """Get shared session key using Elliptic Curve Diffie-Hellman."""
        curve_name = identity.get_curve_name(ecdh=True)
        log.debug('"%s" shared session key (%s) for %r from %s',
                  identity.to_string(), curve_name, pubkey, self)

        # Calculate hash for key derivation input data
        h1 = hashlib.sha256()
        if identity.identity_dict['proto'] == 'ssh':
            id_parts = unidecode.unidecode(identity.identity_dict['user'] + '@' + identity.identity_dict['host']).encode('ascii')
        else:
            id_parts = identity.to_bytes()
        h1.update(id_parts)
        log.info('Identity to hash =%s', id_parts)
        data = h1.hexdigest()
        log.info('Identity hash =%s', data)
        data = codecs.decode(data, 'hex_codec')    

        # Determine type of key to derive on OnlyKey for ecdh
        # Slot 132 used for derived key, slots 101-116 used for stored ecc keys, slots 1-4 used for stored RSA keys
        if (self.dkeyslot==132):
            if curve_name == 'curve25519':
                this_slot_id = 204
                log.info('Key type curve25519')
            elif curve_name == 'nist256p1':
                this_slot_id = 202
                log.info('Key type nistp256')
            else:
                this_slot_id = 203
                log.info('Key type secp256k1')
            raw_message = pubkey + data
        else:
            this_slot_id = self.dkeyslot
            raw_message = pubkey
        
        log.info('Key Slot =%s', this_slot_id)

        log.info('data hash =%s', data)
        h2 = hashlib.sha256()
        h2.update(raw_message)
        d = h2.digest()
        assert len(d) == 32

        def get_button(byte):
            return byte % 6 + 1

        b1, b2, b3 = get_button(d[0]), get_button(d[15]), get_button(d[31])

        log.info('blob to send', repr(raw_message))

        self.ok.send_large_message2(msg=self._defs.Message.OKDECRYPT, payload=raw_message, slot_id=this_slot_id)

        print ('Enter the 3 digit challenge code on OnlyKey to authorize ' + identity.to_string())
        print ('{} {} {}'.format(b1, b2, b3))

        t_end = time.time() + 22
        if (curve_name != 'rsa'):
            while time.time() < t_end:
                try:
                    result = self.ok.read_bytes(timeout_ms=100)
                    if len(result) == 64 and len(set(result[0:63])) != 1:
                        break
                except Exception as e:
                    raise interface.DeviceError(e)
                    return
            if  len(set(result[34:63])) == 1:
                result = b'\x04' + bytes(result[0:32])
        else:
            result = []
            while time.time() < t_end:
                try:
                    dec_part = self.ok.read_bytes(timeout_ms=100)
                    if len(sig_part) == 64 and len(set(dec_part[0:63])) != 1:
                        log.info('received part= %s', repr(dec_part))
                        result += dec_part
                        t_end = time.time() + 1
                        #Todo know RSA type to know how many packets
                except Exception as e:
                    raise interface.DeviceError(e)
                    return

        log.info('received= %s', repr(result))
        log.info('disconnected from %s', self.device_name)
        self.ok.close()

        return bytes(result)

        raise Exception('failed to generate shared session key')


_identity_regexp = re.compile(''.join([
    '^'
    r'(?:(?P<proto>.*)://)?',
    r'(?:(?P<user>.*)@)?',
    r'(?P<host>.*?)',
    r'(?::(?P<port>\w*))?',
    r'(?P<path>/.*)?',
    '$'
]))

def string_to_identity(s, identity_type=dict):
    """Parse string into Identity protobuf."""
    m = _identity_regexp.match(s)
    result = m.groupdict()
    log.debug('parsed identity: %s', result)
    kwargs = {k: v for k, v in result.items() if v}
    return identity_type(**kwargs)

def _parse_ssh_blob(data):
    res = {}
    i = io.BytesIO(data)
    res['nonce'] = util.read_frame(i)
    i.read(1)  # SSH2_MSG_USERAUTH_REQUEST == 50 (from ssh2.h, line 108)
    res['user'] = util.read_frame(i)
    res['conn'] = util.read_frame(i)
    res['auth'] = util.read_frame(i)
    i.read(1)  # have_sig == 1 (from sshconnect2.c, line 1056)
    res['key_type'] = util.read_frame(i)
    public_key = util.read_frame(i)
    res['public_key'] = formats.parse_pubkey(public_key)
    assert not i.read()
    return res

def bytes2num(s):
    """Convert MSB-first bytes to an unsigned integer."""
    res = 0
    for i, c in enumerate(reversed(bytearray(s))):
        res += c << (i * 8)
    return res
