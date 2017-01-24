import socket
from struct import unpack, pack, pack_into
from datetime import datetime
from base64 import b64decode
import time
from Crypto import Random
from Crypto.Hash import SHA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.PublicKey import RSA
from ecdsa import SigningKey
import pyelliptic


typMap = {
    20:  'change_cipher_spec',
    21: 'alert',
    22: 'handshake',
    23: 'application-data'
}

verMap = {
    (3, 1): 'TLS1.0',
    (3, 3): 'TLS1.2'
}

msgTypMap = {
    0: 'hello_request',
    1: 'client_hello',
    2: 'server_hello',
    11: 'certificate',
    12: 'server_key_exchange',
    15: 'certificate_request',
    16: 'server_hello_done',
    20: 'finished'
}

cipherMap = {
    (0x00, 0x00): 'CipherSuite TLS_NULL_WITH_NULL_NULL',
    (0x00, 0x01): 'TLS_RSA_WITH_NULL_MD5',
    (0x00, 0x02): 'TLS_RSA_WITH_NULL_SHA',
    (0x00, 0x3B): 'TLS_RSA_WITH_NULL_SHA256',
    (0x00, 0x04): 'TLS_RSA_WITH_RC4_128_MD5',
    (0x00, 0x05): 'TLS_RSA_WITH_RC4_128_SHA',
    (0x00, 0x0A): 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
    (0x00, 0x2F): 'TLS_RSA_WITH_AES_128_CBC_SHA',
    (0x00, 0x35): 'TLS_RSA_WITH_AES_256_CBC_SHA',
    (0x00, 0x3C): 'TLS_RSA_WITH_AES_128_CBC_SHA256',
    (0x00, 0x3D): 'TLS_RSA_WITH_AES_256_CBC_SHA256',
    (0x00,0x0D): 'TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA',
    (0x00,0x10): 'TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA',
    (0x00,0x13): 'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA',
    (0x00,0x16): 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA',
    (0x00,0x30): 'TLS_DH_DSS_WITH_AES_128_CBC_SHA',
    (0x00,0x31): 'TLS_DH_RSA_WITH_AES_128_CBC_SHA',
    (0x00,0x32): 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA',
    (0x00,0x33): 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
    (0x00,0x36): 'TLS_DH_DSS_WITH_AES_256_CBC_SHA',
    (0x00,0x37): 'TLS_DH_RSA_WITH_AES_256_CBC_SHA',
    (0x00,0x38): 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA',
    (0x00,0x39): 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA',
    (0x00,0x3E): 'TLS_DH_DSS_WITH_AES_128_CBC_SHA256',
    (0x00,0x3F): 'TLS_DH_RSA_WITH_AES_128_CBC_SHA256',
    (0x00,0x40): 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256',
    (0x00,0x67): 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256',
    (0x00,0x68): 'TLS_DH_DSS_WITH_AES_256_CBC_SHA256',
    (0x00,0x69): 'TLS_DH_RSA_WITH_AES_256_CBC_SHA256',
    (0x00,0x6A): 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256',
    (0x00,0x6B): 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256',
    (0x00,0x18): 'TLS_DH_anon_WITH_RC4_128_MD5',
    (0x00,0x1B): 'TLS_DH_anon_WITH_3DES_EDE_CBC_SHA',
    (0x00,0x34): 'TLS_DH_anon_WITH_AES_128_CBC_SHA',
    (0x00,0x3A): 'TLS_DH_anon_WITH_AES_256_CBC_SHA',
    (0x00,0x6C): 'TLS_DH_anon_WITH_AES_128_CBC_SHA256',
    (0x00,0x6D): 'TLS_DH_anon_WITH_AES_256_CBC_SHA256',
    (0x00,0x96): 'TLS_RSA_WITH_SEED_CBC_SHA',
    (0x00,0x97): 'TLS_DH_DSS_WITH_SEED_CBC_SHA',
    (0x00,0x98): 'TLS_DH_RSA_WITH_SEED_CBC_SHA',
    (0x00,0x99): 'TLS_DHE_DSS_WITH_SEED_CBC_SHA',
    (0x00,0x9A): 'TLS_DHE_RSA_WITH_SEED_CBC_SHA',
    (0x00,0x9B): 'TLS_DH_anon_WITH_SEED_CBC_SHA',
    (0x00,0x09): 'TLS_RSA_WITH_DES_CBC_SHA',
    (0x00,0x0C): 'TLS_DH_DSS_WITH_DES_CBC_SHA',
    (0x00,0x0F): 'TLS_DH_RSA_WITH_DES_CBC_SHA',
    (0x00,0x12): 'TLS_DHE_DSS_WITH_DES_CBC_SHA',
    (0x00,0x15): 'TLS_DHE_RSA_WITH_DES_CBC_SHA',
    (0x00,0x1A): 'TLS_DH_anon_WITH_DES_CBC_SHA',
    (0x00,0x0B): 'TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA',
    (0x00,0x0C): 'TLS_DH_DSS_WITH_DES_CBC_SHA',
    (0x00,0x0D): 'TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA',
    (0x00,0x0E): 'TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA',
    (0x00,0x0F): 'TLS_DH_RSA_WITH_DES_CBC_SHA',
    (0x00,0x10): 'TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA',
    (0x00,0x11): 'TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA',
    (0x00,0x12): 'TLS_DHE_DSS_WITH_DES_CBC_SHA',
    (0x00,0x13): 'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA',
    (0x00,0x14): 'TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA',
    (0x00,0x15): 'TLS_DHE_RSA_WITH_DES_CBC_SHA',
    (0x00,0x16): 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA',
    (0x00,0x17): 'TLS_DH_anon_EXPORT_WITH_RC4_40_MD5',
    (0x00,0x18): 'TLS_DH_anon_WITH_RC4_128_MD5',
    (0x00,0x19): 'TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA',
    (0x00,0x1A): 'TLS_DH_anon_WITH_DES_CBC_SHA',
    (0x00,0x1B): 'TLS_DH_anon_WITH_3DES_EDE_CBC_SHA',
    (0x00,0x01): 'TLS_RSA_WITH_NULL_MD5',
    (0x00,0x02): 'TLS_RSA_WITH_NULL_SHA',
    (0x00,0x03): 'TLS_RSA_EXPORT_WITH_RC4_40_MD5',
    (0x00,0x04): 'TLS_RSA_WITH_RC4_128_MD5',
    (0x00,0x05): 'TLS_RSA_WITH_RC4_128_SHA',
    (0x00,0x06): 'TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5',
    (0x00,0x07): 'TLS_RSA_WITH_IDEA_CBC_SHA',
    (0x00,0x08): 'TLS_RSA_EXPORT_WITH_DES40_CBC_SHA',
    (0x00,0x09): 'TLS_RSA_WITH_DES_CBC_SHA',
    (0x00,0x0A): 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
    (0x00,0xFF): 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV',
    (0xC0,0x2B): 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
    (0xC0,0x2C): 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
    (0xC0,0x2D): 'TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256',
    (0xC0,0x2E): 'TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384',
    (0xC0,0x2F): 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    (0xC0,0x30): 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    (0xC0,0x31): 'TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256',
    (0xC0,0x32): 'TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384',
    (0xC0,0x23): 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
    (0xC0,0x24): 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
    (0xC0,0x25): 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256',
    (0xC0,0x26): 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384',
    (0xC0,0x27): 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
    (0xC0,0x28): 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
    (0xC0,0x29): 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256',
    (0xC0,0x2A): 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384',
    (0xC0,0x2B): 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
    (0xC0,0x2C): 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
    (0xC0,0x2D): 'TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256',
    (0xC0,0x2E): 'TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384',
    (0xC0,0x2F): 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    (0xC0,0x30): 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    (0xC0,0x31): 'TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256',
    (0xC0,0x32): 'TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384',
    (0xC0, 0x01): 'TLS_ECDH_ECDSA_WITH_NULL_SHA',
    (0xC0, 0x02): 'TLS_ECDH_ECDSA_WITH_RC4_128_SHA',
    (0xC0, 0x03): 'TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA',
    (0xC0, 0x04): 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA',
    (0xC0, 0x05): 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA',
    (0xC0, 0x06): 'TLS_ECDHE_ECDSA_WITH_NULL_SHA',
    (0xC0, 0x07): 'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA',
    (0xC0, 0x08): 'TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA',
    (0xC0, 0x09): 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
    (0xC0, 0x0A): 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
    (0xC0, 0x0B): 'TLS_ECDH_RSA_WITH_NULL_SHA',
    (0xC0, 0x0C): 'TLS_ECDH_RSA_WITH_RC4_128_SHA',
    (0xC0, 0x0D): 'TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA',
    (0xC0, 0x0E): 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA',
    (0xC0, 0x0F): 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA',
    (0xC0, 0x10): 'TLS_ECDHE_RSA_WITH_NULL_SHA',
    (0xC0, 0x11): 'TLS_ECDHE_RSA_WITH_RC4_128_SHA',
    (0xC0, 0x12): 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA',
    (0xC0, 0x13): 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
    (0xC0, 0x14): 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
    (0xC0, 0x15): 'TLS_ECDH_anon_WITH_NULL_SHA',
    (0xC0, 0x16): 'TLS_ECDH_anon_WITH_RC4_128_SHA',
    (0xC0, 0x17): 'TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA',
    (0xC0, 0x18): 'TLS_ECDH_anon_WITH_AES_128_CBC_SHA',
    (0xC0, 0x19): 'TLS_ECDH_anon_WITH_AES_256_CBC_SHA',
    (0x00,0x9C): 'TLS_RSA_WITH_AES_128_GCM_SHA256',
    (0x00,0x9D): 'TLS_RSA_WITH_AES_256_GCM_SHA384',
    (0x00,0x9E): 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',
    (0x00,0x9F): 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
    (0x00,0xA0): 'TLS_DH_RSA_WITH_AES_128_GCM_SHA256',
    (0x00,0xA1): 'TLS_DH_RSA_WITH_AES_256_GCM_SHA384',
    (0x00,0xA2): 'TLS_DHE_DSS_WITH_AES_128_GCM_SHA256',
    (0x00,0xA3): 'TLS_DHE_DSS_WITH_AES_256_GCM_SHA384',
    (0x00,0xA4): 'TLS_DH_DSS_WITH_AES_128_GCM_SHA256',
    (0x00,0xA5): 'TLS_DH_DSS_WITH_AES_256_GCM_SHA384',
    (0x00,0xA6): 'TLS_DH_anon_WITH_AES_128_GCM_SHA256',
    (0x00,0xA7): 'TLS_DH_anon_WITH_AES_256_GCM_SHA384',
    (0x00, 0x8A): 'TLS_PSK_WITH_RC4_128_SHA',
    (0x00, 0x8B): 'TLS_PSK_WITH_3DES_EDE_CBC_SHA',
    (0x00, 0x8C): 'TLS_PSK_WITH_AES_128_CBC_SHA',
    (0x00, 0x8D): 'TLS_PSK_WITH_AES_256_CBC_SHA',
    (0x00, 0x8E): 'TLS_DHE_PSK_WITH_RC4_128_SHA',
    (0x00, 0x8F): 'TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA',
    (0x00, 0x90): 'TLS_DHE_PSK_WITH_AES_128_CBC_SHA',
    (0x00, 0x91): 'TLS_DHE_PSK_WITH_AES_256_CBC_SHA',
    (0x00, 0x92): 'TLS_RSA_PSK_WITH_RC4_128_SHA',
    (0x00, 0x93): 'TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA',
    (0x00, 0x94): 'TLS_RSA_PSK_WITH_AES_128_CBC_SHA',
    (0x00, 0x95): 'TLS_RSA_PSK_WITH_AES_256_CBC_SHA',
    (0x00,0xA8): 'TLS_PSK_WITH_AES_128_GCM_SHA256',
    (0x00,0xA9): 'TLS_PSK_WITH_AES_256_GCM_SHA384',
    (0x00,0xAA): 'TLS_DHE_PSK_WITH_AES_128_GCM_SHA256',
    (0x00,0xAB): 'TLS_DHE_PSK_WITH_AES_256_GCM_SHA384',
    (0x00,0xAC): 'TLS_RSA_PSK_WITH_AES_128_GCM_SHA256',
    (0x00,0xAD): 'TLS_RSA_PSK_WITH_AES_256_GCM_SHA384',
    (0x00,0xAE): 'TLS_PSK_WITH_AES_128_CBC_SHA256',
    (0x00,0xAF): 'TLS_PSK_WITH_AES_256_CBC_SHA384',
    (0x00,0xB0): 'TLS_PSK_WITH_NULL_SHA256',
    (0x00,0xB1): 'TLS_PSK_WITH_NULL_SHA384',
    (0x00,0xB2): 'TLS_DHE_PSK_WITH_AES_128_CBC_SHA256',
    (0x00,0xB3): 'TLS_DHE_PSK_WITH_AES_256_CBC_SHA384',
    (0x00,0xB4): 'TLS_DHE_PSK_WITH_NULL_SHA256',
    (0x00,0xB5): 'TLS_DHE_PSK_WITH_NULL_SHA384',
    (0x00,0xB6): 'TLS_RSA_PSK_WITH_AES_128_CBC_SHA256',
    (0x00,0xB7): 'TLS_RSA_PSK_WITH_AES_256_CBC_SHA384',
    (0x00,0xB8): 'TLS_RSA_PSK_WITH_NULL_SHA256',
    (0x00,0xB9): 'TLS_RSA_PSK_WITH_NULL_SHA384',
    ( 0x00,0x41 ): 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA',
    ( 0x00,0x42 ): 'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA',
    ( 0x00,0x43 ): 'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA',
    ( 0x00,0x44 ): 'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA',
    ( 0x00,0x45 ): 'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA',
    ( 0x00,0x46 ): 'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA',
    ( 0x00,0x84 ): 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA',
    ( 0x00,0x85 ): 'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA',
    ( 0x00,0x86 ): 'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA',
    ( 0x00,0x87 ): 'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA',
    ( 0x00,0x88 ): 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA',
}

compressMap = {
    0: 'null',
    1: 'DEFLATE',
    255: '255'
}

etMap = {
    0: 'server_name',
    1: 'max_fragment_length',
    2: 'client_certificate_url ',
    3: 'trusted_ca_keys',
    4: 'truncated_hmac',
    5: 'status_request',
    6: 'user_mapping',
    7: 'client_authz',
    8: 'server_authz',
    9: 'cert_type',
    10: 'supported_groups (renamed from "elliptic_curves")',
    11: 'ec_point_formats',
    12: 'srp',
    13: 'signature_algorithms',
    14: 'use_srtp',
    15: 'heartbeat',
    16: 'application_layer_protocol_negotiation',
    17: 'status_request_v2  ',
    18: 'signed_certificate_timestamp   ',
    19: 'client_certificate_type',
    20: 'server_certificate_type',
    21: 'padding',
    22: 'encrypt_then_mac',
    23: 'extended_master_secret ',
    24: 'token_binding',
    25: 'cached_info',
    35: 'SessionTicket TLS',
    65281: 'renegotiation_info',
}

namedCurve = {
    "sect163k1": 1,
    "sect163r1": 2,
    "sect163r2": 3,
    "sect193r1": 4,
    "sect193r2": 5,
    "sect233k1": 6,
    "sect233r1": 7,
    "sect239k1": 8,
    "sect283k1": 9,
    "sect283r1": 10,
    "sect409k1": 11,
    "sect409r1": 12,
    "sect571k1": 13,
    "sect571r1": 14,
    "secp160k1": 15,
    "secp160r1": 16,
    "secp160r2": 17,
    "secp192k1": 18,
    "secp192r1": 19,
    "secp224k1": 20,
    "secp224r1": 21,
    "secp256k1": 22,
    "secp256r1": 23,
    "secp384r1": 24,
    "secp521r1": 25,
    "arbitrary_explicit_prime_curves": 0xFF01,
    "arbitrary_explicit_char2_curves": 0xFF02,
}

def to3bytes(x):
    return (x >> 16, (x >> 8 & 0x00FF), x & 0x0000FF)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 443))
s.listen(10240)

while True:
    c, address = s.accept()
    print("Receive new connection " + ":".join((str(i) for i in address)));
    data = c.recv(5)
    data = unpack('!BBBH', data)
    typ, major, minor, length = data[0], data[1], data[2], data[3]
    print('type: {0}'.format(typMap[typ]))
    print('version: {0}'.format(verMap[(major, minor)]))
    print('length: {0}'.format(length))

    fragment = c.recv(length)

    if typMap[typ] == 'handshake':
        msg_type, len1, len2, len3 = unpack('!BBBB', fragment[:4])
        print('Handshake type: {0}'.format(msgTypMap[msg_type]))
        print('Handshake length: {0}'.format(len1 * 65536 + len2 * 256 + len3))

	if msgTypMap[msg_type] == 'client_hello':
	    #  struct {
	    #    ProtocolVersion client_version;
	    #    Random random;
	    #    SessionID session_id;
	    #    CipherSuite cipher_suites<2..2^16-2>;
	    #    CompressionMethod compression_methods<1..2^8-1>;
	    #    select (extensions_present) {
	    #        case false:
	    #            struct {};
	    #        case true:
	    #            Extension extensions<0..2^16-1>;
	    #    };
	    # } ClientHello;
		major, minor = unpack('!BB', fragment[4:6])
        print('Client Hello version: {0}'.format(verMap[(major, minor)]))

        gmt, random = unpack('!I28s', fragment[6: 6 + 32])
        print('Client Hello GMT: {0}'.format(datetime.fromtimestamp(gmt).strftime('%Y-%m-%d %H:%M:%S')))
        print('Client Hello RANDOM: {0}'.format("".join([str(ord(t)) for t in random])))

        sid_len, = unpack('!B', fragment[38:39])
        print('Client Hello Session ID Length: {0}'.format(sid_len))

        cipher_suites1, cipher_suites2 = unpack('!2B', fragment[39: 41])
        cipher_suites_len = cipher_suites1 * 256 + cipher_suites2
        print('Client Hello Cipher Suites Length: {0}'.format(cipher_suites_len));

        cipher_suites = unpack('!' + str(cipher_suites_len) + 'B', fragment[41: 41 + cipher_suites_len])
        for i in range(0, cipher_suites_len, 2):
            print('Client Hello Cipher Suite: {0}'.format(cipherMap[(cipher_suites[i], cipher_suites[i+1])]))

        odd = fragment[41 + cipher_suites_len:]

        compression_method_len, = unpack('!B', odd[:1])
        print('Client Hello Compression Method Length: {0}'.format(compression_method_len));

        odd = odd[1:]
        compression_methods = unpack('!' + str(compression_method_len) + 'B', odd[:compression_method_len])
        for i in compression_methods:
            print('Client Hello Compression Method: {0}'.format(compressMap[i]))

        odd = odd[compression_method_len:]

        extensions_len, = unpack('!H', odd[:2])
        print('Client Hello Extensions Length: {0}'.format(extensions_len));

        odd = odd[2:]

        while True:
            if len(odd) == 0:
                break
            et, et_len = unpack('!HH', odd[:4])
            print('Client Hello Extensions Type: {0}'.format(etMap[et]))
            print('Client Hello Extensions Length: {0}'.format(et_len))

            odd = odd[4:]
            old_odd = odd

            if et_len == 0:
                continue

            if etMap[et] == 'server_name':
                sni_len, = unpack('!H', odd[:2])
                print('Client Hello Extensions SNI Length: {0}'.format(sni_len))
                odd = odd[2:]
                sni_type, = unpack('!B', odd[:1])
                print('Client Hello Extensions SNI Type: {0}'.format(sni_type))

                odd = odd[1:]
                sni_hostname_len, = unpack('!H', odd[:2])

                odd = odd[2:]
                sni_hostname = unpack('!' + str(sni_hostname_len) + 'B', odd[:sni_hostname_len])

                print('Client Hello Extensions SNI host name Length: {0}'.format(sni_hostname_len))
                print('Client Hello Extensions SNI: {0}'.format("".join([chr(i) for i in sni_hostname])))

    	    elif etMap[et] == 'SessionTicket TLS':
                st_len = unpack('!H', odd[:2])
                print('Client Hello Extensions Session Ticket Length: {0}'.format(st_len))
                odd = odd[2:]

                data = unpack('!' + str(st_len) + 'B', odd[:st_len])
                print('Client Hello Extensions Session Ticket: {0}'.format(data))

            elif etMap[et]  == 'application_layer_protocol_negotiation':
                alpn_len, = unpack('!H', odd[:2])
                print('Cilent Hello Extensions ALPN Length: {0}'.format(alpn_len))
                odd = odd[2:]

                alpn = unpack('!' + str(alpn_len) + 'B', odd[:alpn_len])
                while alpn_len > 0:
                    alpn_str_len = int(alpn[0])
                    print('Client Hello Extensions ALPN String Length: {0}'.format(alpn_str_len))
                    alpn_str = alpn[1:1+alpn_str_len]
                    print('Client Hello Extensions ALPN: {0}'.format("".join(
                        [chr(i) for i in alpn_str])))

                    alpn_len = alpn_len - alpn_str_len - 1

    	    else:
                pass

            odd = old_odd[et_len:]

    print('')
    print('Receive Client Hello Done')

    # struct {
    #    ProtocolVersion server_version;
    #    Random random;
    #    SessionID session_id;
    #    CipherSuite cipher_suite;
    #    CompressionMethod compression_method;
    #    select (extensions_present) {
    #        case false:
    #            struct {};
    #        case true:
    #            Extension extensions<0..2^16-1>;
    #    };
    # } ServerHello;

    server_hello = pack('!BB', 3, 1)
    server_hello += pack('!I', time.time())
    server_random = pack('!28B', 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
        10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27)
    server_hello += server_random
    server_hello += pack('!B', 0)
    server_hello += pack('!2B', 0xC0, 0x14)
    server_hello += pack('!B', 0x00)

    # length
    server_hello = pack('!3B', len(server_hello) >> 16,
                        len(server_hello) >> 8 & 0x00FF,
                        len(server_hello) & 0x0000FF) + server_hello
    # type
    server_hello = pack('!B', 2) + server_hello


    # length
    record_layer_hello = pack('!H', len(server_hello)) + server_hello
    # version
    record_layer_hello = pack('!BB', 3, 1) + record_layer_hello
    # type
    record_layer_hello = pack('!B', 22) + record_layer_hello

    # opaque ASN.1Cert<1..2^24-1>;

    # struct {
    #     ASN.1Cert certificate_list<0..2^24-1>;
    # } Certificate;

    with open("./fixtures/server.crt", "r") as f:
        crt = f.read()

    crt = crt.replace('-----BEGIN CERTIFICATE-----\n', '').replace('\n-----END CERTIFICATE-----\n', '')
    crt = b64decode(crt)
    tmp = to3bytes(len(crt))

    server_certificate = pack('!3B', tmp[0], tmp[1], tmp[2])
    server_certificate += crt

    server_certificate = pack('!3B', tmp[0], tmp[1], tmp[2]) + server_certificate

    tmp = to3bytes(len(server_certificate))
    server_certificate = pack('!3B', tmp[0], tmp[1], tmp[2]) + server_certificate
    server_certificate = pack('!B', 11) + server_certificate

    # length
    record_layer_certificate = pack('!H', len(server_certificate)) + server_certificate
    # version
    record_layer_certificate = pack('!BB', 3, 1) + record_layer_certificate
    # type
    record_layer_certificate = pack('!B', 22) + record_layer_certificate

    # struct {
    #   select (KeyExchangeAlgorithm) {
    #       case dh_anon:
    #           ServerDHParams params;
    #       case dhe_dss:
    #       case dhe_rsa:
    #           ServerDHParams params;
    #           digitally-signed struct {
    #               opaque client_random[32];
    #               opaque server_random[32];
    #               ServerDHParams params;
    #           } signed_params;
    #       case rsa:
    #       case dh_dss:
    #       case dh_rsa:
    #           struct {} ;
    #          /* message is omitted for rsa, dh_dss, and dh_rsa */
    #       /* may be extended, e.g., for ECDH -- see [TLSECC] */
    #   };
    # } ServerKeyExchange;

    server_keyexchange = pack('!B', 3)
    server_keyexchange += pack('!BB', (namedCurve['secp256r1'] & 0xFF00 > 8), namedCurve['secp256r1'] & 0x00FF)

    # with open("./fixtures/rsa.pub") as f:
    #     pub = f.read()
    #     rsapub = RSA.importKey(pub)
    #     pubkey = pub.replace('-----BEGIN PUBLIC KEY-----\n', '').replace('\n-----END PUBLIC KEY-----\n', '')
    ecc = pyelliptic.ECC(curve='secp256k1')
    pubkey = ecc.get_pubkey()
    server_keyexchange += pack('!B', len(pubkey))
    server_keyexchange += pubkey

    #ServerKeyExchange.signed_params.sha_hash
    #SHA(ClientHello.random + ServerHello.random +
                                      #ServerKeyExchange.params);
    with open("./fixtures/server.unsecure.key") as f:
        key = f.read()
    rsakey = RSA.importKey(key)
    signer = Signature_pkcs1_v1_5.new(rsakey)
    digest = SHA.new()
    digest.update(random + server_random + server_keyexchange)
    sign = signer.sign(digest)

    server_keyexchange += pack('!BB', (len(sign) & 0xFF00 > 8), len(sign) & 0x00FF)
    server_keyexchange += sign

    server_keyexchange = pack('!3B', len(server_keyexchange) >> 16,
                                (len(server_keyexchange) >> 8) & 0x00FF,
                                len(server_keyexchange) & 0x0000FF) + server_keyexchange
    server_keyexchange = pack('!B', 12) + server_keyexchange


    record_layer_server_keyexchange = pack('!H', len(server_keyexchange)) + server_keyexchange
    record_layer_server_keyexchange = pack('!BB', 3, 1) + record_layer_server_keyexchange
    record_layer_server_keyexchange = pack('!B', 22) + record_layer_server_keyexchange


    c.send(record_layer_hello + record_layer_certificate)
    c.send(record_layer_server_keyexchange)
