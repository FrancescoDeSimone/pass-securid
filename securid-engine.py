#!/usr/bin/env python3
# pass-securid engine - RSA SecurID (128-bit AES) token support for pass.
#
# Pure Python, standard library only.  Implements:
#   o AES-128 / AES-256 (ECB + CBC)
#   o the RSA SecurID MAC (securid_mac / securid_shortmac)
#   o v1/v2 'ctf' numeric token decoding + seed decryption (password/devid)
#   o v3/v4 base64 (Android-style) token decoding + seed decryption
#   o the SecurID time-based tokencode computation (30s and 60s tokens)
#
# No cryptography module, no third-party dependency.  It is embedded in
# securid.bash; keep securid-engine.py and the embedded copy in sync
# (the Makefile test verifies this).

# ---------------------------------------------------------------- AES
_SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]
_INVSBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INVSBOX[_v] = _i
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1b
        b >>= 1
    return p


def _expand_key(key):
    nk = len(key) // 4
    nr = 6 + nk
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= _RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            t = [_SBOX[b] for b in t]
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return [w[4 * r:4 * r + 4] for r in range(nr + 1)]


def _add_round_key(s, rk):
    for r in range(4):
        for c in range(4):
            s[r][c] ^= rk[c][r]


def _sub_bytes(s):
    for r in range(4):
        for c in range(4):
            s[r][c] = _SBOX[s[r][c]]


def _inv_sub_bytes(s):
    for r in range(4):
        for c in range(4):
            s[r][c] = _INVSBOX[s[r][c]]


def _shift_rows(s):
    for r in range(1, 4):
        s[r] = s[r][r:] + s[r][:r]


def _inv_shift_rows(s):
    for r in range(1, 4):
        s[r] = s[r][4 - r:] + s[r][:4 - r]


def _mix_columns(s):
    for c in range(4):
        a = [s[r][c] for r in range(4)]
        s[0][c] = _gmul(a[0], 2) ^ _gmul(a[1], 3) ^ a[2] ^ a[3]
        s[1][c] = a[0] ^ _gmul(a[1], 2) ^ _gmul(a[2], 3) ^ a[3]
        s[2][c] = a[0] ^ a[1] ^ _gmul(a[2], 2) ^ _gmul(a[3], 3)
        s[3][c] = _gmul(a[0], 3) ^ a[1] ^ a[2] ^ _gmul(a[3], 2)


def _inv_mix_columns(s):
    for c in range(4):
        a = [s[r][c] for r in range(4)]
        s[0][c] = _gmul(a[0], 14) ^ _gmul(a[1], 11) ^ _gmul(a[2], 13) ^ _gmul(a[3], 9)
        s[1][c] = _gmul(a[0], 9) ^ _gmul(a[1], 14) ^ _gmul(a[2], 11) ^ _gmul(a[3], 13)
        s[2][c] = _gmul(a[0], 13) ^ _gmul(a[1], 9) ^ _gmul(a[2], 14) ^ _gmul(a[3], 11)
        s[3][c] = _gmul(a[0], 11) ^ _gmul(a[1], 13) ^ _gmul(a[2], 9) ^ _gmul(a[3], 14)


def _encrypt_block(key, block):
    nk = len(key) // 4
    nr = 6 + nk
    rk = _expand_key(key)
    s = [[block[4 * c + r] for c in range(4)] for r in range(4)]
    _add_round_key(s, rk[0])
    for rnd in range(1, nr):
        _sub_bytes(s)
        _shift_rows(s)
        _mix_columns(s)
        _add_round_key(s, rk[rnd])
    _sub_bytes(s)
    _shift_rows(s)
    _add_round_key(s, rk[nr])
    return bytes(s[r][c] for c in range(4) for r in range(4))


def _decrypt_block(key, block):
    nk = len(key) // 4
    nr = 6 + nk
    rk = _expand_key(key)
    s = [[block[4 * c + r] for c in range(4)] for r in range(4)]
    _add_round_key(s, rk[nr])
    for rnd in range(nr - 1, 0, -1):
        _inv_shift_rows(s)
        _inv_sub_bytes(s)
        _add_round_key(s, rk[rnd])
        _inv_mix_columns(s)
    _inv_shift_rows(s)
    _inv_sub_bytes(s)
    _add_round_key(s, rk[0])
    return bytes(s[r][c] for c in range(4) for r in range(4))


def _aes128_ecb(key, data, encrypt=True):
    assert len(data) == 16 and len(key) == 16
    return (_encrypt_block if encrypt else _decrypt_block)(key, data)


def _aes256_cbc(key, iv, data, encrypt=True):
    assert len(key) == 32 and len(iv) == 16 and len(data) % 16 == 0
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        if encrypt:
            x = bytes(a ^ b for a, b in zip(blk, prev))
            c = _encrypt_block(key, x)
            prev = c
        else:
            c = _decrypt_block(key, blk)
            c = bytes(a ^ b for a, b in zip(c, prev))
            prev = blk
        out += c
    return bytes(out)


# ---------------------------------------------------------------- SecurID MAC
def _mac(data):
    """securid_mac(): the RSA SecurID AES-based message authentication code."""
    work = bytearray([0xFF] * 16)
    n = len(data)
    pad = bytearray(16)
    v = n * 8
    for p in range(15, -1, -1):
        if v == 0:
            break
        pad[p] = v & 0xFF
        v >>= 8
    i = 0
    odd = False
    while n > 16:
        enc = _aes128_ecb(data[i:i + 16], bytes(work))
        for k in range(16):
            work[k] ^= enc[k]
        i += 16
        n -= 16
        odd = not odd
    lastblk = bytearray(16)
    lastblk[:n] = data[i:i + n]
    enc = _aes128_ecb(bytes(lastblk), bytes(work))
    for k in range(16):
        work[k] ^= enc[k]
    if odd:
        enc = _aes128_ecb(bytes(16), bytes(work))
        for k in range(16):
            work[k] ^= enc[k]
    enc = _aes128_ecb(bytes(pad), bytes(work))
    for k in range(16):
        work[k] ^= enc[k]
    out = bytes(work)
    enc = _aes128_ecb(bytes(work), out)
    return bytes(out[k] ^ enc[k] for k in range(16))


def _shortmac(data):
    h = _mac(data)
    return (h[0] << 7) | (h[1] >> 1)


# ---------------------------------------------------------------- bit helpers
def _digits_to_bits(s, n_bits):
    """numinput_to_bits(): each ctf char carries 3 bits, packed MSB-first."""
    out = bytearray((n_bits + 7) // 8)
    for bitpos, ch in zip(range(0, n_bits, 3), s):
        val = (ord(ch) - 48) & 0x07
        for b in range(3):
            if bitpos + b >= n_bits:
                break
            if val & (0x04 >> b):
                out[(bitpos + b) // 8] |= 1 << (7 - ((bitpos + b) % 8))
    return bytes(out)


def _get_bits(buf, start, n_bits):
    out = 0
    for i in range(n_bits):
        out <<= 1
        b = start + i
        if buf[b // 8] & (1 << (7 - (b % 8))):
            out |= 1
    return out


def _url_decode(s):
    out = bytearray()
    i = 0
    n = len(s)
    while i < n:
        if s[i] == '%' and i + 2 < n and all(
                c in '0123456789abcdefABCDEF' for c in (s[i + 1], s[i + 2])):
            out.append(int(s[i + 1:i + 3], 16))
            i += 3
        else:
            out.append(ord(s[i]))
            i += 1
    return out.decode('utf-8', 'replace')


# ---------------------------------------------------------------- v1/v2 tokens
_V2_MAGIC = bytes([0xd8, 0xf5, 0x32, 0x53, 0x82, 0x89])

# flags we care about (see securid.h)
_F_PASSPROT = 1 << 13
_F_SNPROT = 1 << 12
_FNUM = 0x3          # 00=30s 01=60s
_FDIGIT = 0x1C0      # bits 6-8: digit count - 1
_FPINMODE = 0x18     # bits 3-4


class SecuridError(Exception):
    pass


def _v2_decode(s, smartphone):
    """Parse a v1/v2 numeric ctf string (>= 81 chars)."""
    if s[0] not in '12' or len(s) < 81:
        raise SecuridError('not a valid ctf token string')
    vers = int(s[0])
    serial = s[1:13]
    body = s[13:]
    if len(body) < 63 + 5:
        raise SecuridError('ctf token too short')
    data_part = body[:63]
    checksum_part = body[-5:]
    computed = _shortmac((s[0] + serial + body[:-5]).encode())
    token_mac = _get_bits(_digits_to_bits(checksum_part, 15), 0, 15)
    if token_mac != computed:
        raise SecuridError('ctf checksum failed (bad token string)')
    d = _digits_to_bits(data_part, 189)
    return {
        'version': vers,
        'serial': serial,
        'enc_seed': d[0:16],
        'flags': _get_bits(d, 128, 16),
        'exp_date': _get_bits(d, 144, 14),
        'dec_seed_hash': _get_bits(d, 159, 15),
        'device_id_hash': _get_bits(d, 174, 15),
        'smartphone': smartphone,
    }


def _v2_key_hash(passw, devid, vers, smartphone):
    """generate_key_hash(): derive the seed-encryption key and device hash."""
    key = bytearray(40 + 40 + 7 + 1)
    pos = 0
    if passw:
        pw = passw.encode('utf-8', 'surrogateescape')
        if len(pw) > 40:
            raise SecuridError('password too long')
        key[:len(pw)] = pw
        pos = len(pw)
    devid_buf_start = pos
    devid_len = 40 if smartphone else 32
    written = 0
    if devid:
        for c in devid.upper():
            if written >= devid_len:
                break
            if (vers == 1 and not c.isdigit()) or \
               (vers >= 2 and not (c.isdigit() or c in 'ABCDEF')):
                continue
            key[pos] = ord(c)
            pos += 1
            written += 1
    devid_region = bytes(key[devid_buf_start:devid_buf_start + devid_len])
    device_id_hash = _shortmac(devid_region)
    key[pos:pos + len(_V2_MAGIC)] = _V2_MAGIC
    key_hash = _mac(bytes(key[:pos + len(_V2_MAGIC)]))
    return key_hash, device_id_hash


def _v2_unlock(tok, passw, devid):
    key_hash, device_id_hash = _v2_key_hash(passw, devid, tok['version'],
                                            tok['smartphone'])
    if tok['flags'] & _F_SNPROT:
        if device_id_hash != tok['device_id_hash']:
            raise SecuridError('device ID does not match this token')
    dec_seed = _aes128_ecb(key_hash, tok['enc_seed'], encrypt=False)
    if _shortmac(dec_seed) != tok['dec_seed_hash']:
        raise SecuridError('failed to decrypt seed (wrong password?)')
    return dec_seed


# ---------------------------------------------------------------- v3/v4 tokens
_KEY0 = bytes([0xd0, 0x14, 0x43, 0x3c, 0x6d, 0x17, 0x9f, 0xeb,
               0xda, 0x09, 0xab, 0xfc, 0x32, 0x49, 0x63, 0x4c])
_KEY1 = bytes([0x3b, 0xaf, 0xff, 0x4d, 0x91, 0x8d, 0x89, 0xb6,
               0x81, 0x60, 0xde, 0x44, 0x4e, 0x05, 0xc0, 0xdd])

# Known device-class GUIDs, in stoken's discovery order.  Soft tokens are
# frequently bound to one of these; we auto-try them before prompting.
_CLASS_GUIDS = [
    "556f1985-33dd-442c-9155-3a0e994f21b1",  # iPhone
    "a01c4380-fc01-4df0-b113-7fb98ec74694",  # Android
    "868c28f8-31bf-4911-9876-ebece5c3f2ab",  # BlackBerry
    "b77a1d06-d505-4200-90d3-1bb397748704",  # BlackBerry 10
    "c483b592-63f0-4f19-b4cb-a6bce8e57159",  # Windows Phone
    "8f94b226-d362-4204-ac52-3b21fa333b6f",  # Windows
    "d0955a53-569b-4ecc-9cf7-6c2a59d4e775",  # macOS
]

_V3_TOKEN_SIZE = 291  # 0x123
_V3_NONCE = 16
_V3_DEVID = 48
_V3_DAY = 337500
_EPOCH_DAYS = 946684800 // 86400


def _v3_decode(s):
    import base64
    decoded = base64.b64decode(s + '=' * (-len(s) % 4), validate=False)
    if len(decoded) != _V3_TOKEN_SIZE:
        raise SecuridError('bad Android token length %d' % len(decoded))
    version = decoded[0]
    if version not in (3, 4):
        raise SecuridError('bad token version %d' % version)
    return {
        'version': version,
        'password_locked': bool(decoded[1]),
        'devid_locked': bool(decoded[2]),
        'nonce_devid_hash': decoded[3:35],
        'nonce_devid_pass_hash': decoded[35:67],
        'nonce': decoded[67:83],
        'enc_payload': decoded[83:259],
        'mac': decoded[259:291],
    }


def _v3_scrub_devid(devid):
    return ''.join(c.upper() for c in (devid or '') if c.isalnum())[:_V3_DEVID]


def _v3_compute_hash(passw, devid, nonce):
    buf = bytearray(16 + _V3_DEVID + 40)
    buf[0:16] = nonce
    if devid:
        d = devid.encode()
        buf[16:16 + len(d)] = d[:_V3_DEVID]
    pass_len = 0
    if passw:
        pw = passw.encode('utf-8', 'surrogateescape')
        buf[16 + _V3_DEVID:16 + _V3_DEVID + len(pw)] = pw
        pass_len = len(pw)
    return __import__('hashlib').sha256(
        bytes(buf[:16 + _V3_DEVID + pass_len])).digest()


def _v3_derive_key(passw, devid, nonce, key_id, version):
    import hashlib
    pw = (passw or '').encode('utf-8', 'surrogateescape')
    pass_len = len(pw)
    buf0 = bytearray(_V3_DEVID + 16 + 16 + pass_len)
    if pass_len:
        buf0[0:pass_len] = pw
    if devid:
        d = devid.encode()
        buf0[pass_len:pass_len + len(d)] = d[:_V3_DEVID]
    buf0[pass_len + _V3_DEVID:pass_len + _V3_DEVID + 16] = _KEY1 if key_id else _KEY0
    buf0[pass_len + _V3_DEVID + 16:] = nonce
    buf = bytes(buf0[1::2]) if version == 3 else bytes(buf0)
    return hashlib.pbkdf2_hmac('sha256', buf, nonce, 1000, 32)


def _v3_compute_hmac(tok, passw, devid):
    import hmac
    import hashlib
    key = _v3_derive_key(passw, devid, tok['nonce'], 0, tok['version'])
    msg = (bytes([tok['version']]) + bytes([int(tok['password_locked'])]) +
           bytes([int(tok['devid_locked'])]) + tok['nonce_devid_hash'] +
           tok['nonce_devid_pass_hash'] + tok['nonce'] + tok['enc_payload'])
    return hmac.new(key, msg, hashlib.sha256).digest()


def _v3_parse_payload(payload):
    serial = payload[0:12].decode('ascii', 'replace')
    dec_seed = payload[16:32]
    digits = payload[35]
    addpin = payload[36]
    interval = payload[37]
    longdate = int.from_bytes(payload[48:53], 'big')
    exp_date = max(0, longdate // _V3_DAY - _EPOCH_DAYS)
    flags = (1 << 9) | (1 << 14)          # FL_TIMESEEDS | FL_128BIT
    flags |= ((digits - 1) << 6) & _FDIGIT
    if addpin != 0x1f:
        flags |= 0x2 << 3
    if interval == 60:
        flags |= 0x01
    return {'serial': serial, 'dec_seed': dec_seed, 'flags': flags,
            'exp_date': exp_date}


def _v3_unlock(tok, passw, devid):
    devid = _v3_scrub_devid(devid)
    if _v3_compute_hash(None, devid, tok['nonce']) != tok['nonce_devid_hash']:
        raise SecuridError('device ID does not match this token')
    if _v3_compute_hash(passw, devid, tok['nonce']) != tok['nonce_devid_pass_hash']:
        raise SecuridError('password does not match this token')
    if _v3_compute_hmac(tok, passw, devid) != tok['mac']:
        raise SecuridError('token MAC mismatch')
    key = _v3_derive_key(passw, devid, tok['nonce'], 1, tok['version'])
    return _v3_parse_payload(_aes256_cbc(key, tok['nonce'], tok['enc_payload'],
                                         encrypt=False))


# ---------------------------------------------------------------- tokencode
def _bcd(val, nbytes):
    out = bytearray(nbytes)
    for i in range(nbytes - 1, -1, -1):
        out[i] = val % 10
        val //= 10
        out[i] |= (val % 10) << 4
        val //= 10
    return bytes(out)


def _key_from_time(bcd_time, nbytes, serial):
    key = bytearray([0xAA] * 16)
    key[0:nbytes] = bcd_time[0:nbytes]
    key[12:16] = bytes([0xBB] * 4)
    for j, i in enumerate(range(4, 12, 2)):
        key[8 + j] = ((ord(serial[i]) - 48) << 4) | (ord(serial[i + 1]) - 48)
    return bytes(key)


def compute_tokencode(dec_seed, serial, flags, t=None, pin=''):
    """securid_compute_tokencode(): 5-chained AES-128 derivation + digits."""
    import time as _time
    if t is None:
        t = int(_time.time())
    is_30 = (flags & _FNUM) == 0
    gm = _time.gmtime(t)

    bcd_time = bytearray(8)
    bcd_time[0:2] = _bcd(gm.tm_year, 2)         # Python tm_year is full year
    bcd_time[2:3] = _bcd(gm.tm_mon, 1)          # Python tm_mon is 1-based
    bcd_time[3:4] = _bcd(gm.tm_mday, 1)
    bcd_time[4:5] = _bcd(gm.tm_hour, 1)
    bcd_time[5:6] = _bcd(gm.tm_min & ~(0x01 if is_30 else 0x03), 1)
    bcd_time[6] = 0
    bcd_time[7] = 0
    bcd_time = bytes(bcd_time)

    key0 = _key_from_time(bcd_time, 2, serial)
    key0 = _aes128_ecb(dec_seed, key0)
    key1 = _key_from_time(bcd_time, 3, serial)
    key1 = _aes128_ecb(key0, key1)
    key0 = _key_from_time(bcd_time, 4, serial)
    key0 = _aes128_ecb(key1, key0)
    key1 = _key_from_time(bcd_time, 5, serial)
    key1 = _aes128_ecb(key0, key1)
    key0 = _key_from_time(bcd_time, 8, serial)
    key0 = _aes128_ecb(key1, key0)

    if is_30:
        i = ((gm.tm_min & 0x01) << 3) | ((gm.tm_sec >= 30) << 2)
    else:
        i = (gm.tm_min & 0x03) << 2
    tokencode = (key0[i] << 24) | (key0[i + 1] << 16) | \
                (key0[i + 2] << 8) | key0[i + 3]

    digits = ((flags & _FDIGIT) >> 6) + 1
    pin_len = len(pin)
    out = []
    for k in range(digits):
        c = tokencode % 10
        tokencode //= 10
        if k < pin_len:
            c += ord(pin[pin_len - k - 1]) - 48
        out.append(c % 10)
    return ''.join(str(d) for d in reversed(out))


# ---------------------------------------------------------------- token layer
def extract_token(s):
    """Return just the token data from a stoken-style input string."""
    import re
    m = re.search(r'ctfData=(?:3D)?', s)
    if m:
        return s[m.end():]
    s2 = s.strip()
    if s2.startswith('<?xml'):
        raise SecuridError('sdtid XML files are not supported; '
                           'convert the token with stoken export --blocks')
    return s2


def parse_token(s):
    """Probe the token string and return (kind, token_dict)."""
    import re
    raw = extract_token(s)
    smartphone = bool(re.match(
        r'(com\.rsa\.securid\.iphone://ctf|com\.rsa\.securid://ctf|'
        r'http://127\.0\.0\.1/securid/ctf)', s))
    if raw[0] in '12':
        digits = ''.join(c for c in raw if c.isdigit())
        if len(digits) < 81:
            raise SecuridError('ctf string too short')
        return ('v2', _v2_decode(digits, smartphone))
    elif raw[0] in 'AB':
        return ('v3', _v3_decode(_url_decode(raw)))
    raise SecuridError('unrecognized token format')


def token_info(s):
    """Header-level info, no unlock needed."""
    kind, t = parse_token(s)
    if kind == 'v2':
        return {
            'kind': kind, 'version': t['version'], 'serial': t['serial'],
            'flags': t['flags'],
            'password_locked': bool(t['flags'] & _F_PASSPROT),
            'devid_locked': bool(t['flags'] & _F_SNPROT),
            'digits': ((t['flags'] & _FDIGIT) >> 6) + 1,
            'interval': 60 if t['flags'] & 1 else 30,
            'pin_required': ((t['flags'] & _FPINMODE) >> 3) >= 2,
            'exp_date': t['exp_date'],
            'smartphone': t['smartphone'],
            'is_128bit': bool(t['flags'] & (1 << 14)),
        }
    return {
        'kind': kind, 'version': t['version'],
        'password_locked': t['password_locked'],
        'devid_locked': t['devid_locked'],
    }


def unlock(s, passw=None, devid=None):
    """Decrypt the seed. Returns (kind, info_dict, dec_seed_or_None)."""
    kind, t = parse_token(s)
    if kind == 'v2':
        if t['flags'] & _F_PASSPROT and not passw:
            raise SecuridError('password required')
        if t['flags'] & _F_SNPROT and not devid:
            raise SecuridError('device ID required')
        dec_seed = _v2_unlock(t, passw, devid)
        info = token_info(s)
        return kind, info, dec_seed
    else:
        if t['password_locked'] and not passw:
            raise SecuridError('password required')
        if t['devid_locked'] and not devid:
            raise SecuridError('device ID required')
        p = _v3_unlock(t, passw, devid)
        info = {
            'kind': kind, 'version': t['version'], 'serial': p['serial'],
            'flags': p['flags'],
            'password_locked': t['password_locked'],
            'devid_locked': t['devid_locked'],
            'digits': ((p['flags'] & _FDIGIT) >> 6) + 1,
            'interval': 60 if p['flags'] & 1 else 30,
            'pin_required': ((p['flags'] & _FPINMODE) >> 3) >= 2,
            'exp_date': p['exp_date'],
            'smartphone': True,
        }
        return kind, info, p['dec_seed']


def detect_devid(s, passw=None):
    """Return the first known device-class GUID that unlocks `s`, or ''.

    Mirrors stoken's class-GUID auto-detection: soft tokens are commonly
    bound to one of the platform GUIDs, in which case the user should not
    have to type a device ID at all.
    """
    kind, t = parse_token(s)
    requires_pass = (t['flags'] & _F_PASSPROT) if kind == 'v2' else \
        t['password_locked']
    if requires_pass and not passw:
        return ''
    for guid in _CLASS_GUIDS:
        try:
            unlock(s, passw, guid)
            return guid
        except SecuridError:
            continue
    return ''


def code(s, passw=None, devid=None, seed=None, pin='', t=None):
    """Compute a tokencode. `seed` (32 hex chars) bypasses seed decryption."""
    if seed:
        _, info, dec = unlock_cached(s, seed)
    else:
        _, info, dec = unlock(s, passw, devid)
    computed = compute_tokencode(dec, info['serial'], info['flags'], t, pin)
    return computed, info, dec


def unlock_cached(s, seed):
    """Like unlock(), but trust a pre-decrypted 32-hex seed from the vault.

    Only meaningful for v1/v2 tokens: for Android (v3/v4) tokens the flags
    and serial live in the encrypted payload, so a raw cached seed is not
    enough -- the caller must pass --pass/--devid instead.
    """
    kind, info = parse_token(s)
    if kind != 'v2':
        raise SecuridError(
            'cached seed is only supported for ctf tokens; '
            'provide --password/--devid for Android tokens')
    info = token_info(s)
    return kind, info, bytes.fromhex(seed)


# ------------------------------------------------------------------ CLI
def _main(argv):
    import getopt
    import sys
    import time
    try:
        opts, args = getopt.gnu_getopt(argv[1:], '',
                                       ['tok=', 'pass=', 'password=', 'devid=',
                                        'seed=', 'pin=', 'time=', 'json', 'text',
                                        'describe', 'code', 'info', 'validate',
                                        'full', 'detect-devid'])
        cmd = None
        want_full = False
        params = {}
        for o, a in opts:
            if o == '--tok':
                params['tok'] = a
            elif o in ('--pass', '--password'):
                params['passw'] = a
            elif o == '--devid':
                params['devid'] = a
            elif o == '--seed':
                params['seed'] = a
            elif o == '--pin':
                params['pin'] = a
            elif o == '--time':
                params['time'] = a
            elif o == '--json':
                params['json'] = True
            elif o == '--text':
                params['text'] = True
            elif o == '--full':
                want_full = True
            elif o in ('--describe', '--info', '--code', '--validate',
                       '--detect-devid'):
                cmd = o[2:]
        if cmd is None:
            cmd = 'describe'
        tok = params.get('tok')
        if not tok:
            raise SecuridError('missing --tok')
        t = params.get('time')
        if t is not None:
            if t[:1] in ('+', '-'):   # relative offset from "now"
                t = int(time.time()) + int(t)
            else:
                t = int(t)
        pin = params.get('pin', '')
        passw = params.get('passw')
        devid = params.get('devid')
        seed = params.get('seed')

        if cmd == 'info':
            kind, info, _ = unlock(tok, passw, devid)
            if params.get('text'):
                _print_info(info)
            else:
                import json
                print(json.dumps(info))
            return 0

        if cmd == 'describe':
            import json
            print(json.dumps(token_info(tok)))
            return 0

        if cmd == 'validate':
            kind, info, _ = unlock(tok, passw, devid)
            print(info['serial'])
            return 0

        if cmd == 'detect-devid':
            print(detect_devid(tok, passw))
            return 0

        # code
        if cmd == 'code':
            if seed:
                _, info, dec = unlock_cached(tok, seed)
            else:
                _, info, dec = unlock(tok, passw, devid)
            computed = compute_tokencode(dec, info['serial'], info['flags'],
                                         t, pin)
            if want_full:
                import json
                out = dict(info)
                out['code'] = computed
                out['dec_seed'] = dec.hex()
                out['pin'] = pin
                print(json.dumps(out))
            else:
                print(computed)
            return 0
        raise SecuridError('unknown command %s' % cmd)
    except SecuridError as e:
        print('securid: %s' % e, file=sys.stderr)
        return 2
    except SystemExit:
        raise
    except Exception as e:  # pragma: no cover - defensive
        print('securid: internal error: %s' % e, file=sys.stderr)
        return 3


def _print_info(info):
    k = info
    if k['kind'] == 'v2':
        print('Serial number        : %s' % k['serial'])
        print('Key length           : %s' % ('128' if k['is_128bit'] else '64'))
        print('Tokencode digits     : %d' % k['digits'])
        print('Seconds per tokencode: %d' % k['interval'])
        print('PIN mode             : %d' % ((k['flags'] >> 3) & 3))
        print('PIN required         : %s' % ('yes' if k['pin_required'] else 'no'))
        print('Encrypted w/password : %s' % ('yes' if k['password_locked'] else 'no'))
        print('Encrypted w/devid    : %s' % ('yes' if k['devid_locked'] else 'no'))
    else:
        print('Token format         : Android (v%d)' % k['version'])
        if k.get('serial'):
            print('Serial number        : %s' % k['serial'])
            print('Key length           : 128')
            print('Tokencode digits     : %d' % k['digits'])
            print('Seconds per tokencode: %d' % k['interval'])
            print('PIN required         : %s' % ('yes' if k['pin_required'] else 'no'))
        print('Encrypted w/password : %s' % ('yes' if k['password_locked'] else 'no'))
        print('Encrypted w/devid    : %s' % ('yes' if k['devid_locked'] else 'no'))


if __name__ == '__main__':
    import sys
    sys.exit(_main(sys.argv))
