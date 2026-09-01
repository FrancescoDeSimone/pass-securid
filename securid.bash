#!/usr/bin/env bash
# shellcheck disable=SC2178,SC2128,SC2179  # see engine banner: cross-function array/string re-use is local-scoped and verified
# pass securid - Password Store Extension (https://www.passwordstore.org/)
#
# Manage RSA SecurID 128-bit (AES) software tokens inside a pass vault,
# mirroring the pass-otp interface.  Token parsing, decryption and tokencode
# computation are done by a pure-bash engine below, so this extension has no
# runtime dependency beyond bash (and gpg/age, which pass itself needs).
#
# Tokens are stored in a password file as a single token line (a numeric
# "ctf" string or an iPhone/Android URI) optionally followed by metadata:
#
#     com.rsa.securid.iphone://ctf?ctfData=...   <- the token
#     pin: 1234                                  <- optional cached PIN
#     devid: a01c4380-fc01-4df0-b113-7fb98ec74694  <- optional cached device ID
#     seed: 0cd1105cd1aafd893e89f1eb7b800dd8     <- optional cached decrypted seed
#
# Copyright (C) 2026
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.

VERSION="1.0.0"

if [[ $PASSAGE == 1 ]]; then
  EXT="age"
else
  EXT="gpg"
fi

# ===========================================================================
# Module-global result slots: _sec_ret (byte array), _sec_retval (hex/int),
# _sec_err (error message).
#
#   False positives: these flags fire when a variable is used as an array in
#   one function and as a scalar in another (e.g. `out`, `key`, `buf`).  All
#   such uses are `local`-scoped per function; the engine is checked against
#   the fixed reference token vectors, so no shared state is involved.
# ===========================================================================
_sec_ret=()
_sec_retval=""
_sec_err=""

_SEC_SBOX=( 0x63 0x7c 0x77 0x7b 0xf2 0x6b 0x6f 0xc5 0x30 0x01 0x67 0x2b 0xfe 0xd7 0xab 0x76 0xca 0x82 0xc9 0x7d 0xfa 0x59 0x47 0xf0 0xad 0xd4 0xa2 0xaf 0x9c 0xa4 0x72 0xc0 0xb7 0xfd 0x93 0x26 0x36 0x3f 0xf7 0xcc 0x34 0xa5 0xe5 0xf1 0x71 0xd8 0x31 0x15 0x04 0xc7 0x23 0xc3 0x18 0x96 0x05 0x9a 0x07 0x12 0x80 0xe2 0xeb 0x27 0xb2 0x75 0x09 0x83 0x2c 0x1a 0x1b 0x6e 0x5a 0xa0 0x52 0x3b 0xd6 0xb3 0x29 0xe3 0x2f 0x84 0x53 0xd1 0x00 0xed 0x20 0xfc 0xb1 0x5b 0x6a 0xcb 0xbe 0x39 0x4a 0x4c 0x58 0xcf 0xd0 0xef 0xaa 0xfb 0x43 0x4d 0x33 0x85 0x45 0xf9 0x02 0x7f 0x50 0x3c 0x9f 0xa8 0x51 0xa3 0x40 0x8f 0x92 0x9d 0x38 0xf5 0xbc 0xb6 0xda 0x21 0x10 0xff 0xf3 0xd2 0xcd 0x0c 0x13 0xec 0x5f 0x97 0x44 0x17 0xc4 0xa7 0x7e 0x3d 0x64 0x5d 0x19 0x73 0x60 0x81 0x4f 0xdc 0x22 0x2a 0x90 0x88 0x46 0xee 0xb8 0x14 0xde 0x5e 0x0b 0xdb 0xe0 0x32 0x3a 0x0a 0x49 0x06 0x24 0x5c 0xc2 0xd3 0xac 0x62 0x91 0x95 0xe4 0x79 0xe7 0xc8 0x37 0x6d 0x8d 0xd5 0x4e 0xa9 0x6c 0x56 0xf4 0xea 0x65 0x7a 0xae 0x08 0xba 0x78 0x25 0x2e 0x1c 0xa6 0xb4 0xc6 0xe8 0xdd 0x74 0x1f 0x4b 0xbd 0x8b 0x8a 0x70 0x3e 0xb5 0x66 0x48 0x03 0xf6 0x0e 0x61 0x35 0x57 0xb9 0x86 0xc1 0x1d 0x9e 0xe1 0xf8 0x98 0x11 0x69 0xd9 0x8e 0x94 0x9b 0x1e 0x87 0xe9 0xce 0x55 0x28 0xdf 0x8c 0xa1 0x89 0x0d 0xbf 0xe6 0x42 0x68 0x41 0x99 0x2d 0x0f 0xb0 0x54 0xbb 0x16 )
_SEC_INVSBOX=( 0x52 0x09 0x6a 0xd5 0x30 0x36 0xa5 0x38 0xbf 0x40 0xa3 0x9e 0x81 0xf3 0xd7 0xfb 0x7c 0xe3 0x39 0x82 0x9b 0x2f 0xff 0x87 0x34 0x8e 0x43 0x44 0xc4 0xde 0xe9 0xcb 0x54 0x7b 0x94 0x32 0xa6 0xc2 0x23 0x3d 0xee 0x4c 0x95 0x0b 0x42 0xfa 0xc3 0x4e 0x08 0x2e 0xa1 0x66 0x28 0xd9 0x24 0xb2 0x76 0x5b 0xa2 0x49 0x6d 0x8b 0xd1 0x25 0x72 0xf8 0xf6 0x64 0x86 0x68 0x98 0x16 0xd4 0xa4 0x5c 0xcc 0x5d 0x65 0xb6 0x92 0x6c 0x70 0x48 0x50 0xfd 0xed 0xb9 0xda 0x5e 0x15 0x46 0x57 0xa7 0x8d 0x9d 0x84 0x90 0xd8 0xab 0x00 0x8c 0xbc 0xd3 0x0a 0xf7 0xe4 0x58 0x05 0xb8 0xb3 0x45 0x06 0xd0 0x2c 0x1e 0x8f 0xca 0x3f 0x0f 0x02 0xc1 0xaf 0xbd 0x03 0x01 0x13 0x8a 0x6b 0x3a 0x91 0x11 0x41 0x4f 0x67 0xdc 0xea 0x97 0xf2 0xcf 0xce 0xf0 0xb4 0xe6 0x73 0x96 0xac 0x74 0x22 0xe7 0xad 0x35 0x85 0xe2 0xf9 0x37 0xe8 0x1c 0x75 0xdf 0x6e 0x47 0xf1 0x1a 0x71 0x1d 0x29 0xc5 0x89 0x6f 0xb7 0x62 0x0e 0xaa 0x18 0xbe 0x1b 0xfc 0x56 0x3e 0x4b 0xc6 0xd2 0x79 0x20 0x9a 0xdb 0xc0 0xfe 0x78 0xcd 0x5a 0xf4 0x1f 0xdd 0xa8 0x33 0x88 0x07 0xc7 0x31 0xb1 0x12 0x10 0x59 0x27 0x80 0xec 0x5f 0x60 0x51 0x7f 0xa9 0x19 0xb5 0x4a 0x0d 0x2d 0xe5 0x7a 0x9f 0x93 0xc9 0x9c 0xef 0xa0 0xe0 0x3b 0x4d 0xae 0x2a 0xf5 0xb0 0xc8 0xeb 0xbb 0x3c 0x83 0x53 0x99 0x61 0x17 0x2b 0x04 0x7e 0xba 0x77 0xd6 0x26 0xe1 0x69 0x14 0x63 0x55 0x21 0x0c 0x7d )
_SEC_RCON=( 0x01 0x02 0x04 0x08 0x10 0x20 0x40 0x80 0x1b 0x36 )
_SEC_KEY0=( 0xd0 0x14 0x43 0x3c 0x6d 0x17 0x9f 0xeb 0xda 0x09 0xab 0xfc 0x32 0x49 0x63 0x4c )
_SEC_KEY1=( 0x3b 0xaf 0xff 0x4d 0x91 0x8d 0x89 0xb6 0x81 0x60 0xde 0x44 0x4e 0x05 0xc0 0xdd )
_SEC_V2_MAGIC=( 0xd8 0xf5 0x32 0x53 0x82 0x89 )
_SEC_CLASS_GUIDS=(
  "556f1985-33dd-442c-9155-3a0e994f21b1"
  "a01c4380-fc01-4df0-b113-7fb98ec74694"
  "868c28f8-31bf-4911-9876-ebece5c3f2ab"
  "b77a1d06-d505-4200-90d3-1bb397748704"
  "c483b592-63f0-4f19-b4cb-a6bce8e57159"
  "8f94b226-d362-4204-ac52-3b21fa333b6f"
  "d0955a53-569b-4ecc-9cf7-6c2a59d4e775"
)
_SEC_V3_TOKEN_SIZE=291
_SEC_V3_NONCE=16
_SEC_V3_DEVID=48
_SEC_V3_DAY=337500
_SEC_EPOCH_DAYS=10957

_SEC_F_PASSPROT=$(( 1 << 13 ))
_SEC_F_SNPROT=$(( 1 << 12 ))
_SEC_FNUM=0x3
_SEC_FDIGIT=0x1C0
_SEC_FPINMODE=0x18

_sec_fdiv() {  # <a> <b> -> _sec_retval : floor division (python //)
  local a="$1" b="$2"
  if (( a >= 0 )); then _sec_retval=$(( a / b ))
  else _sec_retval=$(( - ((-a + b - 1) / b) )); fi
}
_sec_fmod() {  # <a> <b> -> _sec_retval : python style remainder
  local a="$1" b="$2" r
  r=$(( a % b ))
  if (( r < 0 )); then r=$(( r + b )); fi
  _sec_retval=$r
}

_sec_hex2bytes() {   # <hex> -> _sec_ret[] (decimal ints)
  local h="$1" i n=${#1}
  _sec_ret=()
  for (( i=0; i<n; i+=2 )); do
    _sec_ret+=("$((0x${h:$i:2}))")
  done
}
_sec_bytes2hex() {   # <ints...> -> _sec_retval
  local b h
  _sec_retval=""
  for b in "$@"; do
    printf -v h "%02x" "$b"
    _sec_retval+="$h"
  done
}
_sec_str2bytes() {   # <str> -> _sec_ret[] (utf-8)
  local s="$1" i c cp
  _sec_ret=()
  for (( i=0; i < ${#s}; i++ )); do
    c="${s:$i:1}"
    cp=$(printf '%d' "'${c}")
    if (( cp < 0x80 )); then _sec_ret+=("$cp")
    elif (( cp < 0x800 )); then
      _sec_ret+=("$(( 0xC0 | (cp >> 6) ))" "$(( 0x80 | (cp & 0x3F) ))")
    elif (( cp < 0x10000 )); then
      _sec_ret+=("$(( 0xE0 | (cp >> 12) ))" "$(( 0x80 | ((cp >> 6) & 0x3F) ))" "$(( 0x80 | (cp & 0x3F) ))")
    else
      _sec_ret+=("$(( 0xF0 | (cp >> 18) ))" "$(( 0x80 | ((cp >> 12) & 0x3F) ))" "$(( 0x80 | ((cp >> 6) & 0x3F) ))" "$(( 0x80 | (cp & 0x3F) ))" )
    fi
  done
}
_sec_hex_slice() {   # <hex> <start-byte> <len-bytes> -> _sec_retval (hex)
  _sec_retval="${1:$(($2*2)):$(($3*2))}"
}
_sec_xorbytes() {  # <hex1> <hex2> (same byte length) -> _sec_ret[] and _sec_retval
  local h1="$1" h2="$2" i n=${#1}
  _sec_ret=()
  for (( i=0; i<n; i+=2 )); do
    _sec_ret+=("$(( 0x${h1:$i:2} ^ 0x${h2:$i:2} ))")
  done
  _sec_bytes2hex "${_sec_ret[@]}"
}

# AES
_sec_gmul() {   # <a> <b> -> _sec_retval (GF(2^8) multiply)
  local a="$1" b="$2" p=0 hi
  for _ in 1 2 3 4 5 6 7 8; do
    if (( b & 1 )); then p=$(( p ^ a )); fi
    hi=$(( a & 0x80 ))
    a=$(( (a << 1) & 0xFF ))
    if (( hi )); then a=$(( a ^ 0x1b )); fi
    b=$(( b >> 1 ))
  done
  _sec_retval=$p
}
_sec_aes_keyexpand() {   # <key bytes...> -> _sec_kat[] expanded key (flat)
  local -a key=( "$@" )
  local nk=$(( ${#key[@]} / 4 ))
  local nw=$(( 4 * (nk + 6 + 1) ))
  local i t0 t1 t2 t3 tt0 tt1 tt2 tt3
  _sec_kat=( "${key[@]}" )
  for (( i = nk; i < nw; i++ )); do
    t0=$(( _sec_kat[(i-1)*4] ))
    t1=$(( _sec_kat[(i-1)*4 + 1] ))
    t2=$(( _sec_kat[(i-1)*4 + 2] ))
    t3=$(( _sec_kat[(i-1)*4 + 3] ))
    if (( i % nk == 0 )); then
      tt0=$t0; tt1=$t1; tt2=$t2; tt3=$t3
      t0=$(( _SEC_SBOX[tt1] ))
      t1=$(( _SEC_SBOX[tt2] ))
      t2=$(( _SEC_SBOX[tt3] ))
      t3=$(( _SEC_SBOX[tt0] ))
      t0=$(( t0 ^ _SEC_RCON[(i / nk) - 1] ))
    elif (( nk > 6 && i % nk == 4 )); then
      t0=$(( _SEC_SBOX[t0] ))
      t1=$(( _SEC_SBOX[t1] ))
      t2=$(( _SEC_SBOX[t2] ))
      t3=$(( _SEC_SBOX[t3] ))
    fi
    _sec_kat[i*4]=$(( _sec_kat[(i-nk)*4]     ^ t0 ))
    _sec_kat[i*4 + 1]=$((  _sec_kat[(i-nk)*4 + 1] ^ t1 ))
    _sec_kat[i*4 + 2]=$((  _sec_kat[(i-nk)*4 + 2] ^ t2 ))
    _sec_kat[i*4 + 3]=$((  _sec_kat[(i-nk)*4 + 3] ^ t3 ))
  done
}

# AES state primitives (operate in place on the 16-int module array _sec_st)
_st_addkey() {   # <round> : AddRoundKey
  local rnd="$1" r c k=0
  for r in 0 1 2 3; do
    for c in 0 1 2 3; do
      _sec_st[k]=$(( _sec_st[k] ^ _sec_kat[(rnd*16) + (c*4) + r] ))
      k=$(( k + 1 ))
    done
  done
}
_st_dosub() {    # SubBytes in place
  local i
  for (( i = 0; i < 16; i++ )); do
    _sec_st[i]=$(( _SEC_SBOX[_sec_st[i]] ))
  done
}
_st_invsub() {   # InvSubBytes in place
  local i
  for (( i = 0; i < 16; i++ )); do
    _sec_st[i]=$(( _SEC_INVSBOX[_sec_st[i]] ))
  done
}
_st_shiftrows() {    # encryption shift: row r rotates left by r
  local -a t=( "${_sec_st[@]}" )
  local r c s
  for (( r = 0; r < 4; r++ )); do
    for (( c = 0; c < 4; c++ )); do
      if (( r == 0 )); then s=$c
      else s=$(( r*4 + ((c + r) % 4) )); fi
      _sec_st[r*4 + c]=$(( t[s] ))
    done
  done
}
_st_invshiftrows() { # InvShiftRows: row r rotates right by r
  local -a t=( "${_sec_st[@]}" )
  local r c s
  for (( r = 0; r < 4; r++ )); do
    for (( c = 0; c < 4; c++ )); do
      if (( r == 0 )); then s=$c
      else s=$(( r*4 + ((c + 4 - r) % 4) )); fi
      _sec_st[r*4 + c]=$(( t[s] ))
    done
  done
}

# MixColumns / InvMixColumns (in place on _sec_st)
_st_mix() {
  local -a t=( "${_sec_st[@]}" )
  local c s0 s1 s2 s3
  local m0 m1 m2 m3 m4 m5 m6 m7
  for c in 0 1 2 3; do
    s0=$(( t[c] ));  s1=$(( t[4+c] ))
    s2=$(( t[8+c] )); s3=$(( t[12+c] ))
    _sec_gmul "$s0" 2; m0=$_sec_retval
    _sec_gmul "$s1" 3; m1=$_sec_retval
    _sec_gmul "$s2" 2; m2=$_sec_retval
    _sec_gmul "$s3" 3; m3=$_sec_retval
    _sec_gmul "$s0" 3; m4=$_sec_retval
    _sec_gmul "$s1" 2; m5=$_sec_retval
    _sec_gmul "$s2" 3; m6=$_sec_retval
    _sec_gmul "$s3" 2; m7=$_sec_retval
    _sec_st[c]=$(( m0 ^ m1 ^ s2 ^ s3 ))
    _sec_st[4+c]=$(( s0 ^ m5 ^ m6 ^ s3 ))
    _sec_st[8+c]=$(( s0 ^ s1 ^ m2 ^ m3 ))
    _sec_st[12+c]=$(( m4 ^ s1 ^ s2 ^ m7 ))
  done
}
_st_invmix() {
  local -a t=( "${_sec_st[@]}" )
  local c s0 s1 s2 s3
  local m0 m1 m2 m3 m4 m5 m6 m7
  local m8 m9 m10 m11 m12 m13 m14 m15
  for c in 0 1 2 3; do
    s0=$(( t[c] ));  s1=$(( t[4+c] ))
    s2=$(( t[8+c] )); s3=$(( t[12+c] ))
    _sec_gmul "$s0" 14; m0=$_sec_retval
    _sec_gmul "$s1" 11; m1=$_sec_retval
    _sec_gmul "$s2" 13; m2=$_sec_retval
    _sec_gmul "$s3" 9;  m3=$_sec_retval
    _sec_gmul "$s0" 9;  m4=$_sec_retval
    _sec_gmul "$s1" 14; m5=$_sec_retval
    _sec_gmul "$s2" 11; m6=$_sec_retval
    _sec_gmul "$s3" 13; m7=$_sec_retval
    _sec_gmul "$s0" 13; m8=$_sec_retval
    _sec_gmul "$s1" 9;  m9=$_sec_retval
    _sec_gmul "$s2" 14; m10=$_sec_retval
    _sec_gmul "$s3" 11; m11=$_sec_retval
    _sec_gmul "$s0" 11; m12=$_sec_retval
    _sec_gmul "$s1" 13; m13=$_sec_retval
    _sec_gmul "$s2" 9;  m14=$_sec_retval
    _sec_gmul "$s3" 14; m15=$_sec_retval
    _sec_st[c]=$(( m0 ^ m1 ^ m2 ^ m3 ))
    _sec_st[4+c]=$(( m4 ^ m5 ^ m6 ^ m7 ))
    _sec_st[8+c]=$(( m8 ^ m9 ^ m10 ^ m11 ))
    _sec_st[12+c]=$(( m12 ^ m13 ^ m14 ^ m15 ))
  done
}
# _sec_aes_block <keyhex> <datahex> <enc|dec> : single AES block
# key length 16 (AES-128) or 32 (AES-256).  Result: _sec_ret (16 ints) and
# _sec_retval (32-hex string).  State in the module array _sec_st.
_sec_aes_block() {
  local keyhex="$1" datahex="$2" mode="$3"
  local -a key blk
  local i rnd
  _sec_hex2bytes "$keyhex"
  key=( "${_sec_ret[@]}" )
  _sec_hex2bytes "$datahex"
  blk=( "${_sec_ret[@]}" )
  # load state (transpose)
  _sec_st=( 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 )
  for i in 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    _sec_st[i]=$(( blk[(i%4)*4 + (i/4)] ))
  done
  _sec_aes_keyexpand "${key[@]}"
  local nk=$(( ${#key[@]} / 4 ))
  local nr=$(( nk + 6 ))
  if [[ "$mode" == "E" || "$mode" == "e" ]]; then
    _st_addkey 0
    for (( rnd = 1; rnd < nr; rnd++ )); do
      _st_dosub
      _st_shiftrows
      _st_mix
      _st_addkey "$rnd"
    done
    _st_dosub
    _st_shiftrows
    _st_addkey "$nr"
  else
    _st_addkey "$nr"
    for (( rnd = nr - 1; rnd > 0; rnd-- )); do
      _st_invshiftrows
      _st_invsub
      _st_addkey "$rnd"
      _st_invmix
    done
    _st_invshiftrows
    _st_invsub
    _st_addkey 0
  fi
  # output bytes(s[r][c] for c in 0..3 for r in 0..3): transpose state back
  local -a o=( 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 ) i2
  for i2 in 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    o[i2]=$(( _sec_st[(i2%4)*4 + (i2/4)] ))
  done
  _sec_ret=( "${o[@]}" )
  _sec_bytes2hex "${_sec_ret[@]}"
}

# _sec_aes128_ecb <key16hex> <blk16hex> <E|D> -> _sec_ret, _sec_retval
_sec_aes128_ecb() {
  local keyhex="$1" datahex="$2" mode="$3"
  _sec_aes_block "$keyhex" "$datahex" "$mode"
}

# _sec_aes256_cbc <key32hex> <iv16hex> <datahex> <E|D> -> _sec_ret, _sec_retval
_sec_aes256_cbc() {
  local keyhex="$1" ivhex="$2" datahex="$3" mode="$4"
  local datalen=$(( ${#datahex} / 2 ))
  local i blk c prev out="" x
  prev="$ivhex"
  for (( i = 0; i < datalen; i += 16 )); do
    _sec_hex_slice "$datahex" "$i" 16
    blk="$_sec_retval"
    if [[ "$mode" == "E" || "$mode" == "e" ]]; then
      _sec_xorbytes "$blk" "$prev"
      x="$_sec_retval"
      _sec_aes_block "$keyhex" "$x" "E"
      prev="$_sec_retval"
    else
      _sec_aes_block "$keyhex" "$blk" "D"
      _sec_xorbytes "$_sec_retval" "$prev"
      prev="$blk"
    fi
    out+="$_sec_retval"
  done
  _sec_retval="$out"
  _sec_hex2bytes "$out"
}
# _sec_url_decode <str> -> _sec_retval (decoded string)
_sec_url_decode() {
  local s="$1" n=${#1} out="" i c
  for (( i = 0; i < n; i++ )); do
    c="${s:$i:1}"
    if [[ $c == % ]]; then
      local h2="${s:$((i+1)):2}"
      case "$h2" in
        [0-9a-fA-F][0-9a-fA-F]) printf -v _sec_retval "%b" "\\x$h2"; out+="$_sec_retval"; i=$((i+2)); continue ;;
      esac
    fi
    out+="$c"
  done
  _sec_retval="$out"
}

# _sec_b64val <char> -> _sec_retval : 0..63, -1 invalid, -2 '='
_sec_b64val() {
  case "$1" in
    [A-Z]) _sec_retval=$(( $(printf '%d' "'$1") - 65 )) ;;
    [a-z]) _sec_retval=$(( $(printf '%d' "'$1") - 97 + 26 )) ;;
    [0-9]) _sec_retval=$(( $(printf '%d' "'$1") - 48 + 52 )) ;;
    +) _sec_retval=62 ;;
    /) _sec_retval=63 ;;
    =) _sec_retval=-2 ;;
    *) _sec_retval=-1 ;;
  esac
}
# _sec_b64decode <str> -> _sec_ret[]
_sec_b64decode() {
  local s="$1" n=${#1} i c
  local val=0 bits=0
  local -a out=()
  for (( i = 0; i < n; i++ )); do
    c="${s:$i:1}"
    _sec_b64val "$c"
    local v=$_sec_retval
    if (( v < 0 )); then
      (( v == -2 )) && break   # padding ends decoding
      continue                 # invalid char is skipped
    fi
    val=$(( (val << 6) | v ))
    bits=$(( bits + 6 ))
    while (( bits >= 8 )); do
      out+=("$(( (val >> (bits - 8)) & 0xFF ))")
      bits=$(( bits - 8 ))
    done
  done
  _sec_ret=( "${out[@]}" )
}

# ---------------------------------------------------------------------------
# _sec_mac <hex> -> _sec_ret[] (16 bytes), _sec_machex (hex)
# _sec_shortmac <hex> -> _sec_retval (int)
# ---------------------------------------------------------------------------
_sec_mac() {
  local datahex="$1" n=$(( ${#1} / 2 ))
  local hx=""
  local -a work pad lastblk
  local k i odd=0 v p enc outhex b0 b1 resa
  work=( 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 )
  v=$(( n * 8 ))
  pad=( 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 )
  for (( p = 15; p >= 0; p-- )); do
    (( v == 0 )) && break
    pad[p]=$(( v & 0xFF ))
    v=$(( v >> 8 ))
  done
  i=0
  while (( n > 16 )); do
    _sec_hex_slice "$datahex" "$i" 16; blk="${_sec_retval}"
    _sec_bytes2hex "${work[@]}"; hx="$_sec_retval"
    _sec_aes128_ecb "$blk" "$hx" "E"; enc="$_sec_retval"
    for k in 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
      work[k]=$(( work[k] ^ $(( 0x${enc:$((k*2)):2} )) ))
    done
    i=$(( i + 16 )); n=$(( n - 16 )); odd=$(( 1 ^ odd ))
  done
  lastblk=( 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 )
  for (( k = 0; k < n; k++ )); do
    lastblk[k]=$(( 0x${datahex:$(( (i+k)*2 )):2} ))
  done
  _sec_bytes2hex "${lastblk[@]}"; local lh="$_sec_retval"
  _sec_bytes2hex "${work[@]}"; hx="$_sec_retval"
  _sec_aes128_ecb "$lh" "$hx" "E"; enc="$_sec_retval"
  for k in 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    work[k]=$(( work[k] ^ $(( 0x${enc:$((k*2)):2} )) ))
  done
  if (( odd )); then
    _sec_bytes2hex "${work[@]}"; hx="$_sec_retval"
    _sec_aes128_ecb "00000000000000000000000000000000" "$hx" "E"; enc="$_sec_retval"
    for k in 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
      work[k]=$(( work[k] ^ $(( 0x${enc:$((k*2)):2} )) ))
    done
  fi
  _sec_bytes2hex "${pad[@]}"; local ph="$_sec_retval"
  _sec_bytes2hex "${work[@]}"; hx="$_sec_retval"
  _sec_aes128_ecb "$ph" "$hx" "E"; enc="$_sec_retval"
  for k in 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    work[k]=$(( work[k] ^ $(( 0x${enc:$((k*2)):2} )) ))
  done
  _sec_bytes2hex "${work[@]}"; outhex="$_sec_retval"
  _sec_aes128_ecb "$outhex" "$outhex" "E"; enc="$_sec_retval"
  reshex=""
  for k in 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    b0=$(( 0x${outhex:$((k*2)):2} ))
    b1=$(( 0x${enc:$((k*2)):2} ))
    printf -v resa "%02x" $(( b0 ^ b1 ))
    reshex+="$resa"
  done
  _sec_hex2bytes "$reshex"
  _sec_machex="$reshex"
}
_sec_shortmac() {
  _sec_mac "$1"
  local h="${_sec_machex}"
  local b0=$(( 0x${h:0:2} )) b1=$(( 0x${h:2:2} ))
  _sec_retval=$(( (b0 << 7) | (b1 >> 1) ))
}

# _sec_digits_to_bits <str> <n_bits> -> _sec_ret[]
_sec_digits_to_bits() {
  local s="$1" n="$2"
  local nb=$(( (n + 7) / 8 ))
  local -a out=( )
  local j
  for (( j = 0; j < nb; j++ )); do out[j]=0; done
  local bitpos=0 ch val b
  while (( bitpos < n )); do
    ch="${s:$((bitpos / 3)):1}"
    [[ -n "$ch" ]] || break
    val=$(( ( $(printf '%d' "'$ch") - 48 ) & 0x07 ))
    for b in 0 1 2; do
      if (( bitpos + b >= n )); then break; fi
      if (( val & (4 >> b) )); then
        out[(bitpos + b) / 8]=$(( out[(bitpos + b) / 8] | (1 << (7 - ((bitpos + b) % 8))) ))
      fi
    done
    bitpos=$(( bitpos + 3 ))
  done
  _sec_ret=( "${out[@]}" )
}
# _sec_get_bits <start> <n> <buf bytes...> -> _sec_retval (int)
_sec_get_bits() {
  local st="$1" n="$2"
  shift 2
  local -a buf=( "$@" )
  local i b bits=0
  for (( i = 0; i < n; i++ )); do
    bits=$(( bits << 1 ))
    b=$(( st + i ))
    if (( buf[b / 8] & (1 << (7 - (b % 8))) )); then bits=$(( bits | 1 )); fi
  done
  _sec_retval=$bits
}
# ---------------------------------------------------------------------------
# SHA-256 (FIPS 180-4), fully inlined round math (no per-op function calls)
# so PBKDF2 runs in seconds.  bash builtins only.
#
# Layers:
#   _sec_sha256_blocks <hex-with-padding-and-length>   process whole blocks
#   _sec_sha256        <msghex>                        pad + SHA-256
# and the HMAC fast path reuses post-block-0 states:
#   _sec_hmac_prep     <keyhex>  -> _SEC_IN0/_SEC_OUT0 (post-block-0 states)
#   _sec_hmac_fast     <msghex>  -> _sec_hmachex
# ---------------------------------------------------------------------------
_SEC_SHAK=( 0x428a2f98 0x71374491 0xb5c0fbcf 0xe9b5dba5 0x3956c25b 0x59f111f1 0x923f82a4 0xab1c5ed5
0xd807aa98 0x12835b01 0x243185be 0x550c7dc3 0x72be5d74 0x80deb1fe 0x9bdc06a7 0xc19bf174
0xe49b69c1 0xefbe4786 0x0fc19dc6 0x240ca1cc 0x2de92c6f 0x4a7484aa 0x5cb0a9dc 0x76f988da
0x983e5152 0xa831c66d 0xb00327c8 0xbf597fc7 0xc6e00bf3 0xd5a79147 0x06ca6351 0x14292967
0x27b70a85 0x2e1b2138 0x4d2c6dfc 0x53380d13 0x650a7354 0x766a0abb 0x81c2c92e 0x92722c85
0xa2bfe8a1 0xa81a664b 0xc24b8b70 0xc76c51a3 0xd192e819 0xd6990624 0xf40e3585 0x106aa070
0x19a4c116 0x1e376c08 0x2748774c 0x34b0bcb5 0x391c0cb3 0x4ed8aa4a 0x5b9cca4f 0x682e6ff3
0x748f82ee 0x78a5636f 0x84c87814 0x8cc70208 0x90befffa 0xa4506ceb 0xbef9a3f7 0xc67178f2 )
_sec_sha256_blocks() {
  local msg="$1" i t blk tmp
  local -a H=( 0x6a09e667 0xbb67ae85 0x3c6ef372 0xa54ff53a 0x510e527f 0x9b05688c 0x1f83d9ab 0x5be0cd19 )
  if [[ -n "$_SEC_HINIT" ]]; then
    # resume from a pre-computed 8-word state (HMAC fast path)
    local -a hv
    read -r -a hv <<< "$_SEC_HINIT"
    H=( "${hv[@]}" )
  fi
  local nblocks=$(( ${#msg} / 128 ))
  local -a W=( )
  local A B C D E F G Hh
  local s0 s1 S1 S0 t1 t2 ch ma
  for (( blk = 0; blk < nblocks; blk++ )); do
        for (( i = 0; i < 16; i++ )); do
      W[i]=$(( 0x${msg:$((blk*128 + i*8)):8} ))
    done
    for (( i = 16; i < 64; i++ )); do
      s0=$(( ( ((W[$((i-15))] >> 7) | (W[$((i-15))] << 25)) ^
               ((W[$((i-15))] >> 18) | (W[$((i-15))] << 14)) ^
               (W[$((i-15))] >> 3) ) & 0xFFFFFFFF ))
      s1=$(( ( ((W[$((i-2))] >> 17) | (W[$((i-2))] << 15)) ^
               ((W[$((i-2))] >> 19) | (W[$((i-2))] << 13)) ^
               (W[$((i-2))] >> 10) ) & 0xFFFFFFFF ))
      W[i]=$(( (W[i-16] + s0 + W[i-7] + s1) & 0xFFFFFFFF ))
    done
    A=${H[0]}; B=${H[1]}; C=${H[2]}; D=${H[3]}
    E=${H[4]}; F=${H[5]}; G=${H[6]}; Hh=${H[7]}
    for (( t = 0; t < 64; t++ )); do
      S1=$(( ( ((E >> 6) | (E << 26)) ^ ((E >> 11) | (E << 21)) ^ ((E >> 25) | (E << 7)) ) & 0xFFFFFFFF ))
      ch=$(( (E & F) ^ ((~E) & G) ))
      t1=$(( (Hh + S1 + ch + _SEC_SHAK[t] + W[t]) & 0xFFFFFFFF ))
      S0=$(( ( ((A >> 2) | (A << 30)) ^ ((A >> 13) | (A << 19)) ^ ((A >> 22) | (A << 10)) ) & 0xFFFFFFFF ))
      ma=$(( (A & B) ^ (A & C) ^ (B & C) ))
      t2=$(( (S0 + ma) & 0xFFFFFFFF ))
      Hh=$G; G=$F; F=$E
      E=$(( (D + t1) & 0xFFFFFFFF ))
      D=$C; C=$B; B=$A
      A=$(( (t1 + t2) & 0xFFFFFFFF ))
    done
    H[0]=$(( (H[0] + A) & 0xFFFFFFFF ))
    H[1]=$(( (H[1] + B) & 0xFFFFFFFF ))
    H[2]=$(( (H[2] + C) & 0xFFFFFFFF ))
    H[3]=$(( (H[3] + D) & 0xFFFFFFFF ))
    H[4]=$(( (H[4] + E) & 0xFFFFFFFF ))
    H[5]=$(( (H[5] + F) & 0xFFFFFFFF ))
    H[6]=$(( (H[6] + G) & 0xFFFFFFFF ))
    H[7]=$(( (H[7] + Hh) & 0xFFFFFFFF ))
  done
  local digest="" st="" tmp
  for (( i = 0; i < 8; i++ )); do
    printf -v tmp "%08x" "${H[$i]}"
    digest+="$tmp"
    st+=" ${H[$i]}"
  done
  _sec_shahex="$digest"
  _sec_retval="$digest"
  _sec_sha_state="${st# }"
}

# _sec_sha256 <msghex> : standard SHA-256
_sec_sha256() {
  local msg="$1" nbytes=$(( ${#1} / 2 ))
  local nbits=$(( nbytes * 8 ))
  local ph="$msg" z hx
  ph+="80"
  z=$(( (64 - ((nbytes + 9) % 64)) % 64 ))
  while (( z > 0 )); do ph+="00"; z=$(( z - 1 )); done
  printf -v hx "%016x" "$nbits"
  ph+="$hx"
  _SEC_HINIT=""
  _sec_sha256_blocks "$ph"
}

# _sec_hmac_pad <hex> <total_hex_bytes_before_tail> : append the tail
# (0x80 + zeros + 8-byte BE bit length) so the result is whole 64-byte blocks;
# length covers <total> bytes (message + the 64-byte pad prefix).
_sec_hmac_tail() {  # <hex> <totallen_bytes> -> _sec_retval (padded hex)
  local m="$1" total="$2" L nbytes z hx
  L=${#m}; nbytes=$(( L / 2 ))
  # bytes to add: 1 (0x80) + zero fill + 8; make total multiple of 64
  z=$(( (64 - ((nbytes + 9) % 64)) % 64 ))
  m+="80"
  while (( z > 0 )); do m+="00"; z=$(( z - 1 )); done
  printf -v hx "%016x" $(( total * 8 ))
  m+="$hx"
  _sec_retval="$m"
}
_sec_hmac_prep() {   # <keyhex> -> _SEC_IN0 _SEC_OUT0 (post-block-0 states)
  local key="$1"
  local klen=$(( ${#key} / 2 )) i kb
  local ipad="" opad="" hx
  if (( klen > 64 )); then
    _sec_sha256 "$key"
    key="$_sec_shahex"; klen=64
  fi
  for (( i = 0; i < 64; i++ )); do
    if (( i < klen )); then kb=$(( 0x${key:$((i*2)):2} )); else kb=0; fi
    printf -v hx "%02x" $(( kb ^ 0x36 )); ipad+="$hx"
    printf -v hx "%02x" $(( kb ^ 0x5c )); opad+="$hx"
  done
  _SEC_IPADHEX="$ipad"
  _SEC_OPADHEX="$opad"
  # state after compressing the exact 64-byte pad block (no length)
  _SEC_HINIT=""
  _sec_sha256_blocks "$ipad"
  _SEC_IN0="$_sec_sha_state"
  _SEC_HINIT=""
  _sec_sha256_blocks "$opad"
  _SEC_OUT0="$_sec_sha_state"
}
_sec_hmac_fast() {    # <msghex> (uses prepared pads) -> _sec_hmachex
  local msg="$1" inner pad
  # inner = sha256(ipad(64) || msg): block0 already folded into _SEC_IN0
  _sec_hmac_tail "$msg" $(( 64 + ${#msg} / 2 ))
  _SEC_HINIT="$_SEC_IN0"
  _sec_sha256_blocks "$_sec_retval"
  inner="$_sec_shahex"
  # outer = sha256(opad(64) || inner)
  _sec_hmac_tail "$inner" 96
  _SEC_HINIT="$_SEC_OUT0"
  _sec_sha256_blocks "$_sec_retval"
  _sec_hmachex="$_sec_shahex"
  _sec_retval="$_sec_shahex"
}
#
# Backends, probed once at first call:
#   * openssl >= 3.0 `openssl kdf ... PBKDF2` when available (3-orders faster)
#   * pure-bash fallback otherwise
_sec_pbkdf2() {
  local pw="$1" salt="$2" iter="$3" dk="$4"
  local i hx msg h prev="" T=""
  if [[ -z "$_SEC_PBKDF2_BACKEND" ]]; then
    # probe openssl kdf availability once (only Linux/GNU-style or 3.x CLI)
    _SEC_PBKDF2_BACKEND="bash"
    if command -v openssl >/dev/null 2>&1 && \
       openssl kdf -help >/dev/null 2>&1 && \
       openssl kdf -keylen 16 -kdfopt digest:SHA256 -kdfopt hexpass:70617373 \
          -kdfopt hexsalt:73616c74 -kdfopt iter:1 PBKDF2 >/dev/null 2>&1; then
      local v
      v=$(openssl version 2>/dev/null | head -n1)
      case "$v" in
        OpenSSL[[:space:]]3.*|OpenSSL[[:space:]]4.*) _SEC_PBKDF2_BACKEND="openssl" ;;
      esac
    fi
  fi
  if [[ "$_SEC_PBKDF2_BACKEND" == "openssl" ]]; then
    local o
    o=$(openssl kdf -keylen "$dk" -kdfopt digest:SHA256 \
        -kdfopt "hexpass:$pw" -kdfopt "hexsalt:$salt" \
        -kdfopt "iter:$iter" PBKDF2 2>/dev/null | tr -d ' :\n')
    if [[ -n "$o" ]]; then
      _sec_retval="$(printf '%s' "$o" | tr 'A-F' 'a-f')"
      return 0
    fi
    # openssl failed at runtime - fall back to the pure-bash path
    _SEC_PBKDF2_BACKEND="bash"
  fi
  _sec_hmac_prep "$pw"
  for (( i = 1; i <= iter; i++ )); do
    if (( i == 1 )); then
      printf -v hx "%08x" "$i"
      msg="$salt$hx"
    else
      msg="$prev"
    fi
    _sec_hmac_fast "$msg"
    h="$_sec_hmachex"
    if [[ -z "$T" ]]; then T="$h"
    else
      _sec_xorbytes "$T" "$h"
      T="$_sec_retval"
    fi
    prev="$h"
  done
  _sec_retval="${T:0:$(( dk * 2 ))}"
}
# ---------------------------------------------------------------------------
# UTC calendar math: unix time -> Y/M/D H:M:S in UTC
# Uses Howard Hinnant's civil_from_days algorithm
# ---------------------------------------------------------------------------
# _sec_epoch_parts <t> -> _sec_retval "YYYY MM DD HH MM SS"
_sec_epoch_parts() {
  local t="$1" days soday
  _sec_fdiv "$t" 86400; days=$_sec_retval      # floor division (t>=0 anyway)
  _sec_fmod "$t" 86400; soday=$_sec_retval
  # civil from days
  local z=$(( days + 719468 ))
  local era=$(( (z >= 0 ? z : z - 146096) / 146097 ))
  local doe=$(( z - era * 146097 ))
  local yoe=$(( (doe - doe/1460 + doe/36524 - doe/146096) / 365 ))
  local y=$(( yoe + era * 400 ))
  local doy=$(( doe - (365*yoe + yoe/4 - yoe/100) ))
  local mp=$(( (5*doy + 2)/153 ))
  local dd=$(( doy - (153*mp + 2)/5 + 1 ))
  local mm=$(( mp < 10 ? mp + 3 : mp - 9 ))
  local yyyy=$(( y + (mm <= 2 ? 1 : 0) ))
  local hh=$(( soday / 3600 ))
  local mi=$(( (soday % 3600) / 60 ))
  local se=$(( soday % 60 ))
  _sec_retval="$yyyy $mm $dd $hh $mi $se"
}

# ---------------------------------------------------------------------------
# v1/v2 (ctf) tokens
# ---------------------------------------------------------------------------
# _sec_v2_decode <digits> <smartphone> : sets module fields:
#   _sec_v2_version _sec_v2_serial _sec_v2_enc_seed _sec_v2_flags
#   _sec_v2_exp_date _sec_v2_dec_seed_hash _sec_v2_device_id_hash
_sec_v2_decode() {
  local s="$1" smartphone="$2" d
  _sec_err=""
  local c0="${s:0:1}"
  if [[ $c0 != 1 && $c0 != 2 || ${#s} -lt 81 ]]; then
    _sec_err="not a valid ctf token string"; return 1
  fi
  local vers=$c0
  local serial="${s:1:12}"
  local body="${s:13}"
  if (( ${#body} < 68 )); then _sec_err="ctf token too short"; return 1; fi
  local data_part="${body:0:63}"
  local checksum_part="${body: -5}"
  _sec_bufhex "${s:0:1}${serial}${body:0:${#body}-5}"
  _sec_shortmac "$_sec_retval"
  local computed=$_sec_retval
  _sec_digits_to_bits "$checksum_part" 15
  local -a cb=( "${_sec_ret[@]}" )
  _sec_get_bits 0 15 "${cb[@]}"
  if (( _sec_retval != computed )); then
    _sec_err="ctf checksum failed (bad token string)"; return 1
  fi
  _sec_digits_to_bits "$data_part" 189
  d=( "${_sec_ret[@]}" )
  _sec_bytes2hex "${d[@]:0:16}"
  _sec_v2_enc_seed="$_sec_retval"
  _sec_get_bits 128 16 "${d[@]}"; _sec_v2_flags=$_sec_retval
  _sec_get_bits 144 14 "${d[@]}"; _sec_v2_exp_date=$_sec_retval
  _sec_get_bits 159 15 "${d[@]}"; _sec_v2_dec_seed_hash=$_sec_retval
  _sec_get_bits 174 15 "${d[@]}"; _sec_v2_device_id_hash=$_sec_retval
  _sec_v2_version=$vers
  _sec_v2_serial="$serial"
  _sec_v2_smartphone=$smartphone
  return 0
}
# _sec_bufhex <str> -> _sec_retval (utf-8 bytes as hex); uses _sec_str2bytes
_sec_bufhex() { _sec_str2bytes "$1"; _sec_bytes2hex "${_sec_ret[@]}"; }

# _sec_v2_key_hash <passw> <devid> <vers> <smartphone>:
#   -> _sec_v2_keyhash (16B hex)  _sec_v2_devidhash (int)
_sec_v2_key_hash() {
  local passw="$1" devid="$2" vers="$3" smartphone="$4"
  local -a key
  key=( )
  _sec_err=""
  local pwlen=0
  if [[ -n "$passw" ]]; then
    _sec_str2bytes "$passw"
    pwlen=${#_sec_ret[@]}
    if (( pwlen > 40 )); then _sec_err="password too long"; return 1; fi
    key=( "${_sec_ret[@]}" )
  fi
  local pos=$pwlen
  local devid_buf_start=$pos
  local devid_len=$(( smartphone ? 40 : 32 ))
  local written=0 ch
  if [[ -n "$devid" ]]; then
    local ud="${devid^^}"
    local ich
    for (( ich = 0; ich < ${#ud}; ich++ )); do
      (( written >= devid_len )) && break
      ch="${ud:$ich:1}"
      if [[ $vers == 1 ]]; then [[ $ch == [0-9] ]] || continue
      else [[ $ch == [0-9A-F] ]] || continue; fi
      key[pos]=$(printf '%d' "'${ch}")
      pos=$(( pos + 1 ))
      written=$(( written + 1 ))
    done
  fi
  # device region: key[devid_buf_start .. +devid_len]
  local -a dr=( "${key[@]:devid_buf_start:devid_len}" )
  _sec_bytes2hex "${dr[@]}"
  _sec_shortmac "$_sec_retval"
  _sec_v2_devidhash=$_sec_retval
  # append magic bytes to key
  key+=( "${_SEC_V2_MAGIC[@]}" )
  _sec_bytes2hex "${key[@]:0:pos+6}"
  _sec_mac "$_sec_retval"
  _sec_v2_keyhash="$_sec_machex"
  return 0
}

# _sec_v2_unlock <passw> <devid> : needs _sec_v2_* fields -> _sec_v2_dec_seed (hex)
_sec_v2_unlock() {
  local passw="$1" devid="$2"
  _sec_err=""
  _sec_v2_key_hash "$passw" "$devid" "$_sec_v2_version" "$_sec_v2_smartphone" || return 1
  if (( _sec_v2_flags & _SEC_F_SNPROT )); then
    if (( _sec_v2_devidhash != _sec_v2_device_id_hash )); then
      _sec_err="device ID does not match this token"; return 1
    fi
  fi
  _sec_aes128_ecb "$_sec_v2_keyhash" "$_sec_v2_enc_seed" "D"
  _sec_v2_dec_seed="$_sec_retval"
  _sec_shortmac "$_sec_v2_dec_seed"
  if (( _sec_retval != _sec_v2_dec_seed_hash )); then
    _sec_err="failed to decrypt seed (wrong password?)"; return 1
  fi
  return 0
}

# ---------------------------------------------------------------------------
# tokencode computation
# ---------------------------------------------------------------------------
_sec_bcd() {   # <val> <nbytes> -> _sec_ret[] (BCD, high nibble first)
  local val="$1" n="$2" i
  _sec_ret=()
  for (( i = n - 1; i >= 0; i-- )); do
    _sec_ret[i]=$(( val % 10 ))
    val=$(( val / 10 ))
    _sec_ret[i]=$(( _sec_ret[i] | ((val % 10) << 4) ))
    val=$(( val / 10 ))
  done
}
# _sec_key_from_time <bcd_int[]> <nbytes> <serial>
#   bcd array passed first; call with "${bcd[@]}" <nbytes> <serial>
#   -> _sec_keyfrom_hx (16B hex)
_sec_key_from_time() {
  # args: <bcd...> <nbytes> <serial>  (nbytes next-to-last, serial last)
  # single-element positional slices converted to scalars:
  # shellcheck disable=SC2124
  local -a bcd=( "${@:1:${#@}-2}" )
  # single-element positional slices -> scalars (safe: pos params)
  # shellcheck disable=SC2124
  local nbytes="${@:$(( ${#@} - 1 )):1}"
  # shellcheck disable=SC2124
  local serial="${@: -1}"
  local -a k
  k=( 170 170 170 170 170 170 170 170 170 170 170 170 170 170 170 170 )
  local i
  for (( i = 0; i < nbytes; i++ )); do k[i]=${bcd[$i]}; done
  k[12]=187; k[13]=187; k[14]=187; k[15]=187
  local j i2 s1 s2
  for (( j = 0; j < 4; j++ )); do
    i2=$(( 4 + 2*j ))
    s1="${serial:$i2:1}"; s2="${serial:$((i2+1)):1}"
    k[8+j]=$(( (($(printf '%d' "'${s1}") - 48) << 4) | ($(printf '%d' "'${s2}") - 48) ))
  done
  _sec_bytes2hex "${k[@]}"
  _sec_keyfrom_hx="$_sec_retval"
}
# _sec_compute_tokencode <dec_seedhex> <serial> <flags> <t> <pin>
#   -> _sec_code, _sec_retval
_sec_compute_tokencode() {
  local dec_seed="$1" serial="$2" flags="$3" t="$4" pin="$5"
  _sec_err=""
  # Python's compute_tokencode() used time.time() when t was omitted.  Keep
  # that public behavior here; the direct pass CLI also leaves t empty.
  if [[ -z "$t" ]]; then
    t=$(date +%s)
  elif [[ "${t:0:1}" == "+" || "${t:0:1}" == "-" ]]; then
    t=$(( $(date +%s) + t ))
  fi
  local is_30=1
  if (( (flags & _SEC_FNUM) != 0 )); then is_30=0; fi
  _sec_epoch_parts "$t"
  local yyyy mm dd hh mi ss
  read -r yyyy mm dd hh mi ss <<<"$_sec_retval"
  local -a bcd_time=( 0 0 0 0 0 0 0 0 )
  _sec_bcd "$yyyy" 2; bcd_time[0]=${_sec_ret[0]}; bcd_time[1]=${_sec_ret[1]}
  _sec_bcd "$mm" 1;   bcd_time[2]=${_sec_ret[0]}
  _sec_bcd "$dd" 1;   bcd_time[3]=${_sec_ret[0]}
  _sec_bcd "$hh" 1;   bcd_time[4]=${_sec_ret[0]}
  local m=$mi
  if (( is_30 )); then m=$(( m & ~1 )); else m=$(( m & ~3 )); fi
  _sec_bcd "$m" 1;    bcd_time[5]=${_sec_ret[0]}
  bcd_time[6]=0; bcd_time[7]=0
  local key0 key1
  _sec_key_from_time "${bcd_time[@]}" 2 "$serial"; key0="$_sec_keyfrom_hx"
  _sec_aes128_ecb "$dec_seed" "$key0" "E"; key0="$_sec_retval"
  _sec_key_from_time "${bcd_time[@]}" 3 "$serial"; key1="$_sec_keyfrom_hx"
  _sec_aes128_ecb "$key0" "$key1" "E"; key1="$_sec_retval"
  _sec_key_from_time "${bcd_time[@]}" 4 "$serial"; key0="$_sec_keyfrom_hx"
  _sec_aes128_ecb "$key1" "$key0" "E"; key0="$_sec_retval"
  _sec_key_from_time "${bcd_time[@]}" 5 "$serial"; key1="$_sec_keyfrom_hx"
  _sec_aes128_ecb "$key0" "$key1" "E"; key1="$_sec_retval"
  _sec_key_from_time "${bcd_time[@]}" 8 "$serial"; key0="$_sec_keyfrom_hx"
  _sec_aes128_ecb "$key1" "$key0" "E"; key0="$_sec_retval"
  local i
  if (( is_30 )); then
    i=$(( ((mi & 0x01) << 3) | ((ss >= 30 ? 1 : 0) << 2) ))
  else
    i=$(( (mi & 0x03) << 2 ))
  fi
  local tk=0 j
  for j in 0 1 2 3; do
    tk=$(( (tk << 8) | 0x${key0:$(( (i+j)*2 )):2} ))
  done
  local digits=$(( ((flags & _SEC_FDIGIT) >> 6) + 1 ))
  local pinlen=${#pin}
  local -a out=( )
  local k c ch
  for (( k = 0; k < digits; k++ )); do
    c=$(( tk % 10 )); tk=$(( tk / 10 ))
    if (( k < pinlen )); then
      ch="${pin:$((pinlen-k-1)):1}"
      c=$(( c + $(printf '%d' "'${ch}") - 48 ))
    fi
    out[k]=$(( c % 10 ))
  done
  local code=""
  for (( k = digits - 1; k >= 0; k-- )); do code+="${out[$k]}"; done
  _sec_code="$code"
  _sec_retval="$code"
}
# ---------------------------------------------------------------------------
# v3/v4 Android tokens
# ---------------------------------------------------------------------------
# _sec_scrub_devid <devid> -> _sec_retval : upper alnum, max 48 chars
_sec_scrub_devid() {
  local d="$1" dout="" c
  local n=${#d}
  for (( i = 0; i < n; i++ )); do
    c="${d:$i:1}"
    case "$c" in
      [0-9A-Za-z]) dout+="${c^^}" ;;
    esac
    (( ${#dout} >= 48 )) && break
  done
  _sec_retval="${dout:0:48}"
}

# _sec_v3_decode <b64str> : sets _sec_v3_* fields (hex forms). rc 1 + _sec_err on bad.
_sec_v3_decode() {
  local s="$1"
  _sec_err=""
  _sec_b64decode "$s"
  local ln=${#_sec_ret[@]}
  if (( ln != 291 )); then _sec_err="bad Android token length $ln"; return 1; fi
  _sec_bytes2hex "${_sec_ret[@]}"
  local hx="$_sec_retval"      # 582 hex chars
  _sec_v3_version=$(( 0x${hx:0:2} ))
  if (( _sec_v3_version != 3 && _sec_v3_version != 4 )); then
    _sec_err="bad token version $_sec_v3_version"; return 1
  fi
  _sec_v3_password_locked=$(( 0x${hx:2:2} != 0 ))
  _sec_v3_devid_locked=$(( 0x${hx:4:2} != 0 ))
  _sec_v3_nonce_devid_hash="${hx:6:64}"        # bytes 3..35
  _sec_v3_nonce_devid_pass_hash="${hx:70:64}"  # bytes 35..67
  _sec_v3_nonce="${hx:134:32}"                 # bytes 67..83
  _sec_v3_enc_payload="${hx:166:352}"          # bytes 83..259
  _sec_v3_mac="${hx:518:64}"                   # bytes 259..291
  return 0
}

# _sec_v3_compute_hash <passw> <devid-scrubbed> <noncehex>
#   -> _sec_shahex (32B)
_sec_v3_compute_hash() {
  local passw="$1" devid="$2" nonce="$3" buf="" hx
  buf="$nonce"
  if [[ -n "$devid" ]]; then _sec_hexstr "$devid"; buf+="$_sec_retval"; fi
  # the python buffer is pre-zeroed to 16+48+40 bytes and hashed over
  # buf[:16+48+pass_len]; pad the devid zone to 64 bytes (128 hex).
  while (( ${#buf} < 128 )); do buf+="00"; done
  buf="${buf:0:128}"
  if [[ -n "$passw" ]]; then _sec_hexstr "$passw"; buf+="$_sec_retval"; fi
  _sec_sha256 "$buf"
}
# _sec_hexstr <str> -> _sec_retval (hex bytes)
_sec_hexstr() { _sec_str2bytes "$1"; _sec_bytes2hex "${_sec_ret[@]}"; }

# _sec_v3_derive_key <passw> <devid> <noncehex> <key_id> <version>
#   -> _sec_pbkdf_ret (32B hex) [via _sec_pbkdf2]
_sec_v3_derive_key() {
  local passw="$1" devid="$2" nonce="$3" key_id="$4" version="$5"
  local pw_hex="" d_hex="" buf0=""
  if [[ -n "$passw" ]]; then _sec_hexstr "$passw"; pw_hex="$_sec_retval"; fi
  if [[ -n "$devid" ]]; then _sec_hexstr "$devid"; d_hex="$_sec_retval"; fi
  buf0="$pw_hex"
  buf0+="$d_hex"
  # pad the devid zone (bytes pass_len..pass_len+48) with zeros
  local passlen=$(( ${#pw_hex}/2 ))
  while (( ${#buf0}/2 < passlen + _SEC_V3_DEVID )); do buf0+="00"; done
  if (( key_id )); then _sec_arrhex _SEC_KEY1; buf0+="$_sec_retval"
  else _sec_arrhex _SEC_KEY0; buf0+="$_sec_retval"; fi
  buf0+="$nonce"
  # python zero-pads buf0 to _V3_DEVID+16+16+pass_len bytes before use
  local totlen=$(( _SEC_V3_DEVID + 32 + passlen ))
  while (( ${#buf0} < totlen*2 )); do buf0+="00"; done
  local buf="$buf0"
  if (( version == 3 )); then
    # bytes(buf0[1::2]): every other byte starting at index 1
    local odd="" i
    # bytes(buf0[1::2]): every second BYTE (4 hex chars) from byte 1
    for (( i = 2; i < ${#buf0}; i += 4 )); do odd+="${buf0:$i:2}"; done
    buf="$odd"
  fi
  _sec_pbkdf2 "$buf" "$nonce" 1000 32
  _sec_pbkdf_ret="$_sec_retval"
}
# _sec_arrhex <varname> -> _sec_retval (hex of array)
_sec_arrhex() {
  local -n arr=$1
  _sec_bytes2hex "${arr[@]}"
}

# _sec_v3_compute_hmac <tok fields> <passw> <devid>
#   uses _sec_v3_* fields -> _sec_hmachex
_sec_v3_compute_hmac() {
  local passw="$1" devid="$2"
  _sec_v3_derive_key "$passw" "$devid" "$_sec_v3_nonce" 0 "$_sec_v3_version"
  local key="$_sec_pbkdf_ret"
  local msg=""
  printf -v msg "%02x%02x%02x" "$_sec_v3_version" "$_sec_v3_password_locked" "$_sec_v3_devid_locked"
  msg+="$_sec_v3_nonce_devid_hash$_sec_v3_nonce_devid_pass_hash$_sec_v3_nonce$_sec_v3_enc_payload"
  _sec_hmac_prep "$key"
  _sec_hmac_fast "$msg"
}

# _sec_v3_parse_payload <payloadhex(176B)> -> _sec_payload_* fields
_sec_v3_parse_payload() {
  local p="$1"
  # serial = ascii of bytes 0..12
  local i ser=""
  for (( i = 0; i < 12; i++ )); do
    ser+="$(printf '%b' "\\x${p:$((i*2)):2}")"
  done
  _sec_payload_serial="$ser"
  _sec_payload_dec_seed="${p:32:32}"                    # bytes 16..32
  local digits=$(( 0x${p:70:2} ))                        # byte 35
  local addpin=$(( 0x${p:72:2} ))                        # byte 36
  local interval=$(( 0x${p:74:2} ))                      # byte 37
  local longdate=$(( 0x${p:96:10} ))                     # bytes 48..53
  local exp=$(( longdate / _SEC_V3_DAY - _SEC_EPOCH_DAYS ))
  (( exp < 0 )) && exp=0
  local flags=$(( (1 << 9) | (1 << 14) ))
  flags=$(( flags | (((digits - 1) << 6) & _SEC_FDIGIT) ))
  if (( addpin != 0x1f )); then flags=$(( flags | (2 << 3) )); fi
  if (( interval == 60 )); then flags=$(( flags | 1 )); fi
  _sec_payload_flags=$flags
  _sec_payload_exp_date=$exp
  _sec_payload_digits=$digits
}

# _sec_v3_unlock <passw> <devid> : needs _sec_v3_* fields
#   -> _sec_payload_* fields (serial/dec_seed/flags/exp) ; rc + _sec_err
_sec_v3_unlock() {
  local passw="$1" devid="$2"
  _sec_err=""
  local devid0="" h1 h2
  if [[ -n "$devid" ]]; then _sec_scrub_devid "$devid"; devid0="$_sec_retval"; fi
  _sec_v3_compute_hash "" "$devid0" "$_sec_v3_nonce"
  if [[ "$_sec_shahex" != "$_sec_v3_nonce_devid_hash" ]]; then
    _sec_err="device ID does not match this token"; return 1
  fi
  _sec_v3_compute_hash "$passw" "$devid0" "$_sec_v3_nonce"
  if [[ "$_sec_shahex" != "$_sec_v3_nonce_devid_pass_hash" ]]; then
    _sec_err="password does not match this token"; return 1
  fi
  _sec_v3_compute_hmac "$passw" "$devid0"
  if [[ "$_sec_hmachex" != "$_sec_v3_mac" ]]; then
    _sec_err="token MAC mismatch"; return 1
  fi
  _sec_v3_derive_key "$passw" "$devid0" "$_sec_v3_nonce" 1 "$_sec_v3_version"
  local key="$_sec_pbkdf_ret"
  _sec_aes256_cbc "$key" "$_sec_v3_nonce" "$_sec_v3_enc_payload" "D"
  _sec_v3_parse_payload "$_sec_retval"
  return 0
}
# _sec_extract <s> : strip 'ctfData=' prefix variants -> _sec_retval
_sec_extract() {
  local s="$1" m
  if [[ "$s" == *"ctfData="* ]]; then
    local rest="${s#*ctfData=}"
    # 'ctfData=3D' implies a leading '=' (URL-encoded) that gets eaten
    if [[ "$rest" == 3D* ]]; then rest="${rest:2}"; fi
    _sec_retval="$rest"
    return
  fi
  local s2="${s#"${s%%[![:space:]]*}"}"    # lstrip spaces
  s2="${s2%"${s2##*[![:space:]]}"}"        # rstrip spaces
  if [[ "$s2" == '<?xml'* ]]; then
    _sec_err="sdtid XML files are not supported; convert the token with stoken export --blocks"
    _sec_retval=""
    return 1
  fi
  _sec_retval="$s2"
}

# _sec_parse <s> : determine kind and populate _sec_v2_* / _sec_v3_* fields
#   -> _sec_kind ('v2'|'v3'); rc 1 + _sec_err on garbage
_sec_parse() {
  local s="$1" raw smartphone=0
  _sec_err=""
  _sec_extract "$s" || return 1
  raw="$_sec_retval"
  case "$s" in
    com.rsa.securid.iphone://ctf|com.rsa.securid://ctf|http://127.0.0.1/securid/ctf*)
      smartphone=1 ;;
  esac
  local c0="${raw:0:1}"
  if [[ $c0 == 1 || $c0 == 2 ]]; then
    local digits="" i c
    for (( i = 0; i < ${#raw}; i++ )); do
      c="${raw:$i:1}"
      case "$c" in [0-9]) digits+="$c" ;; esac
    done
    if (( ${#digits} < 81 )); then _sec_err="ctf string too short"; return 1; fi
    _sec_v2_decode "$digits" "$smartphone" || return 1
    _sec_kind="v2"
    return 0
  elif [[ $c0 == A || $c0 == B ]]; then
    _sec_url_decode "$raw"
    _sec_v3_decode "$_sec_retval" || return 1
    _sec_kind="v3"
    return 0
  fi
  _sec_err="unrecognized token format"
  return 1
}

# _sec_token_info <s> : header info (no unlock) -> _sec_ti_* fields
_sec_token_info() {
  local s="$1"
  _sec_full_info=0
  _sec_parse "$s" || return 1
  if [[ "$_sec_kind" == "v2" ]]; then
    _sec_ti_kind="v2"
    _sec_ti_version="$_sec_v2_version"
    _sec_ti_serial="$_sec_v2_serial"
    _sec_ti_flags="$_sec_v2_flags"
    _sec_ti_flags="${_sec_v2_flags}"
    if (( _sec_v2_flags & _SEC_F_PASSPROT )); then _sec_ti_password_locked=1; else _sec_ti_password_locked=0; fi
    if (( _sec_v2_flags & _SEC_F_SNPROT )); then _sec_ti_devid_locked=1; else _sec_ti_devid_locked=0; fi
    _sec_ti_digits=$(( ((_sec_v2_flags & _SEC_FDIGIT) >> 6) + 1 ))
    if (( _sec_v2_flags & 1 )); then _sec_ti_interval=60; else _sec_ti_interval=30; fi
    if (( ((_sec_v2_flags & _SEC_FPINMODE) >> 3) >= 2 )); then _sec_ti_pin_required=1; else _sec_ti_pin_required=0; fi
    _sec_ti_exp_date="$_sec_v2_exp_date"
    _sec_ti_smartphone="$_sec_v2_smartphone"
    if (( _sec_v2_flags & (1 << 14) )); then _sec_ti_is_128bit=1; else _sec_ti_is_128bit=0; fi
    _sec_ti_serial_valid=1
  else
    _sec_ti_kind="v3"
    _sec_ti_version="$_sec_v3_version"
    _sec_ti_password_locked="$_sec_v3_password_locked"
    _sec_ti_devid_locked="$_sec_v3_devid_locked"
    _sec_ti_serial_valid=0
  fi
  return 0
}

# _sec_unlock <s> <passw> <devid> : populates _sec_v2_dec_seed / _sec_payload_*
#   (kind held in _sec_kind); rc 1 + _sec_err on failure
_sec_unlock() {
  local s="$1" passw="$2" devid="$3"
  _sec_parse "$s" || return 1
  if [[ "$_sec_kind" == "v2" ]]; then
    if (( _sec_v2_flags & _SEC_F_PASSPROT )) && [[ -z "$passw" ]]; then
      _sec_err="password required"; return 1
    fi
    if (( _sec_v2_flags & _SEC_F_SNPROT )) && [[ -z "$devid" ]]; then
      _sec_err="device ID required"; return 1
    fi
    _sec_v2_unlock "$passw" "$devid" || return 1
    _sec_token_info "$s"
    return 0
  else
    if (( _sec_v3_password_locked )) && [[ -z "$passw" ]]; then
      _sec_err="password required"; return 1
    fi
    if (( _sec_v3_devid_locked )) && [[ -z "$devid" ]]; then
      _sec_err="device ID required"; return 1
    fi
    _sec_v3_unlock "$passw" "$devid" || return 1
    return 0
  fi
}

# _sec_detect_devid <s> <passw?> : first class GUID that unlocks -> _sec_retval
_sec_detect_devid() {
  local s="$1" passw="$2" g
  _sec_retval=""
  _sec_parse "$s" || return 0
  local requires_pass=0
  if [[ "$_sec_kind" == "v2" ]]; then
    if (( _sec_v2_flags & _SEC_F_PASSPROT )); then requires_pass=1; fi
  else
    if (( _sec_v3_password_locked )); then requires_pass=1; fi
  fi
  if (( requires_pass )) && [[ -z "$passw" ]]; then return 0; fi
  for g in "${_SEC_CLASS_GUIDS[@]}"; do
    if _sec_unlock "$s" "$passw" "$g" 2>/dev/null; then
      _sec_retval="$g"
      return 0
    fi
  done
  _sec_retval=""
  return 0
}

_sec_json_escape() {   # <s> -> _sec_retval : quoted + escaped JSON string
  local s="$1" esc='"'
  local i c
  for (( i = 0; i < ${#s}; i++ )); do
    c="${s:$i:1}"
    if [[ "$c" == '"' ]]; then
      esc+="\""
    elif [[ "$c" == "\\" ]]; then
      esc+="\\"
    else
      esc+="$c"
    fi
  done
  _sec_retval="$esc\""
}
# output helpers ------------------------------------------------------------
# _sec_describe_json : JSON for token_info(_sec_ti_*)
_sec_describe_json() {
  _sec_json='{'
  if [[ "$_sec_ti_kind" == "v2" ]]; then
    # python token_info (v2): kind,version,serial,flags,pwl,dvl,digits,interval,pin_required,exp_date,smartphone,is_128bit
    _sec_json+="\"kind\": \"v2\", \"version\": $_sec_ti_version, \"serial\": "
    _sec_json_escape "$_sec_ti_serial"; _sec_json+="$_sec_retval"
    _sec_json+=", \"flags\": $_sec_ti_flags, \"password_locked\": "
    if (( _sec_ti_password_locked )); then _sec_json+="true"; else _sec_json+="false"; fi
    _sec_json+=", \"devid_locked\": "
    if (( _sec_ti_devid_locked )); then _sec_json+="true"; else _sec_json+="false"; fi
    _sec_json+=", \"digits\": $_sec_ti_digits, \"interval\": $_sec_ti_interval, \"pin_required\": "
    if (( _sec_ti_pin_required )); then _sec_json+="true"; else _sec_json+="false"; fi
    _sec_json+=", \"exp_date\": $_sec_ti_exp_date, \"smartphone\": "
    if (( _sec_ti_smartphone )); then _sec_json+="true"; else _sec_json+="false"; fi
    _sec_json+=", \"is_128bit\": "
    if (( _sec_ti_is_128bit )); then _sec_json+="true"; else _sec_json+="false"; fi
  else
    if (( _sec_full_info )); then
      # dict(info) for v3 after unlock (python order):
      # kind,version,serial,flags,pwl,dvl,digits,interval,pin_required,exp_date,smartphone
      _sec_json+="\"kind\": \"v3\", \"version\": $_sec_ti_version, \"serial\": "
      _sec_json_escape "$_sec_ti_serial"; _sec_json+="$_sec_retval"
      _sec_json+=", \"flags\": $_sec_ti_flags, \"password_locked\": "
      if (( _sec_ti_password_locked )); then _sec_json+="true"; else _sec_json+="false"; fi
      _sec_json+=", \"devid_locked\": "
      if (( _sec_ti_devid_locked )); then _sec_json+="true"; else _sec_json+="false"; fi
      _sec_json+=", \"digits\": $_sec_ti_digits, \"interval\": $_sec_ti_interval, \"pin_required\": "
      if (( _sec_ti_pin_required )); then _sec_json+="true"; else _sec_json+="false"; fi
      _sec_json+=", \"exp_date\": $_sec_ti_exp_date, \"smartphone\": "
      if (( _sec_ti_smartphone )); then _sec_json+="true"; else _sec_json+="false"; fi
    else
      # python token_info (v3) compact: kind,version,pwl,dvl
      _sec_json+="\"kind\": \"v3\", \"version\": $_sec_ti_version, \"password_locked\": "
      if (( _sec_ti_password_locked )); then _sec_json+="true"; else _sec_json+="false"; fi
      _sec_json+=", \"devid_locked\": "
      if (( _sec_ti_devid_locked )); then _sec_json+="true"; else _sec_json+="false"; fi
    fi
  fi
  _sec_json+="}"
}

# _sec_full_json <code> <decseed> <pin> : --code --full (uses _sec_ti_*)
_sec_full_json() {
  local code="$1" decseed="$2" pin="$3"
  # python: out = dict(info); out['code']; out['dec_seed']; out['pin']
  # info is emitted first (token_info field order), then code/seed/pin appended
  _sec_describe_json
  local base="$_sec_json"
  local body="${base:1:${#base}-2}"     # strip { }
  _sec_json="{${body}, \"code\": "
  _sec_json_escape "$code"; _sec_json+="$_sec_retval"
  _sec_json+=", \"dec_seed\": "
  _sec_json_escape "$decseed"; _sec_json+="$_sec_retval"
  _sec_json+=", \"pin\": "
  _sec_json_escape "$pin"; _sec_json+="$_sec_retval"
  _sec_json+="}"
}

# _sec_print_info_text : the svn '--info --text' writer
_sec_print_info_text() {
  if [[ "$_sec_ti_kind" == "v2" ]]; then
    printf 'Serial number        : %s\n' "$_sec_ti_serial"
    printf 'Key length           : %s\n' "$([ "$_sec_ti_is_128bit" -eq 1 ] && echo 128 || echo 64)"
    printf 'Tokencode digits     : %d\n' "$_sec_ti_digits"
    printf 'Seconds per tokencode: %d\n' "$_sec_ti_interval"
    printf 'PIN mode             : %d\n' "$(( (_sec_ti_flags >> 3) & 3 ))"
    printf 'PIN required         : %s\n' "$([ "$_sec_ti_pin_required" -eq 1 ] && echo yes || echo no)"
    printf 'Encrypted w/password : %s\n' "$([ "$_sec_ti_password_locked" -eq 1 ] && echo yes || echo no)"
    printf 'Encrypted w/devid    : %s\n' "$([ "$_sec_ti_devid_locked" -eq 1 ] && echo yes || echo no)"
  else
    printf 'Token format         : Android (v%d)\n' "$_sec_ti_version"
    if (( _sec_ti_serial_valid )); then
      printf 'Serial number        : %s\n' "$_sec_ti_serial"
      printf 'Key length           : 128\n'
      printf 'Tokencode digits     : %d\n' "$_sec_ti_digits"
      printf 'Seconds per tokencode: %d\n' "$_sec_ti_interval"
      printf 'PIN required         : %s\n' "$([ "$_sec_ti_pin_required" -eq 1 ] && echo yes || echo no)"
    fi
    printf 'Encrypted w/password : %s\n' "$([ "$_sec_ti_password_locked" -eq 1 ] && echo yes || echo no)"
    printf 'Encrypted w/devid    : %s\n' "$([ "$_sec_ti_devid_locked" -eq 1 ] && echo yes || echo no)"
  fi
}

# _sec_engine_cli "$@" : parse same options as the python engine; dispatch.
_sec_engine_cli() {
  local tok="" passw="" devid="" seed="" pin="" time="" cmd="describe"
  local want_full=0 want_text=0
  local arg prev
  prev=""
  for arg in "$@"; do
    case "$prev" in
      --tok) tok="$arg"; prev=""; continue ;;
      --pass|--password) passw="$arg"; prev=""; continue ;;
      --devid) devid="$arg"; prev=""; continue ;;
      --seed) seed="$arg"; prev=""; continue ;;
      --pin) pin="$arg"; prev=""; continue ;;
      --time) time="$arg"; prev=""; continue ;;
    esac
    prev=""
    case "$arg" in
      --tok|--pass|--password|--devid|--seed|--pin|--time) prev="$arg" ;;
      --full) want_full=1 ;;
      --text) want_text=1 ;;
      --json) : ;;
      --describe) cmd="describe" ;;
      --info) cmd="info" ;;
      --code) cmd="code" ;;
      --validate) cmd="validate" ;;
      --detect-devid) cmd="detect-devid" ;;
    esac
  done
  if [[ -z "$tok" ]]; then
    _sec_err="missing --tok"
    echo "securid: $_sec_err" >&2
    return 2
  fi
  # parse time (relative +/- allowed)
  local t=""
  if [[ -n "$time" ]]; then
    if [[ "${time:0:1}" == "+" || "${time:0:1}" == "-" ]]; then
      t=$(( $(date +%s) + time ))
    else
      t=$time
    fi
  fi
  case "$cmd" in
    describe)
      if _sec_token_info "$tok"; then
        _sec_full_info=0
        _sec_describe_json
        printf '%s\n' "$_sec_json"
        return 0
      fi
      echo "securid: $_sec_err" >&2; return 2
      ;;
    info)
      if ! _sec_unlock "$tok" "$passw" "$devid"; then
        echo "securid: $_sec_err" >&2; return 2
      fi
      _sec_token_info "$tok" || { echo "securid: $_sec_err" >&2; return 2; }
      if [[ "$_sec_kind" == "v3" ]]; then
        # fill serial/flags/etc from payload for the non-describe info case
        _sec_ti_serial="$_sec_payload_serial"
        _sec_ti_flags="$_sec_payload_flags"
        _sec_ti_digits=$(( ((_sec_payload_flags & _SEC_FDIGIT) >> 6) + 1 ))
        if (( _sec_payload_flags & 1 )); then _sec_ti_interval=60; else _sec_ti_interval=30; fi
        if (( ((_sec_payload_flags & _SEC_FPINMODE) >> 3) >= 2 )); then _sec_ti_pin_required=1; else _sec_ti_pin_required=0; fi
        _sec_ti_exp_date="$_sec_payload_exp_date"
        _sec_ti_smartphone=1
        _sec_ti_is_128bit=1
        _sec_ti_serial_valid=1
      fi
      if (( want_text )); then _sec_print_info_text
      else
        _sec_describe_json
        printf '%s\n' "$_sec_json"
      fi
      return 0
      ;;
    validate)
      if ! _sec_unlock "$tok" "$passw" "$devid"; then
        echo "securid: $_sec_err" >&2; return 2
      fi
      if [[ "$_sec_kind" == "v2" ]]; then printf '%s\n' "$_sec_v2_serial"
      else printf '%s\n' "$_sec_payload_serial"; fi
      return 0
      ;;
    detect-devid)
      _sec_detect_devid "$tok" "$passw"
      printf '%s\n' "$_sec_retval"
      return 0
      ;;
    code)
      local code decseed=""
      if [[ -n "$seed" ]]; then
        # cached seed allowed only for ctf tokens
        if ! _sec_parse "$tok"; then echo "securid: $_sec_err" >&2; return 2; fi
        if [[ "$_sec_kind" != "v2" ]]; then
          echo "securid: cached seed is only supported for ctf tokens; provide --password/--devid for Android tokens" >&2
          return 2
        fi
        _sec_token_info "$tok"
        decseed="$seed"
        _sec_compute_tokencode "$decseed" "$_sec_ti_serial" "$_sec_ti_flags" "$t" "$pin"
        code="$_sec_code"
      else
        if ! _sec_unlock "$tok" "$passw" "$devid"; then
          echo "securid: $_sec_err" >&2; return 2
        fi
        if [[ "$_sec_kind" == "v2" ]]; then
          decseed="$_sec_v2_dec_seed"; _sec_info_serial="$_sec_v2_serial"; _sec_info_flags="$_sec_v2_flags"
        else
          decseed="$_sec_payload_dec_seed"; _sec_info_serial="$_sec_payload_serial"; _sec_info_flags="$_sec_payload_flags"
          # FIXME: info fields for v3 full output filled by token_info below
        fi
        _sec_token_info "$tok"
        if [[ "$_sec_kind" == "v3" ]]; then
          _sec_ti_serial="$_sec_payload_serial"; _sec_ti_flags="$_sec_payload_flags"
          _sec_ti_digits=$(( ((_sec_payload_flags & _SEC_FDIGIT) >> 6) + 1 ))
          if (( _sec_payload_flags & 1 )); then _sec_ti_interval=60; else _sec_ti_interval=30; fi
          if (( ((_sec_payload_flags & _SEC_FPINMODE) >> 3) >= 2 )); then _sec_ti_pin_required=1; else _sec_ti_pin_required=0; fi
          _sec_ti_exp_date="$_sec_payload_exp_date"
          _sec_ti_smartphone=1; _sec_ti_is_128bit=1; _sec_ti_serial_valid=1
        fi
        _sec_compute_tokencode "$decseed" "$_sec_info_serial" "$_sec_info_flags" "$t" "$pin"
        code="$_sec_code"
      fi
      if (( want_full )); then
        _sec_full_info=1
        _sec_full_json "$code" "$decseed" "$pin"
        printf '%s\n' "$_sec_json"
      else
        printf '%s\n' "$code"
      fi
      return 0
      ;;
    *)
      echo "securid: unknown command $cmd" >&2; return 2
      ;;
  esac
}
_sec_self_test() {
  local passed=0 failed=0 got
  local V2='http://127.0.0.1/securid/ctf?ctfData=258491750817210752367175001073261277346642631755724762324173166222072472716737543'
  local PROT='258491750817271376337025556032745736615071405660444767006173166222072476671610011'
  local V3='http://127.0.0.1/securid/ctf?ctfData=AwEBWoDfCnTYFHKM8RvGCXEbSiReGdGgA88EDrIP6EhAe8tzPkIGiAaXXtInt6UHsgM1NFmwuTVjOlJXIpNXxmj7Iud0hfL2kLmIdPgRiS6jP%2FO8q9Fcpwo%2F8tLukZRoIU7gdFjpSl3teO%2FMWlr9rJBZtkTW4q0mAehJ1tl4l0vGjcDycwmIgyzeods7F43ljVETNZjlHkDTudosNSvmS%2Bl643vFrM6NGT%2BHLrlCX0igfo5i4yaUKwDDS4AiAEq%2Bpp0dv8ZzkpZIEJikRzeWaxpfml%2BmsakJ%2BYAVFcfBoR2%2BLzr1%2Flp7mX%2BwMw4TFDZ4hS88BMY3P7uV9%2BGNz08Euaru779p4XDde0JxrPGPuGjWxUBt%2BN5aUjJkcXvAtswhfirK'
  local V4='com.rsa.securid://ctf?ctfData=BAABaKfqKwgEkWDGEgaxp2ZGloQ7dDw2A8PglNlhP8qCBhtop%2BorCASRYMYSBrGnZkaWhDt0PDYDw%2BCU2WE%2FyoIGGznAfd6pVLcjsDtpKoG5APTUrXL51Bdnf%2FCDvZanmNEGhzDCbsDsFTFyLgKzdht0X1tKt23tFwP%2FDYg9xDS1HvS8Jy3QfT04PFNm%2BdCUUZyMIoTzdFT01msNHtrRxePWU7cB32CE48U%2BKlbW4hPyhphJhkg5qxUA38cD05J1s44hI3FTjaq%2FAhAKAQWsDy7TZE6qtU5f6cYIzdr5PKILhTyCeXRxiYuLinAkXEHWm%2F%2FrFKyroQpn%2FVYAA3NLS59HWBQwWyS2kzhtlzJh%2BI25IMhdhLvVdXdjuNzRxkwjc74z'
  local V2P=9999 V2T=1409757465 V2R=65365425
  local V3P=1234 V3T=1410710132 V3R=27957523
  local V4P=1234 V4T=1650391605 V4R=891523
  local PASS='Correct_horse!battery&staple' DEV3='a01c4380-fc01-4df0-b113-7fb98ec74694' DEV4='d82c-467c-56fb-2058-edf8-add6'

  # v2 tokencode
  if _sec_unlock "$V2" "" "" && _sec_compute_tokencode "$_sec_v2_dec_seed" "$_sec_v2_serial" "$_sec_v2_flags" "$V2T" "$V2P" && [[ "$_sec_code" == "$V2R" ]]; then
    passed=$((passed+1)); printf 'ok   v2 tokencode\n'
  else failed=$((failed+1)); printf 'FAIL v2 tokencode (got %s want %s)\n' "$_sec_code" "$V2R"; fi
  # v2 device-hash/decrypt: PROT with password asdf -> same code
  if _sec_unlock "$PROT" "asdf" "" && _sec_compute_tokencode "$_sec_v2_dec_seed" "$_sec_v2_serial" "$_sec_v2_flags" "$V2T" "$V2P" && [[ "$_sec_code" == "$V2R" ]]; then
    passed=$((passed+1)); printf 'ok   v2 password-protected seed\n'
  else failed=$((failed+1)); printf 'FAIL v2 password-protected seed (got %s)\n' "$_sec_code"; fi
  # v2 wrong password rejected
  if _sec_unlock "$PROT" "wrong" "" 2>/dev/null; then
    failed=$((failed+1)); printf 'FAIL v2 wrong password accepted\n'
  else passed=$((passed+1)); printf 'ok   v2 wrong password rejected\n'; fi
  # v3 tokencode
  if _sec_unlock "$V3" "$PASS" "$DEV3" && _sec_compute_tokencode "$_sec_payload_dec_seed" "$_sec_payload_serial" "$_sec_payload_flags" "$V3T" "$V3P" && [[ "$_sec_code" == "$V3R" ]]; then
    passed=$((passed+1)); printf 'ok   v3 tokencode\n'
  else failed=$((failed+1)); printf 'FAIL v3 tokencode (got %s)\n' "$_sec_code"; fi
  # v3 auto-detect devid
  _sec_detect_devid "$V3" "$PASS"
  got="$_sec_retval"
  if [[ "$got" == "$DEV3" ]]; then
    passed=$((passed+1)); printf 'ok   v3 detect class GUID\n'
  else failed=$((failed+1)); printf 'FAIL v3 detect class GUID (got %s)\n' "$got"; fi
  # v4 tokencode
  if _sec_unlock "$V4" "" "$DEV4" && _sec_compute_tokencode "$_sec_payload_dec_seed" "$_sec_payload_serial" "$_sec_payload_flags" "$V4T" "$V4P" && [[ "$_sec_code" == "$V4R" ]]; then
    passed=$((passed+1)); printf 'ok   v4 tokencode\n'
  else failed=$((failed+1)); printf 'FAIL v4 tokencode (got %s)\n' "$_sec_code"; fi
  # v4 unique devid: no false positive
  _sec_detect_devid "$V4" ""
  got="$_sec_retval"
  if [[ -z "$got" ]]; then
    passed=$((passed+1)); printf 'ok   v4 no false-positive devid\n'
  else failed=$((failed+1)); printf 'FAIL v4 no false-positive devid (got %s)\n' "$got"; fi
  # garbage rejected
  if _sec_parse "999" 2>/dev/null; then
    failed=$((failed+1)); printf 'FAIL garbage token accepted\n'
  else passed=$((passed+1)); printf 'ok   rejects garbage\n'; fi
  # v2 describe fields
  if _sec_token_info "$V2" && [[ "$_sec_ti_serial" == "584917508172" ]]; then
    passed=$((passed+1)); printf 'ok   v2 describe serial\n'
  else failed=$((failed+1)); printf 'FAIL v2 describe serial (got %s)\n' "$_sec_ti_serial"; fi

  printf 'securid self-test: %d passed, %d failed\n' "$passed" "$failed"
  [[ $failed -eq 0 ]]
}

# Is a line a SecurID token (as opposed to metadata / comment / other text)?
_securid_is_token_line() {
  case "$1" in
    ''|'#'*) return 1 ;;
    pin:*|devid:*|seed:*) return 1 ;;
    [12][0-9]*) return 0 ;;    # numeric ctf string
    [AB]*) return 0 ;;         # base64 Android token
    *ctfData=*) return 0 ;;    # iPhone/Android URI
    *) return 1 ;;
  esac
}

# _securid_read_entry <passfile>  -> sets _toke, _pin, _devid, _seed
_securid_read_entry() {
  local passfile="$1" contents line
  _toke="" _pin="" _devid="" _seed=""
  if [[ $PASSAGE == 1 ]]; then
    contents=$($AGE -d -i "$IDENTITIES_FILE" "$passfile") \
      || die "Error: unable to decrypt $passfile"
  else
    contents=$($GPG -d "${GPG_OPTS[@]}" "$passfile") \
      || die "Error: unable to decrypt $passfile"
  fi
  while IFS= read -r line || [[ -n "$line" ]]; do
    if _securid_is_token_line "$line"; then
      [[ -n "$_toke" ]] || _toke="$line"
    else
      local value="${line#*:}"
      value="${value#"${value%%[![:space:]]*}"}"
      case "$line" in
        pin:*)   _pin="$value" ;;
        devid:*) _devid="$value" ;;
        seed:*)  _seed="$value" ;;
      esac
    fi
  done < <(printf '%s\n' "$contents")
}

# _securid_write_entry <passfile> <contents> <message>
# Requires set_ggit/set_gpg_recipients to have run (caller responsibility).
_securid_write_entry() {
  local passfile="$1" contents="$2" message="$3"
  if [[ $PASSAGE == 1 ]]; then
    echo "$contents" | $AGE -e "${AGE_RECIPIENT_ARGS[@]}" -o "$passfile" \
      || die "Error: token encryption aborted"
  else
    echo "$contents" | $GPG -e "${GPG_RECIPIENT_ARGS[@]}" -o "$passfile" "${GPG_OPTS[@]}" \
      || die "Error: token encryption aborted."
  fi
  git_add_file "$passfile" "$message"
}

# Read a token string from --file, a CLI argument, or stdin.  Sets _secret_input.
# $4 is the "echo" flag: with it, prompt input is echoed; otherwise hidden.
_securid_read_token() {
  local prompt="$1" file="$2" cli="$3" echo_flag="${4:-1}"
  if [[ -n "$file" ]]; then
    if [[ "$file" == "-" ]]; then
      _secret_input=$(cat)
    else
      _secret_input=$(cat "$file") || die "Error: cannot read $file"
    fi
    _secret_input=$(printf '%s\n' "$_secret_input" | sed '/^[[:space:]]*$/d' | head -n1)
    [[ -n "$_secret_input" ]] || die "Error: $file is empty"
  elif [[ -n "$cli" ]]; then
    _secret_input="$cli"
  elif [[ -t 0 ]]; then
    if [[ $echo_flag -eq 1 ]]; then
      read -r -p "Enter SecurID token string for $prompt: " -e _secret_input || exit 1
    else
      read -r -p "Enter SecurID token string for $prompt: " -s _secret_input || exit 1
      echo >&2
    fi
  else
    read -r _secret_input   # piped input, e.g. zbarimg | pass securid insert
  fi
  [[ -n "$_secret_input" ]] || die "Error: no token string provided"
}

_securid_guess_devid() {
  local tok="$1" passw="$2"
  _devid_guess=""
  _sec_detect_devid "$tok" "$passw"
  _devid_guess="$_sec_retval"
}

_securid_prompt_hidden() {   # _securid_prompt_hidden <prompt> <varname>
  local prompt="$1" var="$2" value=""
  if [[ -t 0 ]]; then
    read -r -s -p "$prompt" value || exit 1
    echo >&2
  else
    die "Error: interactive prompt needed ($prompt); supply the value via a flag instead."
  fi
  printf -v "$var" '%s' "$value"
}

_securid_getopts() {
  local cmd="$1"; shift
  _force=0 _echo=0 _store_seed=0 _file="" _pin="" _devid="" _password=""
  _securid_positional=()
  local opts
  opts="$($GETOPT -o fes -l force,echo,store-seed,file:,pin:,devid:,password: \
          -n "$PROGRAM" -- "$@")"
  local err=$?
  eval set -- "$opts"
  while true; do case $1 in
    -f|--force) _force=1; shift ;;
    -e|--echo) _echo=1; shift ;;
    -s|--store-seed) _store_seed=1; shift ;;
    --file) _file=$2; shift; shift ;;
    --pin) _pin=$2; shift; shift ;;
    --devid) _devid=$2; shift; shift ;;
    --password) _password=$2; shift; shift ;;
    --) shift; break ;;
  esac done
  _securid_positional=("$@")
  [[ $err -ne 0 ]] && die "Usage: $PROGRAM $COMMAND [--force,-f] [--echo,-e] [--store-seed,-s] [--file FILE] [--pin PIN] [--devid DEVID] [--password PASS] [pass-name]"
}

cmd_securid_usage() {
  cat <<-_EOF
Usage:

    $PROGRAM securid [code] [--clip,-c] [--quiet,-q]
              [--pin PIN] [--password PASS] [--devid DEVID] [--time TIME]
              pass-name
        Generate an RSA SecurID tokencode and optionally put it on the
        clipboard (cleared in $CLIP_TIME seconds).  The PIN, password and
        device ID are taken, in order, from command-line flags, metadata
        cached in the pass file, or an interactive prompt -- only when the
        token requires them.
        --time is a testing aid (unix time, or +N/-N to offset "now").

    $PROGRAM securid insert [--force,-f] [--echo,-e] [--store-seed,-s]
              [--file FILE] [--pin PIN] [--devid DEVID] [--password PASS]
              [pass-name]
        Prompt for (or accept as an argument) a SecurID token: a numeric
        ctf string, an iPhone/Android URI, or a string pasted/scanned from
        a QR code.  Validates the token and stores it under pass-name
        (defaulting to the token's serial number).  The device ID is asked
        for once and cached if the token requires it.
        --store-seed also decrypts the seed now (asking for the token
        password if required) and caches "seed:", so later codes need no
        password prompt.  This command accepts input from stdin.

    $PROGRAM securid append [--force,-f] [--echo,-e] [--store-seed,-s]
              [--file FILE] [--pin PIN] [--devid DEVID] [--password PASS]
              pass-name
        Attach a SecurID token to an existing password entry.

    $PROGRAM securid uri [--clip,-c] pass-name
        Display the token string stored under pass-name.

    $PROGRAM securid info [--password PASS] [--devid DEVID] pass-name
        Display the token's serial number, digit count, interval, PIN mode,
        expiration and protection flags.

    $PROGRAM securid validate [--password PASS] [--devid DEVID]
              [--file FILE|-] token-string
        Verify that a token string is well-formed and decryptable; print its
        serial number on success.

    $PROGRAM securid version
    $PROGRAM securid help
_EOF
  exit 0
}

cmd_securid_version() {
  echo $VERSION
  exit 0
}

# _securid_render_entry <token> [pin] [devid] [seed]  -> prints file contents
_securid_render_entry() {
  local token="$1" pin="$2" devid="$3" seed="$4" out="$1"
  [[ -n "$pin" ]]   && out+=$'\n'"pin: $pin"
  [[ -n "$devid" ]] && out+=$'\n'"devid: $devid"
  [[ -n "$seed" ]]  && out+=$'\n'"seed: $seed"
  printf '%s' "$out"
}

# _securid_insert_common <is_append> "$@"
_securid_insert_common() {
  local is_append="$1"; shift
  local cmd="$COMMAND"
  _securid_getopts "$cmd" "$@"
  local path="" token_arg="" looks_like_token=0

  if [[ $is_append -eq 1 ]]; then
    # append requires exactly one positional, which is the pass-name.
    [[ ${#_securid_positional[@]} -eq 1 ]] || die "Usage: $PROGRAM $cmd [opts] pass-name"
    path="${_securid_positional[0]%/}"
  elif [[ ${#_securid_positional[@]} -ge 1 ]]; then
    # insert: a single positional may be either the token string itself or
    # the pass-name; decide by whether it looks like a token.
    token_arg="${_securid_positional[0]}"
    case "$token_arg" in
      *ctfData=*) looks_like_token=1 ;;
      [12][0-9]*) looks_like_token=1 ;;
      [AB]*) looks_like_token=1 ;;
    esac
    [[ $looks_like_token -eq 0 ]] && path="${token_arg%/}"
  fi

  local prompt="this token"
  [[ -n "$path" ]] && prompt="$path"
  _securid_read_token "$prompt" "$_file" "$([[ $looks_like_token -eq 1 ]] && echo "$token_arg")" "$_echo"
  local token="$_secret_input"

  local pass_locked devid_locked pin_required serial kind
  _sec_token_info "$token" || die "Invalid token string."
  kind="$_sec_ti_kind"
  serial="$_sec_ti_serial"
  if (( _sec_ti_password_locked )); then pass_locked="true"; else pass_locked="false"; fi
  if (( _sec_ti_devid_locked )); then devid_locked="true"; else devid_locked="false"; fi
  if (( _sec_ti_pin_required )); then pin_required="true"; else pin_required="false"; fi

  # Collect the credential material we can gather now.
  local password="$_password" devid="$_devid" seed=""
  [[ $pin_required != "true" ]] && _pin=""

  # The device ID is worth caching for devid-bound tokens (it is not
  # secret and is needed for every code).  First try the known device-class
  # GUIDs, like stoken; only fall back to prompting if none matches.
  if [[ $devid_locked == "true" && -z "$devid" ]]; then
    if [[ $pass_locked == "false" || -n "$password" ]]; then
      _securid_guess_devid "$token" "$password"
      if [[ -n "$_devid_guess" ]]; then
        devid="$_devid_guess"
        printf '%s\n' "Using class GUID $_devid_guess; use --devid to override." >&2
      fi
    fi
    if [[ -z "$devid" ]]; then
      [[ -t 0 ]] || die "Error: device ID needed; cache it with --devid or in the pass file."
      read -r -p "Enter device ID (from the RSA 'About' screen): " devid || exit 1
    fi
  fi

  # Validate now only when we can do so without demanding a hidden prompt:
  #   - the seed is being decrypted anyway (--store-seed), or
  #   - an explicit --password was given, or
  #   - the token only needs a device ID (no password) and we have one.
  local do_validate=0
  if [[ $_store_seed -eq 1 ]]; then
    do_validate=1
    if [[ $pass_locked == "true" && -z "$password" ]]; then
      _securid_prompt_hidden "Enter password to decrypt token: " password
    fi
    if [[ $pass_locked == "true" && -z "$password" ]]; then
      die "Error: a password is required to decrypt this token (use --password or --store-seed)."
    fi
  elif [[ -n "$password" || ($pass_locked == "false" && -n "$devid") ]]; then
    do_validate=1
  fi

  if [[ $do_validate -eq 1 ]]; then
    _sec_unlock "$token" "$password" "$devid" || {
      die "Error: cannot decrypt token: $_sec_err"
    }
  fi
  if [[ $_store_seed -eq 1 ]]; then
    _sec_unlock "$token" "$password" "$devid" \
      || die "Error: cannot decrypt token: $_sec_err"
    if [[ "$_sec_kind" == "v2" ]]; then
      seed="$_sec_v2_dec_seed"
    else
      seed="$_sec_payload_dec_seed"
    fi
  fi

  # Determine the default path from the serial number when inserting.
  local passfile
  if [[ $is_append -eq 1 ]]; then
    passfile="$PREFIX/$path.$EXT"
    [[ -f "$passfile" ]] || die "Passfile not found."
    [[ $_force -eq 0 ]] && yesno "Append a SecurID token to $path?"
  else
    if [[ -z "$path" ]]; then
      if [[ -n "$serial" ]]; then
        path="$serial"
      else
        die "Cannot determine pass-name."
      fi
    fi
    passfile="$PREFIX/$path.$EXT"
    if [[ $_force -eq 0 && -e "$passfile" ]]; then
      yesno "An entry already exists for $path. Overwrite it?"
    fi
  fi

  check_sneaky_paths "$path"
  mkdir -p -v "$PREFIX/$(dirname "$path")" >&2
  set_git "$passfile"
  if [[ $PASSAGE == 1 ]]; then
    set_age_recipients "$(dirname "$path")"
  else
    set_gpg_recipients "$(dirname "$path")"
  fi

  if [[ $is_append -eq 0 ]]; then
    _securid_write_entry "$passfile" \
      "$(_securid_render_entry "$token" "$_pin" "$devid" "$seed")" \
      "Add SecurID token for $path to store."
  else
    local old
    if [[ $PASSAGE == 1 ]]; then
      old=$($AGE -d -i "$IDENTITIES_FILE" "$passfile")
    else
      old=$($GPG -d "${GPG_OPTS[@]}" "$passfile")
    fi
    # Replace an existing token line in place if present, else append.
    local nl=$'\n' new="" line replaced=0
    if [[ -z "$old" ]]; then
      new="$token"
    else
      while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ $replaced -eq 0 ]] && _securid_is_token_line "$line"; then
          line="$token"
          replaced=1
        fi
        new+="$line$nl"
      done < <(printf '%s' "${old%$'\n'}")
      [[ $replaced -eq 1 ]] || new+="$token$nl"
      new="${new%"$nl"}"
    fi
    _securid_write_entry "$passfile" "$new" \
      "Append SecurID token for $path."
  fi
}

cmd_securid_code() {
  local opts clip=0 quiet=0 pin="" password="" devid="" time=""
  opts="$($GETOPT -o cq -l clip,quiet,pin:,password:,devid:,time: -n "$PROGRAM" -- "$@")"
  local err=$?
  eval set -- "$opts"
  while true; do case $1 in
    -c|--clip) clip=1; shift ;;
    -q|--quiet) quiet=1; shift ;;
    --pin) pin=$2; shift; shift ;;
    --password) password=$2; shift; shift ;;
    --devid) devid=$2; shift; shift ;;
    --time) time=$2; shift; shift ;;
    --) shift; break ;;
  esac done

  [[ $err -ne 0 || $# -ne 1 ]] && \
    die "Usage: $PROGRAM $COMMAND [--clip,-c] [--quiet,-q] [--pin PIN] [--password PASS] [--devid DEVID] [--time TIME] pass-name"

  local path="$1"
  local passfile="$PREFIX/${path%/}.$EXT"
  check_sneaky_paths "$path"
  [[ -f "$passfile" ]] || die "$path: passfile not found."

  _securid_read_entry "$passfile"
  [[ -n "$_toke" ]] || die "$path: no SecurID token found."

  local pass_locked devid_locked pin_required kind
  _sec_token_info "$_toke" || die "Invalid token stored in $path."
  kind="$_sec_ti_kind"
  if (( _sec_ti_password_locked )); then pass_locked="true"; else pass_locked="false"; fi
  if (( _sec_ti_devid_locked )); then devid_locked="true"; else devid_locked="false"; fi
  if (( _sec_ti_pin_required )); then pin_required="true"; else pin_required="false"; fi

  local use_seed=0
  if [[ -n "$_seed" ]]; then
    if [[ "$kind" == "v2" ]]; then
      use_seed=1
    else
      printf '%s\n' "Warning: cached seed is not used for Android tokens" >&2
      _seed=""
    fi
  fi

  # Resolve the credential set.
  local resolved_devid="" resolved_passwd="$password"
  if [[ $use_seed -eq 0 ]]; then
    if [[ -z "$resolved_passwd" && $pass_locked == "true" ]]; then
      _securid_prompt_hidden "Enter password to decrypt token: " resolved_passwd
    fi
    if [[ -n "$devid" ]]; then
      resolved_devid="$devid"
    elif [[ -n "$_devid" ]]; then
      resolved_devid="$_devid"
    elif [[ $devid_locked == "true" ]]; then
      # Try the known device-class GUIDs before bothering the user.
      if [[ $pass_locked == "false" || -n "$resolved_passwd" ]]; then
        _securid_guess_devid "$_toke" "$resolved_passwd"
        if [[ -n "$_devid_guess" ]]; then
          resolved_devid="$_devid_guess"
        fi
      fi
      if [[ -z "$resolved_devid" ]]; then
        [[ -t 0 ]] || die "Error: device ID needed; pass --devid or cache it in the pass file."
        read -r -p "Enter device ID (from the RSA 'About' screen): " resolved_devid || exit 1
      fi
    fi
  fi

  local pw=""
  if [[ -n "$pin" ]]; then
    pw="$pin"
  elif [[ -n "$_pin" ]]; then
    pw="$_pin"
  elif [[ $pin_required == "true" ]]; then
    _securid_prompt_hidden "Enter PIN: " pw
  fi
  local t=""
  [[ -n "$time" ]] && t="$time"

  local out dec serial flags
  if [[ $use_seed -eq 1 ]]; then
    dec="$_seed"; serial="$_sec_ti_serial"; flags="$_sec_ti_flags"
  else
    _sec_unlock "$_toke" "$resolved_passwd" "$resolved_devid" \
      || die "$path: failed to generate tokencode: $_sec_err"
    if [[ "$_sec_kind" == "v2" ]]; then
      dec="$_sec_v2_dec_seed"; serial="$_sec_v2_serial"; flags="$_sec_v2_flags"
    else
      dec="$_sec_payload_dec_seed"; serial="$_sec_payload_serial"; flags="$_sec_payload_flags"
    fi
  fi
  _sec_compute_tokencode "$dec" "$serial" "$flags" "$t" "$pw" \
    || die "$path: failed to generate tokencode: $_sec_err"
  out="$_sec_code"

  if [[ $clip -ne 0 ]]; then
    clip "$out" "SecurID tokencode for $path"
  else
    [[ $quiet -eq 1 ]] || echo "$out"
    [[ $quiet -ne 0 ]] && printf '%s' "$out"
  fi
}

cmd_securid_uri() {
  local opts clip=0
  opts="$($GETOPT -o c -l clip -n "$PROGRAM" -- "$@")"
  local err=$?
  eval set -- "$opts"
  while true; do case $1 in
    -c|--clip) clip=1; shift ;;
    --) shift; break ;;
  esac done
  [[ $err -ne 0 || $# -ne 1 ]] && die "Usage: $PROGRAM $COMMAND uri [--clip,-c] pass-name"

  local path="$1"
  local passfile="$PREFIX/${path%/}.$EXT"
  check_sneaky_paths "$path"
  [[ -f "$passfile" ]] || die "Passfile not found."
  _securid_read_entry "$passfile"
  [[ -n "$_toke" ]] || die "$path: no SecurID token found."

  if [[ $clip -eq 1 ]]; then
    clip "$_toke" "SecurID token for $path"
  else
    echo "$_toke"
  fi
}

cmd_securid_info() {
  local opts password="" devid=""
  opts="$($GETOPT -o '' -l password:,devid: -n "$PROGRAM" -- "$@")"
  local err=$?
  eval set -- "$opts"
  while true; do case $1 in
    --password) password=$2; shift; shift ;;
    --devid) devid=$2; shift; shift ;;
    --) shift; break ;;
  esac done
  [[ $err -ne 0 || $# -ne 1 ]] && die "Usage: $PROGRAM $COMMAND info [--password PASS] [--devid DEVID] pass-name"

  local path="$1"
  local passfile="$PREFIX/${path%/}.$EXT"
  check_sneaky_paths "$path"
  [[ -f "$passfile" ]] || die "Passfile not found."
  _securid_read_entry "$passfile"
  [[ -n "$_toke" ]] || die "$path: no SecurID token found."

  local pass_locked devid_locked
  _sec_token_info "$_toke"
  if (( _sec_ti_password_locked )); then pass_locked="true"; else pass_locked="false"; fi
  if (( _sec_ti_devid_locked )); then devid_locked="true"; else devid_locked="false"; fi
  [[ -z "$password" && $pass_locked == "true" ]] && \
    _securid_prompt_hidden "Enter password to decrypt token: " password
  [[ -z "$devid" && -z "$_devid" && $devid_locked == "true" ]] && {
    read -r -p "Enter device ID (from the RSA 'About' screen): " devid || exit 1
  }
  [[ -z "$devid" ]] && devid="$_devid"

  _sec_unlock "$_toke" "$password" "$devid" || die "Error: cannot decrypt token: $_sec_err"
  # fill the info fields for printing (v3 needs the payload-derived values)
  if [[ "$_sec_kind" == "v3" ]]; then
    _sec_ti_serial="$_sec_payload_serial"
    _sec_ti_flags="$_sec_payload_flags"
    _sec_ti_digits=$(( ((_sec_payload_flags & _SEC_FDIGIT) >> 6) + 1 ))
    if (( _sec_payload_flags & 1 )); then _sec_ti_interval=60; else _sec_ti_interval=30; fi
    if (( ((_sec_payload_flags & _SEC_FPINMODE) >> 3) >= 2 )); then _sec_ti_pin_required=1; else _sec_ti_pin_required=0; fi
    _sec_ti_exp_date="$_sec_payload_exp_date"
    _sec_ti_smartphone=1
    _sec_ti_is_128bit=1
    _sec_ti_serial_valid=1
  fi
  _sec_print_info_text
}

cmd_securid_validate() {
  local opts file="" password="" devid=""
  opts="$($GETOPT -o '' -l file:,password:,devid: -n "$PROGRAM" -- "$@")"
  local err=$?
  eval set -- "$opts"
  while true; do case $1 in
    --file) file=$2; shift; shift ;;
    --password) password=$2; shift; shift ;;
    --devid) devid=$2; shift; shift ;;
    --) shift; break ;;
  esac done
  [[ $err -ne 0 ]] && die "Usage: $PROGRAM $COMMAND validate [--file FILE|-] [--password PASS] [--devid DEVID] [token]"

  _securid_read_token "this token" "$file" "$1"
  local token="$_secret_input"
  _sec_unlock "$token" "$password" "$devid" || {
    echo "securid: $_sec_err" >&2
    exit 1
  }
  if [[ "$_sec_kind" == "v2" ]]; then
    echo "OK: serial $_sec_v2_serial"
  else
    echo "OK: serial $_sec_payload_serial"
  fi
}

# ---- engine CLI tollroad --------------------------------------------------
# When invoked directly with engine-style options (as securid-engine.py would
# be), behave like the engine instead of the pass extension.  This keeps the
# tests and the stoken test-suite vectors working:
#   securid.bash --tok <URI> --code ...
#   securid.bash __selftest

if [[ "$1" == __selftest ]]; then
  shift
  _sec_self_test
  exit $?
fi

case "$1" in
  --tok|--describe|--info|--code|--validate|--detect-devid)
    _sec_engine_cli "$@"
    exit $?
    ;;
esac

case "$1" in
  help|--help|-h) shift; cmd_securid_usage "$@" ;;
  version|--version) shift; cmd_securid_version "$@" ;;
  insert|add) shift; COMMAND="securid insert"; _securid_insert_common 0 "$@" ;;
  append) shift; COMMAND="securid append"; _securid_insert_common 1 "$@" ;;
  uri) shift; cmd_securid_uri "$@" ;;
  info|show) shift; cmd_securid_info "$@" ;;
  validate) shift; cmd_securid_validate "$@" ;;
  code|show-code) shift; cmd_securid_code "$@" ;;
  *) cmd_securid_code "$@" ;;
esac
exit 0
