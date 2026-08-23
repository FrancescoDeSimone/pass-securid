#!/usr/bin/env bash
# End-to-end test suite for pass-securid.
#
# Requirements: bash, gpg, git, pass (>= 1.7), getopt.
# Builds an isolated vault + GPG key, then exercises insert/code/uri/info/
# validate/append against real SecurID token vectors with known outputs.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENGINE="$ROOT/securid.bash"
EXTDIR="$ROOT"

PASS="${PASS:-pass}"

# --- test vectors (from the upstream stoken test-suite, fixed time/pin) -----
V2='http://127.0.0.1/securid/ctf?ctfData=258491750817210752367175001073261277346642631755724762324173166222072472716737543'
V2_T=1409757465 V2_PIN=9999 V2_REF='65365425'

PROT='258491750817271376337025556032745736615071405660444767006173166222072476671610011'
PROT_PASS='asdf'

V3='http://127.0.0.1/securid/ctf?ctfData=AwEBWoDfCnTYFHKM8RvGCXEbSiReGdGgA88EDrIP6EhAe8tzPkIGiAaXXtInt6UHsgM1NFmwuTVjOlJXIpNXxmj7Iud0hfL2kLmIdPgRiS6jP%2FO8q9Fcpwo%2F8tLukZRoIU7gdFjpSl3teO%2FMWlr9rJBZtkTW4q0mAehJ1tl4l0vGjcDycwmIgyzeods7F43ljVETNZjlHkDTudosNSvmS%2Bl643vFrM6NGT%2BHLrlCX0igfo5i4yaUKwDDS4AiAEq%2Bpp0dv8ZzkpZIEJikRzeWaxpfml%2BmsakJ%2BYAVFcfBoR2%2BLzr1%2Flp7mX%2BwMw4TFDZ4hS88BMY3P7uV9%2BGNz08Euaru779p4XDde0JxrPGPuGjWxUBt%2BN5aUjJkcXvAtswhfirK'
V3_T=1410710132 V3_PIN=1234 V3_PASS='Correct_horse!battery&staple' V3_DEV='a01c4380-fc01-4df0-b113-7fb98ec74694' V3_REF='27957523'

V4='com.rsa.securid://ctf?ctfData=BAABaKfqKwgEkWDGEgaxp2ZGloQ7dDw2A8PglNlhP8qCBhtop%2BorCASRYMYSBrGnZkaWhDt0PDYDw%2BCU2WE%2FyoIGGznAfd6pVLcjsDtpKoG5APTUrXL51Bdnf%2FCDvZanmNEGhzDCbsDsFTFyLgKzdht0X1tKt23tFwP%2FDYg9xDS1HvS8Jy3QfT04PFNm%2BdCUUZyMIoTzdFT01msNHtrRxePWU7cB32CE48U%2BKlbW4hPyhphJhkg5qxUA38cD05J1s44hI3FTjaq%2FAhAKAQWsDy7TZE6qtU5f6cYIzdr5PKILhTyCeXRxiYuLinAkXEHWm%2F%2FrFKyroQpn%2FVYAA3NLS59HWBQwWyS2kzhtlzJh%2BI25IMhdhLvVdXdjuNzRxkwjc74z'
V4_T=1650391605 V4_PIN=1234 V4_DEV='d82c-467c-56fb-2058-edf8-add6' V4_REF='891523'

# --- helpers ----------------------------------------------------------------
PASSES=0 FAILS=0
ok()   { PASSES=$((PASSES+1)); printf 'ok   %s\n' "$1"; }
bad()  { FAILS=$((FAILS+1));  printf 'FAIL %s\n' "$1"; }

check() { # check <desc> <expected> <actual>
  if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi
}

# ---------------------------------------------------------------------------
# 1) engine unit vectors (no pass/gpg needed)
# ---------------------------------------------------------------------------
got=$("$ENGINE" --code --tok "$V2" --pin "$V2_PIN" --time "$V2_T" 2>/dev/null)
check "engine v2 tokencode" "$V2_REF" "$got"

got=$("$ENGINE" --code --tok "$V3" --pass "$V3_PASS" --devid "$V3_DEV" --pin "$V3_PIN" --time "$V3_T" 2>/dev/null)
check "engine v3 tokencode" "$V3_REF" "$got"

got=$("$ENGINE" --code --tok "$V4" --devid "$V4_DEV" --pin "$V4_PIN" --time "$V4_T" 2>/dev/null)
check "engine v4 tokencode" "$V4_REF" "$got"

# class-GUID auto-detection (like stoken)
got=$("$ENGINE" --detect-devid --tok "$V3" --pass "$V3_PASS" 2>/dev/null)
check "engine detect class GUID (android)" "$V3_DEV" "$got"
got=$("$ENGINE" --detect-devid --tok "$V4" 2>/dev/null)
check "engine no false-positive (unique devid)" "" "$got"

if "$ENGINE" --describe --tok "999999" 2>/dev/null; then
  bad "engine rejects garbage"; else ok "engine rejects garbage"; fi


# ---------------------------------------------------------------------------
# 2) full pass integration in an isolated vault
# ---------------------------------------------------------------------------
TMP=$(mktemp -d /tmp/pass-securid-test.XXXXXX)
trap 'rm -rf "$TMP"' EXIT
export GNUPGHOME="$TMP/gnupg"
mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"

cat > "$TMP/keygen" <<EOF
%no-protection
Key-Type: RSA
Key-Length: 2048
Name-Real: pass-securid test
Name-Email: test@example.invalid
Expire-Date: 0
%commit
EOF
gpg --batch --pinentry-mode loopback --generate-key "$TMP/keygen" >/dev/null 2>&1
KEY=$(gpg --list-secret-keys --with-colons 2>/dev/null | awk -F: '/^sec/{print $5; exit}')
[[ -n "$KEY" ]] || { echo "SKIP: cannot generate a GPG key (gpg or entropy unavailable)"; exit 0; }

export PASSWORD_STORE_DIR="$TMP/store"
export PASSWORD_STORE_ENABLE_EXTENSIONS=true
export PASSWORD_STORE_EXTENSIONS_DIR="$EXTDIR"
export PASSWORD_STORE_GPG_OPTS="--batch --pinentry-mode loopback --yes"
git config --global user.email "test@example.invalid" 2>/dev/null || true
git config --global user.name "pass-securid test" 2>/dev/null || true
mkdir -p "$PASSWORD_STORE_DIR"
(cd "$PASSWORD_STORE_DIR" && git init -q)

"$PASS" init "$KEY" >/dev/null 2>&1 || { echo "SKIP: pass init failed"; exit 0; }
git -C "$PASSWORD_STORE_DIR" config user.signingkey "$KEY" 2>/dev/null || true
git -C "$PASSWORD_STORE_DIR" config commit.gpgsign false 2>/dev/null || true

p() { "$PASS" securid "$@"; }

# insert (echoed token) + code
got=$(printf '%s\n' "$V2" | p insert --force token1) && got=$(p code --pin "$V2_PIN" --time "$V2_T" token1 2>/dev/null)
check "pass insert + code (v2)" "$V2_REF" "$got"

# uri
got=$(p uri token1)
check "pass uri" "${V2#*ctfData=}" "${got#*ctfData=}"

# info (human-readable)
if p info token1 2>/dev/null | grep -q 'Serial number.*584917508172'; then
  ok "pass info"; else bad "pass info"; fi

# validate good vs bad
if p validate "$V2" 2>/dev/null | grep -q 'serial 584917508172'; then
  ok "pass validate (good)"; else bad "pass validate (good)"; fi
if p validate "2584917508172" 2>/dev/null; then
  bad "pass validate (bad)"; else ok "pass validate (bad)"; fi

# insert with --store-seed, then code without any password/pin flag (pin cached off)
got=$(printf '%s\n' "$V2" | p insert --force --store-seed token2 2>/dev/null) \
  && got=$(p code --pin "$V2_PIN" --time "$V2_T" token2 2>/dev/null)
check "pass insert --store-seed + code" "$V2_REF" "$got"

# password-protected v2: cache seed once, code needs no password
got=$(printf '%s\n' "$PROT" | p insert --force --store-seed --password "$PROT_PASS" prot 2>/dev/null) \
  && got=$(p code --pin "$V2_PIN" --time "$V2_T" prot 2>/dev/null)
check "pass password-protected seed cache" "$V2_REF" "$got"
# ... and code directly with --password (not stored)
got=$(printf '%s\n' "$PROT" | p insert --force --password "$PROT_PASS" prot2 2>/dev/null) \
  && got=$(p code --password "$PROT_PASS" --pin "$V2_PIN" --time "$V2_T" prot2 2>/dev/null)
check "pass password-protected code --password" "$V2_REF" "$got"

# Android v3 with cached device ID + password
got=$(printf '%s\n' "$V3" | p insert --force --devid "$V3_DEV" android 2>/dev/null) \
  && got=$(p code --password "$V3_PASS" --pin "$V3_PIN" --time "$V3_T" android 2>/dev/null)
check "pass v3 android code" "$V3_REF" "$got"
# ... device ID auto-detected from the class GUID list (no --devid)
got=$(printf '%s\n' "$V3" | p insert --force --password "$V3_PASS" auto 2>/dev/null) \
  && got=$(p code --password "$V3_PASS" --pin "$V3_PIN" --time "$V3_T" auto 2>/dev/null)
check "pass v3 auto device ID" "$V3_REF" "$got"
# ... device ID is cached, only password is needed
got=$(p code --password "$V3_PASS" --pin "$V3_PIN" --time "$V3_T" android 2>/dev/null)
check "pass v3 cached devid" "$V3_REF" "$got"

# v4
got=$(printf '%s\n' "$V4" | p insert --force --devid "$V4_DEV" v4t 2>/dev/null) \
  && got=$(p code --pin "$V4_PIN" --time "$V4_T" v4t 2>/dev/null)
check "pass v4 code" "$V4_REF" "$got"

# append to an existing entry with a plain password line
printf 'my-regular-password\n' | "$PASS" insert -m -f webmail >/dev/null 2>&1
printf '%s\n' "$PROT" | p append --password "$PROT_PASS" webmail >/dev/null 2>&1
content=$("$PASS" show webmail)
if [[ $(grep -c '^2584' <<<"$content") -eq 1 && "$content" == my-regular-password* ]]; then
  ok "pass append keeps entry + adds token"
else
  bad "pass append keeps entry + adds token"
fi
got=$(p code --password "$PROT_PASS" --pin "$V2_PIN" --time "$V2_T" webmail 2>/dev/null)
check "pass code from appended entry" "$V2_REF" "$got"

# version
got=$(p version)
check "pass version" "1.0.0" "$got"

# help exits 0
if p help >/dev/null 2>&1; then ok "pass help"; else bad "pass help"; fi

# ---------------------------------------------------------------------------
echo
echo "pass-securid: $PASSES passed, $FAILS failed"
[[ $FAILS -eq 0 ]]
