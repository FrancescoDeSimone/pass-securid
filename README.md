# pass-securid

A [pass](https://www.passwordstore.org/) extension for managing **RSA SecurID
128-bit (AES) software tokens**, with an interface modeled on
[pass-otp](https://github.com/tadfisher/pass-otp) and inspiration
from [stoken](https://github.com/stoken-dev/stoken)

`pass securid code token-name` prints the current SecurID tokencode; the
token and any needed PIN/device ID/seed are stored, encrypted, in your pass
vault.

## Requirements / dependencies

- `pass` >= 1.7 (for extension support)
- `bash` — the AES, the SecurID CBC-MAC, token parsing/decryption and the
  tokencode computation are all implemented in pure bash inside
  `securid.bash`. No `python`, no `stoken`, no `oathtool`, no cryptography
  module. (gpg/age is pass's own requirement for the vault.)
- Android (v3/v4) tokens derive their keys with 1000-iteration PBKDF2-SHA256.
  When `openssl` (>= 3.0) is on PATH that derivation is delegated to
  `openssl kdf` and codes come back in ~1s; otherwise the pure-bash
  implementation handles it in a few seconds

## Usage

```
Usage:

    pass securid [code] [--clip,-c] [--quiet,-q]
              [--pin PIN] [--password PASS] [--devid DEVID] [--time TIME]
              pass-name
        Generate an RSA SecurID tokencode and optionally put it on the
        clipboard (cleared in 45 seconds).  The PIN, password and device
        ID are taken, in order, from command-line flags, metadata cached
        in the pass file, or an interactive prompt -- only when the token
        requires them.
        --time is a testing aid (unix time, or +N/-N to offset "now").

    pass securid insert [--force,-f] [--echo,-e] [--store-seed,-s]
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

    pass securid append [--force,-f] [--echo,-e] [--store-seed,-s]
              [--file FILE] [--pin PIN] [--devid DEVID] [--password PASS]
              pass-name
        Attach a SecurID token to an existing password entry.

    pass securid uri [--clip,-c] pass-name
        Display the token string stored under pass-name.

    pass securid info [--password PASS] [--devid DEVID] pass-name
        Display the token's serial number, digit count, interval, PIN mode,
        expiration and protection flags.

    pass securid validate [--password PASS] [--devid DEVID]
              [--file FILE|-] token-string
        Verify that a token string is well-formed and decryptable; print its
        serial number on success.

    pass securid version
    pass securid help
```

More information may be found in the `pass-securid(1)` man page.

## Examples

Insert a token scanned from a QR code (or pasted from your RSA portal):

```
$ zbarimg -q --raw qrcode.png | pass securid insert
```

or with an explicit name:

```
$ pass securid insert --force vpn
Enter SecurID token string for vpn: 258491750817210752367175001073261277346...
```

For a device-bound token the device ID is asked once and cached:

```
$ pass securid insert vpn
Enter SecurID token string for vpn: 2584917508172...
Enter device ID (from the RSA 'About' screen): a01c4380-fc01-4df0-b113-7fb98ec74694
```

Most soft tokens are bound to a well-known *device-class GUID* (Android,
iPhone, ...); the extension auto-detects these like `stoken` does, so you
usually are not asked for a device ID at all:

```
$ pass securid insert vpn
Using class GUID a01c4380-fc01-4df0-b113-7fb98ec74694; use --devid to override.
```

Generate the current tokencode:

```
$ pass securid vpn
85361459
```

Copy it to the clipboard instead:

```
$ pass securid --clip vpn
```

Password-protected tokens ask for their password each time; if you trust the
pass vault (it is gpg-encrypted) you can cache the decrypted seed once and
never be asked again:

```
$ pass securid insert --store-seed vpn
...
$ pass securid vpn
85361459
```

Attach a SecurID token to an existing password entry:

```
$ pass securid append corporate-vpn
```

Inspect a token:

```
$ pass securid info vpn
Serial number        : 584917508172
Key length           : 128
Tokencode digits     : 8
Seconds per tokencode: 60
PIN mode             : 3
PIN required         : yes
Encrypted w/password : no
Encrypted w/devid    : no
```

## Supported token formats

- **v1/v2 numeric `ctf` strings** (81+ digits, with or without dashes) and
  `com.rsa.securid.iphone://ctf?ctfData=...` URIs. These cover most soft
  tokens supplied as numbers/QR codes, including output from
  `stoken export --blocks` / `--iphone`.
- **Android v3/v4 tokens** (`http://127.0.0.1/securid/ctf?ctfData=...` or
  `com.rsa.securid://ctf?ctfData=...`, base64 payload). These use
  PBKDF2-HMAC-SHA256 + AES-256-CBC; a cached seed is not enough for them, so
  the password/device ID are required (device ID can be cached in the pass
  file).
- 30-second and 60-second tokens, 6- and 8-digit tokencodes, PINs, and
  password- and/or device-ID-bound seeds are all handled.

Tokens that require a password (flag `FL_PASSPROT`) or device ID
(`FL_SNPROT`) are decrypted on every `code` invocation unless a cached seed
(`--store-seed`) or cached device ID is present. This mirrors `stoken`'s
behavior.

**sdtid XML files** are not supported directly; convert them first, e.g.
`stoken import --file X.sdtid && stoken export --blocks`.

## Stored pass file format

The pass entry holds one token string plus optional metadata lines:

```
com.rsa.securid.iphone://ctf?ctfData=...
pin: 1234
devid: a01c4380-fc01-4df0-b113-7fb98ec74694
seed: 0cd1105cd1aafd893e89f1eb7b800dd8
```

The `pin`, `devid`, and `seed` lines are cache hints; all content is inside
the gpg/age-encrypted vault, so nothing beyond pass's own security model is
exposed.

## Installation

```
sudo make install
```

or install into the user extension directory (used together with
`PASSWORD_STORE_ENABLE_EXTENSIONS=true` and
`PASSWORD_STORE_EXTENSIONS_DIR`):

```
make install PREFIX=$HOME/.local LIBDIR=$HOME/.local
```

### Nix

`default.nix` builds the extension as a `pass` extension package. Combine it
with the standard `withExtensions` mechanism, e.g.:

```nix
let
  pkgs = import <nixpkgs> { };
  pass-securid = pkgs.callPackage ./path/to/pass-securid { };
in
pkgs.pass.withExtensions (exts: [ pass-securid ])
```

`securid.bash` needs only bash. If `openssl` >= 3.0 is present it is used
to speed up Android-token key derivation; without it, the pure-bash engine
still works, just slower on v3/v4 tokens.

## Testing

Run the end-to-end suite (spins up an isolated vault + gpg key; needs `pass`,
`gpg`, `git`):

```
make test
```

The test vectors are the fixed-seed tokens from the upstream `stoken` test
suite, with fixed timestamps, so the expected tokencodes are deterministic.

## Development

- `securid.bash` is the single source: the whole crypto/parsing engine and the
  pass command layer live in one file.  The engine is a 1:1 port of the old
  Python engine (removed) using only bash builtins.
- `securid.bash __selftest` runs the fixed token vectors as an install-time
  self-verification; `make test` runs the full vault integration suite.
- `make check` lints with shellcheck and runs the tests.

## Related projects to thanks

- https://github.com/stoken-dev/stoken
- https://github.com/pass-extension/pass-otp

## License

GPLv3 (see `LICENSE`). Not affiliated with RSA Security; "SecurID" is a
trademark of RSA Security LLC.
