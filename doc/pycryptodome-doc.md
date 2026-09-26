# PyCryptodome working reference for AI-assisted analysis

## Summary — read this first

**PyCryptodome** supplies concrete cryptographic primitives in Python. Install the
**`pycryptodome`** distribution and import from **`Crypto`**, for example
`from Crypto.Cipher import AES`. The separate distribution `pycryptodomex` uses
`Cryptodome` instead. ReversEnv pins **pycryptodome==3.23.0**; this reference was
validated with that version on **CPython 3.12.14, Linux x86-64, 2026-09-26**.

Normal workflow: identify the exact algorithm and wire format → obtain or derive
the appropriate key → create a fresh cipher/MAC/signature object → supply bytes
and all parameters → verify authentication before using recovered plaintext →
check against independent evidence or a known-answer vector. For a new encryption
workflow, use authenticated encryption; for reverse engineering, reproduce the
actual target's mode and encoding even when they are legacy choices.

Essential rules:

1. Cryptographic APIs operate on **bytes**, not text or symbolic expressions.
   Encode text explicitly and decode plaintext only after successful verification.
2. AES keys are 16, 24, or 32 **bytes**; AES blocks are always 16 bytes. RSA key
   generation takes **bits**. Most lengths here are bytes; CFB segment size is bits.
3. Never repeat a GCM, EAX, CTR, or ChaCha20 nonce/counter stream with the same key.
   Preserve the nonce/IV with ciphertext; it is not a secret key.
4. Prefer `encrypt_and_digest` / `decrypt_and_verify` for AEAD. A successful
   `decrypt()` alone authenticates nothing. Treat authentication failure as failure
   of the entire message, including tentative plaintext already produced.
5. Cipher objects maintain state. Use a fresh object for each message and for
   decryption. Reusing a key is not the same as reusing a nonce or cipher object.
6. A password is not an AES key. Use a password KDF such as scrypt with explicit,
   recorded costs and a random salt. HKDF is for high-entropy secrets, not passwords.
7. Specify hashes explicitly. `PBKDF2` defaults to only 1,000 iterations and
   HMAC-SHA1; RSA-OAEP defaults to SHA1; `HMAC.new` defaults to MD5 in this release.
   These compatibility defaults are not this guide's choices for new designs.
8. Signature verification succeeds by not raising. PSS/EdDSA return `None`, but
   DSS returns `False` on success in 3.23.0. Never use return truthiness as a verdict.
9. RSA encryption is for short messages such as session keys. Use a hybrid scheme
   for bulk data. OAEP encryption alone does not authenticate the sender.
10. A decryption candidate, valid padding, or a round-trip test is not proof that a
    recovered algorithm/key is correct. State assumptions, test vectors, failure
    checks, and what evidence authenticates or independently confirms the result.

## Task index — retrieve only the needed section

| Task / API | Section |
| --- | --- |
| Installation, `Crypto` vs `Cryptodome`, local versions | [S01](#s01) |
| Minimal AES-GCM encryption, verification, tamper rejection | [S02](#s02) |
| Bytes, cipher state, randomness, errors | [S03](#s03) |
| Choose GCM/EAX/CCM/SIV/ChaCha20-Poly1305; AAD and tag | [S04](#s04) |
| Reproduce CBC/CTR/CFB/ECB; `pad`, `unpad`, `Counter.new` | [S05](#s05) |
| Hashing, SHA3 vs Keccak, HMAC and CMAC | [S06](#s06) |
| `scrypt`, `PBKDF2`, `HKDF`; KDF known-answer test | [S07](#s07) |
| Complete password-encrypted serialized record | [S08](#s08) |
| RSA-OAEP and hybrid encryption | [S09](#s09) |
| RSA-PSS signing and verification | [S10](#s10) |
| ECC, ECDSA, Ed25519 / EdDSA | [S11](#s11) |
| ECDH / X25519 key agreement | [S12](#s12) |
| Import/export keys and encrypted PKCS#8 | [S13](#s13) |
| Integer conversions, XOR, padding utilities | [S14](#s14) |
| Reverse-engineering workflow and limits | [S15](#s15) |
| Exceptions and common mistakes | [S16](#s16) |
| Reproduce tests, scope, and version record | [S17](#s17) |
| Primary sources and specialist features | [S18](#s18) |

Sections have stable explicit anchors. **Runnable example** blocks contain their
own imports, inputs, and assertions; each is independent. **Doctest** blocks show
interactive input and expected results. **Fragment/recipe** blocks require the
stated context. Random keys/ciphertexts are intentionally not fixed expected output.

<a id="s01"></a>
## [S01] Installation and version checks

Use the project's existing environment. **Fragment/recipe — from ReversEnv:**

```sh
.venv/bin/python -c 'import sys, Crypto; print(sys.version); print(Crypto.__version__); print(Crypto.__file__)'
```

For an isolated installation, create a virtual environment and install
`pycryptodome==3.23.0` there. Do not install old PyCrypto alongside PyCryptodome:
both use the `Crypto` namespace. A local `Crypto.py` or conflicting package can
also shadow the real library. `pycryptodomex` is an alternative namespace, not the
name imported by this reference. Native components must match the interpreter
and platform; a successful top-level import alone does not exercise them all.

**Fragment/recipe — optional upstream suite, not run for this reference:**

```sh
.venv/bin/python -m Crypto.SelfTest
```

The examples here exercise a focused subset. Some upstream tests need separately
installed test vectors. See [installation](https://www.pycryptodome.org/src/installation).

<a id="s02"></a>
## [S02] Minimal authenticated encryption, with negative checks

**Runnable example — AES-GCM.** Uses a fresh random 12-byte nonce and a 16-byte
tag. The sender and receiver already share the key; key distribution is outside
this example. Each decryption attempt gets a new object.

```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(32)
nonce = get_random_bytes(12)
header = b'example/v1;type=message'
message = b'binary data: \x00\xff'
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
cipher.update(header)
ciphertext, tag = cipher.encrypt_and_digest(message)

def open_message(k, n, aad, data, mac):
    decipher = AES.new(k, AES.MODE_GCM, nonce=n, mac_len=16)
    decipher.update(aad)
    return decipher.decrypt_and_verify(data, mac)

assert open_message(key, nonce, header, ciphertext, tag) == message
flip = lambda value: bytes([value[0] ^ 1]) + value[1:]
for args in [
    (key, nonce, header, flip(ciphertext), tag),
    (key, nonce, header, ciphertext, flip(tag)),
    (key, nonce, header + b'!', ciphertext, tag),
    (flip(key), nonce, header, ciphertext, tag),
    (key, flip(nonce), header, ciphertext, tag),
]:
    try:
        open_message(*args)
    except ValueError:
        pass
    else:
        raise AssertionError('Changed authenticated message was accepted')
print('AES-GCM round-trip and five rejection checks passed')
```

This tests the API workflow and rejects these mutations; it is not a statistical
proof of the authentication bound or a complete protocol. Nonce uniqueness across
processes, crashes, and all writers sharing a key remains an application concern.
For serialized data and password-derived keys, see [S08](#s08).

<a id="s03"></a>
## [S03] Concrete bytes, state, randomness, and failure behavior

`bytes`, `bytearray`, and suitable `memoryview` inputs are accepted by many APIs.
Use `bytes` at interoperability boundaries unless a specific writable-buffer API
is intended. Hexadecimal text needs `bytes.fromhex(text)`; base64 needs decoding;
`b'0011'` contains four ASCII bytes, not two decoded bytes. Python integers have
unbounded precision, but cryptographic encodings impose explicit width and range.

| API / concept | Contract and effect |
| --- | --- |
| `Crypto.Random.get_random_bytes(n)` | Returns `n` random bytes from the OS-backed source. Use for random keys, salts, and appropriate nonce generation; not `random.Random`. |
| `AES.new(key, mode, **kwargs)` | Returns a stateful cipher object. Mode controls valid parameters and methods. Invalid key/nonce sizes generally raise `ValueError`; incompatible types can raise `TypeError`. |
| `encrypt(data)` / `decrypt(data)` | Usually return bytes and advance cipher state. Block modes can impose alignment; stream-like modes accept arbitrary lengths. Encryption and decryption directions cannot be freely alternated on one object. |
| AEAD `update(aad)` | Authenticates cleartext associated data; call before message encryption/decryption. It does not encrypt the header or add it to the ciphertext. |
| AEAD `encrypt_and_digest(data)` | Returns `(ciphertext, tag)` for the usual allocating call. |
| AEAD `decrypt_and_verify(data, tag)` | Returns plaintext only on success; raises `ValueError` for authentication failure. |
| Optional `output=` buffer | Where supported, writes output into caller-owned writable storage; the normal returned byte string becomes `None`. Treat decrypted output as untrusted until verification succeeds, including when the call later raises. |

Do not log keys, passwords, private-key components, or unauthenticated plaintext.
Python does not promise reliable erasure of immutable byte strings or all native
copies. Round-trip success is a correctness check for the supplied parameters,
not a security assessment of a system that stores its key next to its ciphertext.

Catch expected failures narrowly at the trust boundary. During debugging, keep
parameter/type errors distinguishable from a bad tag internally. At a decryption
service boundary, do not reveal distinctions that become padding or key oracles.
A resource timeout or memory exhaustion means incomplete work, not a bad key.

<a id="s04"></a>
## [S04] Authenticated modes and interoperability

The following values were checked against the installed 3.23.0 implementation and
mode docstrings. Parameters and formats must match the other endpoint exactly.

| Mode | Key / nonce / tag contract | Important choice |
| --- | --- | --- |
| AES-GCM | AES key; nonempty nonce; default random nonce is **16 bytes**; `mac_len=16` by default, accepts 4..16 bytes | Explicit 12-byte nonces are common in protocols; do not silently substitute the library's 16-byte default. |
| AES-EAX | AES key; nonempty nonce; default random nonce 16 bytes; tag up to 16 bytes, default 16 | Good self-contained AEAD interface; not wire-compatible with GCM. |
| AES-CCM | AES key; nonce 7..13 bytes, default 11; even tag lengths 4..16 | Nonce length limits message length. Supply `msg_len` and `assoc_len` for planned streaming; otherwise message calls are restricted. |
| AES-OCB | AES key; nonce 1..15 bytes, default 15; tag 8..16 bytes, default 16 | Buffering/finalization differs from GCM; use its documented one-shot methods unless handling its final flush. |
| AES-SIV | Key **32/48/64 bytes**; optional nonce; 16-byte tag | Without nonce it is deterministic; repeated inputs can reveal equality. Uses one-shot encrypt-and-digest / decrypt-and-verify APIs. |
| ChaCha20-Poly1305 | 32-byte key; nonce 8 or 12 bytes; default random 12; 16-byte tag | Use the protocol's variant, usually 12-byte nonce. Bare ChaCha20 has no authentication. |
| XChaCha20-Poly1305 | Same constructor with **24-byte nonce** | Longer nonce changes the variant; peers must support it. |

AEAD authenticity binds the header bytes exactly. Serializing equivalent JSON in
a different field order can change AAD. Use an explicit canonical encoding or
retain the exact original header bytes. Authenticate version/algorithm identifiers
when they affect interpretation; bound and validate their structure before using
untrusted KDF or allocation parameters.

**Runnable example — EAX and XChaCha20-Poly1305:**

```python
from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Random import get_random_bytes

for name in ('EAX', 'XChaCha20-Poly1305'):
    key = get_random_bytes(32)
    nonce = get_random_bytes(16 if name == 'EAX' else 24)
    def new_cipher():
        if name == 'EAX':
            return AES.new(key, AES.MODE_EAX, nonce=nonce, mac_len=16)
        return ChaCha20_Poly1305.new(key=key, nonce=nonce)
    encryptor = new_cipher()
    encryptor.update(b'header')
    ciphertext, tag = encryptor.encrypt_and_digest(b'payload')
    decryptor = new_cipher()
    decryptor.update(b'header')
    assert decryptor.decrypt_and_verify(ciphertext, tag) == b'payload'
    invalid = new_cipher()
    invalid.update(b'other header')
    try:
        invalid.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        pass
    else:
        raise AssertionError('AAD was not authenticated')
print('EAX and XChaCha20-Poly1305 checks passed')
```

For larger messages, authentication at the end means earlier plaintext must stay
quarantined. Independently authenticated chunks need a specified construction
binding sequence numbers, message identity, and final length to prevent reordering
or truncation; a loop around GCM alone does not define one.

Reference: [AEAD modes](https://www.pycryptodome.org/src/cipher/modern).

<a id="s05"></a>
## [S05] Legacy modes, counters, and padding in reverse engineering

CBC, CTR, CFB, OFB, and ECB do not authenticate data by themselves. Their presence
in a target is a reason to reproduce parameters accurately, not to copy them into
a new message format without an authenticated construction.

| Mode | Parameters that commonly cause mismatches |
| --- | --- |
| CBC | AES IV is 16 bytes. Input length must be a multiple of 16. Padding is external. For fresh encryption the IV must be unpredictable. |
| CTR | AES `nonce` has 0..15 bytes; omitted nonce defaults to 8 random bytes. `initial_value` defaults to **0**, counter is big-endian with the simple API. No padding. Counter wrap raises `OverflowError`. |
| CFB | AES IV 16 bytes; `segment_size` is **bits**, defaults to **8**, not 128. No block padding required. |
| OFB | AES IV 16 bytes. Keystream-style behavior, no padding; never repeat key/IV stream. |
| ECB | No IV. Independent blocks reveal equal blocks. Suitable here for a known-answer primitive check, not a message format. |

`Crypto.Util.Counter.new(nbits, prefix=b'', suffix=b'', initial_value=1,
little_endian=False, allow_wraparound=False)` builds a counter configuration for
`AES.new(key, AES.MODE_CTR, counter=...)`. **Its initial value defaults to 1**, unlike
the simple CTR API. `nbits` is bits and a multiple of 8; prefix + counter + suffix
must fill the 16-byte AES block. `allow_wraparound` does not permit wrap in this
implementation. Do not combine `counter=` with `nonce=` / `initial_value=`.

`pad(data, block_size, style='pkcs7')` and
`unpad(data, block_size, style='pkcs7')` take a block size in bytes. Supported styles
include `pkcs7`, `iso7816`, and `x923`. Unpadding invalid input raises `ValueError`.
A valid padding result does not authenticate anything.

**Runnable example — published AES-128 primitive vector and CBC fixture.**
The fixed key/IV are public test values, not operational encryption parameters.

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
block = bytes.fromhex('00112233445566778899aabbccddeeff')
expected = bytes.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a')
assert AES.new(key, AES.MODE_ECB).encrypt(block) == expected
iv = bytes(range(16))
message = b'legacy fixture\x00'
ciphertext = AES.new(key, AES.MODE_CBC, iv=iv).encrypt(pad(message, 16))
recovered = AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ciphertext)
assert unpad(recovered, 16) == message
try:
    unpad(b'\x00' * 16, 16)
except ValueError:
    pass
else:
    raise AssertionError('Invalid PKCS#7 padding was accepted')
print('AES known-answer and CBC fixture passed')
```

The AES vector is the standard AES-128 example; see
[NIST AES examples](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values).
For CTR analysis, first establish nonce bytes, counter width/endianness, start
value, and any seek offset; readable output alone is weak evidence of a match.

<a id="s06"></a>
## [S06] Hashes, HMAC, and CMAC

`SHA256.new(data=b'')` returns a hash object. `update(bytes)` appends input;
`digest()` returns 32 bytes; `hexdigest()` returns 64 hex characters. `copy()`
branches the state without rereading the prefix. Hashes are not encryption, and
an unkeyed digest does not authenticate a sender. MD5/SHA1 can be needed to match
legacy identifiers but are unsuitable when collision resistance is required.

`HMAC.new(key, msg=b'', digestmod=None)` defaults to MD5 in this build; always
supply `digestmod=SHA256` (or the protocol's algorithm). `verify(tag)` /
`hexverify(text)` raise `ValueError` for mismatch and return `None` on success.
Use these methods instead of comparing tag bytes manually. `CMAC.new(key,
msg=None, ciphermod=None, cipher_params=None, mac_len=None, update_after_digest=False)`
is the block-cipher MAC counterpart: explicitly pass `ciphermod=AES` because it
has no usable default cipher. AES CMAC's full tag is 16 bytes. MAC keys need their own purpose/domain separation.

SHA3-256 and Keccak-256 use different domain padding and produce different
results. `Crypto.Hash.keccak.new(digest_bits=256)` matches Keccak, while
`SHA3_256.new()` matches SHA3. SHAKE uses `read(n)` for variable output; reads
advance the output stream rather than repeatedly returning the same digest.

**Runnable example — hash known answer and MAC verification:**

```python
from Crypto.Hash import SHA256, SHA3_256, keccak, HMAC, CMAC
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

assert SHA256.new(b'abc').hexdigest() == (
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
prefix = SHA256.new(b'ab')
branch = prefix.copy()
branch.update(b'c')
assert branch.digest() == SHA256.new(b'abc').digest()
assert prefix.digest() == SHA256.new(b'ab').digest()
assert SHA3_256.new(b'').digest() != keccak.new(data=b'', digest_bits=256).digest()
key = get_random_bytes(32)
message = b'metadata to authenticate'
tag = HMAC.new(key, message, digestmod=SHA256).digest()
assert HMAC.new(key, message, digestmod=SHA256).verify(tag) is None
try:
    HMAC.new(key, message + b'!', digestmod=SHA256).verify(tag)
except ValueError:
    pass
else:
    raise AssertionError('Changed HMAC message was accepted')
cmac = CMAC.new(key, ciphermod=AES)
cmac.update(message)
check = CMAC.new(key, ciphermod=AES)
check.update(message)
assert check.verify(cmac.digest()) is None
print('Hash and MAC checks passed')
```

<a id="s07"></a>
## [S07] Password KDFs and high-entropy key derivation

| Function | Parameters, defaults, and return |
| --- | --- |
| `scrypt(password, salt, key_len, N, r, p, num_keys=1)` | Explicit costs required. `N` is a power of two greater than 1, less than 2**32; `r`, `p` positive and subject to implementation bounds. Length is bytes. Returns bytes for one key, otherwise a list of keys in tested 3.23.0. |
| `PBKDF2(password, salt, dkLen=16, count=1000, prf=None, hmac_hash_module=None)` | Returns `dkLen` bytes. Default PRF is HMAC-SHA1; `count` is iteration count. Set `hmac_hash_module=SHA256` and explicit count; do not also set `prf`. |
| `HKDF(master, key_len, salt, hashmod, num_keys=1, context=None)` | High-entropy input only. Returns bytes or a list in tested 3.23.0; total output at most `255 * digest_size`. `context` separates key purposes. |

The 3.23.0 scrypt/HKDF docstrings describe multi-key output as a tuple, but
execution and source inspection show a **list** when `num_keys > 1`. Do not depend
on the inaccurate tuple annotation.

Use explicit UTF-8 encoding for a textual password; document any Unicode
normalization because changing it changes the key. Some KDFs accept strings with
legacy encoding behavior, so passing Python text directly is an interoperability
trap. Random salts can be public and should be stored with KDF algorithm, costs,
and encoding version. A salt is not a cipher nonce or pepper.

Select password costs against the deployment's memory/latency budget and policy;
old examples and package defaults are not a current universal recommendation.
The scrypt lab cost below (`N=2**14,r=8,p=1`) is a bounded **test setting**, about
16 MiB for the dominant working memory, not a recommended production policy.
Before running KDF parameters from an untrusted record, enforce permitted values
and input sizes to prevent a memory/CPU denial of service.

**Runnable example — RFC 5869 SHA256 HKDF test case 1, plus scrypt repeatability:**

```python
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF, scrypt

ikm = b'\x0b' * 22
salt = bytes.fromhex('000102030405060708090a0b0c')
info = bytes.fromhex('f0f1f2f3f4f5f6f7f8f9')
expected = bytes.fromhex(
    '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf'
    '34007208d5b887185865')
assert HKDF(ikm, 42, salt, SHA256, context=info) == expected
password, salt = b'public test password', b'0123456789abcdef'
a = scrypt(password, salt, 32, N=2**14, r=8, p=1)
b = scrypt(password, salt, 32, N=2**14, r=8, p=1)
assert a == b and len(a) == 32
assert scrypt(password + b'!', salt, 32, N=2**14, r=8, p=1) != a
print('HKDF known answer and scrypt checks passed')
```

Sources: [KDF API](https://www.pycryptodome.org/src/protocol/kdf),
[RFC 5869 test vectors](https://www.rfc-editor.org/rfc/rfc5869#appendix-A.1).

<a id="s08"></a>
## [S08] Complete password-encrypted record

**Runnable example — bounded, one-message JSON lab format.** The record stores a
version, fixed suite identifier, salt, nonce, ciphertext, and tag. This is not a
standard wire format or a production password policy. The test password is public.
The suite fixes scrypt costs, so an attacker cannot select arbitrarily expensive
parameters. All fields have structural limits before derivation; AAD binds the
metadata used by this format. No plaintext is returned on failed verification.

```python
import base64
import json
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

SUITE = 'lab-scrypt-N16384-r8-p1-AES256-GCM'
MAX_MESSAGE = 4096

def b64(data):
    return base64.b64encode(data).decode('ascii')

def header(record):
    fields = {k: record[k] for k in ('v', 'suite', 'salt', 'nonce')}
    return json.dumps(fields, sort_keys=True, separators=(',', ':')).encode('ascii')

def derive(password, salt):
    return scrypt(password, salt, 32, N=2**14, r=8, p=1)

def seal(password, message):
    if not isinstance(password, bytes) or not isinstance(message, bytes):
        raise TypeError('Use explicitly encoded bytes')
    if len(message) > MAX_MESSAGE:
        raise ValueError('Message exceeds lab limit')
    salt, nonce = get_random_bytes(16), get_random_bytes(12)
    record = dict(v=1, suite=SUITE, salt=b64(salt), nonce=b64(nonce))
    cipher = AES.new(derive(password, salt), AES.MODE_GCM, nonce=nonce, mac_len=16)
    cipher.update(header(record))
    ciphertext, tag = cipher.encrypt_and_digest(message)
    record.update(ciphertext=b64(ciphertext), tag=b64(tag))
    return json.dumps(record, sort_keys=True, separators=(',', ':')).encode('ascii')

def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate record field')
        result[key] = value
    return result

def open_record(password, encoded):
    if not isinstance(password, bytes) or not isinstance(encoded, bytes):
        raise TypeError('Use bytes')
    if len(encoded) > 8192:
        raise ValueError('Record exceeds lab limit')
    record = json.loads(encoded, object_pairs_hook=reject_duplicates)
    required = {'v', 'suite', 'salt', 'nonce', 'ciphertext', 'tag'}
    if not isinstance(record, dict) or set(record) != required:
        raise ValueError('Invalid fields')
    if type(record['v']) is not int or record['v'] != 1 or record['suite'] != SUITE:
        raise ValueError('Unsupported suite/version')
    parts = {}
    for field in ('salt', 'nonce', 'ciphertext', 'tag'):
        if not isinstance(record[field], str):
            raise ValueError('Invalid byte encoding')
        parts[field] = base64.b64decode(record[field], validate=True)
    if (len(parts['salt']), len(parts['nonce']), len(parts['tag'])) != (16, 12, 16):
        raise ValueError('Invalid salt/nonce/tag length')
    if len(parts['ciphertext']) > MAX_MESSAGE:
        raise ValueError('Ciphertext exceeds lab limit')
    cipher = AES.new(derive(password, parts['salt']), AES.MODE_GCM,
                     nonce=parts['nonce'], mac_len=16)
    cipher.update(header(record))
    return cipher.decrypt_and_verify(parts['ciphertext'], parts['tag'])

password = 'public demonstration password'.encode('utf-8')
record = seal(password, b'authenticated record\x00')
assert open_record(password, record) == b'authenticated record\x00'
changed = json.loads(record)
old_tag = base64.b64decode(changed['tag'])
changed['tag'] = b64(bytes([old_tag[0] ^ 1]) + old_tag[1:])
for pw, data in [(password + b'!', record),
                 (password, json.dumps(changed).encode('ascii')),
                 (password, b'{}'), (password, b'X' * 8193)]:
    try:
        open_record(pw, data)
    except ValueError:
        pass
    else:
        raise AssertionError('Invalid record/password was accepted')
print('Password record round-trip and rejection checks passed')
```

This format provides no replay prevention, key rotation, or multi-record ordering.
Production protocols must specify those independently. A wrong password and an
altered authenticated record both fail verification; do not claim the exception
identifies which occurred.

<a id="s09"></a>
## [S09] RSA-OAEP and hybrid encryption

`RSA.generate(bits, randfunc=None, e=65537)` returns an RSA private key;
`key.public_key()` returns its public counterpart. `bits` is modulus size, not
message length. Use scheme modules instead of raw modular exponentiation.

`PKCS1_OAEP.new(key, hashAlgo=None, mgfunc=None, label=b'', randfunc=None)` returns a
cipher. Default hash is SHA1; default MGF1 follows the selected hash. Specify
`hashAlgo=SHA256` when that is the agreed suite. Encrypt with the public key;
decrypt needs the private key. For modulus byte size `k` and digest size `hLen`,
maximum plaintext length is `k - 2*hLen - 2`; at 2048 bits with SHA256 it is 190
bytes. Ciphertext is `k` bytes. Oversized plaintext or invalid OAEP ciphertext
raises `ValueError`; a public-only key cannot decrypt.

**Runnable example — RSA wraps a random AES key, AES-GCM encrypts the payload.**
The 2048-bit key is a test fixture; choose deployment key strength by policy. This
is an API lab, not a sender-authenticated transport protocol.

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

recipient = RSA.generate(2048)
session_key = get_random_bytes(32)
label = b'example/session-key/v1'
wrapped = PKCS1_OAEP.new(recipient.public_key(), hashAlgo=SHA256,
                        label=label).encrypt(session_key)
nonce = get_random_bytes(12)
cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
cipher.update(wrapped)
payload = b'bulk data\x00' * 200
ciphertext, tag = cipher.encrypt_and_digest(payload)
unwrapped = PKCS1_OAEP.new(recipient, hashAlgo=SHA256, label=label).decrypt(wrapped)
decipher = AES.new(unwrapped, AES.MODE_GCM, nonce=nonce)
decipher.update(wrapped)
assert decipher.decrypt_and_verify(ciphertext, tag) == payload
assert len(wrapped) == recipient.size_in_bytes()
try:
    PKCS1_OAEP.new(recipient, hashAlgo=SHA256, label=b'wrong').decrypt(wrapped)
except ValueError:
    pass
else:
    raise AssertionError('Mismatched OAEP label was accepted')
print('Hybrid encryption checks passed')
```

Anyone with the public key can construct a fresh valid encrypted message. Do not
interpret successful OAEP/GCM decryption as identification of its sender. OAEP
hash, MGF hash, and label must all agree with other implementations.

<a id="s10"></a>
## [S10] RSA-PSS signatures

`pss.new(rsa_key, salt_bytes=..., mask_func=...)` creates a signer/verifier.
`sign(hash_object)` returns signature bytes. `verify(hash_object, signature)`
returns `None` or raises `ValueError`. Signing requires a private key. Default PSS
salt length is the digest length; some external implementations choose another
length. The verifier's policy must match the signature suite.

The argument is a hash **object**, not its `digest()` bytes. A signature verifies
only the supplied message under the supplied public key. Trust in that public key
and the authorization represented by the message require an external protocol.
PKCS#1 v1.5 signatures live in `Crypto.Signature.pkcs1_15`; legacy encryption with
that name is a different scheme, not interchangeable with OAEP or signatures.

**Runnable example — RSA-PSS with explicit SHA256 and salt length:**

```python
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pss

key = RSA.generate(2048)
message = b'example signed manifest/v1'
signature = pss.new(key, salt_bytes=32).sign(SHA256.new(message))
verifier = pss.new(key.public_key(), salt_bytes=32)
assert verifier.verify(SHA256.new(message), signature) is None
try:
    verifier.verify(SHA256.new(message + b'!'), signature)
except ValueError:
    pass
else:
    raise AssertionError('Changed signed message was accepted')
print('RSA-PSS verification and rejection passed')
```

<a id="s11"></a>
## [S11] ECC: ECDSA and EdDSA are different schemes

`ECC.generate(curve=...)` returns an ECC private key; `public_key()` extracts its
public counterpart. Match the curve and signature scheme: P-256 is not Ed25519,
and Ed25519 signing is not X25519 agreement.

| Scheme | Constructor / input / encoding |
| --- | --- |
| ECDSA | `DSS.new(key, mode, encoding='binary', randfunc=None)`. `mode='fips-186-3'` uses randomness; `'deterministic-rfc6979'` derives the signing nonce. Pass a hash object to `sign` / `verify`. |
| ECDSA output | Default `'binary'` is fixed-width `r \|\| s`; `'der'` is an ASN.1 sequence. A valid DER signature can have variable length. Peers must use the same encoding. |
| EdDSA | `eddsa.new(key, mode='rfc8032', context=None)`. Ed25519/Ed448 only. Pure mode takes message bytes; prehash variants require the appropriate hash object, not arbitrary digest bytes. |
| Verification | Invalid signatures raise `ValueError`. In 3.23.0, DSS returns **`False` on success** (a legacy-compatibility safeguard), while EdDSA returns `None`. Do not use a boolean test. Invalid key/scheme combinations can fail at construction. |

**Runnable example — P-256 ECDSA and pure Ed25519:**

```python
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Signature import DSS, eddsa

message = b'signed binary metadata'
p256 = ECC.generate(curve='P-256')
signer = DSS.new(p256, 'deterministic-rfc6979', encoding='der')
signature = signer.sign(SHA256.new(message))
assert signature == signer.sign(SHA256.new(message))
verifier = DSS.new(p256.public_key(), 'deterministic-rfc6979', encoding='der')
verifier.verify(SHA256.new(message), signature)  # No exception means success.
ed = ECC.generate(curve='Ed25519')
ed_signature = eddsa.new(ed, 'rfc8032').sign(message)
assert len(ed_signature) == 64
ed_verifier = eddsa.new(ed.public_key(), 'rfc8032')
assert ed_verifier.verify(message, ed_signature) is None
for check in (lambda: verifier.verify(SHA256.new(message + b'!'), signature),
              lambda: ed_verifier.verify(message + b'!', ed_signature)):
    try:
        check()
    except ValueError:
        pass
    else:
        raise AssertionError('Changed ECC message was accepted')
print('ECDSA and Ed25519 checks passed')
```

For raw EdDSA encodings, use `eddsa.import_public_key(encoded)` and
`eddsa.import_private_key(seed)`. Raw key bytes are not DER/PEM; do not pass a raw
seed to a generic parser and assume it infers the format. For Ed25519ph, use the
specified SHA512 object; signing its digest bytes as a pure message is a different
scheme. Reference: [EdDSA](https://www.pycryptodome.org/src/signature/eddsa).

<a id="s12"></a>
## [S12] Key agreement and domain separation

`Crypto.Protocol.DH.key_agreement(**kwargs)` accepts local `static_priv` or
`eph_priv`, peer `static_pub` or `eph_pub`, and a `kdf` callable. At least one
private and one public key are required; curves must be compatible. It returns
derived bytes. For raw X25519 keys, the DH module supplies
`import_x25519_public_key` / `import_x25519_private_key`; do not use the EdDSA
importers just because both encodings can be 32 bytes.

**Runnable example — ephemeral P-256 agreement with HKDF:**

```python
from Crypto.PublicKey import ECC
from Crypto.Protocol.DH import key_agreement
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

alice = ECC.generate(curve='P-256')
bob = ECC.generate(curve='P-256')
salt = get_random_bytes(32)  # Shared public input, not a private key.
context = b'example/v1/alice-to-bob'
def kdf(shared):
    return HKDF(shared, 32, salt, SHA256, context=context)
a = key_agreement(eph_priv=alice, eph_pub=bob.public_key(), kdf=kdf)
b = key_agreement(eph_priv=bob, eph_pub=alice.public_key(), kdf=kdf)
assert a == b and len(a) == 32
other = ECC.generate(curve='P-256')
assert key_agreement(eph_priv=alice, eph_pub=other.public_key(), kdf=kdf) != a
print('ECDH agreement and peer distinction passed')
```

Matching derived keys proves this fixture's calculation, not peer identity. An
unauthenticated public-key exchange permits a man-in-the-middle. A real protocol
binds identities, both public keys, roles, and transcript to authentication and key
derivation; directional keys need distinct contexts. Do not reuse a signing key
as an agreement key casually. See [DH API](https://www.pycryptodome.org/src/protocol/dh).

<a id="s13"></a>
## [S13] Key import, export, and storage

| Call | Contract / common mistake |
| --- | --- |
| `RSA.import_key(extern_key, passphrase=None)` | Parses supported PEM/DER/OpenSSH formats; returns an RSA key. Invalid input/password may raise `ValueError`, `IndexError`, or `TypeError`. |
| `RSA.RsaKey.export_key(format='PEM', passphrase=None, pkcs=1, protection=None, prot_params=None)` | Returns **bytes**, including PEM. Default unprotected private export exposes the private key. Use explicit PKCS#8 and protection settings for password protection. |
| `ECC.import_key(encoded, passphrase=None, curve_name=None)` | Returns an ECC key. Some bare public point encodings require a curve name. Unsupported encoding or inconsistent data raises. |
| `ECC.EccKey.export_key(format=..., passphrase=..., use_pkcs8=True, protection=..., prot_params=...)` | PEM/OpenSSH returns **str**; DER/raw/SEC1 returns **bytes**. Raw export is public material, not a generic private-seed export. |
| `key.has_private()` | Boolean: whether private components exist. Check it before private-key operations. |

Specifying a passphrase alone does not select a strong or interoperable private-key
container. Set PKCS#8, protection algorithm, and costs explicitly; record them.
Default/legacy PEM encryption is different. Certificate parsing or extracting a
public key is not certificate chain validation, hostname checking, or revocation.

**Runnable example — encrypted ECC PKCS#8 export/import and wrong-password rejection.**
The passphrase and cost are lab settings; no secret is written to disk.

```python
from Crypto.PublicKey import ECC

key = ECC.generate(curve='P-256')
password = b'public lab passphrase'
encoded = key.export_key(format='PEM', passphrase=password, use_pkcs8=True,
                        protection='PBKDF2WithHMAC-SHA512AndAES256-CBC',
                        prot_params={'iteration_count': 100000})
assert isinstance(encoded, str) and 'ENCRYPTED PRIVATE KEY' in encoded
restored = ECC.import_key(encoded, passphrase=password)
assert restored.has_private()
assert restored.public_key().export_key(format='DER') == key.public_key().export_key(format='DER')
try:
    ECC.import_key(encoded, passphrase=b'wrong password')
except (ValueError, IndexError, TypeError):
    pass
else:
    raise AssertionError('Wrong private-key password was accepted')
print('Encrypted PKCS#8 import/export passed')
```

When saving private material, choose file permissions and storage protection
explicitly. Public-key fingerprints need a specified canonical encoding and hash;
hashing PEM text can change with line endings while the key remains the same.
Reference: [RSA key API](https://www.pycryptodome.org/src/public_key/rsa).

<a id="s14"></a>
## [S14] Byte/integer utilities and fixed-width encodings

`Crypto.Util.number.bytes_to_long(data)` decodes an unsigned big-endian integer;
`long_to_bytes(n, blocksize=0)` encodes unsigned big-endian with minimal length, or
pads to a **multiple** of `blocksize`. It is not a strict width validator. Prefer
Python `int.to_bytes(width, byteorder, signed=...)` when overflow must be rejected.
`strxor(a, b, output=None)` needs equal-length byte strings and performs concrete
bytewise XOR. None of these operations creates symbolic bitvectors or constraints.

**Doctest — exact encoding and padding semantics:**

```pycon
>>> from Crypto.Util.number import bytes_to_long, long_to_bytes
>>> from Crypto.Util.strxor import strxor
>>> from Crypto.Util.Padding import pad, unpad
>>> bytes_to_long(b'\x00\x80')
128
>>> long_to_bytes(128)
b'\x80'
>>> (128).to_bytes(2, 'big')
b'\x00\x80'
>>> long_to_bytes(256, blocksize=1)
b'\x01\x00'
>>> int.from_bytes(b'\xff\xff', 'little', signed=True)
-1
>>> strxor(b'\x01\x02', b'\x03\x04')
b'\x02\x06'
>>> pad(b'abcd', 4)
b'abcd\x04\x04\x04\x04'
>>> unpad(pad(b'abc', 4), 4)
b'abc'
```

RSA values encoded as fixed-width blocks may begin with zero bytes that disappear
if converted through a minimal-length integer encoding. Preserve the original
width. Byte order is an encoding choice, not determined by the host CPU.

<a id="s15"></a>
## [S15] Reverse-engineering workflow and evidence

Start with concrete observations: input/output samples, buffer lengths, constants,
key material provenance, call order, padding, counter layout, and serialization.
Record exact algorithm, mode, key size, IV/nonce, tag size, AAD, KDF, salt/costs,
encoding, and byte order. Isolate a small transformation and replay it against a
captured input/output pair before generalizing to whole files.

| Evidence | What it supports | What it does not establish |
| --- | --- | --- |
| Known-answer vector matches | Implementation and supplied parameters match that vector | Every protocol use is safe or interoperable. |
| Encrypt/decrypt round-trip | Both sides agree within this implementation | Correctness against a target that uses different defaults. |
| Candidate plaintext is readable | A promising hypothesis | Correct key/mode; unauthenticated data can be misleading. |
| Padding validates | Candidate meets a padding grammar | Authenticity, correct key, or unmodified data. |
| MAC/tag verifies with a trusted key | Authentication under the selected construction and assumptions | Sender identity if the key is shared by many parties; freshness/replay resistance. |
| Signature verifies | Message/key/signature match | Public-key trust or authorization policy. |

PyCryptodome is not a symbolic crypto model, key-search scheduler, or binary
loader. Use binary analysis tools to locate data and reconstruct preconditions;
use this package for concrete candidate checks. Unfinished search, timeout, or
unsupported input is not a proof that no key or interpretation exists. Do not
replace a target's SHA1, little-endian counter, or CFB-8 with a preferred modern
choice while claiming to reproduce the target.

AES key-wrap modes, specialized ASN.1 helpers, number-theory utilities, Shamir
sharing, and legacy ciphers have distinct contracts beyond the main workflows
here. In particular, successful decoding/unwrap and protocol authentication are
not interchangeable concepts. Consult installed APIs and add targeted vectors
before using a specialist feature.

<a id="s16"></a>
## [S16] Troubleshooting

| Symptom | Likely explanation | Action |
| --- | --- | --- |
| `No module named Crypto` / native extension load error | Wrong environment, namespace, or wheel | Check interpreter, `Crypto.__file__`, installed version, and package collision. |
| Incorrect AES key length | Text/hex used as bytes, wrong KDF length, SIV doubled key requirement | Decode explicitly; count bytes; inspect mode. |
| Data must be padded / block boundary error | CBC/ECB length not aligned | Reproduce the format's padding, once; CTR/GCM do not need PKCS#7. |
| MAC check failed | Key, nonce, ciphertext, tag, or AAD differs | Compare all encoded parameters; discard plaintext; do not infer one exact cause. |
| Correct key but CTR/CFB output differs | Wrong counter layout/start or CFB segment size | CTR simple API starts at 0; Counter.new starts at 1; CFB default is 8 bits. |
| Wrong nonce length in another library | GCM default here is 16 bytes, peer expects 12 | Set and serialize an explicit agreed size. |
| `verify(...)` appears false | DSS returns `False` on success; PSS/EdDSA/MAC verification returns `None` | Treat no exception as success, not return truthiness. |
| RSA plaintext too long | OAEP size bound exceeded | Wrap a session key and encrypt bulk data with AEAD. |
| OAEP/PSS interoperability failure | Hash, MGF, label, or salt length mismatch | Set suite parameters explicitly at both ends. |
| ECDSA signature rejected | Binary `r\|\|s` versus DER, wrong curve/hash | Match all three; do not assume defaults define the peer wire format. |
| Ed25519 signature mismatch | Pure versus prehash/context mismatch | Match scheme and message representation, not only curve name. |
| PEM write raises type error | RSA PEM is bytes; ECC PEM is text | Match file mode or encode text explicitly. |
| Password KDF consumes too much memory/time | Excessive or attacker-selected costs | Bound inputs before KDF; benchmark allowed costs. |
| A second cipher call changes output / raises state error | Cipher stream advanced or finalized | Construct a fresh object with correct parameters for each independent message. |

<a id="s17"></a>
## [S17] Validation and reproduction

Version record: repository pin **3.23.0**, installed `Crypto.__version__`
**3.23.0**, **CPython 3.12.14**, Linux x86-64. No dependency pins were changed.
The online site identified itself as **3.240b0** during consultation; installed
3.23.0 source/docstrings and execution govern the contracts tested here.

Executed successfully: **11 Runnable examples**, **11 doctest statements**,
all internal anchor targets, and Markdown fence checks. The reproducible harness
appears below. Tests include independent AES,
SHA256, and HKDF expected values, plus successful and rejected cryptographic
operations. Randomized tests assert properties rather than a fixed random output.

Not covered: external-library interoperability, production KDF policy, upstream
full self-tests, timing/side-channel analysis, certified-module status, all legacy
ciphers/modes, streaming output buffers, CCM/OCB/SIV execution, raw X25519 vectors,
certificate validation, or a complete authenticated network protocol. Passing
examples does not imply those properties. Fragment/recipe commands are not counted
as executed examples.

**Fragment/recipe — maintenance harness.** Save this block outside the document
and execute it with `.venv/bin/python` from ReversEnv. It runs only the explicitly
labeled, trusted example blocks in this file, each in its own process.

```python
from pathlib import Path
import doctest
import re
import subprocess
import sys
import tempfile

path = Path('doc/pycryptodome-doc.md')
text = path.read_text()
sections = re.split(r'^<a id="s\d+"></a>\s*$', text, flags=re.M)
count = 0
with tempfile.TemporaryDirectory() as directory:
    for section in sections:
        if not re.search(r'^\*\*Runnable example', section, re.M):
            continue
        blocks = re.findall(r'^```python\n(.*?)^```\s*$', section, re.M | re.S)
        assert len(blocks) == 1
        script = Path(directory)/f'example_{count}.py'
        script.write_text(blocks[0])
        subprocess.run([sys.executable, str(script)], check=True, timeout=120)
        count += 1
assert count == 11
interactive = '\n\n'.join(re.findall(r'^```pycon\n(.*?)^```\s*$', text, re.M | re.S))
runner = doctest.DocTestRunner()
runner.run(doctest.DocTestParser().get_doctest(interactive, {}, str(path), str(path), 0))
result = runner.summarize()
assert result.failed == 0 and result.attempted == 11
anchors = re.findall(r'<a id="([^"]+)"></a>', text)
assert len(anchors) == len(set(anchors))
assert set(re.findall(r'\]\(#([^)]*)\)', text)) <= set(anchors)
opened = False
for line in text.splitlines():
    if line.startswith('```'):
        if opened:
            assert line == '```'
        opened = not opened
assert not opened
print(f'{count} runnable examples, {result.attempted} doctests, links/fences passed')
```

<a id="s18"></a>
## [S18] Primary source record and further APIs

Sources consulted on **2026-09-26**. This is original guidance and original lab
code except for the explicitly attributed standard test values; no upstream
manual or tutorial is reproduced. Installed modules provide the release-specific
implementation and method docstrings needed to resolve rolling-site differences.

| Primary source | Used for |
| --- | --- |
| Installed `Crypto.Cipher`, `Crypto.Hash`, `Crypto.Protocol`, `Crypto.PublicKey`, `Crypto.Signature`, `Crypto.Util` | Verified signatures, defaults, units, state/error behavior, and executable tests. |
| [PyCryptodome installation](https://www.pycryptodome.org/src/installation) | Namespace and installation context. |
| [AEAD modes](https://www.pycryptodome.org/src/cipher/modern) | Authenticated mode and tag semantics. |
| [KDF reference](https://www.pycryptodome.org/src/protocol/kdf) | Password versus high-entropy derivation and parameter contracts. |
| [RSA reference](https://www.pycryptodome.org/src/public_key/rsa) | Key structures and serialization. |
| [EdDSA reference](https://www.pycryptodome.org/src/signature/eddsa) | Pure/prehash signature distinction. |
| [DH reference](https://www.pycryptodome.org/src/protocol/dh) | Agreement key roles and KDF integration. |
| [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869#appendix-A.1) | Independent HKDF known-answer values. |
| [NIST example values](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values) | AES/SHA algorithm validation context. |

Keep this guide self-contained when extending it: include fixtures, explicit
expected checks, negative cases when applicable, and a precise tested version.
