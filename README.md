# ГОСТ · Защищённая передача сообщений

Three-factor authenticated web system built on your own GOST primitives.
C++ does the cryptography, Python does the web, and they meet at exactly one
place: a command-line program called `crypto_cli`.

> **Language note.** `README.md` and `docs/CODE_TOUR.md` are in English, for you.
> `docs/ОТЧЁТ.md` and `docs/DEMO.md` are in Russian, for submission and the defense.
> Code comments are Russian, matching your existing sources.

---

## Read this first: two bugs that were in the crypto, and are now fixed

Both were silent — the GOST test vectors passed anyway — and both would have
broken the system. They are worth understanding before anything else, and they
are good material for the defense.

### 1. Kuznyechik ignored your key

`grasshopperCode()` called `generateKeysCorrect()`, which **hardcoded the ten
round keys from the GOST test vector and discarded the `key` argument
entirely**. The test vector passed because its round keys were pasted in
literally. Encrypting with any other key produced the same result as the demo
key — so every message in the system would have shared one publicly known key.

Fixed: `generateKeys()` now implements the real schedule from
ГОСТ Р 34.12-2015 §4.4 — four pairs, eight applications of `F` each,
constants C₁…C₃₂. Verified by deriving all ten round keys from the master key
and comparing them to the standard's published values
(`crypto_cli selftest`).

### 2. Stribog could only hash 63 bytes

The driver had `for (int i = 0; i < 1; i++)` — literally one block — and took
the message length from `BigInt::bitLength()`, which loses leading zero bytes.
The GOST M1 vector is 63 bytes, so it fit; anything longer was silently wrong.
That breaks password hashing and makes signing a PDF impossible.

Fixed: full multi-block algorithm per ГОСТ Р 34.11-2012 §8, with Σ addition
reduced mod 2⁵¹², and a byte-oriented entry point `stribogHash()`. Verified
against the standard's M2 vector (72 bytes — two blocks).

A third, smaller problem: all of `grasshopper.cpp`'s round-by-round tracing went
to **stdout**, which would have made the CLI contract impossible. It now goes to
`stderr`, and only with `--verbose`.

Your original files are kept as `grasshopper.cpp.bak` and `stribog.cpp.bak` if
you want to diff them.

> ⚠ **Stale binaries.** `grasshopper_app.exe`, `stribog_app.exe`, `rsa.exe`
> and the `.o` files in `ЗИ_ЛР/` were built before these fixes and still contain
> the bugs. Rebuild with `make labs` or delete them.

---

## What is here

```
ИБ/
├── README.md               ← you are here
├── PLAN.md                 the original roadmap
├── docs/
│   ├── CODE_TOUR.md        file-by-file reading guide (start here to review)
│   ├── ОТЧЁТ.md            design decisions and known limitations, for the report
│   └── DEMO.md             five-minute demo script
├── secrets/master.key      server master key — NOT in git, back it up
├── ЗИ_ЛР/                  C++ crypto layer
│   ├── crypto_cli.cpp      the one executable: ten subcommands
│   ├── kuz_ctr.{h,cpp}     CTR mode + hex/byte/BigInt conversions
│   ├── grasshopper.cpp     Kuznyechik  (key schedule fixed)
│   ├── stribog.cpp         Stribog     (multi-block added)
│   ├── rsa_bigint.cpp      RSA on BigInt (unchanged, it was fine)
│   ├── BigInt.cpp/h        long arithmetic (unchanged)
│   ├── Makefile, build.sh  build
│   └── test_cli.sh         30 end-to-end checks of the CLI contract
└── web/                    FastAPI application
    ├── app.py              all routes
    ├── config.py           every setting, read from the environment
    ├── crypto.py           THE SEAM — the only module that knows about crypto_cli
    ├── db.py               SQLite schema
    ├── security.py         passwords, sessions, roles, audit, rate limits
    ├── threefa.py          email OTP, TOTP, recovery codes, login state machine
    ├── mailer.py           SMTP to Mailpit, with a file fallback
    ├── documents.py        PDF + detached signature
    ├── seed_admin.py       creates the first admin (console only, not a route)
    ├── test_app.py         47 end-to-end checks of the whole web flow
    ├── templates/          Jinja2 pages
    └── var/                database, temp files, saved mail, cached PDFs
```

---

## Running it

### 1. Build the C++ layer

There is no `g++` on this machine's Windows PATH, so the binary is built in WSL
and the Python side calls it through `wsl.exe` (see *The WSL bridge* below).

```bash
wsl -d Ubuntu-22.04
cd "/mnt/c/Users/Public/Thac si/ИБ/ЗИ_ЛР"
./build.sh          # or: make
./crypto_cli selftest
./test_cli.sh       # 30 checks; add a key prefix to test a different key
```

### 2. Install the web dependencies

Already done — `web/.venv` exists. To recreate:

```bat
cd web
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
```

### 3. Create the first admin

```bat
cd web
set PYTHONUTF8=1
.venv\Scripts\python seed_admin.py admin admin@example.com "Administrator-2026!"
```

It prints the TOTP secret and ten recovery codes **once**. One admin is already
seeded with exactly that command; its secret is in your terminal scrollback.

### 4. Start the mail catcher (optional but much better for the demo)

Download Mailpit (one binary, `github.com/axllent/mailpit`) and run it. SMTP
listens on 1025, the web inbox is at <http://localhost:8025>. Without it the
app still works — undelivered mail is written to `web/var/mail/*.eml` and the
login page says so.

### 5. Run

```bat
web\run.cmd
```

Then open <http://127.0.0.1:8000>.

### 6. Run the tests

```bat
cd web
set PYTHONUTF8=1
.venv\Scripts\python test_app.py
```

47 checks covering registration, all three factors, both ciphers, the PDF
signature, access control and the audit log. It uses its own database
(`var/test.sqlite3`), the 2048-bit dev key and 50 KDF iterations, so it finishes
in about a minute.

---

## The WSL bridge

`crypto_cli` is a Linux ELF binary; Python runs on Windows. `crypto.py` bridges
them by prefixing `wsl.exe -d Ubuntu-22.04 --` and rewriting `C:\...` paths to
`/mnt/c/...`. It costs about 0.5 s per call.

To get rid of it, build a native `crypto_cli.exe` (MinGW-w64 — MSVC cannot
compile this code, it uses `__uint128_t` and `__builtin_clzll`) and set:

```bat
set CRYPTO_CLI_LAUNCHER=
set CRYPTO_CLI=C:\...\ЗИ_ЛР\crypto_cli.exe
```

Nothing else changes. On Windows link with `-lbcrypt`:
`make LDLIBS=-lbcrypt`.

---

## Settings worth knowing

All of these are environment variables; the defaults are in `web/config.py`.

| Variable | Default | What it does |
|---|---|---|
| `RSA_KEY_PREFIX` | `ЗИ_ЛР/key_32768` | Which RSA key to use. Switch to `key_dev` (2048-bit) during development — RSA decrypt and sign drop from 16 s to instant. |
| `KDF_ITERATIONS` | `5000` | Password hashing cost. ≈0.8 s per login check on this machine. Stored per user, so raising it does not invalidate anyone. |
| `CRYPTO_CLI_LAUNCHER` | `wsl` on Windows | Empty means run the binary directly. |
| `SMTP_HOST` / `SMTP_PORT` | `localhost` / `1025` | Mailpit by default. |
| `PDF_FONT` | Arial | Any TTF with Cyrillic coverage. |

---

## Measured performance

On this machine (WSL, g++ 11.4, `-O2`):

| Operation | Time |
|---|---|
| Kuznyechik CTR, 10 KB | 0.05 s |
| Stribog, 1 MB | 0.69 s |
| Password KDF, 5000 iterations | ≈0.8 s |
| RSA-32768 encrypt / verify | 0.02 s / 0.71 s |
| RSA-32768 **decrypt / sign** | **16 s** |
| RSA-32768 keygen (already done) | 912 s |
| WSL bridge overhead per call | ≈0.5 s |

The 16 s is real and expected: a full 32768-bit exponentiation with a
32768-bit private exponent, no CRT optimisation. The UI says so on the relevant
pages. Nothing is broken.

---

## What is deliberately not done

Named here so you can name them first at the defense — see `docs/ОТЧЁТ.md` for
the full discussion.

- **RSA has no padding scheme.** Raw `m^e mod n`. Deterministic and malleable;
  a real system uses OAEP for encryption and PSS for signatures (RFC 8017).
- **The password KDF is not memory-hard.** Iterated Stribog resists CPU brute
  force but not GPU; Argon2id would additionally cost the attacker RAM.
- **No HTTPS.** Cookies are set with `secure=False` because the demo is over
  HTTP. One flag in `config.py` when a certificate exists.
- **No CRT in RSA decryption.** It would cut the 16 s to roughly 4 s but
  requires keeping `p` and `q`, which `rsa-keygen` currently discards.
- **SQLite single writer.** Fine for one demo user, not for concurrency.
