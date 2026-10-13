# Code tour

Read the files in this order. Each section says what the file is for, what to
look at, and what you would be asked about it.

Total: about 1,400 new lines of C++ and Python. Nothing in here is clever —
if something looks surprising, there is a comment at that line saying why.

---

## Part 1 — The C++ layer (`ЗИ_ЛР/`)

### 1. `kuz_ctr.h` — read this first (65 lines)

Pure documentation plus five declarations. It explains CTR mode, why CTR and
not CBC, and the IV-reuse rule. If you read nothing else, read this header.

**Look at:** the comment on `bigIntToBytes`. Fixed-width conversion is not
pedantry — `BigInt::str()` drops leading zeros, so a keystream block starting
with a zero byte would come back 15 bytes long and corrupt that block only,
roughly 1 block in 256. Every conversion in the project goes through this one
function.

### 2. `kuz_ctr.cpp` (78 lines)

The implementation. The loop in `kuznyechikCtr` is the whole of CTR mode:

```cpp
counter = iv (8 bytes) || blockIndex (8 bytes, big-endian)
gamma   = grasshopperCode(counter, key)
data[i] ^= gamma[i]              // truncated for the last partial block
```

**Look at:** the data never passes through the cipher. The cipher only ever
encrypts counters. That is what makes encryption and decryption identical,
removes padding entirely, and leaves `grasshopperDeCode` unused.

### 3. `grasshopper.cpp` — the parts that changed (~90 lines of 460)

Everything above `Ffunc` is your original, unchanged, and correct — the S-box,
the GF(2⁸) multiply, the R/L transforms, the 9+1 round structure.

**`dbg()` at the top (lines 5–30).** A stream that writes to `stderr` when
`grasshopperVerbose` is set and discards otherwise. The 39 former
`std::cout` tracing sites now go through it. An `std::ofstream` that was never
opened silently swallows writes — that is the trick, and it is commented.

**`Ffunc` (~line 275).** One application of GOST's F:

```
F[C](a1, a0) = ( L(S(a1 XOR C)) XOR a0 ,  a1 )
```

The old version applied S and L twice and used a wrong constant index.

**`generateKeys` (~line 322).** The real schedule: `(K1,K2)` are the two halves
of the master key, then four pairs, each produced by eight applications of `F`
with its own eight constants — 32 constants in total.

**You will be asked:** *how do you know the key schedule is right?*
Answer: `crypto_cli selftest` derives all ten round keys from the master key and
compares each one against the values printed in ГОСТ Р 34.12-2015 Appendix A.
Checking only the ciphertext of one block would not have caught the old bug,
because the old code hardcoded exactly those round keys.

### 4. `stribog.cpp` — the driver (~110 lines of 336)

Everything above the `/* Драйвер хеширования */` banner is your original
compression function `g` and its S/P/L transforms, unchanged.

**`stribogHash`** implements §8 of the standard:

| Stage | What happens |
|---|---|
| 1 | `h` = IV (zeros for 512-bit, `0x01` bytes for 256-bit), `N` = 0, `Σ` = 0 |
| 2 | while ≥ 64 bytes remain: take the **last** 64 bytes, `h = g(h,m,N)`, `N += 512`, `Σ += m` |
| 3 | pad the remainder as `0…01 ‖ M`, one more `g`, then `g(h,N,0)` and `g(h,Σ,0)` |

**Look at three things:**

- `fitTo512Bits` — `Sfunc`/`Pfunc`/`Lfunc` index `numbers[0..7]` with no bounds
  check, so a short `BigInt` would read past the end of its vector.
- `addMod512` — `Σ` is a sum modulo 2⁵¹². Plain `BigInt +=` grows a ninth word
  on carry, and that ninth word would silently corrupt the final hash. This only
  shows up with multiple blocks, which is why the old single-block code never hit it.
- Stage 2 walks the message **backwards**, from the last 64 bytes to the first.
  That is what the standard specifies, and it is confirmed empirically: the
  M2 vector (72 bytes) only matches in this order.

### 5. `crypto_cli.cpp` (480 lines) — the seam

The contract, restated at the top of the file:

> stdout = the result and nothing else · stderr = errors and tracing ·
> exit 0 = success · exit ≠ 0 = failure

Ten subcommands. Read `main()` at the bottom first — it is a flat chain of
`if (command == ...)`, and every error path funnels into one `catch` that
prints to stderr and returns 1.

**Look at:**

- `class Args` (40 lines) — the entire argument parser. A library would have
  been more code than this.
- `cmdKdf` — the password KDF runs its whole loop inside C++. 5,000 iterations
  through subprocess calls would take 45 minutes instead of 0.8 seconds.
- `cmdRsaEncrypt` — the `0x01` marker byte. Not a padding scheme (say this
  carefully at the defense), just length preservation, because `BigInt` does
  not keep leading zeros. Without it a plaintext starting with `\0` would
  come back shorter.
- `cmdRsaSign` — signing is `rsaDecrypt` applied to a hash. Same exponentiation,
  private exponent.
- `cmdSelftest` — GOST vectors plus CTR round trips. Runs with no files and no
  arguments, so it is both a build smoke test and a defense exhibit.

### 6. `test_cli.sh` (200 lines)

30 checks that call the CLI exactly as Python does. Includes the negative
cases: a short key is rejected, a wrong key produces garbage, a tampered
document fails verification, a too-long message is refused rather than
truncated, errors never reach stdout.

---

## Part 2 — The web layer (`web/`)

### 7. `config.py` (130 lines)

Every setting in one place, all overridable from the environment. Read the
comment above `KDF_ITERATIONS` — it shows the measurement the number came from.

### 8. `crypto.py` (230 lines) — the only module that touches C++

**This is the file to read most carefully.** Everything else in the web app
calls these functions and never thinks about processes, hex or temp files.

**Look at:**

- `_run()` — three lines of error handling, once, for all ten subcommands.
  That is the entire payoff of the stdout/exit-code discipline.
- `_to_cli_path()` — the Windows→WSL path translation. Delete-able the day you
  have a native `.exe`.
- `wrap_key` / `unwrap_key` — envelope encryption. The message key is random and
  used once; what the database stores is that key encrypted under a master key
  held in a file outside the web directory. A stolen database alone decrypts
  nothing.
- `random_bytes` uses Python's `secrets`, not the CLI. Same system entropy
  source, without paying 0.5 s for a process launch.

### 9. `db.py` (180 lines)

The schema, as one SQL string with a comment above each table explaining why it
exists. No ORM, no migrations.

**You will be asked:** *where could SQL injection be?* Nowhere — every value
goes through a `?` parameter. `grep -n "execute(f" web/*.py` returns nothing;
that is the check to run in front of the examiner.

### 10. `security.py` (270 lines)

Passwords, validation, sessions, roles, audit, rate limiting.

**Look at:**

- `PASSWORD_RULES` — four separate checks, so the user is told *which* rule
  failed. The equivalent single lookahead regex is in the comment, for the report.
- `verify_password` uses `compare_digest`, not `==`. Plain comparison returns at
  the first differing byte, and the timing difference leaks the prefix.
- `hash_token` has no iterations, deliberately — one Stribog is enough for a
  random high-entropy token. Only the password, which humans choose, needs the
  iterated KDF.
- `rate_limited` counts rows in `audit_log` instead of keeping a separate
  counter table. The log is written anyway, and this way you can see exactly
  why a block happened.
- `create_session` — the cookie holds only a random token. The role is read from
  the database on every single request.

### 11. `threefa.py` (210 lines) — the most interesting file

The login state machine. The header comment explains why the three factors are
three different *categories* of evidence rather than one factor three times.

**Look at:** `load_flow(token, required_stage)`. It returns a row only if the
flow is actually at the stage the handler expects, read from the database.
That single query is what makes 3FA real. If the stage lived in a hidden form
field or a cookie, an attacker with only the password would submit `stage=3`
and walk in.

Also: OTPs are stored hashed, attempts are capped at 5 (six digits is a million
guesses — trivial without a cap), and recovery codes substitute for factors 2
and 3 together and are single-use.

### 12. `documents.py` (155 lines)

PDF generation and the detached signature.

**Look at the header comment — this is the exam trap.** You cannot put a
signature inside the document it signs: adding it changes the bytes, which
changes the hash, which invalidates the signature. So `report.pdf` and
`report.pdf.sig` are separate files, and the PDF bytes themselves are signed.

The second decision follows from the first: the generated PDF and its signature
are cached on disk. If the PDF were rebuilt per request, the embedded creation
date would differ, the bytes would differ, and the signature the user downloaded
a minute ago would no longer verify. (It also avoids paying 16 s twice.)

### 13. `app.py` (640 lines) — the routes

Long but flat. Every handler is 10–30 lines and does the same four things:
check access, validate, act, log.

**Look at:**

- `require_user` / `require_admin` — one dependency each, applied explicitly.
  `grep -c require_admin web/app.py` is the audit.
- `check_csrf` — compared against the session's token for every state-changing
  POST.
- `_load_message` — returns **404, not 403**, for someone else's message. A 403
  would confirm that the id exists.
- `history()` — `WHERE user_id = ?` with the id taken from the session, never
  from the URL.
- `encrypt()` — re-checks `db.enabled_methods()` even though the form only
  offered enabled ones. The form is not a security boundary.
- `_decrypt()` — decryption happens on demand, on read. There is no plaintext
  column anywhere.

### 14. `test_app.py` (250 lines)

47 checks walking the whole journey, plus the negative cases: stage skipping,
CSRF forgery, reading another user's message, POSTing a disabled method. Read
it as executable documentation of what the system promises.

---

## Fast review checklist

Commands to run in front of an examiner, in order:

```bash
# 1. The crypto is correct against the published standards
cd ЗИ_ЛР && ./crypto_cli selftest

# 2. The C++/Python contract holds, including every failure path
./test_cli.sh

# 3. The whole web system works and the protections actually trigger
cd ../web && PYTHONUTF8=1 .venv/Scripts/python test_app.py

# 4. No SQL injection anywhere
grep -rn "execute(f\|execute(\"" web/*.py | grep -v "?"

# 5. No unescaped user data in templates
#    (one hit, and it is the comment in base.html explaining the rule)
grep -rn "|safe" web/templates/

# 6. The master key is not in the repository
cat .gitignore | grep -i secret
```

Expected: 22 crypto checks, 30 CLI checks, 47 web checks, nothing from grep 4,
and only the explanatory comment from grep 5.
