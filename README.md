# hash-identifier

![Python](https://img.shields.io/badge/python-3.13%2B-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
![Tests](https://img.shields.io/badge/tests-pytest-yellow?logo=pytest)
![Style](https://img.shields.io/badge/lint-ruff-orange)

A small CLI that guesses what algorithm produced a hash string, based on its prefix, length, and character set — the identification step that comes before any cracking attempt.

## Why

Given a bare string like `5f4dcc3b5aa765d61d8327deb882cf99`, it's not obvious at a glance whether it's MD5, NTLM, or MD4 — they're all 32 hex characters. `hash-identifier` runs a set of independent detection rules against the input and ranks the plausible algorithms by confidence, with a one-line reason for each guess.

## Install

```bash
git clone https://github.com/r-ahamedasri/hash-identifier.git
cd hash-identifier
just setup
```

Requires [`uv`](https://github.com/astral-sh/uv) and [`just`](https://github.com/casey/just). If you don't have them:

![Windows](https://img.shields.io/badge/Windows-PowerShell-5391FE?logo=powershell&logoColor=white)

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
winget install --id Casey.Just -e
```

![macOS/Linux](https://img.shields.io/badge/macOS%2FLinux-bash-4EAA25?logo=gnubash&logoColor=white)

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
curl --proto '=https' --tlsv1.2 -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin
```

## Usage

**One-shot:**

![Windows](https://img.shields.io/badge/-PowerShell-5391FE?logo=powershell&logoColor=white) ![macOS/Linux](https://img.shields.io/badge/-macOS%2FLinux-4EAA25?logo=gnubash&logoColor=white)

```bash
just scan '5f4dcc3b5aa765d61d8327deb882cf99'
```

![cmd.exe](https://img.shields.io/badge/-cmd.exe-4D4D4D)

```cmd
just scan "5f4dcc3b5aa765d61d8327deb882cf99"
```

That prints a colored report ranking every plausible algorithm by confidence. For the MD5 example above, it ranks **MD5** highest (32 hex characters is most commonly MD5), with **NTLM** and **MD4** listed below it as lower-confidence alternatives, since both also produce 32-character hex output — each result comes with a one-line reason.

**Interactive mode** — just run `just shell` and paste hashes one after another without re-invoking the CLI each time.

**Scriptable output:**

![PowerShell](https://img.shields.io/badge/-PowerShell-5391FE?logo=powershell&logoColor=white) ![macOS/Linux](https://img.shields.io/badge/-macOS%2FLinux-4EAA25?logo=gnubash&logoColor=white)

```bash
uv run hashid '5f4dcc3b5aa765d61d8327deb882cf99' --json
```

```json
{
  "sample": "5f4dcc3b5aa765d61d8327deb882cf99",
  "findings": [
    { "algorithm": "MD5", "confidence": "Medium", "reason": "32 hex characters — the most common algorithm at this length", "is_hash": true },
    { "algorithm": "NTLM", "confidence": "Low", "reason": "32 hex characters also matches NTLM's output size", "is_hash": true },
    { "algorithm": "MD4", "confidence": "Low", "reason": "32 hex characters also matches MD4's output size", "is_hash": true }
  ]
}
```
> [!IMPORTANT]
> Wrap any hash starting with `$` in single quotes — otherwise your shell will try to expand `$2`, `$1`, `$argon2id` etc. as variables and mangle the input before it reaches the program.

## What it recognizes

| Category | Examples |
|---|---|
| PHC / crypt-style prefixes | bcrypt (`$2a$`/`$2b$`/`$2y$`), Argon2i/Argon2id/Argon2d, MD5/SHA-256/SHA-512-crypt, Apache `$apr1$`, yescrypt, scrypt |
| Framework-specific | Django `pbkdf2_sha256$`, LDAP `{SSHA}` / `{SHA}` |
| Shape-based | MySQL5 (`*` + 40 hex), NetNTLMv1/v2, traditional DES crypt |
| Plain hex digests, by length | MD5/NTLM/MD4 (32), SHA-1 (40), SHA-256/SHA3-256/BLAKE2s (64), SHA-512/SHA3-512/BLAKE2b (128), and a few in between |
| Non-hash lookalikes | JWTs, generic base64 blobs — flagged so you don't waste a cracking attempt on the wrong target |

## How it works

Detection rules live in `src/hash_identifier/rules.py` as small, independently-registered functions — no central if/elif chain. Each rule inspects the raw sample and yields zero or more `Finding`s with a confidence tier (`HIGH` / `MEDIUM` / `LOW`) and a reason string. `engine.scan()` runs every registered rule and returns a `ScanReport` sorted by confidence.

Adding a new hash format means writing one new function decorated with `@rule` in `rules.py` — nothing else in the codebase changes.

```
src/hash_identifier/
├── models.py    # Confidence, Finding, ScanReport
├── rules.py     # the detection rules themselves
├── engine.py    # scan() — runs all rules, builds the report
└── cli.py       # argparse + rich UI, one-shot and interactive modes
```

## Development

```bash
just test     # run the test suite
just check    # ruff + mypy
just fix      # auto-fix lint issues
```

## License

MIT
