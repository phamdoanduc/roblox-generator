# Roblox Account Generator

Go-based Roblox account register tool. Replaced original CDS-Solver with self-hosted [Funcaptcha-Solve-RSA](https://github.com/Negt-dev/Funcaptcha-Solve-RSA) for FunCaptcha solving using YesCaptcha.

## Pipeline

```
Generator                     Funcaptcha-Solve-RSA (localhost:2323)       YesCaptcha API
    │                              │                                          │
    ├── POST /createTask ─────────►│                                          │
    │   { publicKey, site,        │                                          │
    │     surl, blob, bda }       │                                          │
    │                              ├── fetch api.js (Arkose CDN)             │
    │                              ├── solve PoW locally                     │
    │                              ├── /fc/gt2/ → captcha session            │
    │                              ├── /fc/gfct/ → waves                     │
    │                              ├── send wave images ───────────────────► │
    │                              │    ← image answers                      │
    │                              ├── /fc/ca/ → submit answers              │
    │                              │    ← captcha token                      │
    │  ◄── { status, token } ─────┤                                          │
    │                              │                                          │
    ├── use token → register Roblox account                                  │
```

## Setup

### 1. Start FunCaptcha solver

```cmd
set RECOGNITION_PROVIDER=yescaptcha
set RECOGNITION_API_KEY=9331bda2e6320144fa23b01fb55fd3dd4eb1a55489373
build\server.exe
```

Run from the Funcaptcha-Solve-RSA repo root so `rsa_keys.json` and `fingerprint/` are found.

### 2. Configure generator

Edit `input/config.yml`:
```yaml
captcha:
  solve_pow: true
  solver_url: "http://127.0.0.1:2323"
limit_accounts: 20
threads: 5
```

### 3. Run

```cmd
go run src/threads/threads.go
```

Or use `register.exe`.

## Files

| File | Purpose |
|------|---------|
| `src/internal/helpers/funcaptcha/funcaptcha.go` | Solver client: POSTs to `/createTask`, polls `/getTask` |
| `input/config.yml` | All settings: solver URL, account limit, threads |
| `input/proxies.txt` | Proxies — format: `protocol://user:pass@ip:port` |

## Notes

- Server must be running before the generator starts
- Generator output is logged to stdout; accounts saved to `output/accounts.txt`
- ~80% solve success rate observed
- Requires `obfuscator-io-deobfuscator` (npm global) for PoW deobfuscation