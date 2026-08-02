# Regression Notes — roblox-generator-netz

> Root-cause doc for the 11% (original `roblox-generator`) → 0% (this `roblox-generator-netz`
> fork) Roblox-registration success-rate cliff. Written after diffing both trees
> file-by-file and **empirically confirming** the fix on 2026-08-02
> (2/16 ≈ 12.5% success after revert — matches the original baseline).

## TL;DR

The netz fork drifted from the working original across **5 behavioral
variables simultaneously**, none of which were ever isolated in an A/B test
prior to this. Reverting all five (commit `e72140b`) restored success:

| variable | netz (broke) | original (worked) | reverted to |
|---|---|---|---|
| `accept_language` | `fr-FR,fr;q=0.9,en;q=0.8` | `en-US,en;q=0.9` | `en-US,en;q=0.9` |
| cookies | carry every `Set-Cookie` through flow (`__cf_bm`/`_px3`/`pxcts`) | strict 5-name allowlist strip | 5-name allowlist |
| X-Csrf-Token | rotate on every response | rotate only on `Token Validation Failed` body | only on TVF body |
| post-signup | 3-step logout→ticket→redeem chain | extract `.ROBLOSECURITY` + save | extract + save only |
| signup URL | `?urlLocale=en_us` (single) | `?urlLocale=en_us&urlLocale=en_us` (double) | double |

Plus minor: `x-retry-attempt` hardcoded `"1"` (was `strconv.Itoa(attempt)`),
fixed a malformed `sec-ch-ua-platform` header on the validator-fallback path.

## What was deliberately KEPT from netz (correct, not regressions)

- **SAI / `secureAuthenticationIntent` with raw IEEE P1363 signature**
  (`utils.GenerateSecureAuth`). The original used ASN.1 DER; the netz fix to
  raw P1363 (matching WebCrypto's `crypto.subtle.sign` output) is correct and
  was kept. See `CHANGELOG.md` 2026-08-02 cont. 7-8 in the solver repo.
- **Per-request traceparent span-id** (`Traceparent()` regenerates span-id each
  call, fixed trace-id). More browser-correct than the original's static
  traceparent; kept.
- **`isTLSConsistentUA` Chrome/133 pinning** + comment. Correct given
  azuretls v1.13.2's fixed ClientHello; kept.

## Why each revert was correct

### 1. `accept_language: fr-FR → en-US`
The URL locale is hardcoded `?urlLocale=en_us` on every call. A French
`accept_language` over an en_us-locale request is a clean locale/geo
contradiction the risk engine can score deterministically. The original used
`en-US` matching `en_us`. Note: at the time of this fix the proxy pool was
Germany (nettify.xyz `country-DE`); en-US over a German IP is still a softer
mismatch than French, and the empirical result confirms en-US works.

### 2. Cookies: full carry → strict 5-name allowlist
Counter-intuitive but empirically confirmed. The "more correct" behavior
(carrying rotating `__cf_bm`/`_px3`/`pxcts` like a real cookie jar) produced
0% across multiple A/B tests, while the original's strict strip of everything
except `rbx-ip2, RBXEventTrackerV2, GuestData, RBXPaymentsFlowContext, RBXcb`
gets ~11%. Hypothesis: the rotating PX/CF cookie values go stale between
requests in a way the risk engine flags, OR a rich `_px*` set on an
unauthenticated pre-signup session is itself the signal. Either way, the
working recipe is to strip them.

### 3. X-Csrf-Token: every-response → only on TVF body
The netz fork rotated CSRF on every response (`DoRequest` picks up
`X-Csrf-Token` unconditionally). This races the continue/retry sequence: the
token from `/challenge/v1/continue`'s response gets sent on the retry signup,
which is not what the original does. Reverted to rotate only when the body is
`{"code":0,"message":"Token Validation Failed"}`.

### 4. `finalizeSignup`: removed logout/ticket/redeem chain
The original's success path is one line: grab `.ROBLOSECURITY` from the signup
response's `set-cookie`, save it. The netz fork added a 3-step
`/v2/logout` → `/v1/authentication-ticket` → `/v1/authentication-ticket/redeem`
chain after every success. This (a) the original never sends, and (b) adds 3
extra authenticated POSTs that are themselves risk signals. Removed.

### 5. Signup URL: single → double urlLocale
`https://auth.roblox.com/v2/signup?urlLocale=en_us&urlLocale=en_us` — the
duplicated query param is a real captured-browser artifact (Roblox's own JS
produces it). The netz fork "cleaned it up" to single; reverted.

## How to reproduce / verify

```bash
cd "D:\codev1\Tool Roblox\Roblox Account Generator\roblox-generator-netz"
# config.yml has provider: "cds", limit_accounts: 5
cd src && go build -o ../netz_cds_test.exe ./threads
cd .. && ./netz_cds_test.exe
# Expect ~1-2 SUCCESS per ~16 attempts (≈12.5%, matching original baseline)
```

## What this is NOT

- This is **not** a fix for the underlying Arkose silentpass/trust-signal
  problem documented at length in the solver repo's `CHANGELOG.md`. The
  `ag=101` tokens that succeed here do so via cds-solver.com's (presumably
  higher-fidelity) backend; this fork's own solver (`Captcha.NetZ.Vn`) still
  gets 0% on `ag=101` for reasons covered there (JS-sensor / fingerprint gap).
- This does **not** implement HBA / `x-bound-auth-token`. That remains a
  documented open lead (solver `CHANGELOG.md` 2026-08-02 cont. 2-5).
- Production cadence: `limit_accounts` was lowered to 5 for the cheap A/B.
  Bump it back up for real runs.
