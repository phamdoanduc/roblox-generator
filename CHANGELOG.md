# Roblox Generator & Captcha NetZ Solver - CHANGELOG & TECHNICAL AUDIT

## [v3.0.0] - 2026-09-02 - Sticky Proxy Session Auto-Rotation & Dynamic Client-Hint Parity

### 1. Auto-Randomized Sticky Proxy Session Routing
- **Per-Thread Sticky Exit IP Generation (`src/internal/register/register.go`)**:
  - Enhanced `EnsureStickyProxy` with regex-based auto-rotation for `nettify.xyz` (`-session-<rand6>`).
  - Completely prevents concurrent multi-threaded requests (10 threads) from reusing the exact same sticky exit IP in parallel.
  - Guarantees every single account generation thread receives a 100% fresh, isolated residential proxy IP, eliminating Arkose rate-limiting and 10-wave (`hopscotchv3`) penalty triggers.

### 2. Dynamic Cross-Request Identity Synchronization
- **Dynamic `sec-ch-ua` Header Derivation**:
  - Implemented `secChUAForUA(ua)` in `register.go` to automatically extract the Chromium major version from `token.UserAgent` and construct exact matching client-hint brand structures.
  - Expanded `isTLSConsistentUA` to support any modern Chromium major version (145..152), ensuring no fallback mismatch occurs between the solver's BDA signature and the Roblox `/continue` header.

### 3. Production Log Cleanliness
- **Credential & Debug Log Sanitization**:
  - Removed internal proxy URLs from user-facing `[SUCCESS]` and `[FAILED]` logs when `debug: false`.
  - Harmonized tool output to standard formatted status badges.

---

## [v2.5.0] - 2026-08-31 - HBA Key Rotation & Challenge Metadata Parity
- Reinforced HBA ECDSA P-256 key generation per signup session.
- Synchronized `x-bound-auth-token` generation across all challenge continue requests (`/v2/alt-captcha` & `/challenge/v1/continue`).

---

## [v2.4.3] - 2026-08-08 - BDA AUDIT FIX & PREFETCH ENFORCEMENT EXPERIMENT

> **Mục tiêu**: Hạ Wave count từ 10 → 0–1 Wave (Silentpass)
> **Kết quả**: Baseline ổn định **5 Waves**, xác nhận `PrefetchEnforcement` backend phản tác dụng

### 1. [Captcha.NetZ.Vn] Fix `wh` Window Prototype Hash
**File**: `internal/fingerprint/refresh.go`
- Xóa đoạn code overwrite 16 ký tự đầu của `wh` bằng `randomHexN(16)`.
- `wh` hash (ví dụ: `faa9642196d006adf3b35bf19dcc7ed9|b7de8bbf9978b5cc7beeffa64f1f6f4f`) nay được bảo toàn 100% từ Playwright harvest.
- **Tác động**: Góp phần hạ Wave 10 → 5.

### 2. [Captcha.NetZ.Vn] Fix `fe` Array Duplicate Entries & Order
**File**: `gen_fp.py`
- Xóa duplicate `JSF`, `P`, `T`, `H`, `SWF` trong mảng `fe`.
- Xóa `DNT:false` khỏi `fe[0]` — Chrome 148 chuẩn đặt `L:<locale>` tại `fe[0]`.

### 3. [Captcha.NetZ.Vn] Fix `client_config__language` null
**File**: `gen_fp.py`
- Thay `client_config__language: null` → locale thực từ Chrome (`"en-GB"` / `"en-US"` theo geo proxy).

### 4. [Captcha.NetZ.Vn] Fix Canvas Fingerprint (`CFP`) — Unsigned 32-bit
**File**: `gen_fp.py`
- Tính `CFP` bằng `hash >>> 0` trong Playwright JS để đảm bảo unsigned 32-bit.
- Kết quả ví dụ: `CFP:2160505824`.

### 5. [Captcha.NetZ.Vn] PrefetchEnforcement Experiment — Xác nhận Phản Tác Dụng
**File**: `internal/config/config.go`, `internal/solver/funcaptcha.go`
- Thử nghiệm A: `PrefetchEnforcement=true` call tại `Solve()` → Wave 5 → **10** ❌
- Thử nghiệm B: Move `prefetchEnforcement()` vào `generateChallenge()` sau `capturedSecCHUA` → Wave vẫn **10** ❌
- **Nguyên nhân**: Backend Go không có full Roblox session cookie bundle → Arkose coi là unauthenticated probe.
- **Kết luận**: Set `PrefetchEnforcement = false` vĩnh viễn.

---

## [v2.4.0] - 2026-08-06 - V2 Challenge & Fingerprint Alignment Update

### 1. PerimeterX & TLS Fingerprint Synchronization (Chrome 148 Alignment)
- **User-Agent Alignment across Services**:
  - `src/internal/register/register.go`: Pinned `effectiveUA` to `Chrome/148.0.0.0` and `effectiveSecChUa` to Chrome 148 brands to ensure 100% match with captured BDA fingerprints.
  - `D:\codev1\Captcha.NetZ.Vn\internal\config\config.go`: Updated `DefaultUserAgent` from `Chrome/133` to `Chrome/148.0.0.0`.
  - `input/config.yml`: Updated `browser_version` to `Chrome148`.

### 2. Fingerprint Pool Expansion & PC Scope Locking
- **905 Real Browser PC Fingerprints Pool**:
  - Populated `D:\codev1\Captcha.NetZ.Vn\fingerprint\windows-desktop`.
  - Scope locked to `"windows-desktop"`.

### 3. Proxy Session & Sticky Session Management
- Fixed `EnsureStickyProxy` in `register.go` to maintain exact original proxy credentials for `nettify.xyz` proxies.
- Preserved session-locking for `dataimpulse.com` (`_session-XXXX`).
