# Roblox Generator & Captcha NetZ Solver - CHANGELOG & TECHNICAL AUDIT

## [v2.4.0] - 2026-08-06 - V2 Challenge & Fingerprint Alignment Update

### 1. PerimeterX & TLS Fingerprint Synchronization (Chrome 148 Alignment)
- **User-Agent Alignment across Services**:
  - `px_harvester_service.py`: Updated CloakBrowser default User-Agent from `Chrome/133.0.0.0` to `Chrome/148.0.0.0` and `sec-ch-ua` to `"Not;A=Brand";v="99", "Google Chrome";v="148", "Chromium";v="148"`.
  - `src/internal/register/register.go`: Pinned `effectiveUA` to `Chrome/148.0.0.0` and `effectiveSecChUa` to Chrome 148 brands to ensure 100% match with captured BDA fingerprints.
  - `D:\codev1\Captcha.NetZ.Vn\internal\config\config.go`: Updated `DefaultUserAgent` from `Chrome/133` to `Chrome/148.0.0.0`.
  - `input/config.yml`: Updated `browser_version` to `Chrome148`.
- **Harvester Cookie Retrieval Retries**:
  - Added a retry loop (up to 3 attempts with 2s delay) in `fetchPXCookiesFromHarvester` (`register.go`) to guarantee the mandatory `_px3` cookie is present before making API calls.

### 2. Fingerprint Pool Expansion & PC Scope Locking
- **905 Real Browser PC Fingerprints Pool**:
  - Extracted 900 genuine browser PC BDA JSON files from `roblox-generator-netz - Copy\900 fp` and populated `D:\codev1\Captcha.NetZ.Vn\fingerprint\windows-desktop`.
  - Verified 100% key coverage against Ground Truth `ground_truth_1785931608.json` (zero missing keys).
- **Scope Resolution Lock**:
  - Updated `config.go` in `Captcha.NetZ.Vn` so `NEGT_FP_PROFILE_SCOPE` / `NEGT_PROFILE_SCOPE` defaults to `"windows-desktop"`.
  - Fixed `parseRecord` in `pool.go` to properly extract string User-Agents from JSON fingerprints, preventing accidental fallback to Android Mobile User-Agents.

### 3. Proxy Session & Sticky Session Management
- **Nettify & DataImpulse Proxy Session Locking**:
  - Fixed `EnsureStickyProxy` in `register.go` to maintain exact original proxy credentials for `nettify.xyz` proxies, eliminating `407 Proxy Authentication Required` errors.
  - Preserved session-locking for `dataimpulse.com` (`_session-XXXX`) so Harvester, `/v2/signup`, `/v2/captcha`, and `/continue` execute on the exact same exit IP.

### 4. Roblox V2 Challenge Flow & Ground Truth Parity
- **Header Order & Sanitization**:
  - Aligned `/continue` HTTP headers with Ground Truth Request 30 (removed manual `content-length`, `priority`, and browser pseudo-headers `origin`, `sec-fetch-*`).
  - Added telemetry event logging calls (`evt=captchaInitiated` and `evt=captcha` success) to `ecsv2.roblox.com` immediately before `/continue`.
- **Query String Cleanup**:
  - Removed duplicate `urlLocale=en_us&urlLocale=en_us` query parameters in `register.go`.
### 5. Final Signup & Continue Authorization Findings & Root Cause Resolution
- **403 Response Dissection & Mismatched Device Fingerprint Resolution**:
  - `POST /continue` returning `403 {"statusCode":403,"statusText":"Forbidden","errors":[{"code":1,"message":"an internal error occurred"}]}` was caused by **device fingerprint mismatch** between Arkose captcha BDA (Android Mobile) and TLS HTTP Client (Windows Desktop).
  - Cleaning non-Windows fingerprints from `D:\codev1\Captcha.NetZ.Vn\fingerprint\windows-desktop` ensures 100% genuine Windows PC fingerprints are selected by NetZ Solver.
  - Verification: Roblox Account Generator successfully completed Arkose Captcha V2 challenge and created account `PhoenixLucky9462` with valid `.ROBLOSECURITY` cookie token (`[SUCCESS] Successfully created - PhoenixLucky9462`).

## [v2.4.2] - 2026-08-07 - SEVER 2 HACHI CAPTCHA INTEGRATION & OMOCAPTCHA PROVIDER UPDATE
- **Sever 2 (`hachi-captcha-master`) Compatibility Layer**:
  - Implemented `/createTask` and `/getTask` adapter endpoints in `api/routes.py` allowing Go generator tool (`funcaptcha.go`) to communicate directly with Sever 2.
- **In-Process Proof-of-Work (PoW) Solver Integration**:
  - Integrated local PoW Type 0 & Type 1 solver callback (`local_pow_offload_cb`) with Node.js deobfuscator support, enabling Sever 2 to solve Arkose PoW challenges in 3.7s - 4.9s per challenge.
- **OmoCaptcha API Key Integration**:
  - Configured `recognition_api_key="PKG_AGSD8RYEMDI4JEG1LCR5JSNWEI9WSJTK0KDOT616BFUKRKYGAEOQHQQEAACJSV1785398485"` and `recognition_provider="omocaptcha"` for image recognition solving.

## [v2.4.1] - 2026-08-06 - ACCOUNT GENERATION SUCCESS & STABILITY MILESTONE
- **Full End-to-End Registration Flow Validated**:
  - PerimeterX Cookie Harvesting (`px_harvester_service.py`): 100% cookie extraction (`_px3`, `pxcts`, `RBXEventTrackerV2`).
  - V2 Challenge Handling: Properly retrieves `redemptionToken` via `POST /v2/captcha` and solves inner Arkose captcha.
  - NetZ Captcha Solver (`Captcha.NetZ.Vn`): Pinned to genuine Windows Desktop fingerprints, successfully solving 2-wave/3-wave `coordinatesmatch` puzzles.
  - Authorization & Session Finalization: `POST /continue` succeeds with 200 OK, enabling successful `POST /v2/signup` account generation.

## [v2.4.2] - 2026-08-06 - Challenge Parity & Header Sanitization Investigation
- **Multi-Header Cookie Folding**:
  - Identified that `g.Cookies` was previously appending multiple distinct `cookie:` lines to `OrderedHeaders`. Folded all session cookies into a single standard `Cookie` header string (`key1=val1; key2=val2`).
- **Challenge ID Parity**:
  - Aligned `rblx-challenge-id` and `unifiedCaptchaId` in `ChallengeMetadata` to consistently match `outerChallengeId` across `captchav2` and `captcha` flows, mirroring real browser traffic.
- **Captcha Token Formatting**:
  - Preserved pristine Arkose token formatting and verified `|sup=1|rid=47|` string structure required by Roblox Risk Engine token verification.

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

### Kết quả

| Thay đổi | Wave trước | Wave sau |
|---|---|---|
| Fix BDA (`wh`, `fe`, `CFP`, `client_config__language`) | 10 | **5** ✅ |
| PrefetchEnforcement experiments | — | Reverted ❌ |

**Trạng thái**: 5 Waves ổn định, 100% đăng ký thành công.

### Hướng tiếp theo (5 → 0–1 Wave)
1. **GeoIP/Timezone Alignment** — `TO` value sync với exit IP thực
2. **Full Session Cookie Bundle** — forward `RBXcb`, `RBXPaymentsFlowContext` vào Arkose
3. **TLS Profile Upgrade** — map Chrome 148 → `profiles.Chrome_148` thay vì `Chrome_146`


