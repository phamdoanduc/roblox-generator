# Fix: Roblox Challenge Metadata Format Change

## Problem

Roblox thay đổi format `Rblx-Challenge-Metadata` header. Format mới không có `dataExchangeBlob`, thay vào đó dùng:

```json
{
  "challengeId": "us-central-xxx",
  "redemptionToken": "",
  "sharedParameters": {
    "eligibleMethods": [],  // rỗng = không có captcha để solve
    "genericChallengeId": "us-central-xxx",
    ...
  }
}
```

Format cũ (code đang expect):

```json
{
  "dataExchangeBlob": "...",
  "unifiedCaptchaId": "..."
}
```

**Kết quả:** `DataExchangeBlob` = rỗng → code gọi solver với blob rỗng → solver fail → loop vô tận.

## Files Changed

### `src/internal/helpers/class/class.go`

Thêm 2 struct mới để parse format mới:

```go
type ChallengeMetadataRaw struct {
    DataExchangeBlob string `json:"dataExchangeBlob"`   // format cũ
    UnifiedCaptchaId string `json:"unifiedCaptchaId"`   // format cũ
    ChallengeId      string `json:"challengeId"`         // format mới
    RedemptionToken  string `json:"redemptionToken"`     // format mới
    SharedParameters *SharedParameters `json:"sharedParameters,omitempty"`
}

type SharedParameters struct {
    ShouldAnalyze         bool     `json:"shouldAnalyze"`
    GenericChallengeId    string   `json:"genericChallengeId"`
    UseContinueMode       bool     `json:"useContinueMode"`
    RenderNativeChallenge bool     `json:"renderNativeChallenge"`
    DelayParameters       any      `json:"delayParameters"`
    EligibleMethods       []string `json:"eligibleMethods"`
}
```

### `src/internal/helpers/utils/utils.go`

Update `ParseArkoseHeader` - parse cả 2 format:

```go
func ParseArkoseHeader(headerVal string) (*class.ArkoseResponse, error) {
    // decode base64
    var raw class.ChallengeMetadataRaw
    json.Unmarshal(decoded, &raw)

    ark := &class.ArkoseResponse{
        DataExchangeBlob: raw.DataExchangeBlob,
        UnifiedCaptchaId: raw.UnifiedCaptchaId,
    }

    // Format mới: dùng challengeId thay vì unifiedCaptchaId
    if ark.DataExchangeBlob == "" && raw.ChallengeId != "" {
        ark.UnifiedCaptchaId = raw.ChallengeId
    }

    return ark, nil
}
```

### `src/internal/register/register.go`

Trả về error ngay khi blob rỗng, không gọi solver vô ích:

```go
if len(ArkoseBlob) == 0 {
    utils.Output("DEBUG", fmt.Sprintf("Raw header (decoded): %s", utils.DecodeBase64Safe(header)))
    if logErr := utils.LogEmptyBlob(UnifiedCaptchaId, header); logErr != nil {
        utils.Output("DEBUG", fmt.Sprintf("LogEmptyBlob error: %s", logErr))
    }
    // RETURN NGAY - không gọi solver với blob rỗng
    return fmt.Errorf("empty blob from Roblox - no eligible captcha method, retry with new proxy")
}
```

## Flow Sau Fix

```
Signup request
  → Roblox trả về "Challenge is required"
  → Parse Rblx-Challenge-Metadata
  → Nếu blob rỗng (format mới) → return error → thread nhận job mới (proxy mới)
  → Nếu blob có → gọi solver như bình thường
```

## Log Khi Gặp Format Mới

Output sẽ thấy:

```
[12:34:56] DEBUG  Blob len=0, UnifiedCaptchaId=us-central-xxx-xxx
[12:34:56] DEBUG  Raw header (decoded): {"challengeId":"us-central-xxx",...}
[12:34:56] DEBUG  LogEmptyBlob error: ...
[12:34:56] FAILED User123 - empty blob from Roblox - no eligible captcha method, retry with new proxy
```

## Verify

- Chạy `go build ./...` trong thư mục `src/` - không lỗi
- Log `output/empty_blob_log.txt` vẫn ghi raw header để debug

## Chưa Fix

- Server solver chưa chạy (`dial tcp 127.0.0.1:2323`) - cần start server trước khi chạy generator
