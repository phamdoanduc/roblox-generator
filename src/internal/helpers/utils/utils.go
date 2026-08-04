package utils

import (
	"RobloxRegister/src/internal/helpers/class"
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	randa "crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	proxies []string
	mu      sync.Mutex
)

// rawP1363Signature encodes r and s as a fixed-width big-endian pair
// (IEEE P1363 format), matching the byte layout crypto.subtle.sign()
// produces for ECDSA — the format the server-side verifier expects.
func rawP1363Signature(r, s *big.Int, curve elliptic.Curve) []byte {
	byteLen := (curve.Params().BitSize + 7) / 8
	out := make([]byte, byteLen*2)
	r.FillBytes(out[:byteLen])
	s.FillBytes(out[byteLen:])
	return out
}

func init() {

	file, err := os.Open("input/proxies.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	proxies = lines
}

func eZ() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}

	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80

	return hex.EncodeToString(b)
}

func e8() string {
	id := eZ()
	if len(id) < 16 {
		return ""
	}
	return id[16:]
}

func GetProxy() string {
	p := proxies[rand.Intn(len(proxies))]
	
	// Normalize the proxy string by removing the protocol prefix if present
	p = strings.TrimPrefix(p, "http://")
	p = strings.TrimPrefix(p, "https://")
	
	parts := strings.Split(p, ":")
	if len(parts) == 4 {
		// format is host:port:user:pass
		return fmt.Sprintf("http://%s:%s@%s:%s", parts[2], parts[3], parts[0], parts[1])
	}
	
	// For other formats (e.g. host:port, or already formatted user:pass@host:port)
	if !strings.HasPrefix(p, "http://") && !strings.HasPrefix(p, "https://") && !strings.HasPrefix(p, "socks") {
		p = "http://" + p
	}
	return p
}

func GenerateSecureAuth(serverNonce string) (*class.SecureAuth, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), randa.Reader)
	if err != nil {
		return nil, err
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	clientPublicKey := base64.StdEncoding.EncodeToString(pubBytes)

	clientEpochTimestamp := time.Now().Unix()

	payload := clientPublicKey + "|" +
		strconv.FormatInt(clientEpochTimestamp, 10) + "|" +
		serverNonce

	hash := sha256.Sum256([]byte(payload))

	r, s, err := ecdsa.Sign(randa.Reader, privateKey, hash[:])
	if err != nil {
		return nil, err
	}

	// WebCrypto's crypto.subtle.sign({name:"ECDSA",...}) returns a raw,
	// fixed-width IEEE P1363 signature (r||s, each padded to the curve's
	// coordinate size), not an ASN.1 DER SEQUENCE. Real browsers running
	// generateSecureAuthIntent() produce this raw form, so we must match it
	// here instead of asn1.Marshal-ing an ECDSASignature{R,S}.
	rawSignature := rawP1363Signature(r, s, elliptic.P256())

	saiSignature := base64.StdEncoding.EncodeToString(rawSignature)

	return &class.SecureAuth{
		ClientPublicKey:      clientPublicKey,
		ClientEpochTimestamp: clientEpochTimestamp,
		ServerNonce:          serverNonce,
		SaiSignature:         saiSignature,
	}, nil
}

// NewTraceID returns a fresh W3C trace-id, meant to be generated once per
// top-level operation (e.g. once per registration attempt) and kept stable
// across the requests that belong to it.
func NewTraceID() string {
	return eZ()
}

// NewSpanID returns a fresh W3C span-id. Real browser tracing instrumentation
// mints a new span-id per outgoing HTTP request even when the trace-id is
// shared, so callers must call this per-request rather than reusing one value.
func NewSpanID() string {
	return e8()
}

func DecodeBase64Safe(s string) string {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return fmt.Sprintf("base64 error: %s", err)
	}
	return string(decoded)
}

// ParseArkoseHeader decodes the Rblx-Challenge-Metadata base64 header and
// returns an ArkoseResponse. It handles both the old format
// (dataExchangeBlob/unifiedCaptchaId) and the new format
// (challengeId/sharedParameters with eligibleMethods).
func ParseArkoseHeader(headerVal string) (*class.ArkoseResponse, error) {
	decoded, err := base64.StdEncoding.DecodeString(headerVal)
	if err != nil {
		return nil, err
	}

	var raw class.ChallengeMetadataRaw
	if err := json.Unmarshal(decoded, &raw); err != nil {
		return nil, err
	}

	ark := &class.ArkoseResponse{
		DataExchangeBlob: raw.DataExchangeBlob,
		UnifiedCaptchaId: raw.UnifiedCaptchaId,
		RequestPath:      raw.RequestPath,
		RequestMethod:    raw.RequestMethod,
	}

	// New format: dataExchangeBlob is missing, use challengeId as UnifiedCaptchaId
	if ark.DataExchangeBlob == "" && raw.ChallengeId != "" {
		ark.UnifiedCaptchaId = raw.ChallengeId
		// No blob in new format when eligibleMethods is empty
	}

	return ark, nil
}

func SaveAccount(user, pass, cookie string) error {
	line := user + ":" + pass + ":" + cookie + "\n"

	mu.Lock()
	defer mu.Unlock()

	f, err := os.OpenFile("output/accounts.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(line)
	return err
}

// LogEmptyBlob persists the raw Rblx-Challenge-Metadata header whenever the
// decoded DataExchangeBlob comes back empty, so real examples are available
// for root-causing why Roblox/Arkose sometimes issues a blank blob.
func LogEmptyBlob(unifiedCaptchaID, rawHeaderB64 string) error {
	mu.Lock()
	defer mu.Unlock()

	if err := os.MkdirAll("output", 0755); err != nil {
		return err
	}

	f, err := os.OpenFile("output/empty_blob_log.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	entry := fmt.Sprintf(
		"[%s] UnifiedCaptchaId=%s rawHeaderB64=%s decoded=%s\n",
		time.Now().Format(time.RFC3339),
		unifiedCaptchaID,
		rawHeaderB64,
		DecodeBase64Safe(rawHeaderB64),
	)
	_, err = f.WriteString(entry)
	return err
}

func rgbGradient(r1, g1, b1, r2, g2, b2, n int) [][3]int {
	gradient := make([][3]int, n)
	for i := 0; i < n; i++ {
		gradient[i][0] = r1 + (r2-r1)*i/n
		gradient[i][1] = g1 + (g2-g1)*i/n
		gradient[i][2] = b1 + (b2-b1)*i/n
	}
	return gradient
}

func Output(msgType, msg string) {
	mu.Lock()
	defer mu.Unlock()

	now := time.Now().Format("15:04:05")
	timeColor := "\033[90m"
	reset := "\033[0m"

	var typeColor string
	var startRGB, endRGB [3]int

	switch msgType {
	case "INFO":
		typeColor = "\033[38;2;0;123;255m"
		startRGB = [3]int{0, 123, 255}
		endRGB = [3]int{0, 200, 255}
	case "CAPTCHA":
		typeColor = "\033[38;2;255;193;7m"
		startRGB = [3]int{255, 193, 7}
		endRGB = [3]int{255, 230, 100}
	case "SUCCESS":
		typeColor = "\033[38;2;0;200;83m"
		startRGB = [3]int{0, 200, 83}
		endRGB = [3]int{100, 255, 150}
	case "FAILED":
		typeColor = "\033[38;2;255;82;82m"
		startRGB = [3]int{255, 82, 82}
		endRGB = [3]int{255, 150, 150}
	default:
		typeColor = "\033[37m"
		startRGB = [3]int{255, 255, 255}
		endRGB = [3]int{200, 200, 200}
	}

	fmt.Printf("%s[%s]%s %s[%s]%s ", timeColor, now, reset, typeColor, msgType, reset)

	gradient := rgbGradient(startRGB[0], startRGB[1], startRGB[2], endRGB[0], endRGB[1], endRGB[2], len(msg))
	for i, c := range msg {
		r, g, b := gradient[i][0], gradient[i][1], gradient[i][2]
		fmt.Printf("\033[38;2;%d;%d;%dm%c", r, g, b, c)
	}
	fmt.Println(reset)
}
