package register

import (
	"RobloxRegister/src/internal/helpers/class"
	"RobloxRegister/src/internal/helpers/funcaptcha"
	"RobloxRegister/src/internal/helpers/roblox_profile"
	"RobloxRegister/src/internal/helpers/utils"

	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Noooste/azuretls-client"
	fhttp "github.com/Noooste/fhttp"
	"github.com/google/uuid"
)

type Container struct {
	HttpClient  *azuretls.Session
	Proxy       string
	Cookies     [][]string
	CapConfig   class.CaptchaConfig
	User        string
	Password    string
	Birthday    string
	Gender      int
	XCsrfToken  string
	TraceID     string
}

// Traceparent builds a fresh W3C traceparent header value for a single
// outgoing request: the trace-id stays fixed for the whole registration
// attempt, but the span-id is regenerated every call. Reusing one static
// traceparent (trace-id AND span-id) across every request in the flow, as
// real browsers never do, is a mechanically detectable automation signature.
func (g *Container) Traceparent() string {
	return fmt.Sprintf("00-%s-%s-00", g.TraceID, utils.NewSpanID())
}

var (
	order_cookies = []string{"rbx-ip2", "RBXEventTrackerV2", "GuestData", "RBXPaymentsFlowContext", "RBXcb"}
	regexCsrf     = regexp.MustCompile(`<meta\s+name=["']csrf-token["']\s+data-token=["']([^"']+)["']`)
)

const (
	maxRetries = 3
	// The fingerprint pool files were captured from Chrome/148 browsers —
	// their BDA telemetry (canvas hash, WebGL renderer, audio fingerprint,
	// user_agent_data_brands) all claim Chrome/148. The HTTP User-Agent and
	// sec-ch-ua sent by the generator MUST match the BDA version; any
	// mismatch is a deterministic bot signal that bumps Arkose wave count.
	// The azuretls TLS ClientHello is Chrome-133-shaped but Arkose's risk
	// engine does not cross-check JA3 vs application-layer UA directly.
	userAgent       = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"
	sec_ch_ua       = `"Not/A)Brand";v="8", "Chromium";v="148", "Google Chrome";v="148"`
	accept_language = "en-US,en;q=0.9;q=0.9"
)

func isTLSConsistentUA(ua string) bool {
	return strings.Contains(ua, "Chrome/148") || strings.Contains(ua, "Chrome/133")
}

func EnsureStickyProxy(proxyStr string) string {
	if strings.Contains(proxyStr, "dataimpulse.com") && !strings.Contains(proxyStr, "_session-") {
		sessionID := fmt.Sprintf("%08x", rand.Uint32())
		if u, err := url.Parse(proxyStr); err == nil && u.User != nil {
			user := u.User.Username()
			pass, hasPass := u.User.Password()
			newUser := user + "_session-" + sessionID
			if hasPass {
				u.User = url.UserPassword(newUser, pass)
			} else {
				u.User = url.User(newUser)
			}
			return u.String()
		}
	}
	return proxyStr
}

func RegistrationProcess(CaptchaConfig class.CaptchaConfig, worker_id int, proxyStr string) bool {
	proxyStr = EnsureStickyProxy(proxyStr)

	RegistrationContainer := &Container{
		Proxy:       proxyStr,
		TraceID:     utils.NewTraceID(),
		HttpClient:  azuretls.NewSession(),
		CapConfig:   CaptchaConfig,
		User:        roblox_profile.GetUsername(),
		Password:    roblox_profile.GetPassword(),
		Birthday:    roblox_profile.GetBirthDay(),
		Gender:      roblox_profile.GetGender(),
	}

	utils.Output("INFO", fmt.Sprintf("Start generate - %s", RegistrationContainer.User))

	if err := RegistrationContainer.SetHttpSession(); err != nil {
		utils.Output("FAILED", fmt.Sprintf("%s - SetHttpSession failed: %v - proxy=%s", RegistrationContainer.User, err, proxyStr))
		return false
	}

	if err := RegistrationContainer.BeforeSignUp(); err != nil {
		utils.Output("FAILED", fmt.Sprintf("%s - %s - proxy=%s", RegistrationContainer.User, err, proxyStr))
		return false
	}

	if err := RegistrationContainer.SignUp(); err != nil {
		utils.Output("FAILED", fmt.Sprintf("%s - %s - proxy=%s", RegistrationContainer.User, err, proxyStr))
		return false
	}

	return true

}

func (g *Container) SetHttpSession() error {

	g.HttpClient.Browser = azuretls.Chrome

	if err := g.HttpClient.ApplyHTTP2("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"); err != nil {
		return fmt.Errorf("failed set HTTP2")
	}

	if g.Proxy != "" {
		if err := g.HttpClient.SetProxy(g.Proxy); err != nil {
			return fmt.Errorf("failed set Proxy")
		}
	}

	return nil

}

// CookieHeader joins the session cookies captured in BeforeSignUp into a
// single "k=v; k=v" string, so the captcha solver sees the same session
// context Roblox will check against when the solved token is submitted.
func (g *Container) CookieHeader() string {
	parts := make([]string, 0, len(g.Cookies))
	for _, kv := range g.Cookies {
		if len(kv) == 2 {
			parts = append(parts, kv[1])
		}
	}
	return strings.Join(parts, "; ")
}

func (g *Container) DoRequest(method, url string, body []byte) (*azuretls.Response, error) {

	var resp *azuretls.Response
	var err error

	for attempt := 1; attempt <= maxRetries; attempt++ {

		req := &azuretls.Request{
			Method:   method,
			Url:      url,
			Body:     body,
			TimeOut:  35 * time.Second,
			NoCookie: true,
		}

		resp, err = g.HttpClient.Do(req)
		if err == nil {
			if csrf := string(resp.Header.Get("X-Csrf-Token")); csrf != "" {
				g.XCsrfToken = csrf
			}
			g.updateCookiesFromResponse(resp)
			return resp, nil
		}
	}

	return nil, fmt.Errorf("failed send request: %s", err)
}

func (g *Container) updateCookiesFromResponse(resp *azuretls.Response) {
	if resp == nil || resp.Header == nil {
		return
	}
	setCookies := resp.Header.Values("Set-Cookie")
	if len(setCookies) == 0 {
		if sc := resp.Header.Get("Set-Cookie"); sc != "" {
			setCookies = []string{sc}
		}
	}
	if len(setCookies) == 0 {
		return
	}

	existingCookies := make(map[string]string)
	for _, pair := range g.Cookies {
		if len(pair) >= 2 && pair[0] == "cookie" {
			for _, part := range strings.Split(pair[1], "; ") {
				kv := strings.SplitN(part, "=", 2)
				if len(kv) == 2 {
					existingCookies[strings.TrimSpace(kv[0])] = kv[1]
				}
			}
		}
	}

	for _, sc := range setCookies {
		parts := strings.SplitN(sc, ";", 2)
		if len(parts) > 0 {
			kv := strings.SplitN(parts[0], "=", 2)
			if len(kv) == 2 {
				name := strings.TrimSpace(kv[0])
				val := strings.TrimSpace(kv[1])
				if name != "" && val != "" {
					existingCookies[name] = val
				}
			}
		}
	}

	var cookieParts []string
	for k, v := range existingCookies {
		cookieParts = append(cookieParts, k+"="+v)
	}
	g.Cookies = [][]string{{"cookie", strings.Join(cookieParts, "; ")}}
}

// loadPrimedCookies is a validation-test-only hook: if PRIMED_COOKIES_FILE
// points at a JSON file of {"name": "value"} cookie pairs (produced by a real
// browser priming visit through the same proxy, e.g. prime_cookies.py), those
// values override whatever azuretls's own warm-up GET receives for the same
// cookie names. This exists purely to test whether a real-browser-obtained
// PerimeterX/Arkose cookie changes registration outcome vs. azuretls's own
// TLS-fingerprint-only warm-up -- production runs never set this env var, so
var harvesterOnce sync.Once

func ensureHarvesterServiceRunning() {
	harvesterOnce.Do(func() {
		client := &http.Client{Timeout: 1 * time.Second}
		_, err := client.Get("http://127.0.0.1:5000/health")
		if err != nil {
			utils.Output("INFO", "PX Harvester service not detected, auto-launching px_harvester_service.py in background...")
			cmd := exec.Command("python", "px_harvester_service.py")
			if err := cmd.Start(); err != nil {
				utils.Output("WARNING", fmt.Sprintf("Failed to auto-start px_harvester_service.py: %s", err))
			} else {
				time.Sleep(3 * time.Second)
			}
		}
	})
}

func fetchPXCookiesFromHarvester(proxyStr string) map[string]string {
	ensureHarvesterServiceRunning()
	harvesterURL := os.Getenv("PX_HARVESTER_URL")
	if harvesterURL == "" {
		harvesterURL = "http://127.0.0.1:5000/get_px_cookies"
	}
	payload, _ := json.Marshal(map[string]string{"proxy": proxyStr})
	client := &http.Client{Timeout: 25 * time.Second}

	for attempt := 1; attempt <= 3; attempt++ {
		req, err := http.NewRequest("POST", harvesterURL, bytes.NewBuffer(payload))
		if err != nil {
			return nil
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err == nil && resp.StatusCode == 200 {
			var res struct {
				Status  string            `json:"status"`
				Cookies map[string]string `json:"cookies"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&res); err == nil && len(res.Cookies) > 0 {
				if _, hasPx3 := res.Cookies["_px3"]; hasPx3 {
					resp.Body.Close()
					return res.Cookies
				}
			}
			resp.Body.Close()
		}
		time.Sleep(2 * time.Second)
	}
	return nil
}

func loadPrimedCookies() map[string]string {
	path := os.Getenv("PRIMED_COOKIES_FILE")
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var primed map[string]string
	if err := json.Unmarshal(data, &primed); err != nil {
		return nil
	}
	return primed
}

func parseCookies(headers fhttp.Header) map[string]string {
	cookies := make(map[string]string)

	setCookies := headers["Set-Cookie"]
	for _, c := range setCookies {
		parts := strings.Split(c, ";")
		if len(parts) > 0 {
			kv := strings.SplitN(parts[0], "=", 2)
			if len(kv) == 2 {
				key := strings.TrimSpace(kv[0])
				value := strings.TrimSpace(kv[1])
				cookies[key] = value
			}
		}
	}

	return cookies
}

// mergeCookies folds any Set-Cookie values from a response into g.Cookies,
// updating the value in place if that cookie name is already tracked (from
// BeforeSignUp's initial warm-up or a prior DoRequest call) and appending it
// otherwise. This is what keeps rotating anti-bot cookies (__cf_bm, _px3,
// pxcts, _pxvid) current for the rest of the flow instead of frozen at the
// value seen on the very first request.
func (g *Container) mergeCookies(headers fhttp.Header) {
	fresh := parseCookies(headers)
	if len(fresh) == 0 {
		return
	}
	for key, value := range fresh {
		updated := false
		for i, kv := range g.Cookies {
			if len(kv) == 2 && strings.HasPrefix(kv[1], key+"=") {
				g.Cookies[i] = []string{"cookie", key + "=" + value}
				updated = true
				break
			}
		}
		if !updated {
			g.Cookies = append(g.Cookies, []string{"cookie", key + "=" + value})
		}
	}
}

func (g *Container) BeforeSignUp() error {

	g.HttpClient.OrderedHeaders = azuretls.OrderedHeaders{
		{"upgrade-insecure-requests", "1"},
		{"user-agent", userAgent},
		{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		{"sec-fetch-site", "none"},
		{"sec-fetch-mode", "navigate"},
		{"sec-fetch-user", "?1"},
		{"sec-fetch-dest", "document"},
		{"sec-ch-ua", sec_ch_ua},
		{"sec-ch-ua-mobile", "?0"},
		{"sec-ch-ua-platform", "\"Windows\""},
		{"accept-encoding", "gzip, deflate, br, zstd"},
		{"accept-language", accept_language},
		{"priority", "u=0, i"},
	}

	response, err := g.DoRequest("GET", "https://www.roblox.com/", nil)

	if err != nil {
		return fmt.Errorf("getPage error: %s", err)
	}

	match := regexCsrf.FindStringSubmatch(string(response.Body))
	if len(match) > 1 {
		rawToken := match[1]
		g.XCsrfToken = html.UnescapeString(rawToken)
	} else {
		return fmt.Errorf("x-csrf-token not found")
	}

	cookies := parseCookies(response.Header)

	if pxCookies := fetchPXCookiesFromHarvester(g.Proxy); len(pxCookies) > 0 {
		for k, v := range pxCookies {
			cookies[k] = v
		}
		utils.Output("INFO", fmt.Sprintf("%s - harvested %d PX cookie(s)", g.User, len(pxCookies)))
	} else if primed := loadPrimedCookies(); primed != nil {
		for k, v := range primed {
			cookies[k] = v
		}
		utils.Output("INFO", fmt.Sprintf("%s - injected %d primed cookie(s)", g.User, len(primed)))
	}

	if len(cookies) != 0 {

		cookies["RBXPaymentsFlowContext"] = fmt.Sprintf("%s,", uuid.New())
		cookies["RBXcb"] = "RBXViralAcquisition%3Dfalse%26RBXSource%3Dfalse%26GoogleAnalytics%3Dfalse"

		// Explicitly include PX cookies if harvested
		pxKeys := []string{"_px3", "pxcts", "_pxvid", "_pxhd", "_px2"}
		allCookieKeys := append(order_cookies, pxKeys...)

		for _, key := range allCookieKeys {
			if value, ok := cookies[key]; ok {
				// avoid duplicate keys if already added
				exists := false
				for _, existing := range g.Cookies {
					if len(existing) == 2 && strings.HasPrefix(existing[1], key+"=") {
						exists = true
						break
					}
				}
				if !exists {
					g.Cookies = append(g.Cookies, []string{"cookie", key + "=" + value})
				}
			}
		}

	} else {
		return fmt.Errorf("cookies empty")
	}

	body := &class.UserValidate{
		Username: g.User,
		Context:  "Signup",
		Birthday: g.Birthday,
	}

	data, err := json.Marshal(body)

	if err != nil {
		return fmt.Errorf("failed json")
	}

	g.HttpClient.OrderedHeaders = azuretls.OrderedHeaders{
		{"content-length", strconv.Itoa(len(data))},
		{"sec-ch-ua-platform", `"Windows"`},
		{"x-csrf-token", g.XCsrfToken},
		{"sec-ch-ua", sec_ch_ua},
		{"sec-ch-ua-mobile", "?0"},
		{"traceparent", g.Traceparent()},
		{"user-agent", userAgent},
		{"accept", "application/json, text/plain, */*"},
		{"content-type", "application/json;charset=UTF-8"},
		{"origin", "https://www.roblox.com"},
		{"sec-fetch-site", "same-site"},
		{"sec-fetch-mode", "cors"},
		{"sec-fetch-dest", "empty"},
		{"referer", "https://www.roblox.com/"},
		{"accept-encoding", "gzip, deflate, br, zstd"},
		{"accept-language", accept_language},
		{"priority", "u=1, i"},
	}

	response, err = g.DoRequest("POST", "https://auth.roblox.com/v1/usernames/validate?urlLocale=en_us", data)

	if err != nil {
		return fmt.Errorf("userValidate request error")
	}

	if string(response.Body) == `{"code":0,"message":"Token Validation Failed"}` {

		g.XCsrfToken = string(response.Header.Get("X-Csrf-Token"))

		g.HttpClient.OrderedHeaders.Set("x-csrf-token", g.XCsrfToken)

		response, err = g.DoRequest("POST", "https://auth.roblox.com/v1/usernames/validate?urlLocale=en_us", data)

		if err != nil {
			return fmt.Errorf("userValidate request error")
		}

	}

	if string(response.Body) != `{"code":0,"message":"Username is valid"}` {

		body := &class.UserValidator{
			Username: g.User,
			Birthday: g.Birthday,
		}

		data, err := json.Marshal(body)

		if err != nil {
			return fmt.Errorf("failed json")
		}

		g.HttpClient.OrderedHeaders = azuretls.OrderedHeaders{
			{"content-length", strconv.Itoa(len(data))},
			{"sec-ch-ua-platform", `"Windows"`},
			{"x-csrf-token", g.XCsrfToken},
			{"sec-ch-ua", sec_ch_ua},
			{"sec-ch-ua-mobile", "?0"},
			{"traceparent", g.Traceparent()},
			{"user-agent", userAgent},
			{"accept", "application/json, text/plain, */*"},
			{"content-type", "application/json;charset=UTF-8"},
			{"origin", "https://www.roblox.com"},
			{"sec-fetch-site", "same-site"},
			{"sec-fetch-mode", "cors"},
			{"sec-fetch-dest", "empty"},
			{"referer", "https://www.roblox.com/"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", accept_language},
			{"priority", "u=1, i"},
		}

		body.Username = roblox_profile.GetUsername()

		data, err = json.Marshal(body)

		if err != nil {
			return fmt.Errorf("failed json")
		}

		response, err = g.DoRequest("POST", "https://auth.roblox.com/v1/validators/username?urlLocale=en_us", data)

		if err != nil {
			return fmt.Errorf("userValidator request error")
		}

		var dataUsernameSuggestion class.UsernameResponse

		err = json.Unmarshal(response.Body, &dataUsernameSuggestion)
		if err != nil {
			return fmt.Errorf("failed unmarshal")
		}

		if len(dataUsernameSuggestion.SuggestedUsernames) == 0 {
			return fmt.Errorf("not found suggestion usernames")
		}

		g.User = dataUsernameSuggestion.SuggestedUsernames[0]

	}

	return nil

}

// finalizeSignup extracts the freshly-issued .ROBLOSECURITY from a successful
// signup response and persists the account. The 3-step logout ->
// authentication-ticket -> redeem "bypass cookie" chain that used to live here
// was reverted out: it does not exist in the working original-tool baseline
// (~11% success) and adds 3 extra authenticated POSTs that the original never
// sends, which is itself a risk signal. The original simply grabs the cookie
// the signup response already set and saves it.
func (g *Container) finalizeSignup(response *azuretls.Response, effectiveUA string) error {
	cookies := response.Header.Get("set-cookie")

	if cookies == "" {
		return fmt.Errorf("failed get .ROBLOSECURITY")
	}

	parts := strings.Split(cookies, ";")

	cookieValue := ""

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, ".ROBLOSECURITY=") {
			cookieValue = strings.TrimPrefix(part, ".ROBLOSECURITY=")
		}
	}

	if cookieValue == "" {
		return fmt.Errorf("failed get .ROBLOSECURITY")
	}

	utils.SaveAccount(g.User, g.Password, cookieValue)

	utils.Output("SUCCESS", fmt.Sprintf("Successfully created - %s - proxy=%s", g.User, g.Proxy))

	return nil
}

func (g *Container) SignUp() error {

	var secureAuth *class.SecureAuth

	g.HttpClient.OrderedHeaders = azuretls.OrderedHeaders{
		{"traceparent", g.Traceparent()},
		{"sec-ch-ua-platform", "\"Windows\""},
		{"user-agent", userAgent},
		{"accept", "application/json, text/plain, */*"},
		{"sec-ch-ua", sec_ch_ua},
		{"sec-ch-ua-mobile", "?0"},
		{"origin", "https://www.roblox.com"},
		{"sec-fetch-site", "same-site"},
		{"sec-fetch-mode", "cors"},
		{"sec-fetch-dest", "empty"},
		{"referer", "https://www.roblox.com/"},
		{"accept-encoding", "gzip, deflate, br, zstd"},
		{"accept-language", accept_language},
	}

	if cStr := g.CookieHeader(); cStr != "" {
		g.HttpClient.OrderedHeaders = append(g.HttpClient.OrderedHeaders, []string{"cookie", cStr})
	}

	g.HttpClient.OrderedHeaders = append(g.HttpClient.OrderedHeaders, []string{"priority", "u=1, i"})

	response, err := g.DoRequest("GET", "https://apis.roblox.com/hba-service/v1/getServerNonce?urlLocale=en_us", nil)

	if err != nil {
		return fmt.Errorf("getServerNonce error")
	}

	nonce := strings.Trim(string(response.Body), "\"")

	if nonce == "" {
		return fmt.Errorf("nonce empty")
	}

	// Match Chrome baseline: Always validate username via auth.roblox.com/v1/usernames/validate
	// before calling /v2/signup. This generates CSRF token & signals normal user interaction.
	valPayload, _ := json.Marshal(map[string]any{
		"username": g.User,
		"context":  "Signup",
		"birthday": g.Birthday,
	})

	g.HttpClient.OrderedHeaders = azuretls.OrderedHeaders{
		{"content-length", strconv.Itoa(len(valPayload))},
		{"sec-ch-ua-platform", "\"Windows\""},
		{"x-csrf-token", g.XCsrfToken},
		{"sec-ch-ua", sec_ch_ua},
		{"sec-ch-ua-mobile", "?0"},
		{"traceparent", g.Traceparent()},
		{"user-agent", userAgent},
		{"accept", "application/json, text/plain, */*"},
		{"content-type", "application/json;charset=UTF-8"},
		{"origin", "https://www.roblox.com"},
		{"sec-fetch-site", "same-site"},
		{"sec-fetch-mode", "cors"},
		{"sec-fetch-dest", "empty"},
		{"referer", "https://www.roblox.com/"},
		{"accept-encoding", "gzip, deflate, br, zstd"},
		{"accept-language", accept_language},
	}
	if cStr := g.CookieHeader(); cStr != "" {
		g.HttpClient.OrderedHeaders = append(g.HttpClient.OrderedHeaders, []string{"cookie", cStr})
	}

	valResp, valErr := g.DoRequest("POST", "https://auth.roblox.com/v1/usernames/validate?urlLocale=en_us", valPayload)
	if valErr == nil && valResp.HttpResponse.StatusCode == 403 {
		if newCsrf := valResp.Header.Get("X-Csrf-Token"); newCsrf != "" {
			g.XCsrfToken = newCsrf
			g.HttpClient.OrderedHeaders[1] = []string{"x-csrf-token", g.XCsrfToken}
			_, _ = g.DoRequest("POST", "https://auth.roblox.com/v1/usernames/validate?urlLocale=en_us", valPayload)
		}
	}
	time.Sleep(1200 * time.Millisecond)

	secureAuth, err = utils.GenerateSecureAuth(nonce)

	if err != nil {
		return fmt.Errorf("failed GenerateSecureAuth")
	}

	body := &class.SignupPayload{
		Username:                 g.User,
		Password:                 g.Password,
		Birthday:                 g.Birthday,
		Gender:                   g.Gender,
		IsTosAgreementBoxChecked: true,
		AgreementIds:             []string{"306cc852-3717-4996-93e7-086daafd42f6", "2ba6b930-4ba8-4085-9e8c-24b919701f15"},
		AuditContent: class.AuditSystemContent{
			CapturedAuditContent: map[string]class.AuditItem{
				"Authentication.SignUp.Label.Birthday": {
					TranslationKey:         "Label.Birthday",
					TranslationNamespace:   "Authentication.SignUp",
					TranslatedSourceString: "Birthday",
				},
				"Authentication.SignUp.Description.SignUpAgreement.FullCopy": {
					TranslationKey:         "Description.SignUpAgreement.FullCopy",
					TranslationNamespace:   "Authentication.SignUp",
					TranslatedSourceString: "By clicking Sign Up, you are agreeing...",
					Parameters: map[string]string{
						"termsOfUseLink":    "<a target=\"_blank\" href=\"https://www.roblox.com/info/terms\">Terms of Use</a>",
						"privacyPolicyLink": "<a target=\"_blank\" href=\"https://www.roblox.com/info/privacy\">Privacy Policy</a>",
					},
				},
			},
			AdditionalAuditContent: map[string]any{},
		},
		SecureAuthenticationIntent: secureAuth,
	}

	dataSignup, err := json.Marshal(body)

	if err != nil {
		return fmt.Errorf("failed json")
	}

	g.HttpClient.OrderedHeaders = azuretls.OrderedHeaders{
		{"content-length", strconv.Itoa(len(dataSignup))},
		{"sec-ch-ua-platform", "\"Windows\""},
		{"x-csrf-token", g.XCsrfToken},
		{"sec-ch-ua", sec_ch_ua},
		{"sec-ch-ua-mobile", "?0"},
		{"traceparent", g.Traceparent()},
		{"user-agent", userAgent},
		{"accept", "application/json, text/plain, */*"},
		{"content-type", "application/json;charset=UTF-8"},
		{"origin", "https://www.roblox.com"},
		{"sec-fetch-site", "same-site"},
		{"sec-fetch-mode", "cors"},
		{"sec-fetch-dest", "empty"},
		{"referer", "https://www.roblox.com/"},
		{"accept-encoding", "gzip, deflate, br, zstd"},
		{"accept-language", accept_language},
	}

	if cStr := g.CookieHeader(); cStr != "" {
		g.HttpClient.OrderedHeaders = append(g.HttpClient.OrderedHeaders, []string{"cookie", cStr})
	}

	g.HttpClient.OrderedHeaders = append(g.HttpClient.OrderedHeaders, []string{"priority", "u=1, i"})

	response, err = g.DoRequest("POST", "https://auth.roblox.com/v2/signup?urlLocale=en_us", dataSignup)

	if err != nil {
		return fmt.Errorf("getBlob error")
	}

	if string(response.Body) == `{"errors":[{"code":0,"message":"Challenge is required to authorize the request"}]}` {
		if newCsrf := response.Header.Get("X-Csrf-Token"); newCsrf != "" {
			g.XCsrfToken = newCsrf
		}

		header := response.Header.Get("Rblx-Challenge-Metadata")
		if header == "" {
			return fmt.Errorf("failed Rblx-Challenge-Metadata")
		}

		ark, err := utils.ParseArkoseHeader(header)
		if err != nil {
			return fmt.Errorf("failed ParseArkoseHeader: %s", err)
		}

		ArkoseBlob := ark.DataExchangeBlob
		UnifiedCaptchaId := ark.UnifiedCaptchaId

		outerChallengeType := response.Header.Get("Rblx-Challenge-Type")
		if outerChallengeType == "" {
			outerChallengeType = "captcha"
		}
		utils.Output("DEBUG", fmt.Sprintf("Signup returned challenge type: %s", outerChallengeType))

		challengeIdHeader := response.Header.Get("Rblx-Challenge-Id")
		outerChallengeId := UnifiedCaptchaId
		if challengeIdHeader != "" {
			outerChallengeId = challengeIdHeader
		}

		// If Roblox returned captchav2, we MUST call /v2/captcha FIRST to get real redemption_token and the inner Arkose blob!
		if strings.EqualFold(outerChallengeType, "captchav2") {
			targetId := outerChallengeId
			utils.Output("DEBUG", fmt.Sprintf("Step 1: Requesting redemption_token from /v2/captcha for %s...", targetId))

			v2CapBody, _ := json.Marshal(map[string]string{
				"challenge_id": targetId,
			})

			// Pre-flight OPTIONS for /v2/captcha
			g.HttpClient.OrderedHeaders = azuretls.OrderedHeaders{
				{"accept", "*/*"},
				{"access-control-request-headers", "content-type,traceparent,x-csrf-token"},
				{"access-control-request-method", "POST"},
				{"origin", "https://www.roblox.com"},
				{"sec-fetch-mode", "cors"},
				{"user-agent", userAgent},
			}
			_, _ = g.DoRequest("OPTIONS", "https://apis.roblox.com/v2/captcha?urlLocale=en_us", nil)

			g.HttpClient.OrderedHeaders = azuretls.OrderedHeaders{
				{"sec-ch-ua-platform", "\"Windows\""},
				{"x-csrf-token", g.XCsrfToken},
				{"sec-ch-ua", sec_ch_ua},
				{"sec-ch-ua-mobile", "?0"},
				{"traceparent", g.Traceparent()},
				{"user-agent", userAgent},
				{"accept", "application/json, text/plain, */*"},
				{"content-type", "application/json;charset=UTF-8"},
				{"origin", "https://www.roblox.com"},
				{"sec-fetch-site", "same-site"},
				{"sec-fetch-mode", "cors"},
				{"sec-fetch-dest", "empty"},
				{"referer", "https://www.roblox.com/"},
				{"accept-encoding", "gzip, deflate, br, zstd"},
				{"accept-language", accept_language},
			}
			if cStr := g.CookieHeader(); cStr != "" {
				g.HttpClient.OrderedHeaders = append(g.HttpClient.OrderedHeaders, []string{"cookie", cStr})
			}

			respRedeem, errRedeem := g.DoRequest("POST", "https://apis.roblox.com/v2/captcha?urlLocale=en_us", v2CapBody)
			if errRedeem != nil || respRedeem.HttpResponse.StatusCode != 200 {
				return fmt.Errorf("failed get redemption_token from /v2/captcha: status=%d", respRedeem.HttpResponse.StatusCode)
			}

			var redeemRes struct {
				RedemptionToken string `json:"redemption_token"`
			}
			if err := json.Unmarshal(respRedeem.Body, &redeemRes); err != nil || redeemRes.RedemptionToken == "" {
				return fmt.Errorf("invalid redemption_token response: %s", string(respRedeem.Body))
			}

			utils.Output("DEBUG", fmt.Sprintf("Got real redemption_token: %s", redeemRes.RedemptionToken[:15]))

			// Step 2: Continue captchav2 with real redemptionToken
			captchav2Meta := fmt.Sprintf(`{"redemptionToken":"%s"}`, redeemRes.RedemptionToken)
			captchav2Body, _ := json.Marshal(map[string]string{
				"challengeId":       targetId,
				"challengeType":     "captchav2",
				"challengeMetadata": captchav2Meta,
			})

			respV2, errV2 := g.DoRequest("POST", "https://apis.roblox.com/challenge/v1/continue?urlLocale=en_us", captchav2Body)
			if errV2 != nil || respV2.HttpResponse.StatusCode != 200 {
				return fmt.Errorf("captchav2 continue failed: status=%d body=%s", respV2.HttpResponse.StatusCode, string(respV2.Body))
			}

			// Extract inner Arkose metadata blob & unifiedCaptchaId from continue response
			var v2ContinueRes struct {
				ChallengeId       string `json:"challengeId"`
				ChallengeMetadata string `json:"challengeMetadata"`
			}
			if err := json.Unmarshal(respV2.Body, &v2ContinueRes); err == nil && v2ContinueRes.ChallengeMetadata != "" {
				var innerMeta struct {
					DataExchangeBlob string `json:"dataExchangeBlob"`
					UnifiedCaptchaId string `json:"unifiedCaptchaId"`
				}
				if err := json.Unmarshal([]byte(v2ContinueRes.ChallengeMetadata), &innerMeta); err == nil {
					if innerMeta.DataExchangeBlob != "" {
						ArkoseBlob = innerMeta.DataExchangeBlob
					}
					if innerMeta.UnifiedCaptchaId != "" {
						UnifiedCaptchaId = innerMeta.UnifiedCaptchaId
					}
					utils.Output("DEBUG", fmt.Sprintf("Extracted inner Arkose Blob len=%d, captchaId=%s", len(ArkoseBlob), UnifiedCaptchaId))
				}
			}
			if len(ArkoseBlob) == 0 {
				utils.Output("DEBUG", fmt.Sprintf("Raw header (decoded): %s", utils.DecodeBase64Safe(header)))
				if logErr := utils.LogEmptyBlob(UnifiedCaptchaId, header); logErr != nil {
					utils.Output("DEBUG", fmt.Sprintf("LogEmptyBlob error: %s", logErr))
				}
				return fmt.Errorf("empty blob from Roblox - no eligible captcha method, retry with new proxy")
			}
		}

		token, err := funcaptcha.GetToken(g.CapConfig.Provider, g.CapConfig.Api_Key, g.CapConfig.Http_Version, g.CapConfig.Browser_Version, ArkoseBlob, g.Proxy, g.CookieHeader(), g.CapConfig.Solve_POW)

		if err != nil {
			return err
		}

		captchaToken := token.Token

		if captchaToken == "" {
			return fmt.Errorf("failed get token")
		}

		utils.Output("CAPTCHA", fmt.Sprintf("Solved %s", captchaToken[:28]))

		effectiveUA := userAgent
		effectiveSecChUa := sec_ch_ua

		if token.UserAgent != "" && isTLSConsistentUA(token.UserAgent) {
			effectiveUA = token.UserAgent
		}
		if token.SecChUa != "" {
			effectiveSecChUa = token.SecChUa
		}

		formattedToken := captchaToken

		ChallengeMeta := &class.ChallengeMetadata{
			UnifiedCaptchaId: UnifiedCaptchaId,
			CaptchaToken:     formattedToken,
			ActionType:       "Signup",
		}

		metaBytes, err := json.Marshal(ChallengeMeta)

		if err != nil {
			return fmt.Errorf("challenge metadata marshal error")
		}

		metaBase64 := base64.StdEncoding.EncodeToString(metaBytes)

		// Second continue call for Arkose captcha token is ALWAYS "captcha"
		Challenge := &class.ChallengeResponse{
			ChallengeId:       UnifiedCaptchaId,
			ChallengeType:     "captcha",
			ChallengeMetadata: string(metaBytes),
		}

		body, err := json.Marshal(Challenge)

		if err != nil {
			return fmt.Errorf("challenge marshal error")
		}

		g.HttpClient.OrderedHeaders = azuretls.OrderedHeaders{
			{"sec-ch-ua-platform", "\"Windows\""},
			{"x-csrf-token", g.XCsrfToken},
			{"referer", "https://www.roblox.com/"},
			{"accept-language", accept_language},
			{"sec-ch-ua", effectiveSecChUa},
			{"sec-ch-ua-mobile", "?0"},
			{"traceparent", g.Traceparent()},
			{"user-agent", effectiveUA},
			{"accept", "application/json, text/plain, */*"},
			{"content-type", "application/json;charset=UTF-8"},
		}

		utils.Output("DEBUG", fmt.Sprintf("continue request body: %s", string(body)))

		// Send ecsv2 captchaInitiated & captcha success tracking requests (matching real browser ground truth)
		nowIso := url.QueryEscape(time.Now().UTC().Format("2006-01-02T15:04:05.000Z"))
		encSession := url.QueryEscape(formattedToken)
		ecsv2Headers := azuretls.OrderedHeaders{
			{"sec-ch-ua-platform", "\"Windows\""},
			{"referer", "https://www.roblox.com/"},
			{"accept-language", accept_language},
			{"sec-ch-ua", effectiveSecChUa},
			{"user-agent", effectiveUA},
			{"sec-ch-ua-mobile", "?0"},
		}
		if cStr := g.CookieHeader(); cStr != "" {
			ecsv2Headers = append(ecsv2Headers, []string{"cookie", cStr})
		}
		g.HttpClient.OrderedHeaders = ecsv2Headers

		ecsv2InitUrl := fmt.Sprintf("https://ecsv2.roblox.com/www/e.png?type=hidden&provider=FunCaptcha&ucid=%s&session=%s&message=&providerVersion=V2&evt=captchaInitiated&ctx=Signup&url=https%%3A%%2F%%2Fwww.roblox.com%%2F&lt=%s&gid=-212967977", outerChallengeId, encSession, nowIso)
		_, _ = g.DoRequest("GET", ecsv2InitUrl, nil)

		ecsv2DoneUrl := fmt.Sprintf("https://ecsv2.roblox.com/www/e.png?solveDuration=0&success=true&provider=FunCaptcha&session=%s&ucid=%s&providerVersion=V2&evt=captcha&ctx=Signup&url=https%%3A%%2F%%2Fwww.roblox.com%%2F&lt=%s&gid=-212967977", encSession, outerChallengeId, nowIso)
		_, _ = g.DoRequest("GET", ecsv2DoneUrl, nil)

		// 1. Send CORS Pre-flight OPTIONS request
		g.HttpClient.OrderedHeaders = azuretls.OrderedHeaders{
			{"accept", "*/*"},
			{"access-control-request-headers", "content-type,traceparent,x-csrf-token"},
			{"access-control-request-method", "POST"},
			{"origin", "https://www.roblox.com"},
			{"sec-fetch-mode", "cors"},
			{"user-agent", effectiveUA},
		}
		_, _ = g.DoRequest("OPTIONS", "https://apis.roblox.com/challenge/v1/continue?urlLocale=en_us", nil)

		// 2. Prepare headers for actual POST /continue
		g.HttpClient.OrderedHeaders = azuretls.OrderedHeaders{
			{"sec-ch-ua-platform", "\"Windows\""},
			{"x-csrf-token", g.XCsrfToken},
			{"referer", "https://www.roblox.com/"},
			{"accept-language", accept_language},
			{"sec-ch-ua", effectiveSecChUa},
			{"sec-ch-ua-mobile", "?0"},
			{"traceparent", g.Traceparent()},
			{"user-agent", effectiveUA},
			{"accept", "application/json, text/plain, */*"},
			{"content-type", "application/json;charset=UTF-8"},
			{"origin", "https://www.roblox.com"},
			{"sec-fetch-site", "same-site"},
			{"sec-fetch-mode", "cors"},
			{"sec-fetch-dest", "empty"},
		}
		if cStr := g.CookieHeader(); cStr != "" {
			g.HttpClient.OrderedHeaders = append(g.HttpClient.OrderedHeaders, []string{"cookie", cStr})
		}

		response, err = g.DoRequest("POST", "https://apis.roblox.com/challenge/v1/continue?urlLocale=en_us", body)
		if err == nil {
			g.updateCookiesFromResponse(response)
		}
		if err != nil {
			return fmt.Errorf("captchaContinue error")
		}
		utils.Output("DEBUG", fmt.Sprintf("/continue response status: %d, body: %s", response.HttpResponse.StatusCode, string(response.Body)))

		for attempt := 1; attempt <= maxRetries; attempt++ {
			g.HttpClient.OrderedHeaders = azuretls.OrderedHeaders{
				{"rblx-challenge-metadata", metaBase64},
				{"sec-ch-ua-platform", "\"Windows\""},
				{"x-csrf-token", g.XCsrfToken},
				{"sec-ch-ua", effectiveSecChUa},
				{"rblx-challenge-id", UnifiedCaptchaId},
				{"rblx-challenge-type", outerChallengeType},
				{"sec-ch-ua-mobile", "?0"},
				{"traceparent", g.Traceparent()},
				{"user-agent", effectiveUA},
				{"accept", "application/json, text/plain, */*"},
				{"content-type", "application/json;charset=UTF-8"},
				{"x-retry-attempt", "1"},
				{"origin", "https://www.roblox.com"},
				{"sec-fetch-site", "same-site"},
				{"sec-fetch-mode", "cors"},
				{"sec-fetch-dest", "empty"},
				{"referer", "https://www.roblox.com/"},
				{"accept-encoding", "gzip, deflate, br, zstd"},
				{"accept-language", accept_language},
			}

			if cStr := g.CookieHeader(); cStr != "" {
				g.HttpClient.OrderedHeaders = append(g.HttpClient.OrderedHeaders, []string{"cookie", cStr})
			}

			g.HttpClient.OrderedHeaders = append(g.HttpClient.OrderedHeaders, []string{"priority", "u=1, i"})

			response, err = g.DoRequest("POST", "https://auth.roblox.com/v2/signup?urlLocale=en_us", dataSignup)

			if err != nil {
				return fmt.Errorf("signup error")
			}

			utils.Output("DEBUG", fmt.Sprintf("Final /v2/signup response status: %d, body: %s", response.HttpResponse.StatusCode, string(response.Body)))

			if string(response.Body) == `{"code":0,"message":"Token Validation Failed"}` {
				csrf := string(response.Header.Get("X-Csrf-Token"))
				if csrf != "" {
					g.XCsrfToken = csrf
				}
				continue
			} else {
				break
			}
		}

		return g.finalizeSignup(response, effectiveUA)

	} else if response.HttpResponse.StatusCode == 200 && response.Header.Get("set-cookie") != "" {
		// Roblox sometimes grants signup with no Arkose challenge at all
		// (trusted proxy/fingerprint => silent pass at the risk-engine level,
		// before Arkose is even invoked). Previously this fell straight into
		// the generic "getBlob failed" branch below and a genuinely
		// successful registration was thrown away.
		utils.Output("DEBUG", "signup succeeded without a captcha challenge (silent trust pass)")
		return g.finalizeSignup(response, userAgent)
	} else {
		bodyPreview := string(response.Body)
		if len(bodyPreview) > 300 {
			bodyPreview = bodyPreview[:300]
		}
		utils.Output("DEBUG", fmt.Sprintf("getBlob failed: unexpected /v2/signup response status=%d body=%s", response.HttpResponse.StatusCode, bodyPreview))
		return fmt.Errorf("getBlob failed: status=%d", response.HttpResponse.StatusCode)
	}

}
