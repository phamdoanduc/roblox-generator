package register

import (
	"RobloxRegister/src/internal/helpers/class"
	"RobloxRegister/src/internal/helpers/funcaptcha"
	"RobloxRegister/src/internal/helpers/roblox_profile"
	"RobloxRegister/src/internal/helpers/utils"

	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"math/rand"
	"os"
	"regexp"
	"strconv"
	"strings"
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
	// azuretls.Chrome (github.com/Noooste/azuretls-client v1.13.2) only ever emits
	// a Chrome-133-shaped ClientHello (see GetLastChromeVersion in profiles.go) --
	// it does not vary with whatever UA string we declare. Every header identity
	// below MUST stay pinned to Chrome/133 so the JA3 fingerprint and the
	// application-layer UA agree; sending e.g. Chrome/146 headers over a Chrome/133
	// ClientHello is a deterministic, trivially-detectable bot signature.
	userAgent       = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
	sec_ch_ua       = `"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"`
	// Reverted from fr-FR to en-US to match urlLocale=en_us and the working
	// original-tool baseline (~11% success). The netz fork's French header over
	// a Germany/France residential pool with an en_us URL locale is a clean
	// locale/geo contradiction the risk engine can score deterministically.
	accept_language = "en-US,en;q=0.9"
)

// isTLSConsistentUA reports whether a UA string declares the same Chrome major
// version that azuretls.Chrome actually negotiates at the TLS layer (133).
// Adopting a solver-provided UA that claims a different version would fix the
// Arkose-blob/UA match at the cost of breaking the JA3/UA match on every
// request this client itself sends to Roblox -- so such UAs must be rejected.
func isTLSConsistentUA(ua string) bool {
	return strings.Contains(ua, "Chrome/133")
}

func RegistrationProcess(CaptchaConfig class.CaptchaConfig, worker_id int, proxyStr string) bool {

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
		utils.Output("FAILED", fmt.Sprintf("%s - %s - proxy=%s", RegistrationContainer.User, err, proxyStr))
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

	if err := g.HttpClient.SetProxy(g.Proxy); err != nil {
		return fmt.Errorf("failed set Proxy")
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
			TimeOut:  10 * time.Second,
			NoCookie: true,
		}

		resp, err = g.HttpClient.Do(req)
		if err == nil {
			return resp, nil
		}
	}

	return nil, fmt.Errorf("failed send request: %s", err)
}

// loadPrimedCookies is a validation-test-only hook: if PRIMED_COOKIES_FILE
// points at a JSON file of {"name": "value"} cookie pairs (produced by a real
// browser priming visit through the same proxy, e.g. prime_cookies.py), those
// values override whatever azuretls's own warm-up GET receives for the same
// cookie names. This exists purely to test whether a real-browser-obtained
// PerimeterX/Arkose cookie changes registration outcome vs. azuretls's own
// TLS-fingerprint-only warm-up -- production runs never set this env var, so
// this is a no-op by default.
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

	if primed := loadPrimedCookies(); primed != nil {
		for k, v := range primed {
			cookies[k] = v
		}
		utils.Output("INFO", fmt.Sprintf("%s - injected %d primed cookie(s)", g.User, len(primed)))
	}

	if len(cookies) != 0 {

		// Reverted to the original-tool's strict 5-name allowlist. The netz
		// fork's "carry every Set-Cookie through the flow" change (incl. rotating
		// __cf_bm/_px3/pxcts) was tested live multiple times and produced 0%
		// success vs the original's ~11% with the strict strip. Stripping the
		// anti-bot vendor cookies is what the working baseline actually does.
		cookies["RBXPaymentsFlowContext"] = fmt.Sprintf("%s,", uuid.New())
		cookies["RBXcb"] = "RBXViralAcquisition%3Dfalse%26RBXSource%3Dfalse%26GoogleAnalytics%3Dfalse"

		for _, key := range order_cookies {
			if value, ok := cookies[key]; ok {
				g.Cookies = append(g.Cookies, []string{"cookie", key + "=" + value})
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

	g.HttpClient.OrderedHeaders = append(g.HttpClient.OrderedHeaders, g.Cookies...)

	g.HttpClient.OrderedHeaders = append(g.HttpClient.OrderedHeaders, []string{"priority", "u=1, i"})

	response, err := g.DoRequest("GET", "https://apis.roblox.com/hba-service/v1/getServerNonce?urlLocale=en_us", nil)

	if err != nil {
		return fmt.Errorf("getServerNonce error")
	}

	nonce := strings.Trim(string(response.Body), "\"")

	if nonce == "" {
		return fmt.Errorf("nonce empty")
	}

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

	g.HttpClient.OrderedHeaders = append(g.HttpClient.OrderedHeaders, g.Cookies...)

	g.HttpClient.OrderedHeaders = append(g.HttpClient.OrderedHeaders, []string{"priority", "u=1, i"})

	response, err = g.DoRequest("POST", "https://auth.roblox.com/v2/signup?urlLocale=en_us&urlLocale=en_us", dataSignup)

	if err != nil {
		return fmt.Errorf("getBlob error")
	}

	if string(response.Body) == `{"errors":[{"code":0,"message":"Challenge is required to authorize the request"}]}` {

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

		utils.Output("DEBUG", fmt.Sprintf("Blob len=%d, UnifiedCaptchaId=%s", len(ArkoseBlob), UnifiedCaptchaId))
		utils.Output("DEBUG", fmt.Sprintf("RAW CHALLENGE HEADER: %s", utils.DecodeBase64Safe(header)))
		if len(ArkoseBlob) == 0 {
			utils.Output("DEBUG", fmt.Sprintf("Raw header (decoded): %s", utils.DecodeBase64Safe(header)))
			if logErr := utils.LogEmptyBlob(UnifiedCaptchaId, header); logErr != nil {
				utils.Output("DEBUG", fmt.Sprintf("LogEmptyBlob error: %s", logErr))
			}
			return fmt.Errorf("empty blob from Roblox - no eligible captcha method, retry with new proxy")
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

		// Only adopt the solver's fingerprint UA when it's TLS-consistent (Chrome/133,
		// matching azuretls.Chrome's fixed ClientHello -- see isTLSConsistentUA).
		// A solver UA from a different Chrome version would match the Arkose blob
		// but break the JA3/UA match on this client's own requests to Roblox, which
		// is the mismatch actually observed at the /challenge/v1/continue 403s.
		effectiveUA := userAgent
		effectiveSecChUa := sec_ch_ua
		if strings.TrimSpace(token.UserAgent) != "" && isTLSConsistentUA(token.UserAgent) {
			effectiveUA = token.UserAgent
			if strings.TrimSpace(token.SecChUa) != "" {
				effectiveSecChUa = token.SecChUa
			}
		} else if strings.TrimSpace(token.UserAgent) != "" {
			utils.Output("DEBUG", fmt.Sprintf("solver UA %q is not TLS-consistent (want Chrome/133) - falling back to pinned identity", token.UserAgent))
		}

		// Real browser's challengeMetadata (both in the /challenge/v1/continue body and
		// the rblx-challenge-metadata retry header) has exactly these 3 fields -- no
		// requestPath/requestMethod, confirmed against a captured real-browser signup HAR.
		ChallengeMeta := &class.ChallengeMetadata{
			UnifiedCaptchaId: UnifiedCaptchaId,
			CaptchaToken:     captchaToken,
			ActionType:       "Signup",
		}

		metaBytes, err := json.Marshal(ChallengeMeta)

		if err != nil {
			return fmt.Errorf("challenge metadata marshal error")
		}

		metaBase64 := base64.StdEncoding.EncodeToString(metaBytes)

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
			{"content-length", strconv.Itoa(len(body))},
			{"sec-ch-ua-platform", "\"Windows\""},
			{"x-csrf-token", g.XCsrfToken},
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
			{"referer", "https://www.roblox.com/"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", accept_language},
		}

		g.HttpClient.OrderedHeaders = append(g.HttpClient.OrderedHeaders, g.Cookies...)

		g.HttpClient.OrderedHeaders = append(g.HttpClient.OrderedHeaders, []string{"priority", "u=1, i"})

		utils.Output("DEBUG", fmt.Sprintf("continue request body: %s", string(body)))

		// A real user takes a beat between the widget resolving and the
		// browser's own JS firing this POST (render + microtask delay, not
		// instant). Submitting it in the same instant the token is minted is
		// a zero-latency signature the risk engine can key on deterministically.
		time.Sleep(time.Duration(1200+rand.Intn(1800)) * time.Millisecond)

		response, err = g.DoRequest("POST", "https://apis.roblox.com/challenge/v1/continue?urlLocale=en_us", body)

		if err != nil {
			return fmt.Errorf("captchaContiniue error")
		}

		if response.HttpResponse.StatusCode != 200 {
			fmt.Printf("[DEBUG] reject continiue by API. Status: %d, Body: %s\n", response.HttpResponse.StatusCode, string(response.Body))
			return fmt.Errorf("reject continiue by API")
		} else {

			for attempt := 1; attempt <= maxRetries; attempt++ {
				g.HttpClient.OrderedHeaders = azuretls.OrderedHeaders{
					{"content-length", strconv.Itoa(len(dataSignup))},
					{"rblx-challenge-metadata", metaBase64},
					{"sec-ch-ua-platform", "\"Windows\""},
					{"x-csrf-token", g.XCsrfToken},
					{"sec-ch-ua", effectiveSecChUa},
					{"rblx-challenge-id", UnifiedCaptchaId},
					{"rblx-challenge-type", "captcha"},
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

				g.HttpClient.OrderedHeaders = append(g.HttpClient.OrderedHeaders, g.Cookies...)

				g.HttpClient.OrderedHeaders = append(g.HttpClient.OrderedHeaders, []string{"priority", "u=1, i"})

				response, err = g.DoRequest("POST", "https://auth.roblox.com/v2/signup?urlLocale=en_us&urlLocale=en_us", dataSignup)

				if err != nil {
					return fmt.Errorf("signup error")
				}

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
		}

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
