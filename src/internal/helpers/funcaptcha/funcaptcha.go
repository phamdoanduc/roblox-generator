package funcaptcha

import (
	"RobloxRegister/src/internal/helpers/utils"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var client = &http.Client{
	Timeout: 45 * time.Second,
	Transport: &http.Transport{
		Proxy:             nil,
		DisableKeepAlives: true,
	},
}

// This project's own solver (see Captcha.NetZ.Vn), not the third-party cds-solver.com.
// Override with NEGT_SOLVER_URL if the solver runs on a different host/port.
var serverURL = func() string {
	if v := strings.TrimSpace(os.Getenv("NEGT_SOLVER_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "http://127.0.0.1:2323"
}()

// The self-hosted hachi-captcha solver (Python FastAPI server, see
// Hiu Share/hachi-captcha-master-changed). Override with HACHI_SOLVER_URL if
// it runs on a different host/port.
var hachiServerURL = func() string {
	if v := strings.TrimSpace(os.Getenv("HACHI_SOLVER_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "http://127.0.0.1:8080"
}()

// hachi's /solve blocks server-side until the challenge is solved (up to its
// own DIRECT_SOLVE_WAIT_SECONDS=200s), so give the HTTP client enough room.
var hachiClient = &http.Client{
	Timeout: 220 * time.Second,
	Transport: &http.Transport{
		Proxy:             nil,
		DisableKeepAlives: true,
	},
}

const (
	robloxRegisterPublicKey = "A2A14B1D-1AF3-C791-9BBC-EE33CC7A0A6F"
	robloxSite              = "https://www.roblox.com"
	robloxAPIURL            = "https://arkoselabs.roblox.com"
)

func debugLog(format string, args ...interface{}) {
	if !utils.IsDebugEnabled {
		return
	}
	fmt.Fprintf(os.Stderr, "[SOLVE] "+format+"\n", args...)
}

// redactProxy strips embedded user:pass credentials before logging, since
// stderr from this package routinely gets redirected to on-disk log files.
func redactProxy(proxy string) string {
	scheme := ""
	rest := proxy
	if idx := strings.Index(proxy, "://"); idx != -1 {
		scheme = proxy[:idx+3]
		rest = proxy[idx+3:]
	}
	if at := strings.LastIndex(rest, "@"); at != -1 {
		return scheme + "***:***@" + rest[at+1:]
	}
	return proxy
}

func parseCookieString(cookies string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(cookies, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		out[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
	}
	return out
}

// TokenResult carries the solved Arkose token plus the exact browser identity
// (User-Agent / sec-ch-ua) the solver used to build that token, so the caller
// can align its own HTTP requests to the same identity instead of redeeming
// the token under a mismatched, hardcoded UA.
type TokenResult struct {
	Token     string
	UserAgent string
	SecChUa   string
	Cookies   map[string]string
}

// GetToken solves the Roblox FunCaptcha and returns an Arkose token.
// provider selects the backend: "cds" calls cds-solver.com directly (paid
// third-party service, one HTTP client away); anything else (including "")
// uses this project's own solver at serverURL. Switching backends is a
// config change (settings_captcha.provider), not a code change.
func GetToken(provider, api_key, http_version, browser_version, blob, proxy, cookies string, solvePOW bool, recognitionProvider, recognitionAPIKey string) (*TokenResult, error) {
	switch {
	case strings.EqualFold(strings.TrimSpace(provider), "cds"):
		return getTokenCDS(api_key, http_version, browser_version, blob, proxy, cookies, solvePOW)
	case strings.EqualFold(strings.TrimSpace(provider), "hachi"):
		return getTokenHachi(api_key, blob, proxy, cookies, solvePOW)
	case strings.EqualFold(strings.TrimSpace(provider), "hba"):
		return getTokenHBA(blob, proxy)
	}
	return getTokenNetz(api_key, http_version, browser_version, blob, proxy, cookies, solvePOW, recognitionProvider, recognitionAPIKey)
}

func getTokenNetz(api_key, http_version, browser_version, blob, proxy, cookies string, solvePOW bool, recognitionProvider, recognitionAPIKey string) (*TokenResult, error) {
	body := map[string]interface{}{
		"challengeInfo": map[string]interface{}{
			"publicKey":  robloxRegisterPublicKey,
			"site":       robloxSite,
			"surl":       robloxAPIURL,
			"capiMode":   "inline",
			"styleTheme": "default",
			"extraData": map[string]interface{}{
				"blob": blob,
			},
			"ancestorOrigins":              []string{},
			"treeIndex":                    []int{},
			"treeStructure":                "[]",
			"locationHref":                 robloxSite + "/CreateAccount",
			"clientConfigSitedataLocation": robloxSite + "/CreateAccount",
			"clientConfigLanguage":         "",
		},
		"proxy":     proxy,
		"cookies":   parseCookieString(cookies),
		"solve_pow": solvePOW,
	}
	if browser_version != "" {
		body["browser_version"] = browser_version
	}
	if strings.TrimSpace(recognitionProvider) != "" {
		body["recognition_provider"] = strings.TrimSpace(recognitionProvider)
	}
	if strings.TrimSpace(recognitionAPIKey) != "" {
		body["recognition_api_key"] = strings.TrimSpace(recognitionAPIKey)
	}

	debugLog("blob_len=%d proxy=%q", len(blob), redactProxy(proxy))

	jsonBody, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", serverURL+"/createTask", bytes.NewBuffer(jsonBody))
	if err != nil {
		debugLog("createTask req err: %v", err)
		return nil, fmt.Errorf("failed createTask")
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		debugLog("createTask do err: %v", err)
		return nil, fmt.Errorf("failed createTask: %s", err)
	}
	defer resp.Body.Close()

	data, _ := ioutil.ReadAll(resp.Body)

	var taskResp map[string]interface{}
	if err := json.Unmarshal(data, &taskResp); err != nil {
		debugLog("createTask json err: %v body=%s", err, string(data))
		return nil, fmt.Errorf("failed jsonParse createTask: %s", err)
	}

	status, _ := taskResp["status"].(string)
	debugLog("createTask response status=%s", status)

	if status == "started" || status == "processing" {

		taskID, ok := taskResp["task_id"].(string)
		if !ok {
			debugLog("no task_id in response")
			return nil, fmt.Errorf("failed get taskID")
		}

		debugLog("poll starting task_id=%s", taskID)
		for count := 0; count <= 350; count++ {
			pollURL := fmt.Sprintf("%s/getTask?task_id=%s", serverURL, url.QueryEscape(taskID))
			req2, _ := http.NewRequest("GET", pollURL, nil)

			resp2, err := client.Do(req2)
			if err != nil {
				debugLog("poll %d get err: %v", count, err)
				time.Sleep(600 * time.Millisecond)
				continue
			}

			respData, _ := ioutil.ReadAll(resp2.Body)
			resp2.Body.Close()

			var tokenResp map[string]interface{}
			if err := json.Unmarshal(respData, &tokenResp); err != nil {
				debugLog("poll %d json err: %v", count, err)
				time.Sleep(600 * time.Millisecond)
				continue
			}

			status, _ := tokenResp["status"].(string)

			switch status {
			case "processing", "pow_needed":
				if count%10 == 0 {
					debugLog("poll %d still processing", count)
				}
				time.Sleep(600 * time.Millisecond)

			case "success":
				tok, ok := tokenResp["token"].(string)
				if ok {
					ua, _ := tokenResp["user_agent"].(string)
					secChUa, _ := tokenResp["sec_ch_ua"].(string)
					debugLog("SUCCESS token_len=%d ua=%q", len(tok), ua)
					return &TokenResult{Token: tok, UserAgent: ua, SecChUa: secChUa}, nil
				}
				debugLog("success but no token field")
				return nil, fmt.Errorf("failed get token")

			case "error", "failed":
				errMsg, ok := tokenResp["error"].(string)
				if ok {
					debugLog("failed: %s", errMsg)
					return nil, fmt.Errorf("failed: %s", errMsg)
				}
				debugLog("failed no msg")
				return nil, fmt.Errorf("failed get token")

			default:
				debugLog("unexpected status: %s", status)
				return nil, fmt.Errorf("unexpected status: %s", status)
			}
		}
		debugLog("poll exhausted")
	} else if status == "failed" {
		errMsg, _ := taskResp["error"].(string)
		debugLog("createTask failed: %s", errMsg)
		return nil, fmt.Errorf("failed solve captcha - %s", errMsg)
	} else {
		debugLog("unknown initial status: %s", status)
	}

	return nil, fmt.Errorf("failed get token")
}

// getTokenCDS talks to cds-solver.com directly using its createTask/getTask
// contract. It never returns a UserAgent/SecChUa, so the caller falls back
// to its own pinned browser identity.
func getTokenCDS(api_key, http_version, browser_version, blob, proxy, cookies string, solvePOW bool) (*TokenResult, error) {
	body := map[string]interface{}{
		"api_key":      api_key,
		"site_key":     robloxRegisterPublicKey,
		"proxy":        proxy,
		"locale":       "en-US",
		"blob":         blob,
		"cookies":      cookies,
		"http_version": http_version,
		"solve_pow":    solvePOW,
	}
	if browser_version != "" {
		body["browser_version"] = browser_version
	}

	jsonBody, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", "https://cds-solver.com/createTask", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed createTask")
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		debugLog("cds createTask do err: %v", err)
		return nil, fmt.Errorf("failed createTask: %s", err)
	}
	defer resp.Body.Close()

	data, _ := ioutil.ReadAll(resp.Body)

	var taskResp map[string]interface{}
	if err := json.Unmarshal(data, &taskResp); err != nil {
		debugLog("cds createTask json err: %v body=%s", err, string(data))
		return nil, fmt.Errorf("failed jsonParse createTask")
	}

	status, ok := taskResp["status"].(string)
	if !ok {
		debugLog("cds createTask no status, http=%d", resp.StatusCode)
		return nil, fmt.Errorf("failed get status")
	}

	if status != "started" {
		if status == "failed" {
			errMsg, _ := taskResp["error"].(string)
			return nil, fmt.Errorf("failed solve captcha - %s", errMsg)
		}
		return nil, fmt.Errorf("failed solve captcha - status: %s", status)
	}

	taskID, ok := taskResp["task_id"].(string)
	if !ok {
		return nil, fmt.Errorf("failed get taskID")
	}

	payload := map[string]interface{}{
		"api_key": api_key,
		"task_id": taskID,
	}

	for count := 0; count <= 120; count++ {
		jsonPayload, _ := json.Marshal(payload)
		req2, _ := http.NewRequest("POST", "https://cds-solver.com/getTask", bytes.NewBuffer(jsonPayload))
		req2.Header.Set("Content-Type", "application/json")

		resp2, err := client.Do(req2)
		if err != nil {
			time.Sleep(600 * time.Millisecond)
			continue
		}

		respData, _ := ioutil.ReadAll(resp2.Body)
		resp2.Body.Close()

		var tokenResp map[string]interface{}
		if err := json.Unmarshal(respData, &tokenResp); err != nil {
			time.Sleep(600 * time.Millisecond)
			continue
		}

		status, _ := tokenResp["status"].(string)
		switch status {
		case "processing":
			time.Sleep(600 * time.Millisecond)

		case "success":
			tok, ok := tokenResp["token"].(string)
			if ok {
				return &TokenResult{Token: tok}, nil
			}
			return nil, fmt.Errorf("failed get token")

		case "failed":
			errMsg, ok := tokenResp["error"].(string)
			if ok {
				return nil, fmt.Errorf("failed: %s", errMsg)
			}
			return nil, fmt.Errorf("failed get token")

		default:
			return nil, fmt.Errorf("unexpected status: %s", status)
		}
	}

	return nil, fmt.Errorf("failed get token")
}

// getTokenHachi talks to the self-hosted hachi-captcha solver's blocking
// POST /solve endpoint. api_key is expected as "recognition_provider:key"
// (e.g. "omocaptcha:PKG_..."); this is how settings_captcha.api_key threads
// the third-party image-recognition credential through to hachi without
// needing dedicated config.yml fields. solve_pow is always requested from
// hachi locally (SOLVE_POW_LOCAL=true server-side), so a "pow_needed"
// response (client-side POW, unimplemented here) is treated as a failure.
func getTokenHachi(api_key, blob, proxy, cookies string, solvePOW bool) (*TokenResult, error) {
	recognitionProvider := ""
	recognitionKey := api_key
	if idx := strings.Index(api_key, ":"); idx != -1 {
		recognitionProvider = strings.TrimSpace(api_key[:idx])
		recognitionKey = strings.TrimSpace(api_key[idx+1:])
	}

	additionalInfo := map[string]interface{}{
		"proxy":   proxy,
		"cookies": parseCookieString(cookies),
	}
	if recognitionKey != "" {
		additionalInfo["recognition_api_key"] = recognitionKey
	}
	if recognitionProvider != "" {
		additionalInfo["recognition_provider"] = recognitionProvider
	}

	body := map[string]interface{}{
		"challenge": map[string]interface{}{
			"public_key":                            robloxRegisterPublicKey,
			"site_url":                              robloxSite,
			"api_url":                               robloxAPIURL,
			"locale":                                "en-US",
			"window_ancestor_origins":               []string{robloxSite, robloxSite},
			"window_tree_index":                     []int{0, 0},
			"window_tree_structure":                 "[[[]]]",
			"window_location_href":                  robloxSite + "/arkose/iframe",
			"client_config_site_data_location_href": robloxSite + "/arkose/iframe",
			"client_config_api_url":                 robloxAPIURL,
			"capi_mode":                             "inline",
			"style_theme":                           "default",
			"solve_pow":                             solvePOW,
			"max_waves":                             20,
			"extra_data": map[string]interface{}{
				"blob": blob,
			},
		},
		"additional_info": additionalInfo,
	}

	debugLog("hachi blob_len=%d proxy=%q", len(blob), redactProxy(proxy))

	jsonBody, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", hachiServerURL+"/solve", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed hachi solve request")
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := hachiClient.Do(req)
	if err != nil {
		debugLog("hachi solve do err: %v", err)
		return nil, fmt.Errorf("failed hachi solve: %s", err)
	}
	defer resp.Body.Close()

	data, _ := ioutil.ReadAll(resp.Body)

	var solveResp map[string]interface{}
	if err := json.Unmarshal(data, &solveResp); err != nil {
		debugLog("hachi solve json err: %v body=%s", err, string(data))
		return nil, fmt.Errorf("failed jsonParse hachi solve")
	}

	if resp.StatusCode != http.StatusOK {
		msg, _ := solveResp["detail"].(string)
		if msg == "" {
			msg, _ = solveResp["message"].(string)
		}
		debugLog("hachi solve http=%d msg=%s", resp.StatusCode, msg)
		return nil, fmt.Errorf("failed hachi solve: %s", msg)
	}

	status, _ := solveResp["status"].(string)
	debugLog("hachi solve response status=%s", status)

	switch status {
	case "done":
		tok, ok := solveResp["token"].(string)
		if !ok || tok == "" {
			return nil, fmt.Errorf("hachi done but no token field")
		}
		debugLog("hachi SUCCESS token_len=%d", len(tok))
		return &TokenResult{Token: tok}, nil

	case "pow_needed":
		return nil, fmt.Errorf("hachi requires client-side POW (unsupported); check SOLVE_POW_LOCAL on the hachi server")

	default:
		msg, _ := solveResp["message"].(string)
		return nil, fmt.Errorf("hachi failed: %s", msg)
	}
}

func getTokenHBA(blob, proxy string) (*TokenResult, error) {
	body := map[string]interface{}{
		"blob":  blob,
		"proxy": proxy,
	}
	jsonBody, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", "http://127.0.0.1:8766/prime", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed HBA request creation: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	hbaClient := &http.Client{Timeout: 95 * time.Second}
	resp, err := hbaClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed HBA call: %w", err)
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed read HBA response: %w", err)
	}

	var hbaResp map[string]interface{}
	if err := json.Unmarshal(data, &hbaResp); err != nil {
		return nil, fmt.Errorf("failed parse HBA response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		errMsg, _ := hbaResp["error"].(string)
		return nil, fmt.Errorf("HBA error status %d: %s", resp.StatusCode, errMsg)
	}

	token, ok := hbaResp["token"].(string)
	if !ok || token == "" {
		return nil, fmt.Errorf("HBA returned empty token")
	}

	isSilent, _ := hbaResp["is_silentpass"].(bool)
	ua, _ := hbaResp["user_agent"].(string)

	cookieMap := map[string]string{}
	if rawCookies, ok := hbaResp["cookies"].(map[string]interface{}); ok {
		for k, v := range rawCookies {
			if valStr, ok := v.(string); ok {
				cookieMap[k] = valStr
			}
		}
	}

	debugLog("HBA SUCCESS token_len=%d is_silentpass=%v cookies_len=%d", len(token), isSilent, len(cookieMap))
	return &TokenResult{
		Token:     token,
		UserAgent: ua,
		Cookies:   cookieMap,
	}, nil
}
