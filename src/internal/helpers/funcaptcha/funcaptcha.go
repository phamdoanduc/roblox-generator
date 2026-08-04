package funcaptcha

import (
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

const (
	robloxRegisterPublicKey = "A2A14B1D-1AF3-C791-9BBC-EE33CC7A0A6F"
	robloxSite               = "https://www.roblox.com"
	robloxAPIURL             = "https://arkoselabs.roblox.com"
)

func debugLog(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[FUNCAPTCHA] "+format+"\n", args...)
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
}

// GetToken solves the Roblox FunCaptcha and returns an Arkose token.
// provider selects the backend: "cds" calls cds-solver.com directly (paid
// third-party service, one HTTP client away); anything else (including "")
// uses this project's own solver at serverURL. Switching backends is a
// config change (settings_captcha.provider), not a code change.
func GetToken(provider, api_key, http_version, browser_version, blob, proxy, cookies string, solvePOW bool) (*TokenResult, error) {
	if strings.EqualFold(strings.TrimSpace(provider), "cds") {
		return getTokenCDS(api_key, http_version, browser_version, blob, proxy, cookies, solvePOW)
	}
	return getTokenNetz(api_key, http_version, browser_version, blob, proxy, cookies, solvePOW)
}

func getTokenNetz(api_key, http_version, browser_version, blob, proxy, cookies string, solvePOW bool) (*TokenResult, error) {
	body := map[string]interface{}{
		"challengeInfo": map[string]interface{}{
			"publicKey": robloxRegisterPublicKey,
			"site":      robloxSite,
			"surl":      robloxAPIURL,
			"capiMode":  "inline",
			"styleTheme": "default",
			"extraData": map[string]interface{}{
				"blob": blob,
			},
			"ancestorOrigins": []string{robloxSite, robloxSite},
			"treeIndex":       []int{0, 0},
			"treeStructure":   "[[[]]]",
			"locationHref":    robloxSite + "/arkose/iframe",
		},
		"proxy":   proxy,
		"cookies": parseCookieString(cookies),
	}
	if browser_version != "" {
		body["browser_version"] = browser_version
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
		for count := 0; count <= 150; count++ {
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
