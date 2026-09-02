// Package fingerprint generates Arkose FunCaptcha bda fingerprint payloads
// from a pool of real, purchased device captures under mua/ instead of
// synthesizing device signals from scratch. Only the handful of fields that
// are genuinely session/site-specific get overwritten per call; every
// WebGL/font/plugin/screen signal is left byte-identical to a real capture,
// so cross-field consistency (a real device's actual GPU+screen+font
// combination) is preserved by construction.
package fingerprint

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// kv mirrors the real bda array-of-{key,value} shape so unmarshal/marshal
// round-trips preserve field order (it's a slice, not a map) and untouched
// values pass through byte-identical via json.RawMessage.
type kv struct {
	Key   string          `json:"key"`
	Value json.RawMessage `json:"value"`
}

type Platform string

const (
	PlatformAny     Platform = ""
	PlatformWindows Platform = "windows"
	PlatformAndroid Platform = "android"
)

// invisibleSeparator is the trailing U+2063 character Arkose appends to the
// "1l2l5234ar2" timestamp value in every real capture observed.
const invisibleSeparator = "⁣"

// Context carries the site-specific values a real capture can't supply,
// since every sample was captured on an unrelated third-party page.
type Context struct {
	Referrer     string // page the fingerprint should claim to be loaded from, e.g. "https://www.roblox.com/"
	Surl         string // Arkose surl for the target site, e.g. "https://arkoselabs.roblox.com"
	LocationHref string // enforcement iframe URL; defaults to Surl + "/v2/enforcement.html" when empty
}

type profile struct {
	top      []kv
	platform Platform
}

var (
	poolOnce sync.Once
	pool     []profile
	poolErr  error
)

// findMuaDir walks upward from the current working directory looking for a
// mua/ directory. Running the built binary from the repo root finds it
// immediately; `go test` runs with the package directory as its working
// directory instead, so the walk-up is what lets tests find it too.
func findMuaDir() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		candidate := filepath.Join(dir, "mua")
		if info, statErr := os.Stat(candidate); statErr == nil && info.IsDir() {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("fingerprint: could not locate mua/ directory")
		}
		dir = parent
	}
}

func loadPool() {
	muaDir, err := findMuaDir()
	if err != nil {
		poolErr = err
		return
	}

	var loaded []profile
	_ = filepath.WalkDir(muaDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.EqualFold(filepath.Ext(path), ".json") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var top []kv
		if err := json.Unmarshal(data, &top); err != nil {
			return nil
		}
		plat, ok := detectPlatform(top)
		if !ok {
			return nil
		}
		loaded = append(loaded, profile{top: top, platform: plat})
		return nil
	})

	if len(loaded) == 0 {
		poolErr = fmt.Errorf("fingerprint: no usable captures found under mua/")
		return
	}
	pool = loaded
}

// detectPlatform inspects a parsed capture's enhanced_fp for
// user_agent_data_mobile rather than trusting the source folder name, since
// the pool is built by walking the whole mua/ tree without regard to layout.
//
// user_agent_data_mobile is only populated by browsers that implement the
// User-Agent Client Hints API (Chromium-based). Safari doesn't support it, so
// genuine iOS/Safari captures report it as JSON null rather than false — that
// must NOT be treated as "false" (desktop), or an iPhone/Safari capture (with
// its own GPU/font/plugin signal set) silently lands in the windows bucket
// and Generate(PlatformWindows, ...) can hand out a Safari device dressed up
// as Chrome/Windows. Captures like that are excluded from the pool entirely
// rather than guessed at, consistent with how unparseable files are skipped.
func detectPlatform(top []kv) (Platform, bool) {
	enhanced, ok := findEnhancedFP(top)
	if !ok {
		return "", false
	}
	for _, e := range enhanced {
		if e.Key != "user_agent_data_mobile" {
			continue
		}
		switch strings.TrimSpace(string(e.Value)) {
		case "true":
			return PlatformAndroid, true
		case "false":
			return PlatformWindows, true
		default:
			return "", false
		}
	}
	return "", false
}

func findEnhancedFP(top []kv) ([]kv, bool) {
	for _, e := range top {
		if e.Key != "enhanced_fp" {
			continue
		}
		var enhanced []kv
		if err := json.Unmarshal(e.Value, &enhanced); err != nil {
			return nil, false
		}
		return enhanced, true
	}
	return nil, false
}

// Generate picks a random real capture matching platform (PlatformAny
// matches any), overwrites its session/site-specific fields with values
// derived from ctx and the current time, and returns the resulting bda
// payload as JSON bytes in the original key order.
func Generate(platform Platform, ctx Context) ([]byte, error) {
	poolOnce.Do(loadPool)
	if poolErr != nil {
		return nil, poolErr
	}

	var matches []profile
	for _, p := range pool {
		if platform == PlatformAny || p.platform == platform {
			matches = append(matches, p)
		}
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("fingerprint: no captures available for platform %q", platform)
	}
	src := matches[rand.Intn(len(matches))]

	top := deepCopyKV(src.top)

	enhanced, ok := findEnhancedFP(top)
	if !ok {
		return nil, fmt.Errorf("fingerprint: selected capture missing enhanced_fp")
	}

	if ctx.LocationHref == "" {
		ctx.LocationHref = strings.TrimRight(ctx.Surl, "/") + "/v2/enforcement.html"
	}
	origin := ctx.Referrer
	if idx := strings.Index(origin, "://"); idx != -1 {
		if slash := strings.Index(origin[idx+3:], "/"); slash != -1 {
			origin = origin[:idx+3+slash]
		}
	}

	now := time.Now()
	overrides := map[string]interface{}{
		"1l2l5234ar2":                          strconv.FormatInt(now.UnixMilli(), 10) + invisibleSeparator,
		"4b4b269e68":                           uuid.NewString(),
		"document__referrer":                   ctx.Referrer,
		"window__ancestor_origins":             []string{origin},
		"window__location_href":                ctx.LocationHref,
		"client_config__sitedata_location_href": ctx.Referrer,
		"client_config__surl":                  ctx.Surl,
	}
	if err := applyOverrides(enhanced, overrides); err != nil {
		return nil, err
	}
	enhancedBytes, err := json.Marshal(enhanced)
	if err != nil {
		return nil, err
	}
	if err := setKV(top, "enhanced_fp", enhancedBytes); err != nil {
		return nil, err
	}

	nBytes, err := json.Marshal(base64.StdEncoding.EncodeToString([]byte(strconv.FormatInt(now.Unix(), 10))))
	if err != nil {
		return nil, err
	}
	if err := setKV(top, "n", nBytes); err != nil {
		return nil, err
	}

	return json.Marshal(top)
}

func applyOverrides(entries []kv, overrides map[string]interface{}) error {
	for key, val := range overrides {
		raw, err := json.Marshal(val)
		if err != nil {
			return err
		}
		if err := setKV(entries, key, raw); err != nil {
			return err
		}
	}
	return nil
}

func setKV(entries []kv, key string, value json.RawMessage) error {
	for i := range entries {
		if entries[i].Key == key {
			entries[i].Value = value
			return nil
		}
	}
	return fmt.Errorf("fingerprint: key %q not found in capture", key)
}

func deepCopyKV(src []kv) []kv {
	out := make([]kv, len(src))
	for i, e := range src {
		v := make(json.RawMessage, len(e.Value))
		copy(v, e.Value)
		out[i] = kv{Key: e.Key, Value: v}
	}
	return out
}
