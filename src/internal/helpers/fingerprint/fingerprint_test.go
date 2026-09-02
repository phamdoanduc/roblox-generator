package fingerprint

import (
	"encoding/json"
	"testing"
)

func testContext() Context {
	return Context{
		Referrer: "https://www.roblox.com/",
		Surl:     "https://arkoselabs.roblox.com",
	}
}

func TestPoolLoadsBothPlatforms(t *testing.T) {
	poolOnce.Do(loadPool)
	if poolErr != nil {
		t.Fatalf("pool failed to load: %v", poolErr)
	}

	var winCount, droidCount int
	for _, p := range pool {
		switch p.platform {
		case PlatformWindows:
			winCount++
		case PlatformAndroid:
			droidCount++
		}
	}
	if winCount == 0 {
		t.Error("expected at least one windows capture in the pool")
	}
	if droidCount == 0 {
		t.Error("expected at least one android capture in the pool")
	}
}

func TestGenerateProducesValidJSON(t *testing.T) {
	for _, platform := range []Platform{PlatformWindows, PlatformAndroid} {
		out, err := Generate(platform, testContext())
		if err != nil {
			t.Fatalf("Generate(%s) error: %v", platform, err)
		}

		var top []kv
		if err := json.Unmarshal(out, &top); err != nil {
			t.Fatalf("Generate(%s) produced invalid JSON: %v", platform, err)
		}

		wantKeys := []string{"api_type", "f", "n", "wh", "enhanced_fp", "fe", "ife_hash", "jsbd", "user_agent"}
		for _, want := range wantKeys {
			found := false
			for _, e := range top {
				if e.Key == want {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Generate(%s) output missing top-level key %q", platform, want)
			}
		}
	}
}

func TestGenerateOverridesSessionAndSiteFields(t *testing.T) {
	out, err := Generate(PlatformWindows, testContext())
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}

	var top []kv
	if err := json.Unmarshal(out, &top); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	enhanced, ok := findEnhancedFP(top)
	if !ok {
		t.Fatal("missing enhanced_fp")
	}

	get := func(key string) string {
		for _, e := range enhanced {
			if e.Key == key {
				var s string
				_ = json.Unmarshal(e.Value, &s)
				return s
			}
		}
		return ""
	}

	if got := get("document__referrer"); got != "https://www.roblox.com/" {
		t.Errorf("document__referrer = %q, want https://www.roblox.com/", got)
	}
	if got := get("client_config__surl"); got != "https://arkoselabs.roblox.com" {
		t.Errorf("client_config__surl = %q, want https://arkoselabs.roblox.com", got)
	}
	if got := get("window__location_href"); got != "https://arkoselabs.roblox.com/v2/enforcement.html" {
		t.Errorf("window__location_href = %q, want default enforcement URL", got)
	}
	if got := get("4b4b269e68"); len(got) != 36 {
		t.Errorf("4b4b269e68 = %q, want a 36-char UUID", got)
	}
}

func TestGenerateLeavesDeviceSignalsIntact(t *testing.T) {
	out, err := Generate(PlatformWindows, testContext())
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}

	var top []kv
	if err := json.Unmarshal(out, &top); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	enhanced, ok := findEnhancedFP(top)
	if !ok {
		t.Fatal("missing enhanced_fp")
	}

	for _, want := range []string{"webgl_unmasked_renderer", "webgl_unmasked_vendor", "user_agent_data_mobile"} {
		found := false
		for _, e := range enhanced {
			if e.Key == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected untouched device-signal key %q to survive Generate", want)
		}
	}
}

func TestGenerateUnknownPlatformErrors(t *testing.T) {
	if _, err := Generate(Platform("plan9"), testContext()); err == nil {
		t.Error("expected an error for a platform with no matching captures")
	}
}
