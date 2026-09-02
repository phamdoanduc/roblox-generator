package main

import (
	"RobloxRegister/src/internal/helpers/fingerprint"
	"encoding/json"
	"fmt"
)

// Standalone demo/verification harness for the fingerprint package (not part
// of the production build). Prints one generated bda payload per platform so
// the output can be eyeballed and diffed against a source sample under mua/.
// Not wired into register.go/funcaptcha.go — that integration is a separate,
// later task.
//
// Run from the repo root:
//
//	go run ./src/fingerprintgen
func main() {
	// Mirrors funcaptcha.go's robloxSite/robloxAPIURL constants, duplicated
	// locally since they're unexported there and this binary must not
	// depend on the funcaptcha package.
	const (
		robloxSite   = "https://www.roblox.com"
		robloxAPIURL = "https://arkoselabs.roblox.com"
	)

	ctx := fingerprint.Context{
		Referrer: robloxSite + "/",
		Surl:     robloxAPIURL,
	}

	for _, p := range []fingerprint.Platform{fingerprint.PlatformWindows, fingerprint.PlatformAndroid} {
		out, err := fingerprint.Generate(p, ctx)
		if err != nil {
			panic(fmt.Sprintf("Generate(%s): %v", p, err))
		}

		var pretty interface{}
		if err := json.Unmarshal(out, &pretty); err != nil {
			panic(fmt.Sprintf("Generate(%s) produced invalid JSON: %v", p, err))
		}
		prettyBytes, err := json.MarshalIndent(pretty, "", "  ")
		if err != nil {
			panic(err)
		}

		fmt.Printf("===== %s (%d bytes) =====\n", p, len(out))
		fmt.Println(string(prettyBytes))
		fmt.Println()
	}
}
