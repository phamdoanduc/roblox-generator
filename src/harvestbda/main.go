package main

import (
	"RobloxRegister/src/internal/helpers/class"
	"RobloxRegister/src/internal/helpers/utils"
	"RobloxRegister/src/internal/register"

	"flag"
	"fmt"
	"os"

	"go.yaml.in/yaml/v3"
)

// Standalone harvest-mode test harness (not part of the production build).
// Runs RegistrationProcess exactly N times with NEGT_HARVEST_BDA=1 forced on,
// so each run captures a real ArkoseBlob from auth.roblox.com, forwards it to
// hba_live_service.py for BDA priming/dumping, then aborts before any real
// account is created. See Plan 3 in nested-yawning-canyon.md.
//
// Run from the repo root:
//
//	go run ./src/harvestbda -runs=5
func main() {
	runs := flag.Int("runs", 5, "number of harvest attempts to run")
	flag.Parse()

	os.Setenv("NEGT_HARVEST_BDA", "1")

	data, err := os.ReadFile("input/config.yml")
	if err != nil {
		panic(err)
	}
	var cfg class.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		panic(err)
	}
	if err := cfg.Validate(); err != nil {
		panic(err)
	}

	for i := 1; i <= *runs; i++ {
		proxyStr := utils.GetProxy()
		fmt.Printf("[*] Harvest run %d/%d - proxy=%s\n", i, *runs, proxyStr)
		ok := register.RegistrationProcess(cfg.Captcha, i, proxyStr)
		fmt.Printf("[+] Harvest run %d/%d result: %v (false expected - harvest mode always aborts before signup)\n", i, *runs, ok)
	}
}
