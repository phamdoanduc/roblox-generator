package main

import (
	"RobloxRegister/src/internal/helpers/class"
	"RobloxRegister/src/internal/register"

	"bufio"
	"flag"
	"fmt"
	"os"

	"go.yaml.in/yaml/v3"
)

// Standalone A/B test harness (not part of the production build). Runs a
// single RegistrationProcess call through one deterministic proxy line,
// optionally with PRIMED_COOKIES_FILE set so register.go's
// loadPrimedCookies() overrides the warm-up cookies with ones captured by a
// real-browser priming visit (see prime_cookies.py at repo root). Lives under
// src/ (not repo root) because it needs to import internal packages, which
// Go only allows from within the same src/... tree as internal/.
//
// Run from the repo root:
//
//	go run ./src/testprime -primed=primed_cookies.json -proxy-index=0
//	go run ./src/testprime -proxy-index=0   (baseline, no priming)
func main() {
	proxyIndex := flag.Int("proxy-index", 0, "line index in input/proxies.txt to use (must match prime_cookies.py)")
	primedFile := flag.String("primed", "", "path to a primed cookies JSON file; empty = baseline run (no priming)")
	flag.Parse()

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

	proxyStr, err := readProxyLine(*proxyIndex)
	if err != nil {
		panic(err)
	}

	if *primedFile != "" {
		if _, err := os.Stat(*primedFile); err != nil {
			panic(fmt.Sprintf("primed cookies file not found: %s (%v)", *primedFile, err))
		}
		os.Setenv("PRIMED_COOKIES_FILE", *primedFile)
		fmt.Printf("[*] Mode: PRIMED (cookies from %s)\n", *primedFile)
	} else {
		os.Unsetenv("PRIMED_COOKIES_FILE")
		fmt.Println("[*] Mode: BASELINE (no priming)")
	}

	fmt.Printf("[*] Using proxy index %d\n", *proxyIndex)

	ok := register.RegistrationProcess(cfg.Captcha, 1, proxyStr)
	fmt.Printf("[+] RegistrationProcess result: %v\n", ok)
}

func readProxyLine(index int) (string, error) {
	f, err := os.Open("input/proxies.txt")
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	i := 0
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		if i == index {
			return line, nil
		}
		i++
	}
	return "", fmt.Errorf("proxy index %d not found in input/proxies.txt", index)
}
