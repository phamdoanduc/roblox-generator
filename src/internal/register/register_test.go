package register

import "testing"

// Note: utils.init() reads input/proxies.txt relative to the process cwd,
// which `go test` sets to this package's directory -- input/proxies.txt in
// this test directory is a dummy fixture that exists solely to satisfy that
// read during `go test`, not real proxy data.

// Guards against reintroducing the JA3/UA mismatch regression: azuretls.Chrome
// negotiates a fixed Chrome-133-shaped ClientHello (see const block in
// register.go), so isTLSConsistentUA must reject any solver-reported UA that
// claims a different Chrome version.
func TestIsTLSConsistentUA(t *testing.T) {
	cases := []struct {
		ua   string
		want bool
	}{
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36", true},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36", false},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isTLSConsistentUA(c.ua); got != c.want {
			t.Errorf("isTLSConsistentUA(%q) = %v, want %v", c.ua, got, c.want)
		}
	}
}
