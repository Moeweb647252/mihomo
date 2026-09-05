package adapter

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func TestParseWTPProxy(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name":                  "WTP-SW",
		"type":                  "wtp",
		"server":                "104.244.79.19",
		"sni":                   "op.647252.xyz",
		"port":                  443,
		"path":                  "/647252",
		"congestion-controller": "bbr",
		"client-fingerprint":    "chrome",
		"bbr-profile":           "aggressive",
		"udp":                   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if proxy.Type() != C.Wtp {
		t.Fatalf("proxy type = %s, want Wtp", proxy.Type())
	}
	if !proxy.SupportUDP() {
		t.Fatal("WTP proxy did not enable UDP")
	}
	if proxy.Name() != "WTP-SW" {
		t.Fatalf("proxy name = %q, want WTP-SW", proxy.Name())
	}
	_ = proxy.Close()
}
