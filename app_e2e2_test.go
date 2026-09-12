package main

import (
	"os"
	"strings"
	"testing"
)

func TestE2EWithAIUnlock(t *testing.T) {
	app := &App{}
	app.tempSingboxPath = app.prepareSingbox()
	res, err := app.GenerateConfigs("awg", 3, 2)
	if err != nil {
		t.Fatalf("GenerateConfigs failed: %v", err)
	}
	neko := app.nekoContent
	lines := strings.Split(strings.TrimSpace(neko), "\n")
	t.Logf("neko links: %d lines", len(lines))
	for _, line := range lines {
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "wireguard://") {
			t.Fatalf("bad line prefix: %s", line[:40])
		}
		queryPart := strings.SplitN(line, "?", 2)[1]
		if strings.Contains(queryPart, "/k&") || strings.Contains(queryPart, "+F1") {
			t.Fatalf("raw base64 not escaped in query: %s", line)
		}
		if !strings.Contains(line, "%2F32%2C") {
			t.Fatalf("address param not encoded: %s", line)
		}
	}
	if len(lines) == 0 {
		t.Fatal("no links")
	}
	os.WriteFile("C:/dsh-test/e2e2-neko.txt", []byte(neko), 0644)
	os.WriteFile("C:/dsh-test/e2e2-singbox.json", []byte(res["singbox"]), 0644)
	os.WriteFile("C:/dsh-test/e2e2-clash.yaml", []byte(res["clashYaml"]), 0644)
	t.Logf("best=%s", res["best"])
}
