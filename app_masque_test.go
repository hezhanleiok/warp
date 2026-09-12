package main

import (
	"os"
	"strings"
	"testing"
)

// 双态断言: CF 198.2 承载网关有时段性 RST 阻断.
//  - 网关健康: 必须>=2个 masque 节点 + AI 内层 wireguard 兜底
//  - 网关阻断: 必须完整回退 WireGuard 外层 (masque 数 0), protoNote 提示回退,
//    交付的配置永远可用 — 这正是预检存在的意义.
func TestMasqueModeE2E(t *testing.T) {
	app := &App{}
	app.tempSingboxPath = app.prepareSingbox()
	res, err := app.GenerateConfigs("h3", 3, 2)
	if err != nil {
		t.Fatalf("GenerateConfigs(h3) failed: %v", err)
	}
	cy := res["clashYaml"]
	masqueCount := strings.Count(cy, "type: masque")
	aiCount := strings.Count(cy, "type: wireguard")
	gwOK := app.probeMasqueGateway()
	t.Logf("gateway-198.2 reachable: %v, masque nodes: %d, wireguard nodes: %d", gwOK, masqueCount, aiCount)
	if gwOK {
		if !strings.Contains(cy, "type: masque") || masqueCount < 2 {
			t.Fatalf("gateway healthy but masque nodes=%d (expect >=2)", masqueCount)
		}
		if !strings.Contains(cy, "server: 162.159.198.2") {
			t.Fatal("masque gateway must be 162.159.198.2")
		}
		if !strings.Contains(cy, "network: h3") {
			t.Fatal("h3 mode missing network: h3")
		}
		if !strings.Contains(res["protoNote"], "已就绪") {
			t.Fatalf("protoNote should be ready, got: %s", res["protoNote"])
		}
	} else {
		if masqueCount != 0 {
			t.Fatalf("gateway blocked but still emitted %d masque nodes (must fall back to WG)", masqueCount)
		}
		if aiCount < 1 {
			t.Fatal("fallback config must still have wireguard outer nodes")
		}
		if !strings.Contains(res["protoNote"], "回退") {
			t.Fatalf("protoNote should mention fallback, got: %s", res["protoNote"])
		}
	}
	if aiCount < 1 {
		t.Fatal("should yield at least 1 AI inner wireguard node")
	}
	os.WriteFile("C:/dsh-test/masque-e2e-clash.yaml", []byte(cy), 0644)
	os.WriteFile("C:/dsh-test/masque-e2e-singbox.json", []byte(res["singbox"]), 0644)
	t.Logf("protoNote: %s", res["protoNote"])
	t.Logf("best: %s", res["best"])
}