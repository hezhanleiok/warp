package main

import (
	"os"
	"strings"
	"testing"
)

// TestLegacyCompat: 生成的 legacy 配置必须是 sing-box 1.8~1.10 老内核可解析的老格式:
// wireguard 在 outbound 顶层 (server/server_port/peer_public_key/local_address),
// DNS 用老式 address 字段, 路由规则无 action 体系。Karing (KaringX/sing-box fork) 同代.
func TestLegacyCompat(t *testing.T) {
	app := &App{}
	app.tempSingboxPath = app.prepareSingbox()
	res, err := app.GenerateConfigs("awg", 2, 1)
	if err != nil {
		t.Fatalf("GenerateConfigs failed: %v", err)
	}
	legacy := res["legacy"]
	if !strings.Contains(legacy, "peer_public_key") {
		t.Fatal("legacy config missing peer_public_key (old wireguard outbound format)")
	}
	if strings.Contains(legacy, "endpoints") {
		t.Fatal("legacy config must NOT use endpoints array (unsupported by 1.10 kernels)")
	}
	if !strings.Contains(legacy, "\"address\": \"223.5.5.5\"") {
		t.Fatal("legacy DNS must use old-style address field")
	}
	if strings.Contains(legacy, "\"type\": \"udp\"") {
		t.Fatal("legacy DNS must not use new type:udp format")
	}
	if strings.Contains(legacy, "action") {
		t.Fatal("legacy route rules must not contain action (1.11+ only)")
	}
	if strings.Contains(legacy, "default_domain_resolver") {
		t.Fatal("legacy config must not contain default_domain_resolver (1.12+)")
	}
	os.WriteFile("C:/dsh-test/legacy-check.json", []byte(legacy), 0644)
	os.WriteFile("C:/dsh-test/new-check.json", []byte(res["singbox"]), 0644)
	t.Logf("legacy len: %d, new len: %d", len(legacy), len(res["singbox"]))

	// V2rayN 链接: 外层节点 + AI 内层节点都应在, 且 AI 链接用 publickey (无下划线)
	v2n := res["v2raynLinks"]
	outerLinks := strings.Count(v2n, "publickey=")
	aiLinks := strings.Count(v2n, "WARP-AI")
	if aiLinks < 1 {
		t.Fatal("v2rayn links missing AI inner nodes (WARP-AI)")
	}
	if strings.Contains(v2n, "public_key=") {
		t.Fatal("v2rayn links must use publickey (no underscore)")
	}
	t.Logf("v2rayn links: outer=%d, AI=%d, total lines=%d", outerLinks, aiLinks, strings.Count(v2n, "\n")+1)

	// BPB 风格两组: 节点选择 (selector) + 测速分组 (urltest); 旧组名必须全部消失
	sb := res["singbox"]
	if !strings.Contains(sb, "\"tag\": \"测速分组\"") || !strings.Contains(sb, "\"tag\": \"节点选择\"") {
		t.Fatal("singbox config must have exactly two groups: 节点选择 + 测速分组")
	}
	for _, oldTag := range []string{"普通节点", "🤖 AI 专线", "WARP-外层优选"} {
		if strings.Contains(sb, "\"tag\": \""+oldTag+"\"") {
			t.Fatalf("old group %s must be removed", oldTag)
		}
	}
	if !strings.Contains(sb, "\"tolerance\": 150") {
		t.Fatal("urltest group should carry tolerance (anti-flap, official doc)")
	}
	// 节点选择必须平铺: 测速分组 + AI 内层 + 外层节点 + direct
	if !strings.Contains(sb, "\"default\": \"测速分组\"") {
		t.Fatal("节点选择 default must be 测速分组")
	}
	os.WriteFile("C:/dsh-test/bpb-singbox.json", []byte(sb), 0644)
	t.Logf("singbox two-group config saved")
}