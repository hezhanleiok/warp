package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// WarpAccount 结构体：存储 WARP 账户凭据与分配地址
type WarpAccount struct {
	AccountID  string `json:"account_id"`
	Token      string `json:"token"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	IPv4       string `json:"ipv4"`
	IPv6       string `json:"ipv6"`
	Reserved   [3]int `json:"reserved"`
	ClientID   string `json:"client_id"`
}

// EndpointResult 结构体：优选测速结果
type EndpointResult struct {
	IP        string  `json:"ip"`
	Port      int     `json:"port"`
	Latency   int64   `json:"latency"`   // 毫秒
	LossRate  float64 `json:"loss_rate"` // 丢包率 (0.0 - 1.0)
	SpeedMBps float64 `json:"speed_mbps"`
	Status    string  `json:"status"`
}

// ConfigOutput 结构体：输出给前端的多平台配置
type ConfigOutput struct {
	Protocol    string `json:"protocol"`
	ClashYaml   string `json:"clash_yaml"`
	SingBoxJson string `json:"singbox_json"`
	WireGuard   string `json:"wireguard_conf"`
	BestIPCount int    `json:"best_ip_count"`
}

type App struct {
	ctx          context.Context
	account      *WarpAccount
	bestIPs      []EndpointResult
	ipMutex      sync.RWMutex
	accountMutex sync.RWMutex
}

func NewApp() *App {
	return &App{
		bestIPs: make([]EndpointResult, 0),
	}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// ==========================================
// 1. Cloudflare WARP 核心账户注册与密钥对生成
// ==========================================

func (a *App) RegisterWARPAccount(licenseKey string) (*WarpAccount, error) {
	a.accountMutex.Lock()
	defer a.accountMutex.Unlock()

	// 1. 本地生成标准 Curve25519 密钥对
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("生成 Curve25519 密钥对失败: %w", err)
	}

	privKeyBase64 := base64.StdEncoding.EncodeToString(privKey.Bytes())
	pubKeyBase64 := base64.StdEncoding.EncodeToString(privKey.PublicKey().Bytes())

	// 2. 构造 CF 官方注册 Payload
	installID := fmt.Sprintf("%016x%016x", time.Now().UnixNano(), randInt64())
	reqBody := map[string]interface{}{
		"key":        pubKeyBase64,
		"install_id": installID,
		"fcm_token":  fmt.Sprintf("%s:APA91b%016x", installID, time.Now().UnixNano()),
		"tos":        time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"model":      "PC",
		"type":       "Android",
		"locale":     "zh_CN",
	}

	jsonBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 12 * time.Second}
	req, err := http.NewRequestWithContext(a.ctx, "POST", "https://api.cloudflareclient.com/v0a1922/reg", bytes.NewBuffer(jsonBytes))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("User-Agent", "okhttp/3.12.1")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("WARP API 请求失败: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var parsed struct {
		ID      string `json:"id"`
		Token   string `json:"token"`
		Account struct {
			License string `json:"license"`
		} `json:"account"`
		Config struct {
			ClientID  string `json:"client_id"`
			Interface struct {
				Addresses struct {
					V4 string `json:"v4"`
					V6 string `json:"v6"`
				} `json:"addresses"`
			} `json:"interface"`
		} `json:"config"`
	}

	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("反序列化 WARP 响应失败: %w", err)
	}

	// 提取 ClientID 对应的 reserved 3 字节标识
	var reserved [3]int
	if parsed.Config.ClientID != "" {
		if rawReserved, err := base64.StdEncoding.DecodeString(parsed.Config.ClientID); err == nil && len(rawReserved) >= 3 {
			reserved = [3]int{int(rawReserved[0]), int(rawReserved[1]), int(rawReserved[2])}
		}
	}

	// 绑定 License (如果有)
	if licenseKey != "" && parsed.Token != "" && parsed.ID != "" {
		_ = a.applyLicenseKey(parsed.ID, parsed.Token, licenseKey)
	}

	a.account = &WarpAccount{
		AccountID:  parsed.ID,
		Token:      parsed.Token,
		PrivateKey: privKeyBase64,
		PublicKey:  pubKeyBase64,
		IPv4:       parsed.Config.Interface.Addresses.V4,
		IPv6:       parsed.Config.Interface.Addresses.V6,
		Reserved:   reserved,
		ClientID:   parsed.Config.ClientID,
	}

	return a.account, nil
}

func (a *App) applyLicenseKey(id, token, license string) error {
	client := &http.Client{Timeout: 8 * time.Second}
	payload := map[string]string{"license": license}
	b, _ := json.Marshal(payload)

	req, err := http.NewRequest("PUT", fmt.Sprintf("https://api.cloudflareclient.com/v0a1922/reg/%s/account", id), bytes.NewBuffer(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// ==========================================
// 2. 优选 IP 节点扫描与并发测速引擎
// ==========================================

func (a *App) RunEndpointSpeedTest(customCandidates []string, targetCount int) ([]EndpointResult, error) {
	candidates := customCandidates
	if len(candidates) == 0 {
		candidates = defaultWARPEndpoints()
	}

	var (
		results []EndpointResult
		wg      sync.WaitGroup
		mu      sync.Mutex
		sem     = make(chan struct{}, 20) // 最大并发度 20
	)

	for _, ep := range candidates {
		wg.Add(1)
		sem <- struct{}{}

		go func(endpoint string) {
			defer wg.Done()
			defer func() { <-sem }()

			host, portStr, err := net.SplitHostPort(endpoint)
			if err != nil {
				return
			}
			port, _ := strconv.Atoi(portStr)

			// 测量 TCP 往返 RTT 与丢包率
			var totalRTT int64
			packetsSent := 3
			packetsReceived := 0

			for i := 0; i < packetsSent; i++ {
				start := time.Now()
				conn, err := net.DialTimeout("tcp", endpoint, 900*time.Millisecond)
				if err == nil {
					packetsReceived++
					totalRTT += time.Since(start).Milliseconds()
					conn.Close()
				}
				time.Sleep(30 * time.Millisecond)
			}

			if packetsReceived == 0 {
				return
			}

			avgLatency := totalRTT / int64(packetsReceived)
			loss := float64(packetsSent-packetsReceived) / float64(packetsSent)

			mu.Lock()
			results = append(results, EndpointResult{
				IP:        host,
				Port:      port,
				Latency:   avgLatency,
				LossRate:  loss,
				SpeedMBps: estimateThroughput(avgLatency, loss),
				Status:    "Available",
			})
			mu.Unlock()
		}(ep)
	}

	wg.Wait()

	// 综合评分排序：延迟权值 0.6 + 丢包惩罚 0.4
	sort.Slice(results, func(i, j int) bool {
		scoreI := float64(results[i].Latency) + (results[i].LossRate * 500)
		scoreJ := float64(results[j].Latency) + (results[j].LossRate * 500)
		return scoreI < scoreJ
	})

	if targetCount > 0 && len(results) > targetCount {
		results = results[:targetCount]
	}

	a.ipMutex.Lock()
	a.bestIPs = results
	a.ipMutex.Unlock()

	return results, nil
}

// ==========================================
// 3. 多协议 (AWG / H2 / H3) 统一配置构建器
// ==========================================

func (a *App) GenerateConfigs(protocol string) (*ConfigOutput, error) {
	a.accountMutex.RLock()
	acc := a.account
	a.accountMutex.RUnlock()

	if acc == nil {
		var err error
		acc, err = a.RegisterWARPAccount("")
		if err != nil {
			return nil, fmt.Errorf("自动生成临时 WARP 身份失败: %w", err)
		}
	}

	a.ipMutex.RLock()
	endpoints := make([]EndpointResult, len(a.bestIPs))
	copy(endpoints, a.bestIPs)
	a.ipMutex.RUnlock()

	if len(endpoints) == 0 {
		// 备用默认出站
		endpoints = []EndpointResult{
			{IP: "162.159.192.1", Port: 2408, Latency: 45},
			{IP: "162.159.193.10", Port: 2408, Latency: 50},
			{IP: "188.114.96.220", Port: 2408, Latency: 55},
		}
	}

	normalizedProto := strings.ToLower(strings.TrimSpace(protocol))
	if normalizedProto == "" {
		normalizedProto = "awg"
	}

	clashConf := a.buildClashYaml(acc, endpoints, normalizedProto)
	singBoxConf := a.buildSingBoxJson(acc, endpoints, normalizedProto)
	wgConf := a.buildWireguardConf(acc, endpoints[0], normalizedProto)

	return &ConfigOutput{
		Protocol:    normalizedProto,
		ClashYaml:   clashConf,
		SingBoxJson: singBoxConf,
		WireGuard:   wgConf,
		BestIPCount: len(endpoints),
	}, nil
}

// ==========================================
// 4. Clash (Mihomo) 配置生成逻辑
// ==========================================

func (a *App) buildClashYaml(acc *WarpAccount, eps []EndpointResult, proto string) string {
	var sb strings.Builder

	sb.WriteString("port: 7890\n")
	sb.WriteString("socks-port: 7891\n")
	sb.WriteString("allow-lan: false\n")
	sb.WriteString("mode: rule\n")
	sb.WriteString("log-level: info\n")
	sb.WriteString("ipv6: true\n\n")

	sb.WriteString("dns:\n")
	sb.WriteString("  enable: true\n")
	sb.WriteString("  listen: 0.0.0.0:1053\n")
	sb.WriteString("  enhanced-mode: fake-ip\n")
	sb.WriteString("  fake-ip-range: 198.18.0.1/16\n")
	sb.WriteString("  nameserver:\n")
	sb.WriteString("    - 1.1.1.1\n")
	sb.WriteString("    - 8.8.8.8\n\n")

	sb.WriteString("proxies:\n")
	var proxyNames []string

	for i, ep := range eps {
		name := fmt.Sprintf("WARP-%s-%02d", strings.ToUpper(proto), i+1)
		proxyNames = append(proxyNames, name)

		switch proto {
		case "h2", "h3":
			alpnVal := "h2"
			if proto == "h3" {
				alpnVal = "h3"
			}
			sb.WriteString(fmt.Sprintf("  - name: %s\n", name))
			sb.WriteString("    type: http\n")
			sb.WriteString(fmt.Sprintf("    server: %s\n", ep.IP))
			sb.WriteString("    port: 443\n")
			sb.WriteString("    tls: true\n")
			sb.WriteString("    sni: api.cloudflareclient.com\n")
			sb.WriteString("    skip-cert-verify: true\n")
			sb.WriteString("    alpn:\n")
			sb.WriteString(fmt.Sprintf("      - %s\n", alpnVal))
			sb.WriteString("    headers:\n")
			sb.WriteString(fmt.Sprintf("      CF-Access-Client-Id: %s\n", acc.AccountID))
			sb.WriteString("      User-Agent: okhttp/3.12.1\n")

		default: // "awg" 具备特征魔数混淆
			sb.WriteString(fmt.Sprintf("  - name: %s\n", name))
			sb.WriteString("    type: wireguard\n")
			sb.WriteString(fmt.Sprintf("    server: %s\n", ep.IP))
			sb.WriteString(fmt.Sprintf("    port: %d\n", ep.Port))
			sb.WriteString(fmt.Sprintf("    ip: %s\n", strings.Split(acc.IPv4, "/")[0]))
			if acc.IPv6 != "" {
				sb.WriteString(fmt.Sprintf("    ipv6: %s\n", strings.Split(acc.IPv6, "/")[0]))
			}
			sb.WriteString(fmt.Sprintf("    private-key: %s\n", acc.PrivateKey))
			sb.WriteString("    public-key: bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=\n")
			sb.WriteString(fmt.Sprintf("    reserved: [%d, %d, %d]\n", acc.Reserved[0], acc.Reserved[1], acc.Reserved[2]))
			sb.WriteString("    mtu: 1280\n")
			sb.WriteString("    remote-dns-resolve: true\n")
			sb.WriteString("    amnezia-junk-packet-count: 4\n")
			sb.WriteString("    amnezia-junk-packet-min-size: 40\n")
			sb.WriteString("    amnezia-junk-packet-max-size: 70\n")
			sb.WriteString("    amnezia-init-packet-junk-size: 15\n")
			sb.WriteString("    amnezia-response-packet-junk-size: 15\n")
			sb.WriteString("    amnezia-init-packet-magic-header: 1\n")
			sb.WriteString("    amnezia-response-packet-magic-header: 2\n")
			sb.WriteString("    amnezia-underload-packet-magic-header: 3\n")
			sb.WriteString("    amnezia-transport-packet-magic-header: 4\n")
		}
	}

	// 注入固定 AI 落地节点
	aiNodeName := "WARP-AI-Dedicated"
	sb.WriteString(fmt.Sprintf("  - name: %s\n", aiNodeName))
	sb.WriteString("    type: wireguard\n")
	sb.WriteString("    server: 162.159.192.1\n")
	sb.WriteString("    port: 2408\n")
	sb.WriteString(fmt.Sprintf("    ip: %s\n", strings.Split(acc.IPv4, "/")[0]))
	if acc.IPv6 != "" {
		sb.WriteString(fmt.Sprintf("    ipv6: %s\n", strings.Split(acc.IPv6, "/")[0]))
	}
	sb.WriteString(fmt.Sprintf("    private-key: %s\n", acc.PrivateKey))
	sb.WriteString("    public-key: bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=\n")
	sb.WriteString(fmt.Sprintf("    reserved: [%d, %d, %d]\n", acc.Reserved[0], acc.Reserved[1], acc.Reserved[2]))
	sb.WriteString("    mtu: 1280\n")
	sb.WriteString("    remote-dns-resolve: true\n\n")

	sb.WriteString("proxy-groups:\n")
	sb.WriteString("  - name: PROXY\n")
	sb.WriteString("    type: select\n")
	sb.WriteString("    proxies:\n")
	sb.WriteString("      - Auto-Best\n")
	for _, name := range proxyNames {
		sb.WriteString(fmt.Sprintf("      - %s\n", name))
	}

	sb.WriteString("  - name: Auto-Best\n")
	sb.WriteString("    type: url-test\n")
	sb.WriteString("    url: http://www.gstatic.com/generate_204\n")
	sb.WriteString("    interval: 180\n")
	sb.WriteString("    tolerance: 50\n")
	sb.WriteString("    proxies:\n")
	for _, name := range proxyNames {
		sb.WriteString(fmt.Sprintf("      - %s\n", name))
	}

	sb.WriteString("  - name: AI-Suite\n")
	sb.WriteString("    type: select\n")
	sb.WriteString("    proxies:\n")
	sb.WriteString(fmt.Sprintf("      - %s\n", aiNodeName))
	sb.WriteString("      - Auto-Best\n")

	sb.WriteString("\nrules:\n")
	sb.WriteString("  - DOMAIN-SUFFIX,openai.com,AI-Suite\n")
	sb.WriteString("  - DOMAIN-SUFFIX,chatgpt.com,AI-Suite\n")
	sb.WriteString("  - DOMAIN-SUFFIX,oaistatic.com,AI-Suite\n")
	sb.WriteString("  - DOMAIN-SUFFIX,oaiusercontent.com,AI-Suite\n")
	sb.WriteString("  - DOMAIN-SUFFIX,anthropic.com,AI-Suite\n")
	sb.WriteString("  - DOMAIN-SUFFIX,claude.ai,AI-Suite\n")
	sb.WriteString("  - DOMAIN-KEYWORD,gemini,AI-Suite\n")
	sb.WriteString("  - DOMAIN-SUFFIX,generativelanguage.googleapis.com,AI-Suite\n")
	sb.WriteString("  - DOMAIN-SUFFIX,ai.google.dev,AI-Suite\n")
	sb.WriteString("  - GEOIP,CN,DIRECT\n")
	sb.WriteString("  - MATCH,PROXY\n")

	return sb.String()
}

// =========================================================================
// 5. Sing-box 双层 WARP-on-WARP 极致性能架构生成器 (Detour 级联链式代理)
// =========================================================================

func (a *App) buildSingBoxJson(acc *WarpAccount, eps []EndpointResult, proto string) string {
	type SingBoxConfig struct {
		Log       interface{}   `json:"log"`
		DNS       interface{}   `json:"dns"`
		Inbounds  []interface{} `json:"inbounds"`
		Outbounds []interface{} `json:"outbounds"`
		Route     interface{}   `json:"route"`
	}

	logSection := map[string]interface{}{
		"level":     "info",
		"timestamp": true,
	}

	dnsSection := map[string]interface{}{
		"servers": []map[string]interface{}{
			{"tag": "dns-remote", "address": "tls://1.1.1.1", "address_resolver": "dns-local"},
			{"tag": "dns-local", "address": "223.5.5.5", "detour": "direct"},
		},
		"rules": []map[string]interface{}{
			{"geosite": []string{"cn"}, "server": "dns-local"},
			{"clash_mode": "Direct", "server": "dns-local"},
		},
		"strategy": "prefer_ipv4",
	}

	inbounds := []interface{}{
		map[string]interface{}{
			"type":                       "mixed",
			"tag":                        "mixed-in",
			"listen":                     "127.0.0.1",
			"listen_port":                2080,
			"sniff":                      true,
			"set_system_proxy":           false,
		},
	}

	var (
		outbounds        []interface{}
		outerOutboundTags []string
	)

	// 构建第一层：外层突破封锁的 10 个优选节点
	for i, ep := range eps {
		tag := fmt.Sprintf("outer-%s-%02d", strings.ToLower(proto), i+1)
		outerOutboundTags = append(outerOutboundTags, tag)

		switch proto {
		case "h2", "h3":
			alpn := []string{"h2"}
			if proto == "h3" {
				alpn = []string{"h3"}
			}
			outbounds = append(outbounds, map[string]interface{}{
				"type":        "http",
				"tag":         tag,
				"server":      ep.IP,
				"server_port": 443,
				"tls": map[string]interface{}{
					"enabled":     true,
					"server_name": "api.cloudflareclient.com",
					"alpn":        alpn,
					"insecure":    true,
				},
				"headers": map[string]string{
					"CF-Access-Client-Id": acc.AccountID,
					"User-Agent":          "okhttp/3.12.1",
				},
			})

		default: // "awg" 模式
			outbounds = append(outbounds, map[string]interface{}{
				"type":        "wireguard",
				"tag":         tag,
				"server":      ep.IP,
				"server_port": ep.Port,
				"local_address": []string{
					fmt.Sprintf("%s/32", strings.Split(acc.IPv4, "/")[0]),
					fmt.Sprintf("%s/128", strings.Split(acc.IPv6, "/")[0]),
				},
				"private_key":     acc.PrivateKey,
				"peer_public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
				"reserved":        []int{acc.Reserved[0], acc.Reserved[1], acc.Reserved[2]},
				"mtu":             1280,
				"amneziawg": map[string]interface{}{
					"jc":   4,
					"jmin": 40,
					"jmax": 70,
					"s1":   15,
					"s2":   15,
					"h1":   1,
					"h2":   2,
					"h3":   3,
					"h4":   4,
				},
			})
		}
	}

	// 外层自动测速选择组 (urltest)
	outbounds = append(outbounds, map[string]interface{}{
		"type":      "urltest",
		"tag":       "outer-auto",
		"outbounds": outerOutboundTags,
		"url":       "https://www.gstatic.com/generate_204",
		"interval":  "3m",
		"tolerance": 50,
	})

	// 第二层：内层 WARP-on-WARP 固定落地节点 (核心 Detour 级联至 outer-auto)
	outbounds = append(outbounds, map[string]interface{}{
		"type":        "wireguard",
		"tag":         "warp-ai-inner",
		"detour":      "outer-auto", // 核心！内层流量全部通过最快直连节点转发
		"server":      "162.159.192.1",
		"server_port": 2408,
		"local_address": []string{
			fmt.Sprintf("%s/32", strings.Split(acc.IPv4, "/")[0]),
			fmt.Sprintf("%s/128", strings.Split(acc.IPv6, "/")[0]),
		},
		"private_key":     acc.PrivateKey,
		"peer_public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
		"reserved":        []int{acc.Reserved[0], acc.Reserved[1], acc.Reserved[2]},
		"mtu":             1280,
	})

	// 专用分流选择组
	outbounds = append(outbounds, map[string]interface{}{
		"type":      "selector",
		"tag":       "AI-Suite",
		"outbounds": []string{"warp-ai-inner", "outer-auto", "direct"},
	})

	allSelectors := append([]string{"outer-auto", "warp-ai-inner"}, outerOutboundTags...)
	outbounds = append(outbounds, map[string]interface{}{
		"type":      "selector",
		"tag":       "GLOBAL-PROXY",
		"outbounds": allSelectors,
	})

	// 基础直连与阻断
	outbounds = append(outbounds,
		map[string]interface{}{"type": "direct", "tag": "direct"},
		map[string]interface{}{"type": "block", "tag": "block"},
		map[string]interface{}{"type": "dns", "tag": "dns-out"},
	)

	// 路由分流规则 (保证 OpenAI / Claude / Gemini 直抵内层 WARP 隧道)
	routeSection := map[string]interface{}{
		"auto_detect_interface": true,
		"rules": []map[string]interface{}{
			{"protocol": "dns", "outbound": "dns-out"},
			{"clash_mode": "Direct", "outbound": "direct"},
			{"clash_mode": "Global", "outbound": "GLOBAL-PROXY"},
			{
				"domain_suffix": []string{
					"openai.com",
					"chatgpt.com",
					"oaistatic.com",
					"oaiusercontent.com",
					"anthropic.com",
					"claude.ai",
					"ai.google.dev",
					"generativelanguage.googleapis.com",
					"gemini.google.com",
					"bard.google.com",
				},
				"outbound": "AI-Suite",
			},
			{
				"domain_keyword": []string{
					"openai",
					"chatgpt",
					"anthropic",
					"claude",
					"gemini",
				},
				"outbound": "AI-Suite",
			},
			{"ip_is_private": true, "outbound": "direct"},
			{"geosite": []string{"cn"}, "outbound": "direct"},
			{"geoip": []string{"cn"}, "outbound": "direct"},
			{"outbound": "GLOBAL-PROXY"},
		},
	}

	fullConfig := SingBoxConfig{
		Log:       logSection,
		DNS:       dnsSection,
		Inbounds:  inbounds,
		Outbounds: outbounds,
		Route:     routeSection,
	}

	bytes, _ := json.MarshalIndent(fullConfig, "", "  ")
	return string(bytes)
}

// ==========================================
// 6. AmneziaWG 客户端配置文件导出
// ==========================================

func (a *App) buildWireguardConf(acc *WarpAccount, best EndpointResult, proto string) string {
	var sb strings.Builder

	sb.WriteString("[Interface]\n")
	sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", acc.PrivateKey))
	sb.WriteString(fmt.Sprintf("Address = %s, %s\n", acc.IPv4, acc.IPv6))
	sb.WriteString("DNS = 1.1.1.1, 2606:4700:4700::1111\n")
	sb.WriteString("MTU = 1280\n")

	if proto == "awg" {
		sb.WriteString("Jc = 4\n")
		sb.WriteString("Jmin = 40\n")
		sb.WriteString("Jmax = 70\n")
		sb.WriteString("S1 = 15\n")
		sb.WriteString("S2 = 15\n")
		sb.WriteString("H1 = 1\n")
		sb.WriteString("H2 = 2\n")
		sb.WriteString("H3 = 3\n")
		sb.WriteString("H4 = 4\n")
	}

	sb.WriteString("\n[Peer]\n")
	sb.WriteString("PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=\n")
	sb.WriteString("AllowedIPs = 0.0.0.0/0, ::/0\n")
	sb.WriteString(fmt.Sprintf("Endpoint = %s:%d\n", best.IP, best.Port))
	sb.WriteString("PersistentKeepalive = 25\n")

	return sb.String()
}

// ==========================================
// 辅助计算与默认候选节点
// ==========================================

func randInt64() int64 {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return int64(b[0]) | int64(b[1])<<8 | int64(b[2])<<16 | int64(b[3])<<24 |
		int64(b[4])<<32 | int64(b[5])<<40 | int64(b[6])<<48 | int64(b[7])<<56
}

func estimateThroughput(latency int64, loss float64) float64 {
	if latency <= 0 {
		latency = 1
	}
	// Mathis 吞吐估算模型近似算子
	lossFactor := loss
	if lossFactor < 0.001 {
		lossFactor = 0.001
	}
	rttSec := float64(latency) / 1000.0
	mbps := (1460.0 * 8.0) / (rttSec * 1024.0 * 1024.0 * (lossFactor * 10))
	if mbps > 300.0 {
		mbps = 300.0
	}
	if mbps < 1.0 {
		mbps = 1.0
	}
	return mbps
}

func defaultWARPEndpoints() []string {
	return []string{
		"162.159.192.1:2408",
		"162.159.192.2:2408",
		"162.159.192.3:2408",
		"162.159.192.4:2408",
		"162.159.192.5:2408",
		"162.159.192.6:2408",
		"162.159.192.7:2408",
		"162.159.192.8:2408",
		"162.159.192.9:2408",
		"162.159.192.10:2408",
		"162.159.193.1:2408",
		"162.159.193.2:2408",
		"162.159.193.3:2408",
		"162.159.193.4:2408",
		"162.159.193.5:2408",
		"162.159.195.1:2408",
		"162.159.195.2:2408",
		"188.114.96.220:2408",
		"188.114.97.220:2408",
		"188.114.98.220:2408",
		"188.114.99.220:2408",
	}
}

// 供前端直接调用的系统剪贴板支持
func (a *App) CopyToClipboard(text string) error {
	return runtime.ClipboardSetText(a.ctx, text)
}
