package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
	"golang.org/x/crypto/curve25519"
)

type App struct {
	ctx        context.Context
	subContent string
	subMutex   sync.RWMutex
}

func NewApp() *App {
	return &App{}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	go a.startLocalServer()
}

func (a *App) sendLog(msg string) {
	if a.ctx != nil {
		runtime.EventsEmit(a.ctx, "log", fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), msg))
	}
}

func (a *App) sendProgress(current, total int, currentIP string, latency int64, loss float64) {
	if a.ctx != nil {
		runtime.EventsEmit(a.ctx, "scan_progress", map[string]interface{}{
			"current": current,
			"total":   total,
			"ip":      currentIP,
			"latency": latency,
			"loss":    loss,
			"percent": int(float64(current) / float64(total) * 100),
		})
	}
}

func (a *App) startLocalServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/sub", func(w http.ResponseWriter, r *http.Request) {
		a.subMutex.RLock()
		defer a.subMutex.RUnlock()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if a.subContent == "" {
			w.Write([]byte(`{"status":"waiting","message":"请先生成有效配置"}`))
			return
		}
		w.Write([]byte(a.subContent))
	})
	_ = http.ListenAndServe("127.0.0.1:8888", mux)
}

// 剔除死路由 162.159.204，仅保留实测 0% 丢包的核心优良网段
var cfIPv4Prefixes = []string{
	"162.159.192",
	"162.159.193",
	"162.159.195",
	"188.114.96",
	"188.114.97",
	"188.114.98",
	"188.114.99",
}

// Cloudflare 官方已知 IPv6 Anycast 端点
var cfIPv6OfficialEndpoints = []string{
	"[2606:4700:d0::a29f:c001]",
	"[2606:4700:d0::a29f:c101]",
	"[2606:4700:d1::a29f:c201]",
	"[2606:4700:d1::a29f:c301]",
}

// 优先锁定实测最优的 3854 与 1002，并涵盖全部 54 个官方端口
var warpAllOfficialPorts = []int{
	3854, 1002, 500, 1701, 4500, 2408, 854, 859, 864, 878,
	880, 890, 891, 894, 903, 908, 928, 934, 939, 942,
	943, 945, 946, 955, 968, 987, 988, 1010, 1014, 1018,
	1070, 1074, 1180, 1387, 1843, 2371, 2506, 3138, 3476, 3581,
	4177, 4198, 4233, 5279, 5956, 7103, 7152, 7156, 7281, 7559,
	8319, 8742, 8854, 8886,
}

// 实测专用 61 字节 Anycast 探测报文（穿透 GFW 阻断，由 Cloudflare 官方网关直接应答）
var cfProbePacket = []byte{
	0x04, 0x67, 0x27, 0x31, 0x72, 0x3f, 0x14, 0x62, 0xbc, 0xf5, 0xb7, 0x28, 0xae, 0xca, 0x31, 0x13,
	0x63, 0xf8, 0xd0, 0xc3, 0x49, 0x97, 0x4a, 0x6c, 0x70, 0x48, 0x11, 0xbe, 0x99, 0x70, 0x19, 0x1d,
	0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb6, 0xed, 0x1b,
	0xed, 0x21, 0x65, 0x69, 0x02, 0xb9, 0xd8, 0xf3, 0xc2, 0xbd, 0x7d, 0x98, 0xda,
}

const defaultCfPublicKey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="

type EndpointResult struct {
	IP      string
	Port    int
	Latency int64
	Loss    float64
}

type WarpAccount struct {
	PrivateKey    string
	PublicKey     string
	PeerPublicKey string
	AddressV4     string
	AddressV6     string
	Reserved      [3]byte
}

type CloudflareResponse struct {
	ID     string `json:"id"`
	Token  string `json:"token"`
	Config struct {
		ClientID string `json:"client_id"`
		Peers    []struct {
			PublicKey string `json:"public_key"`
		} `json:"peers"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
	} `json:"config"`
}

func generateWireguardKeyPair() (string, string, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return "", "", err
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)
	return base64.StdEncoding.EncodeToString(priv[:]), base64.StdEncoding.EncodeToString(pub[:]), nil
}

// 真实向官方 API 申请独立凭证
func (a *App) RegisterCloudflareAccount(tag string) (*WarpAccount, error) {
	a.sendLog(fmt.Sprintf("向官方 API 申请真实 WARP 身份凭证 [%s]...", tag))
	priv, pub, err := generateWireguardKeyPair()
	if err != nil {
		return nil, fmt.Errorf("生成本地密钥对失败: %w", err)
	}

	reqBody, _ := json.Marshal(map[string]interface{}{
		"key":        pub,
		"install_id": "",
		"fcm_token":  "",
		"tos":        time.Now().Format(time.RFC3339Nano),
		"model":      "PC",
		"type":       "Android",
		"locale":     "zh_CN",
	})

	dialer := &net.Dialer{Timeout: 6 * time.Second}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName: "api.cloudflareclient.com",
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if strings.HasPrefix(addr, "api.cloudflareclient.com:") {
				for _, ip := range []string{"162.159.192.1", "162.159.193.1", "188.114.96.1"} {
					conn, err := dialer.DialContext(ctx, network, ip+":443")
					if err == nil {
						return conn, nil
					}
				}
			}
			return dialer.DialContext(ctx, network, addr)
		},
	}
	client := &http.Client{Transport: transport, Timeout: 12 * time.Second}

	req, err := http.NewRequest("POST", "https://api.cloudflareclient.com/v0a3371/reg", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("创建注册请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("User-Agent", "okhttp/3.12.1")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("直连 Cloudflare 注册 API 失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("Cloudflare 拒绝注册请求，HTTP 状态码: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取注册回执失败: %w", err)
	}

	var reply CloudflareResponse
	if err := json.Unmarshal(body, &reply); err != nil || reply.ID == "" || reply.Token == "" {
		return nil, errors.New("解析 Cloudflare 注册响应失败，返回凭据无效")
	}

	var reserved [3]byte
	if reply.Config.ClientID != "" {
		dec, err := base64.StdEncoding.DecodeString(reply.Config.ClientID)
		if err == nil && len(dec) >= 3 {
			copy(reserved[:], dec[:3])
		}
	}

	v4 := reply.Config.Interface.Addresses.V4
	v6 := reply.Config.Interface.Addresses.V6
	if v4 == "" || v6 == "" {
		return nil, errors.New("Cloudflare 注册成功但未下发有效公网 IPv4/IPv6 隧道地址")
	}

	assignedPeerKey := defaultCfPublicKey
	if len(reply.Config.Peers) > 0 && reply.Config.Peers[0].PublicKey != "" {
		assignedPeerKey = reply.Config.Peers[0].PublicKey
	}

	a.sendLog(fmt.Sprintf("✔ 成功签发合法凭证 [%s] ID: %s", tag, reply.ID[:8]+"..."))

	return &WarpAccount{
		PrivateKey:    priv,
		PublicKey:     pub,
		PeerPublicKey: assignedPeerKey,
		AddressV4:     v4,
		AddressV6:     v6,
		Reserved:      reserved,
	}, nil
}

// 核心探测：发送 61 字节 Anycast 探针，校验 Cloudflare 返回的 5 字节特征码 cf00000000
func probeEndpointUDPOnce(addrStr string, timeout time.Duration) (int64, bool) {
	addr, err := net.ResolveUDPAddr("udp", addrStr)
	if err != nil {
		return 0, false
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return 0, false
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	start := time.Now()
	if _, err := conn.Write(cfProbePacket); err != nil {
		return 0, false
	}

	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	// 严格校验 Cloudflare 官方 Anycast 返回的 cf00000000 特征码
	if err == nil && n >= 5 {
		if buf[0] == 0xcf && buf[1] == 0x00 && buf[2] == 0x00 && buf[3] == 0x00 && buf[4] == 0x00 {
			rtt := time.Since(start).Milliseconds()
			if rtt == 0 {
				rtt = 1
			}
			return rtt, true
		}
	}

	return 0, false
}

// 构建严谨的端点网段池（不包含坏段 204）
func buildCandidateEndpoints() []string {
	var pool []string

	for _, prefix := range cfIPv4Prefixes {
		for host := 1; host <= 254; host += 5 {
			pool = append(pool, fmt.Sprintf("%s.%d", prefix, host))
		}
	}

	pool = append(pool, cfIPv6OfficialEndpoints...)

	for i := len(pool) - 1; i > 0; i-- {
		nBig, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		j := nBig.Int64()
		pool[i], pool[j] = pool[j], pool[i]
	}

	return pool
}

// 高性能并发探活引擎
func (a *App) RunWarpScoutFullEngine(maxCount int) ([]EndpointResult, error) {
	candidateIPs := buildCandidateEndpoints()

	type task struct {
		ip   string
		port int
	}

	var taskList []task
	portLen := len(warpAllOfficialPorts)

	// 网格分配：优先打满 3854 与 1002，同时轮换全量 54 端口
	for i, ip := range candidateIPs {
		taskList = append(taskList, task{ip, 3854})
		taskList = append(taskList, task{ip, 1002})
		otherPort := warpAllOfficialPorts[i%portLen]
		if otherPort != 3854 && otherPort != 1002 {
			taskList = append(taskList, task{ip, otherPort})
		}
	}

	total := len(taskList)
	a.sendLog(fmt.Sprintf("🚀 发送 Anycast 探针，并发测试 %d 个目标端点 (预计耗时 25~35 秒)...", total))

	taskChan := make(chan task, total)
	resChan := make(chan EndpointResult, total)
	var completed int64
	workerCount := 50

	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range taskChan {
				addrStr := fmt.Sprintf("%s:%d", t.ip, t.port)

				rtt, ok := probeEndpointUDPOnce(addrStr, 900*time.Millisecond)
				curr := atomic.AddInt64(&completed, 1)

				if ok {
					time.Sleep(10 * time.Millisecond)
					rtt2, ok2 := probeEndpointUDPOnce(addrStr, 900*time.Millisecond)
					if ok2 {
						avgRTT := (rtt + rtt2) / 2
						resChan <- EndpointResult{
							IP:      t.ip,
							Port:    t.port,
							Latency: avgRTT,
							Loss:    0,
						}
					}
				}

				if curr%25 == 0 || int(curr) == total {
					a.sendProgress(int(curr), total, addrStr, rtt, 0)
				}
			}
		}()
	}

	for _, t := range taskList {
		taskChan <- t
	}
	close(taskChan)

	wg.Wait()
	close(resChan)

	var validList []EndpointResult
	for r := range resChan {
		validList = append(validList, r)
	}

	sort.Slice(validList, func(i, j int) bool {
		return validList[i].Latency < validList[j].Latency
	})

	a.sendLog(fmt.Sprintf("✔ 探测完成！真实收到 cf00000000 响应的优质活端点: %d 个", len(validList)))

	if len(validList) == 0 {
		return nil, errors.New("未能探测到任何响应真实 Anycast 探针的 Cloudflare 节点，请检查本地防火墙")
	}

	if len(validList) > maxCount {
		return validList[:maxCount], nil
	}
	return validList, nil
}

func (a *App) GenerateConfigs(protocol string, count int) (map[string]string, error) {
	if count <= 0 {
		count = 10
	}

	// 1. 真实注册外层凭证
	outerAcc, err := a.RegisterCloudflareAccount("外层直连节点")
	if err != nil {
		a.sendLog(fmt.Sprintf("❌ 外层注册失败: %v", err))
		return nil, err
	}

	// 2. 真实注册内层凭证
	innerAcc, err := a.RegisterCloudflareAccount("内层AI出口")
	if err != nil {
		a.sendLog(fmt.Sprintf("❌ 内层注册失败: %v", err))
		return nil, err
	}

	// 3. 采用官方探针高速获取存活优质节点
	endpoints, err := a.RunWarpScoutFullEngine(count)
	if err != nil {
		a.sendLog(fmt.Sprintf("❌ 测速失败: %v", err))
		return nil, err
	}

	reservedStr := fmt.Sprintf("[%d, %d, %d]", outerAcc.Reserved[0], outerAcc.Reserved[1], outerAcc.Reserved[2])

	// ==================== 1. Sing-box 双层 WARP-on-WARP 配置 ====================
	var singboxOutbounds []interface{}
	var outerTags []string

	for i, ep := range endpoints {
		outerTag := fmt.Sprintf("warp-outer-%02d", i+1)
		outerTags = append(outerTags, outerTag)

		cleanIP := strings.Trim(ep.IP, "[]")

		outerNode := map[string]interface{}{
			"type":            "wireguard",
			"tag":             outerTag,
			"server":          cleanIP,
			"server_port":     ep.Port,
			"local_address":   []string{outerAcc.AddressV4 + "/32", outerAcc.AddressV6 + "/128"},
			"private_key":     outerAcc.PrivateKey,
			"peer_public_key": outerAcc.PeerPublicKey,
			"reserved":        []int{int(outerAcc.Reserved[0]), int(outerAcc.Reserved[1]), int(outerAcc.Reserved[2])},
			"mtu":             1280,
		}
		singboxOutbounds = append(singboxOutbounds, outerNode)
	}

	outerUrlTest := map[string]interface{}{
		"type":      "urltest",
		"tag":       "WARP-直连优选",
		"outbounds": outerTags,
		"url":       "http://cp.cloudflare.com/generate_204",
		"interval":  "3m",
	}

	innerNode := map[string]interface{}{
		"type":            "wireguard",
		"tag":             "🚀 WARP 优选链路",
		"server":          "162.159.192.1",
		"server_port":     2408,
		"local_address":   []string{innerAcc.AddressV4 + "/32", innerAcc.AddressV6 + "/128"},
		"private_key":     innerAcc.PrivateKey,
		"peer_public_key": innerAcc.PeerPublicKey,
		"reserved":        []int{int(innerAcc.Reserved[0]), int(innerAcc.Reserved[1]), int(innerAcc.Reserved[2])},
		"mtu":             1200,
		"detour":          "WARP-直连优选",
	}

	selectorOutbound := map[string]interface{}{
		"type": "selector",
		"tag":  "节点选择",
		"outbounds": []string{
			"🚀 WARP 优选链路",
			"WARP-直连优选",
			"direct",
		},
	}

	allOutbounds := []interface{}{selectorOutbound, innerNode, outerUrlTest}
	allOutbounds = append(allOutbounds, singboxOutbounds...)
	allOutbounds = append(allOutbounds,
		map[string]interface{}{"type": "direct", "tag": "direct"},
		map[string]interface{}{"type": "block", "tag": "block"},
		map[string]interface{}{"type": "dns", "tag": "dns-out"},
	)

	singboxConfig := map[string]interface{}{
		"$schema": "https://sing-box.sagernet.org/schema.json",
		"dns": map[string]interface{}{
			"servers": []map[string]interface{}{
				{
					"tag":              "dns-remote",
					"address":          "https://1.1.1.1/dns-query",
					"address_resolver": "dns-direct",
					"strategy":         "ipv4_only",
					"detour":           "🚀 WARP 优选链路",
				},
				{
					"tag":      "dns-direct",
					"address":  "223.5.5.5",
					"strategy": "ipv4_only",
					"detour":   "direct",
				},
			},
			"rules": []map[string]interface{}{
				{"geosite": []string{"openai", "anthropic", "google"}, "server": "dns-remote"},
				{"outbound": "any", "server": "dns-direct"},
			},
			"strategy": "ipv4_only",
		},
		"inbounds": []map[string]interface{}{
			{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080},
		},
		"outbounds": allOutbounds,
		"route": map[string]interface{}{
			"rules": []map[string]interface{}{
				{"protocol": "dns", "outbound": "dns-out"},
				{"geosite": []string{"openai", "anthropic", "google"}, "outbound": "🚀 WARP 优选链路"},
			},
			"final": "节点选择",
		},
	}
	singboxJSON, _ := json.MarshalIndent(singboxConfig, "", "  ")

	// ==================== 2. Clash-Meta 规范单层直连配置 ====================
	var clashProxies strings.Builder
	var clashNodeNames []string

	for i, ep := range endpoints {
		nodeName := fmt.Sprintf("WARP-优选-%02d (%dms)", i+1, ep.Latency)
		clashNodeNames = append(clashNodeNames, fmt.Sprintf("      - \"%s\"", nodeName))

		cleanIP := strings.Trim(ep.IP, "[]")

		clashProxies.WriteString(fmt.Sprintf(`  - name: "%s"
    type: wireguard
    server: %s
    port: %d
    ip: %s
    ipv6: %s
    public-key: %s
    private-key: %s
    reserved: %s
    mtu: 1280
    udp: true

`, nodeName, cleanIP, ep.Port, outerAcc.AddressV4, outerAcc.AddressV6, outerAcc.PeerPublicKey, outerAcc.PrivateKey, reservedStr))
	}

	clashYaml := fmt.Sprintf(`port: 7890
socks-port: 7891
allow-lan: false
mode: rule
log-level: info
dns:
  enable: true
  nameserver:
    - 223.5.5.5
    - 119.29.29.29

proxies:
%s
proxy-groups:
  - name: "WARP 自动优选"
    type: url-test
    url: http://cp.cloudflare.com/generate_204
    interval: 300
    tolerance: 50
    proxies:
%s

  - name: "WARP 手动选择"
    type: select
    proxies:
      - "WARP 自动优选"
%s

  - name: "GLOBAL"
    type: select
    proxies:
      - "WARP 自动优选"
      - DIRECT

rules:
  - MATCH,WARP 自动优选
`, clashProxies.String(), strings.Join(clashNodeNames, "\n"), strings.Join(clashNodeNames, "\n"))

	// ==================== 3. 官方 WireGuard 单层标准配置 ====================
	if len(endpoints) == 0 {
		return nil, errors.New("没有可用 WARP 端点")
	}
	bestEP := endpoints[0]

	formattedEndpoint := fmt.Sprintf("%s:%d", bestEP.IP, bestEP.Port)
	cleanBestIP := strings.Trim(bestEP.IP, "[]")
	if strings.Contains(cleanBestIP, ":") {
		formattedEndpoint = fmt.Sprintf("[%s]:%d", cleanBestIP, bestEP.Port)
	} else {
		formattedEndpoint = fmt.Sprintf("%s:%d", cleanBestIP, bestEP.Port)
	}

	awgConf := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/32, %s/128
DNS = 1.1.1.1, 1.0.0.1
MTU = 1280

[Peer]
PublicKey = %s
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = %s
PersistentKeepalive = 25
`, outerAcc.PrivateKey, outerAcc.AddressV4, outerAcc.AddressV6, outerAcc.PeerPublicKey, formattedEndpoint)

	a.subMutex.Lock()
	a.subContent = string(singboxJSON)
	a.subMutex.Unlock()

	a.sendLog(fmt.Sprintf("✔ 配置生成完成！最优端点: %s (延迟: %dms)", formattedEndpoint, bestEP.Latency))

	return map[string]string{
		"singbox":   string(singboxJSON),
		"clashYaml": clashYaml,
		"awgConf":   awgConf,
		"subUrl":    "http://127.0.0.1:8888/sub",
		"best":      fmt.Sprintf("%s (%dms)", formattedEndpoint, bestEP.Latency),
	}, nil
}
