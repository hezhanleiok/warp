package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
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
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
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

// 官方主力 IPv4 网段
var cfIPv4Prefixes = []string{
	"162.159.192",
	"162.159.193",
	"162.159.195",
	"188.114.96",
	"188.114.97",
	"188.114.98",
	"188.114.99",
}

// 官方已知 IPv6 Anycast 端点
var cfIPv6OfficialEndpoints = []string{
	"[2606:4700:d0::a29f:c001]",
	"[2606:4700:d0::a29f:c101]",
	"[2606:4700:d1::a29f:c201]",
	"[2606:4700:d1::a29f:c301]",
}

// 扩大测速端口集：包含国内高存活率的 IPsec 与常见 UDP 端口
var scanPorts = []int{500, 4500, 1701, 2408}

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
	PrivKeyBytes  [32]byte
	PubKeyBytes   [32]byte
	PeerPublicKey string
	PeerPubBytes  [32]byte
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

func generateWireguardKeyPair() ([32]byte, [32]byte, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return priv, priv, err
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)
	return priv, pub, nil
}

// 向官方 API 注册真实凭证，动态绑定分配的 PeerPublicKey
func (a *App) RegisterCloudflareAccount(tag string) (*WarpAccount, error) {
	a.sendLog(fmt.Sprintf("向官方 API 申请真实 WARP 身份凭证 [%s]...", tag))
	privBytes, pubBytes, err := generateWireguardKeyPair()
	if err != nil {
		return nil, fmt.Errorf("生成本地密钥对失败: %w", err)
	}

	pubBase64 := base64.StdEncoding.EncodeToString(pubBytes[:])
	privBase64 := base64.StdEncoding.EncodeToString(privBytes[:])

	reqBody, _ := json.Marshal(map[string]interface{}{
		"key":        pubBase64,
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

	var peerPubBytes [32]byte
	decPeer, _ := base64.StdEncoding.DecodeString(assignedPeerKey)
	copy(peerPubBytes[:], decPeer)

	a.sendLog(fmt.Sprintf("✔ 成功签发合法凭证 [%s] ID: %s", tag, reply.ID[:8]+"..."))

	return &WarpAccount{
		PrivateKey:    privBase64,
		PublicKey:     pubBase64,
		PrivKeyBytes:  privBytes,
		PubKeyBytes:   pubBytes,
		PeerPublicKey: assignedPeerKey,
		PeerPubBytes:  peerPubBytes,
		AddressV4:     v4,
		AddressV6:     v6,
		Reserved:      reserved,
	}, nil
}

func hash256(data []byte) [32]byte {
	return blake2s.Sum256(data)
}

func hmacBlake2s256(key []byte, data []byte) []byte {
	h := hmac.New(func() hash.Hash {
		x, _ := blake2s.New256(nil)
		return x
	}, key)
	h.Write(data)
	return h.Sum(nil)
}

func kdf2(ck []byte, ikm []byte) ([]byte, []byte) {
	prk := hmacBlake2s256(ck, ikm)
	t1 := hmacBlake2s256(prk, []byte{0x01})
	t2Input := append(append([]byte(nil), t1...), 0x02)
	t2 := hmacBlake2s256(prk, t2Input)
	return t1, t2
}

// 严格遵循 WireGuard Noise_IK RFC 规范组装探针
func createRealWireGuardHandshake(clientPriv [32]byte, clientPub [32]byte, peerPub [32]byte) ([]byte, uint32, error) {
	hInit := hash256([]byte("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"))
	chainingKey := hInit[:]

	var h [32]byte
	h = hash256(append(hInit[:], []byte("WireGuard v1 zx2c4 Jason@zx2c4.com")...))
	h = hash256(append(h[:], peerPub[:]...))

	ephPriv, ephPub, err := generateWireguardKeyPair()
	if err != nil {
		return nil, 0, err
	}
	h = hash256(append(h[:], ephPub[:]...))

	ss1, err := curve25519.X25519(ephPriv[:], peerPub[:])
	if err != nil {
		return nil, 0, err
	}

	var key1 []byte
	chainingKey, key1 = kdf2(chainingKey, ss1)

	aead1, err := chacha20poly1305.New(key1)
	if err != nil {
		return nil, 0, err
	}
	var nonce1 [12]byte
	encryptedStatic := aead1.Seal(nil, nonce1[:], clientPub[:], h[:])
	h = hash256(append(h[:], encryptedStatic...))

	ss2, err := curve25519.X25519(clientPriv[:], peerPub[:])
	if err != nil {
		return nil, 0, err
	}

	var key2 []byte
	chainingKey, key2 = kdf2(chainingKey, ss2)

	tai64n := make([]byte, 12)
	now := time.Now().UTC()
	secs := uint64(now.Unix()) + 4611686018427387914
	binary.BigEndian.PutUint64(tai64n[0:8], secs)
	binary.BigEndian.PutUint32(tai64n[8:12], uint32(now.Nanosecond()))

	aead2, err := chacha20poly1305.New(key2)
	if err != nil {
		return nil, 0, err
	}
	var nonce2 [12]byte
	encryptedTimestamp := aead2.Seal(nil, nonce2[:], tai64n, h[:])

	var senderIdx uint32
	if err := binary.Read(rand.Reader, binary.LittleEndian, &senderIdx); err != nil || senderIdx == 0 {
		senderIdx = uint32(time.Now().UnixNano())
	}

	msg := make([]byte, 148)
	msg[0] = 1
	binary.LittleEndian.PutUint32(msg[4:8], senderIdx)
	copy(msg[8:40], ephPub[:])
	copy(msg[40:88], encryptedStatic)
	copy(msg[88:116], encryptedTimestamp)

	macKeyRaw := append([]byte("mac1----"), peerPub[:]...)
	macKey := hash256(macKeyRaw)
	mac1H, err := blake2s.New128(macKey[:])
	if err != nil {
		return nil, 0, err
	}
	mac1H.Write(msg[0:116])
	copy(msg[116:132], mac1H.Sum(nil))

	return msg, senderIdx, nil
}

// 单次握手探测：超时放宽至 1200ms，严格匹配 receiverIdx
func probeEndpointUDPOnce(addrStr string, account *WarpAccount, timeout time.Duration) (int64, bool) {
	packet, senderIdx, err := createRealWireGuardHandshake(account.PrivKeyBytes, account.PubKeyBytes, account.PeerPubBytes)
	if err != nil {
		return 0, false
	}

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
	if _, err := conn.Write(packet); err != nil {
		return 0, false
	}

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err == nil && n == 92 && buf[0] == 2 {
		receiverIdx := binary.LittleEndian.Uint32(buf[8:12])
		if receiverIdx == senderIdx {
			rtt := time.Since(start).Milliseconds()
			if rtt == 0 {
				rtt = 1
			}
			return rtt, true
		}
	}

	return 0, false
}

func buildCandidateEndpoints() []string {
	var pool []string

	for _, prefix := range cfIPv4Prefixes {
		for host := 1; host <= 254; host += 6 {
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

// 扫描引擎：500/4500/1701/2408 多端口覆盖，先快筛后精测，耗时平稳在 30~50 秒
func (a *App) RunWarpScoutFullEngine(account *WarpAccount, maxCount int) ([]EndpointResult, error) {
	candidateIPs := buildCandidateEndpoints()

	type task struct {
		ip   string
		port int
	}

	var taskList []task
	// 多端口交叉采样：确保不会因为本地运营商封死 2408 导致全军覆没
	for _, ip := range candidateIPs {
		for _, port := range scanPorts {
			taskList = append(taskList, task{ip, port})
		}
	}

	total := len(taskList)
	a.sendLog(fmt.Sprintf("🚀 载入端点池，跨端口（500/4500/1701/2408）握手测速: %d 个目标 (预计 30~50 秒)...", total))

	taskChan := make(chan task, total)
	resChan := make(chan EndpointResult, total)
	var completed int64
	workerCount := 40

	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range taskChan {
				addrStr := fmt.Sprintf("%s:%d", t.ip, t.port)

				// 首次探测：给足 1200ms 超时空间
				rtt, ok := probeEndpointUDPOnce(addrStr, account, 1200*time.Millisecond)
				curr := atomic.AddInt64(&completed, 1)

				if ok {
					// 响应后再复测一次以消除偶然抖动
					time.Sleep(10 * time.Millisecond)
					rtt2, ok2 := probeEndpointUDPOnce(addrStr, account, 1200*time.Millisecond)
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

				if curr%20 == 0 || int(curr) == total {
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

	a.sendLog(fmt.Sprintf("✔ 探测完成！严格验证回包握手，捕获真实活端点: %d 个", len(validList)))

	if len(validList) == 0 {
		return nil, errors.New("未能探测到任何响应真实 WireGuard 握手的 Cloudflare 节点，请确认当前网络未完全拦截 UDP")
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

	outerAcc, err := a.RegisterCloudflareAccount("外层直连节点")
	if err != nil {
		a.sendLog(fmt.Sprintf("❌ 外层注册失败: %v", err))
		return nil, err
	}

	innerAcc, err := a.RegisterCloudflareAccount("内层AI出口")
	if err != nil {
		a.sendLog(fmt.Sprintf("❌ 内层注册失败: %v", err))
		return nil, err
	}

	endpoints, err := a.RunWarpScoutFullEngine(outerAcc, count)
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
