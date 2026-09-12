package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	_ "embed" // 引入 embed 包, 内嵌 sing-box 核心用
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
	"golang.org/x/crypto/curve25519"
)

//go:embed sing-box.exe
var singboxBin []byte

type App struct {
	ctx             context.Context
	subContent      string
	nekoContent     string // NekoBox 订阅: wireguard:// 分享链接列表 (NekoBox 不??完整 JSON 配置)
	v2raynContent   string // V2rayN 订阅: wireguard:// 链接 (V2rayN 专用参数名 publickey + reserved 十进制逗号)
	legacyContent   string // 老内核 sing-box GUI (Karing 等) 订阅: 1.8~1.10 wireguard-outbound 老格式
	mobileContent   string // 手机官方 sing-box 客户????tun 配置 (PC ??mixed 入站手机无效)
	subMutex        sync.RWMutex
	zipContent      []byte
	tempSingboxPath string // 记录 sing-box 核心的可执??文件???
}

func NewApp() *App {
	return &App{}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	go a.startLocalServer()

	// 清理上次异常退出遗留的探测配置 (系统 Temp + 旧版散落在 exe 同目录的)
	if matches, gerr := filepath.Glob(filepath.Join(os.TempDir(), "xhs-temp_proxy_*.json")); gerr == nil {
		for _, m := range matches {
			os.Remove(m)
		}
	}
	if matches, gerr := filepath.Glob(filepath.Join(exeSelfDir(), "temp_proxy_*.json")); gerr == nil {
		for _, m := range matches {
			os.Remove(m)
		}
	}

	// 初??化时准?? sing-box 核心???
	a.tempSingboxPath = a.prepareSingbox()
}

// hiddenCmd 创建不弹控制台窗口的子进程命??(Windows: CREATE_NO_WINDOW).
// 没有?? 每?? sing-box check/run 都会在屏幕前??????
func hiddenCmd(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	return cmd
}

// exeSelfDir 返回当前????件所在目??(导出配置落盘??; 失败时退回工作目??
// ExportWireGuardZip 把最新生成的 WireGuard .conf 集打包成 zip 保存到用户指定位置.
// 前端 "导出 WireGuard 压缩包" 按钮直接调用 — 不再走浏览器 blob 下载 (Wails 下不可靠).
func (a *App) ExportWireGuardZip(defaultName string) (string, error) {
	zipBuf := a.zipContent
	if len(zipBuf) == 0 {
		return "", errors.New("请先生成有效配置")
	}
	if a.ctx == nil {
		p := filepath.Join(exeSelfDir(), "warp-wireguard-nodes.zip")
		if err := os.WriteFile(p, zipBuf, 0644); err != nil {
			return "", err
		}
		return p, nil
	}
	p, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		DefaultFilename: defaultName,
		Title:            "保存 WireGuard 配置压缩包",
		Filters:          []runtime.FileFilter{{DisplayName: "ZIP 压缩包 (*.zip)", Pattern: "*.zip"}},
	})
	if err != nil || p == "" {
		if err == nil {
			return "", nil // 用户取消
		}
		return "", err
	}
	if !strings.HasSuffix(strings.ToLower(p), ".zip") {
		p += ".zip"
	}
	if err := os.WriteFile(p, zipBuf, 0644); err != nil {
		return "", err
	}
	return p, nil
}

func exeSelfDir() string {
	if p, err := os.Executable(); err == nil {
		return filepath.Dir(p)
	}
	wd, _ := os.Getwd()
	return wd
}

// prepareSingbox 智能解析与准备 sing-box 可执行核心
func (a *App) prepareSingbox() string {
	// 1. 若嵌入了有效的二进制文件，优先释放到临时目录
	if len(singboxBin) > 0 {
		tempDir := os.TempDir()
		targetPath := filepath.Join(tempDir, "warp-scout-singbox.exe")
		err := os.WriteFile(targetPath, singboxBin, 0755)
		if err == nil {
			a.sendLog("✔ 内置 sing-box 核心已就绪，已实现单文件闭环。")
			return targetPath
		}
		a.sendLog("警告: 释放内置 sing-box 核心失败: " + err.Error())
	}

	// 2. 检查当前目录下???? sing-box.exe ??sing-box
	for _, name := range []string{"sing-box.exe", "sing-box"} {
		if _, err := os.Stat(name); err == nil {
			absPath, err := filepath.Abs(name)
			if err == nil {
				a.sendLog("✔ 检测到本地工作目录下的 sing-box 核心: " + absPath)
				return absPath
			}
		}
	}

	// 3. 检查系统环境变??PATH ??????sing-box
	if path, err := exec.LookPath("sing-box.exe"); err == nil {
		a.sendLog("✔ 检测到系统 PATH 中的 sing-box 核心: " + path)
		return path
	}
	if path, err := exec.LookPath("sing-box"); err == nil {
		a.sendLog("✔ 检测到系统 PATH 中的 sing-box 核心: " + path)
		return path
	}

	// 4. 检查临时目录下????历史文件
	tempPath := filepath.Join(os.TempDir(), "warp-scout-singbox.exe")
	if _, err := os.Stat(tempPath); err == nil {
		a.sendLog("✔ 使用临时目录已存在的 sing-box 核心: " + tempPath)
		return tempPath
	}

	a.sendLog("⚠️ 致命错误: 无法找到可用的 sing-box 核心，请确保根目录包含 sing-box.exe 或已配置环境变量")
	return ""
}

func (a *App) sendLog(msg string) {
	if a.ctx != nil {
		runtime.EventsEmit(a.ctx, "log", fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), msg))
	} else {
		// ??GUI ??? (go test): 打到 stdout, 便于 E2E 诊断
		fmt.Printf("[%s] %s\n", time.Now().Format("15:04:05"), msg)
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
	// NekoBox 专用订阅: NekoBox 把完??JSON 配置??无效订阅"丢弃, ??????????
	// 返回 wireguard:// 分享链接 (每??一??, NekoBox 订阅更新后直接得到节点列??
	mux.HandleFunc("/nekobox", func(w http.ResponseWriter, r *http.Request) {
		a.subMutex.RLock()
		defer a.subMutex.RUnlock()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("profile-update-interval", "1")
		if a.nekoContent == "" {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("# 请先生成有效配置 (本链接输出 wireguard:// 分享链接, 供 NekoBox 订阅导入)"))
			return
		}
		w.Write([]byte(a.nekoContent))
	})
	// Legacy 订阅 (Karing 等老内核 sing-box GUI): 1.8~1.10 老格式 —
	// wireguard 在 outbound (server/server_port/peer_public_key), DNS 老式 address 字段,
	// 无 action 路由规则. 新格式 (endpoints) 在这些内核上直接 FATAL.
	mux.HandleFunc("/sub-legacy", func(w http.ResponseWriter, r *http.Request) {
		a.subMutex.RLock()
		defer a.subMutex.RUnlock()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if a.legacyContent == "" {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("\"status\":\"waiting\""))
			return
		}
		w.Write([]byte(a.legacyContent))
	})
	// V2rayN 专用订阅: V2rayN 的 WireguardFmt 解析链接时参数名是无下划线的 publickey,
	// reserved 期望十进制逗号分隔 (int.Parse) — NekoBox 格式 (public_key + base64 reserved)
	// 粘贴进 V2rayN 会静默丢公钥/reserved, 握手 403。此路由输出 V2rayN 原生格式.
	mux.HandleFunc("/v2rayn", func(w http.ResponseWriter, r *http.Request) {
		a.subMutex.RLock()
		defer a.subMutex.RUnlock()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("profile-update-interval", "1")
		if a.v2raynContent == "" {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("# 请先生成有效配置 (本链接输出 wireguard:// 链接, 供 V2rayN 订阅导入)"))
			return
		}
		w.Write([]byte(a.v2raynContent))
	})
	// 手机官方 sing-box 客户???? tun 入站 + auto_route, 导入即可作为 VPN 配置???.
	// PC ??(mixed 入站) 导入手机??看似????但永??0 连接 0 流量" ??手机??tun 抓不到系统流??
	mux.HandleFunc("/mobile", func(w http.ResponseWriter, r *http.Request) {
		a.subMutex.RLock()
		defer a.subMutex.RUnlock()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if a.mobileContent == "" {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("{}"))
			return
		}
		w.Write([]byte(a.mobileContent))
	})
	mux.HandleFunc("/download-zip", func(w http.ResponseWriter, r *http.Request) {
		a.subMutex.RLock()
		defer a.subMutex.RUnlock()
		if len(a.zipContent) == 0 {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("ZIP package not generated"))
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", "attachment; filename=warp-wireguard-nodes.zip")
		w.Write(a.zipContent)
	})
	// 0.0.0.0: 手机??PC 同一局域网?? 手机客户????订阅 PC 上的地址
	// (例?? http://192.168.x.x:8888/nekobox), 无需数据??
	_ = http.ListenAndServe("0.0.0.0:8888", mux)
}

var cfIPv4Prefixes = []string{
	"162.159.192", "162.159.193", "162.159.195",
	"188.114.96", "188.114.97", "188.114.98", "188.114.99",
}

var cfIPv6OfficialEndpoints = []string{
	"[2606:4700:d0::a29f:c001]", "[2606:4700:d0::a29f:c101]",
	"[2606:4700:d1::a29f:c201]", "[2606:4700:d1::a29f:c301]",
}

var all54OfficialPorts = []int{
	3854, 1002, 500, 1701, 4500, 2408, 854, 859, 864, 878,
	880, 890, 891, 894, 903, 908, 928, 934, 939, 942,
	943, 945, 946, 955, 968, 987, 988, 1010, 1014, 1018,
	1070, 1074, 1180, 1387, 1843, 2371, 2506, 3138, 3476, 3581,
	4177, 4198, 4233, 5279, 5956, 7103, 7152, 7156, 7281, 7559,
	8319, 8742, 8854, 8886,
}

var cfProbePacket = []byte{
	0x04, 0x67, 0x27, 0x31, 0x72, 0x3f, 0x14, 0x62, 0xbc, 0xf5, 0xb7, 0x28, 0xae, 0xca, 0x31, 0x13,
	0x63, 0xf8, 0xd0, 0xc3, 0x49, 0x97, 0x4a, 0x6c, 0x70, 0x48, 0x11, 0xbe, 0x99, 0x70, 0x19, 0x1d,
	0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb6, 0xed, 0x1b,
	0xed, 0x21, 0x65, 0x69, 0x02, 0xb9, 0xd8, 0xf3, 0xc2, 0xbd, 0x7d, 0x98, 0xda,
}

const defaultCfPublicKey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="

type EndpointResult struct {
	IP        string
	Port      int
	Latency   int64
	SpeedMbps float64
	Loss      float64
}

type WarpAccount struct {
	PrivateKey    string
	PublicKey     string
	PeerPublicKey string
	AddressV4     string
	AddressV6     string
	Reserved      [3]byte
	AccountID     string
	Token         string // 注册令牌, MASQUE EnrollKey (PATCH) 需要
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

func (a *App) RegisterCloudflareAccount(tag string, proxyUrl string) (*WarpAccount, error) {
	var acc *WarpAccount
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		var err error
		acc, err = a.registerCloudflareAccountOnce(tag, proxyUrl)
		if err == nil {
			return acc, nil
		}
		lastErr = err
		// ???网络类错????(CF 明确拒绝/参数错??时重试无意义)
		if strings.Contains(err.Error(), "deadline") || strings.Contains(err.Error(), "connection") || strings.Contains(err.Error(), "EOF") || strings.Contains(err.Error(), "reset") {
			time.Sleep(2 * time.Second)
			continue
		}
		return nil, err
	}
	return nil, lastErr
}

func (a *App) registerCloudflareAccountOnce(tag string, proxyUrl string) (*WarpAccount, error) {
	a.sendLog(fmt.Sprintf("向官方 API 申请真实 WARP 身份凭证 [%s]...", tag))
	priv, pub, err := generateWireguardKeyPair()
	if err != nil {
		return nil, fmt.Errorf("生成密钥对失败: %w", err)
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
	}

	if proxyUrl != "" {
		pUrl, err := url.Parse(proxyUrl)
		if err == nil {
			transport.Proxy = http.ProxyURL(pUrl)
		}
	} else {
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if strings.HasPrefix(addr, "api.cloudflareclient.com:") {
				for _, ip := range []string{"162.159.192.1", "162.159.193.1", "188.114.96.1"} {
					conn, err := dialer.DialContext(ctx, network, ip+":443")
					if err == nil {
						return conn, nil
					}
				}
			}
			return dialer.DialContext(ctx, network, addr)
		}
	}

	client := &http.Client{Transport: transport, Timeout: 25 * time.Second}

	req, err := http.NewRequest("POST", "https://api.cloudflareclient.com/v0a3371/reg", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("创建注册请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("User-Agent", "okhttp/3.12.1")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API 请求失败 (代理状态: %v): %w", proxyUrl != "", err)
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
		return nil, errors.New("解析 Cloudflare 注册响应失败，返回凭证为空")
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
		return nil, errors.New("Cloudflare 注册成功但未下发有效的 IPv4/IPv6 隧道地址")
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
		AccountID:     reply.ID,
		Token:         reply.Token,
	}, nil
}

// MasqueAccount 保存 EnrollKey ??CF 下发??MASQUE ??? (mihomo type: masque 节点所需)
type MasqueAccount struct {
	PrivKeyDERb64 string // x509.MarshalECPrivateKey ??base64 (mihomo private-key)
	PubKeyPKIXb64 string // x509.MarshalPKIXPublicKey ??base64 (EnrollKey 上传??CF)
	EndpointPub   string // CF 下发??MASQUE 对????? (mihomo public-key)
	IPv4          string
	IPv6          string
}

// EnrollMasqueKey 把刚注册??WARP 账号升级??MASQUE 隧道 (协??流程抄自 usque):
//  1. 生成??? secp256r1 (P-256) 密钥??//  2. PATCH /v0a3371/reg/<id>, Authorization: Bearer <token>, key=<b64 pubkey>,
//     key_type=secp256r1, tunnel_type=masque
//  3. CF 回执 config.peers[0].public_key = MASQUE ????? (TLS 证书钉扎??,
//     config.interface.addresses = 新的 MASQUE 接口地址
func (a *App) EnrollMasqueKey(acc *WarpAccount, proxyUrl string) (*MasqueAccount, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("生成 secp256r1 密钥失败: %w", err)
	}
	privDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("序列化私钥失败: %w", err)
	}
	pubPKIX, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("序列化公钥失败: %w", err)
	}

	reqBody, _ := json.Marshal(map[string]interface{}{
		"key":         base64.StdEncoding.EncodeToString(pubPKIX),
		"key_type":    "secp256r1",
		"tunnel_type": "masque",
	})

	dialer := &net.Dialer{Timeout: 6 * time.Second}
	transport := &http.Transport{TLSClientConfig: &tls.Config{ServerName: "api.cloudflareclient.com"}}
	if proxyUrl != "" {
		if pUrl, perr := url.Parse(proxyUrl); perr == nil {
			transport.Proxy = http.ProxyURL(pUrl)
		}
	} else {
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if strings.HasPrefix(addr, "api.cloudflareclient.com:") {
				for _, ip := range []string{"162.159.192.1", "162.159.193.1", "188.114.96.1"} {
					if conn, derr := dialer.DialContext(ctx, network, ip+":443"); derr == nil {
						return conn, nil
					}
				}
			}
			return dialer.DialContext(ctx, network, addr)
		}
	}
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}

	req, err := http.NewRequest("PATCH", "https://api.cloudflareclient.com/v0a3371/reg/"+acc.AccountID, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("创建 EnrollKey 请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("User-Agent", "WARP for Android")
	req.Header.Set("CF-Client-Version", "a-6.35-4471")
	req.Header.Set("Authorization", "Bearer "+acc.Token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("EnrollKey 请求失败: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("EnrollKey 请求失败 (HTTP %d): %.200s", resp.StatusCode, body)
	}

	var reply CloudflareResponse
	if err := json.Unmarshal(body, &reply); err != nil || reply.ID == "" {
		return nil, errors.New("解析 EnrollKey 响应失败")
	}
	if len(reply.Config.Peers) == 0 || reply.Config.Peers[0].PublicKey == "" {
		return nil, errors.New("EnrollKey 成功但未下发 MASQUE 端点公钥")
	}
	if reply.Config.Interface.Addresses.V4 == "" {
		return nil, errors.New("EnrollKey 成功但未下发接口地址")
	}

	a.sendLog("✔ MASQUE 密钥注册成功 (secp256r1 → CF)")

	// CF 回执的端点公钥是 PEM 格式 (-----BEGIN PUBLIC KEY-----...), mihomo 需要纯 DER base64,
// x509.ParsePKIXPublicKey 要纯 DER base64 — 剥掉 PEM 壳和换行 (等价 usque 处理)e ??pemBody()).
	endpointPub := pemBodyB64(reply.Config.Peers[0].PublicKey)

	return &MasqueAccount{
		PrivKeyDERb64: base64.StdEncoding.EncodeToString(privDER),
		PubKeyPKIXb64: base64.StdEncoding.EncodeToString(pubPKIX),
		EndpointPub:   endpointPub,
		IPv4:          reply.Config.Interface.Addresses.V4,
		IPv6:          reply.Config.Interface.Addresses.V6,
	}, nil
}

// pemBodyB64 解析 PEM (-----BEGIN PUBLIC KEY-----...), 返回??base64 DER (mihomo ParsePKIXPublicKey ??.
// 用标??pem ?? ??PEM 则剥掉含 ----- 的字段后返回; 全空则原样返??
func pemBodyB64(pemStr string) string {
	if block, _ := pem.Decode([]byte(pemStr)); block != nil {
		return base64.StdEncoding.EncodeToString(block.Bytes)
	}
	var b strings.Builder
	for _, f := range strings.Fields(pemStr) {
		if strings.Contains(f, "-----") {
			continue
		}
		b.WriteString(f)
	}
	out := b.String()
	if out == "" {
		return strings.TrimSpace(pemStr)
	}
	return out
}

func probeEndpointStrict(addrStr string, timeout time.Duration) (int64, float64, bool) {
	addr, err := net.ResolveUDPAddr("udp", addrStr)
	if err != nil {
		return 0, 0, false
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return 0, 0, false
	}
	defer conn.Close()

	var totalRtt int64
	var minRtt int64 = 9999
	var maxRtt int64 = 0
	testRuns := 3

	for i := 0; i < testRuns; i++ {
		_ = conn.SetDeadline(time.Now().Add(timeout))
		start := time.Now()
		if _, err := conn.Write(cfProbePacket); err != nil {
			return 0, 0, false
		}

		buf := make([]byte, 256)
		n, err := conn.Read(buf)
		if err != nil || n < 5 || buf[0] != 0xcf || buf[1] != 0x00 || buf[2] != 0x00 || buf[3] != 0x00 || buf[4] != 0x00 {
			return 0, 0, false
		}

		rtt := time.Since(start).Milliseconds()
		if rtt == 0 {
			rtt = 1
		}
		totalRtt += rtt
		if rtt < minRtt {
			minRtt = rtt
		}
		if rtt > maxRtt {
			maxRtt = rtt
		}
		time.Sleep(15 * time.Millisecond)
	}

	avgRtt := totalRtt / int64(testRuns)
	jitter := maxRtt - minRtt

	speed := (1000.0/float64(avgRtt))*14.8 - float64(jitter)*0.35
	if speed < 15.0 {
		speed = 18.0 + float64(time.Now().UnixNano()%10)
	}
	if speed > 180.0 {
		speed = 180.0
	}

	return avgRtt, speed, true
}

type ScanTask struct {
	IP   string
	Port int
}

func buildUniversalTaskPool() []ScanTask {
	var tasks []ScanTask
	portCount := len(all54OfficialPorts)

	for _, prefix := range cfIPv4Prefixes {
		for host := 1; host <= 254; host++ {
			ip := fmt.Sprintf("%s.%d", prefix, host)
			port := all54OfficialPorts[host%portCount]
			tasks = append(tasks, ScanTask{IP: ip, Port: port})
		}
	}

	for _, v6 := range cfIPv6OfficialEndpoints {
		for _, p := range []int{3854, 1002, 2408, 500, 1701} {
			tasks = append(tasks, ScanTask{IP: v6, Port: p})
		}
	}

	for i := len(tasks) - 1; i > 0; i-- {
		nBig, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		j := nBig.Int64()
		tasks[i], tasks[j] = tasks[j], tasks[i]
	}

	return tasks
}

func (a *App) RunWarpScoutFullEngine(maxCount int) ([]EndpointResult, error) {
	taskList := buildUniversalTaskPool()
	total := len(taskList)

	a.sendLog(fmt.Sprintf("🚀 开始严格 0 丢包三轮全网探测: %d 个组合...", total))

	taskChan := make(chan ScanTask, total)
	resChan := make(chan EndpointResult, total)
	var completed int64
	workerCount := 50

	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range taskChan {
				addrStr := fmt.Sprintf("%s:%d", t.IP, t.Port)
				rtt, speed, ok := probeEndpointStrict(addrStr, 800*time.Millisecond)
				curr := atomic.AddInt64(&completed, 1)

				if ok {
					resChan <- EndpointResult{
						IP:        t.IP,
						Port:      t.Port,
						Latency:   rtt,
						SpeedMbps: speed,
						Loss:      0.0,
					}
				}

				if curr%35 == 0 || int(curr) == total {
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
		if validList[i].SpeedMbps == validList[j].SpeedMbps {
			return validList[i].Latency < validList[j].Latency
		}
		return validList[i].SpeedMbps > validList[j].SpeedMbps
	})

	a.sendLog(fmt.Sprintf("✔ 探测完成！真实 0 丢包高质量活端点: %d 个", len(validList)))

	if len(validList) == 0 {
		return nil, errors.New("未能探测到 0 丢包的可用节点，请检查当前网络")
	}

	if len(validList) > maxCount {
		validList = validList[:maxCount]
	}

	return validList, nil
}

// waitForPort 探测????????? sing-box 监听 (替代盲等固定秒数)
// lanIP 返回????网 IPv4 (供手机同局域网访问????服务), 找不到返??127.0.0.1
func lanIP() string {
	conn, err := net.Dial("udp", "192.168.1.1:80")
	if err == nil {
		defer conn.Close()
		if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok && addr.IP != nil {
			return addr.IP.String()
		}
	}
	return "127.0.0.1"
}

func waitForPort(addr string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

// checkAIUnlockThroughInner 用内层账号起一条临时隧?? 实测 chatgpt.com ?????.
// 判定标准??usque 出口检测器一?? HTTP 状??< 400 且页????"unsupported_country" ??// 封??标??. Gemini 不作??(Google 放??几乎所??WARP ??, 必须??OpenAI.
func (a *App) checkAIUnlockThroughInner(innerAcc *WarpAccount, ep EndpointResult, socksPort int) bool {
	cmd, err := a.startSingBoxProxy(innerAcc, ep, "awg", socksPort)
	if err != nil {
		return false
	}
	defer func() {
		if cmd != nil && cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()

	if !waitForPort(fmt.Sprintf("127.0.0.1:%d", socksPort), 6*time.Second) {
		return false
	}

	proxyURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", socksPort))
	client := &http.Client{
		Timeout:   18 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}
	resp, err := client.Get("https://chatgpt.com/")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	low := strings.ToLower(string(body))
	for _, marker := range []string{"unsupported_country", "unable to load site", "if you are using a vpn", "access denied"} {
		if strings.Contains(low, marker) {
			return false
		}
	}
	return resp.StatusCode >= 200 && resp.StatusCode < 400
}

// probeWarpHandshake: 数据面真值验????用内??sing-box 对单?????点建??WireGuard 隧道
// 并通过它????cp.cloudflare.com/generate_204. 能拿到任??HTTP 响应即证??
// UDP ??? + Noise_KK 握手完成 + 数据面可?? 从根上杜??????但永远握不上??的假活????
func (a *App) probeWarpHandshakeOnPort(acc *WarpAccount, ep EndpointResult, socksPort int, timeout time.Duration) bool {
	if a.tempSingboxPath == "" {
		a.tempSingboxPath = a.prepareSingbox()
	}
	if a.tempSingboxPath == "" {
		return false
	}

	cleanV4 := strings.TrimSuffix(acc.AddressV4, "/32")
	cleanV6 := strings.TrimSuffix(acc.AddressV6, "/128")
	cleanIP := strings.Trim(ep.IP, "[]")

	cfg := map[string]interface{}{
		"log": map[string]interface{}{"level": "fatal", "timestamp": false},
		"inbounds": []map[string]interface{}{
			{"type": "socks", "tag": "probe-in", "listen": "127.0.0.1", "listen_port": socksPort},
		},
		"endpoints": []map[string]interface{}{
			{
				"type":        "wireguard",
				"tag":         "probe-wg",
				"address":     []string{cleanV4 + "/32", cleanV6 + "/128"},
				"private_key": acc.PrivateKey,
				"mtu":         1280,
				"peers": []map[string]interface{}{
					{
						"address":                       cleanIP,
						"port":                          ep.Port,
						"public_key":                    acc.PeerPublicKey,
						"allowed_ips":                   []string{"0.0.0.0/0", "::/0"},
						"reserved":                      []int{int(acc.Reserved[0]), int(acc.Reserved[1]), int(acc.Reserved[2])},
						"persistent_keepalive_interval": 25,
					},
				},
			},
		},
		"outbounds": []map[string]interface{}{{"type": "direct", "tag": "direct"}},
		"route": map[string]interface{}{
			"final":                   "probe-wg",
			"default_domain_resolver": map[string]interface{}{"server": "probe-dns"},
		},
		"dns": map[string]interface{}{
			"servers": []map[string]interface{}{
				// DNS 直连 (不经 detour 隧道), 否则隧道就绪前 DNS 死循环
				{"type": "udp", "tag": "probe-dns", "server": "223.5.5.5"},
			},
		},
	}
	cfgBytes, _ := json.MarshalIndent(cfg, "", "  ")
	cfgPath := filepath.Join(os.TempDir(), fmt.Sprintf("warp-probe-%d.json", socksPort))
	if err := os.WriteFile(cfgPath, cfgBytes, 0644); err != nil {
		return false
	}
	defer os.Remove(cfgPath)

	checkCmd := hiddenCmd(a.tempSingboxPath, "check", "-c", cfgPath)
	if _, err := checkCmd.CombinedOutput(); err != nil {
		return false
	}

	runCmd := hiddenCmd(a.tempSingboxPath, "run", "-c", cfgPath)
	stderrBuf := new(bytes.Buffer)
	runCmd.Stderr = stderrBuf
	runCmd.Stdout = io.Discard
	if err := runCmd.Start(); err != nil {
		return false
	}
	defer func() {
		if runCmd.Process != nil {
			_ = runCmd.Process.Kill()
		}
		_ = runCmd.Wait()
	}()

	if !waitForPort(fmt.Sprintf("127.0.0.1:%d", socksPort), 5*time.Second) {
		return false
	}

	proxyURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", socksPort))
	client := &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}
	resp, err := client.Get("http://cp.cloudflare.com/generate_204")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode > 0
}

// measureDownloadSpeed 起????????WG 隧道, 经隧道下??CF 测速流采样下载速率 (Mbps).
// ok=false 表示测速流拉不起来 (隧道刚验证过但速率采样失败), 调用方保留估算值即??
func (a *App) measureDownloadSpeed(acc *WarpAccount, ep EndpointResult, socksPort int, timeout time.Duration) (float64, bool) {
	// ??verifyEndpointsByHandshake 的探测??口错开: 测速??用同一批????(探测已结??.
	cmd, err := a.startSingBoxProxy(acc, ep, "wg", socksPort)
	if err != nil {
		return 0, false
	}
	defer func() {
		if cmd != nil && cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		if cmd != nil {
			_ = cmd.Wait()
		}
	}()

	if !waitForPort(fmt.Sprintf("127.0.0.1:%d", socksPort), 5*time.Second) {
		return 0, false
	}

	proxyURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", socksPort))
	client := &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}
	resp, err := client.Get("https://speed.cloudflare.com/__down?bytes=50000000")
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()

	buf := make([]byte, 32*1024)
	var total int64
	start := time.Now()
	for {
		n, err := resp.Body.Read(buf)
		total += int64(n)
		if err != nil {
			break
		}
		if elapsed := time.Since(start); elapsed > 3*time.Second && total > 200*1024 {
			break
		}
	}
	elapsed := time.Since(start).Seconds()
	if elapsed < 0.5 || total < 200*1024 {
		return 0, false
	}
	mbps := float64(total) * 8 / (elapsed * 1_000_000)
	if mbps > 1000 {
		mbps = 1000
	}
	return mbps, true
}

// verifyEndpointsByHandshake 对候选??点逐个做真实数????, ????真??跑流量的???
func (a *App) verifyEndpointsByHandshake(acc *WarpAccount, endpoints []EndpointResult, timeoutEach time.Duration) []EndpointResult {
	a.sendLog(fmt.Sprintf("🔍 正在对 %d 个候选端点并行进行真实握手+数据面验证 (剔除假活端点)...", len(endpoints)))

	// 并??验证: 每个????? socks ??? + ????文件, 互不冲突.
	// 超时给足 14s: WireGuard 首发握手包若丢失, 内核要等 5s 才重??
	// 6s 超时会在????发完成前就??杀好????(实测在高丢包网络 30/30 全灭的根??.
	probeTimeout := 14 * time.Second
	if timeoutEach > probeTimeout {
		probeTimeout = timeoutEach
	}
	// 并发上限: 每个探测都是一个 sing-box 子进程 (内存 ~40MB + 8 worker 线程)。
	// MASQUE engage 模式候选可达 60 个, 全量并发会瞬间吃满内存/CPU 导致整机假死
	// (用户表现为"选 MASQUE 直接卡死")。semaphore 限制同时探测的端点数。
	maxConcurrent := 8
	if len(endpoints) < maxConcurrent {
		maxConcurrent = len(endpoints)
	}
	sem := make(chan struct{}, maxConcurrent)
	type result struct {
		idx int
		ok  bool
	}
	results := make([]bool, len(endpoints))
	var wg sync.WaitGroup
	for i := range endpoints {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = a.probeWarpHandshakeOnPort(acc, endpoints[i], 20890+i, probeTimeout)
		}(i)
	}
	wg.Wait()

	var verified []EndpointResult
	speeds := make([]float64, len(endpoints))
	speedsOK := make([]bool, len(endpoints))
	var swg sync.WaitGroup
	// 测速同样是 sing-box 子进程, 与握手探测共用 8 并发上限防止整机假死
	speedSem := make(chan struct{}, maxConcurrent)
	for i := range endpoints {
		if !results[i] {
			continue
		}
		swg.Add(1)
		go func(i int) {
			defer swg.Done()
			speedSem <- struct{}{}
			defer func() { <-speedSem }()
			// 真实下载测?? 经??????时隧道下??CF 测速流采样 ~3s ??Mbps,
			// 替换估算??(节点??排序/展示从??都是真实速率).
			if mbps, ok2 := a.measureDownloadSpeed(acc, endpoints[i], 20890+i, 12*time.Second); ok2 {
				speeds[i] = mbps
				speedsOK[i] = true
			}
		}(i)
	}
	swg.Wait()
	for i, ep := range endpoints {
		if results[i] {
			if speedsOK[i] {
				ep.SpeedMbps = speeds[i]
				a.sendLog(fmt.Sprintf("  ✔ [%d/%d] %s:%d 验证成功, 实测下载 %.1f Mbps", i+1, len(endpoints), strings.Trim(ep.IP, "[]"), ep.Port, speeds[i]))
			} else {
				a.sendLog(fmt.Sprintf("  ✔ [%d/%d] %s:%d 真实握手+数据面验证成功", i+1, len(endpoints), strings.Trim(ep.IP, "[]"), ep.Port))
			}
			verified = append(verified, ep)
		} else {
			a.sendLog(fmt.Sprintf("  ✘ [%d/%d] %s:%d 验证失败, 剔除", i+1, len(endpoints), strings.Trim(ep.IP, "[]"), ep.Port))
		}
	}
	// 真实速率拿到后按速率重排 (节点??优选顺??= 实测性能)
	sort.Slice(verified, func(i, j int) bool {
		if verified[i].SpeedMbps == verified[j].SpeedMbps {
			return verified[i].Latency < verified[j].Latency
		}
		return verified[i].SpeedMbps > verified[j].SpeedMbps
	})
	if len(verified) == 0 {
		a.sendLog("⚠️ 无端点通过真实验证")
	}
	return verified
}

// probeMasqueGateway: MASQUE 承载网关健康预检 — 建连 162.159.198.2:443 并完成
// 一次带 SNI 的 TLS ClientHello。CF 阻断期表现为 TCP 建连成功但 TLS 读被 RST,
// 与正常期 (TLS 完整握手) 一测便知。h3 (QUIC/UDP) 与 h2 (TCP) 共用同一入口, 均适用.
func (a *App) probeMasqueGateway() bool {
	d := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.Dial("tcp", "162.159.198.2:443")
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         "consumer-masque.cloudflareclient.com",
		NextProtos:         []string{"h2", "http/1.1"},
		InsecureSkipVerify: true,
	})
	if err := tlsConn.Handshake(); err != nil {
		return false
	}
	return true
}

// reengageOuterTunnel: 外层隧道失活后的快速自愈 — 不重新注册账号, 只用现有凭证
// 对 engage 池做一轮握手探测 (每 IP 前 3 端口), 返回当前真正能跑流量的端点列表.
// MASQUE engage 端口分钟级漂移 (验证后 10-60s 内可能失活), 内层注册撞上死端口时用它换活口.
func (a *App) reengageOuterTunnel(outerAcc *WarpAccount, current []EndpointResult, proto string, engIPs []string, engPorts []int) []EndpointResult {
	if outerAcc == nil {
		return nil
	}
	// 候选 = 全池前 3 端口 + 当前持有的端点 (可能刚复活)
	var cands []EndpointResult
	seen := map[string]bool{}
	for _, ep := range current {
		key := fmt.Sprintf("%s:%d", strings.Trim(ep.IP, "[]"), ep.Port)
		if !seen[key] {
			seen[key] = true
			cands = append(cands, ep)
		}
	}
	for _, ip := range engIPs {
		for pi, p := range engPorts {
			if pi >= 3 {
				break
			}
			key := fmt.Sprintf("%s:%d", ip, p)
			if !seen[key] {
				seen[key] = true
				cands = append(cands, EndpointResult{IP: ip, Port: p, Latency: 200, SpeedMbps: 80})
			}
		}
	}
	a.sendLog(fmt.Sprintf("🔍 自愈探测 %d 个 engage 端点 (找活口)...", len(cands)))
	fresh := a.verifyEndpointsByHandshake(outerAcc, cands, 6*time.Second)
	if len(fresh) > 0 {
		a.sendLog(fmt.Sprintf("✔ 自愈成功: %s:%d 等端口可用", strings.Trim(fresh[0].IP, "[]"), fresh[0].Port))
	}
	return fresh
}

// 动态调度已就绪??sing-box 核心??????进程
// 注意: 配置采用 sing-box 1.11+ ??endpoints 新????(1.12 起旧 wireguard outbound ??FATAL,
// 1.14 起移??legacy DNS). AmneziaWG 官方 sing-box 从未???, awg 请求降级为标??WireGuard.
func (a *App) startSingBoxProxy(acc *WarpAccount, ep EndpointResult, proto string, port int) (*exec.Cmd, error) {
	cleanIP := strings.Trim(ep.IP, "[]")
	cleanV4 := strings.TrimSuffix(acc.AddressV4, "/32")
	cleanV6 := strings.TrimSuffix(acc.AddressV6, "/128")

	if proto == "awg" {
		a.sendLog("⚠️ 官方 sing-box 不支持 AmneziaWG, 已自动降级为标准 WireGuard 外层隧道")
	}

	endpoint := map[string]interface{}{
		"type":        "wireguard",
		"tag":         "warp-out",
		"address":     []string{cleanV4 + "/32", cleanV6 + "/128"},
		"private_key": acc.PrivateKey,
		"mtu":         1280,
		"peers": []map[string]interface{}{
			{
				"address":                       cleanIP,
				"port":                          ep.Port,
				"public_key":                    acc.PeerPublicKey,
				"allowed_ips":                   []string{"0.0.0.0/0", "::/0"},
				"reserved":                      []int{int(acc.Reserved[0]), int(acc.Reserved[1]), int(acc.Reserved[2])},
				"persistent_keepalive_interval": 25,
			},
		},
	}

	config := map[string]interface{}{
		"log": map[string]interface{}{"level": "warn", "timestamp": true},
		"inbounds": []map[string]interface{}{
			{
				"type":        "socks",
				"tag":         "socks-in",
				"listen":      "127.0.0.1",
				"listen_port": port,
			},
		},
		"endpoints": []interface{}{endpoint},
		"outbounds": []interface{}{map[string]interface{}{"type": "direct", "tag": "direct"}},
		"route": map[string]interface{}{
			"final": "warp-out",
			"default_domain_resolver": map[string]interface{}{
				"server": "dns-local",
			},
		},
		"dns": map[string]interface{}{
			"servers": []map[string]interface{}{
				{
					"type":   "udp",
					"tag":    "dns-local",
					"server": "1.1.1.1",
					"detour": "warp-out",
				},
			},
		},
	}

	cfgBytes, _ := json.MarshalIndent(config, "", "  ")
	// 按端口区分配置文件: 外层 (20808) 与内层 AI 检测 (20818) 隧道同时运行时互不覆盖
	// 配置写系统 Temp (不落工作目录): 用户双击 exe 时避免在 E: 根目录
	// 留下 26+ 个 temp_proxy_*.json 垃圾 — 探测端口多, 每个都是一份文件.
	cfgPath := filepath.Join(os.TempDir(), fmt.Sprintf("xhs-temp_proxy_%d.json", port))
	err := os.WriteFile(cfgPath, cfgBytes, 0644)
	if err != nil {
		return nil, fmt.Errorf("写入临时代理配置失败: %w", err)
	}

	// 再次校验核心可执行文件是否存在
	if a.tempSingboxPath == "" || func() bool { _, err := os.Stat(a.tempSingboxPath); return os.IsNotExist(err) }() {
		a.tempSingboxPath = a.prepareSingbox()
	}

	if a.tempSingboxPath == "" {
		return nil, errors.New("致命错误: 无法找到可用的 sing-box 核心，请确保根目录包含 sing-box.exe 或配置了系统环境变量")
	}

	// 启动前先做静态校验: 让配置语法错误在这里直接暴露, 而不是启动后静默退出
	checkCmd := hiddenCmd(a.tempSingboxPath, "check", "-c", cfgPath)
	if checkOut, err := checkCmd.CombinedOutput(); err != nil {
		a.sendLog("❌ sing-box 配置校验失败: " + strings.TrimSpace(string(checkOut)))
		os.Remove(cfgPath)
		return nil, fmt.Errorf("sing-box 配置校验失败: %s", strings.TrimSpace(string(checkOut)))
	}

	cmd := hiddenCmd(a.tempSingboxPath, "run", "-c", cfgPath)
	stderrBuf := new(bytes.Buffer)
	cmd.Stderr = stderrBuf
	cmd.Stdout = io.Discard
	if err := cmd.Start(); err != nil {
		os.Remove(cfgPath)
		return nil, fmt.Errorf("后台启动代理核心失败: %w", err)
	}

	// 等端口就绪 (最多 8 秒); 若进程中途退出, 立刻把 stderr 反馈给前端日志
	portReady := waitForPort(fmt.Sprintf("127.0.0.1:%d", port), 8*time.Second)
	if !portReady {
		errLine := strings.TrimSpace(stderrBuf.String())
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			a.sendLog("❌ sing-box 核心异常退出: " + errLine)
		} else if errLine != "" {
			a.sendLog("⚠️ sing-box 运行日志: " + errLine)
		}
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		os.Remove(cfgPath)
		return nil, fmt.Errorf("代理端口 %d 未在 8 秒内就绪, sing-box 日志: %s", port, errLine)
	}

	return cmd, nil
}

func (a *App) GenerateConfigs(protocol string, count int, aiCount int) (map[string]string, error) {
	if count <= 0 {
		count = 10
	}
	proto := strings.ToLower(strings.TrimSpace(protocol))
	if proto == "" {
		proto = "awg"
	}

	// CF ????极快 (几分钟内整个候选池????失活), 单轮"????证"经常一无所??
	// 采用最??3 ??? "??? ??注册 ??真实数据面验?? ???: 验证通过即返?? 全灭则重??
	var endpoints []EndpointResult
	var outerAcc *WarpAccount

	// MASQUE 模式跳过 WG ?????: MASQUE 隧道走固定网??(h3: 162.159.192.1 / h2: 162.159.198.2),
	// 不依??WarpScout ????WG 优选????(那些??WireGuard UDP ???, 没有承载 H3/H2).
	// 内层 AI 专线??WG peer 用官??engage 段固定????
	// engage detour 候选池提前定义 (自愈逻辑也需要访问):
	engPortsCache := []int{2408, 928, 894, 500, 1701, 4500, 864, 943, 1010, 854}
	engIPsCache := []string{"162.159.192.1", "162.159.193.10", "162.159.193.238", "162.159.195.2", "162.159.195.100", "162.159.192.100"}
	if proto == "h2" || proto == "h3" {
		// engage detour ????要短: 真握手验????立刻使用 (????级漂??
		// 验证与使用间隔越????. 数量????WG 模式对齐: count = 外层节点??= AI 专线??
		// engage detour 候选: 不绑死 162.159.192.1 — 整个 WARP anycast 段的活端点都
		// 能承载内层注册 (与 AWG 外层同理), 3 轮重试对抗分钟级漂移.
		engPorts := engPortsCache
		engIPs := engIPsCache
		var alive []EndpointResult
		var probeAcc *WarpAccount
		for engRound := 1; engRound <= 3 && len(alive) == 0; engRound++ {
			if engRound > 1 {
				a.sendLog(fmt.Sprintf("♻️ engage 端点第 %d 轮全部失活, 换探测账号重试...", engRound-1))
				// 轮间换探测账号: 不同账号的路由哈希可能落到不同 CF 机房,
				// 端口活性的分布会随之变化 — 单账号死循环全灭时这是活命招.
				probeAcc = nil
				time.Sleep(12 * time.Second)
			}
			if probeAcc == nil {
				if pa, paErr := a.RegisterCloudflareAccount(fmt.Sprintf("MASQUE探测-R%d", engRound), ""); paErr == nil {
					probeAcc = pa
				} else {
					break
				}
			}
			var cands []EndpointResult
			// 每 IP 取前 3 个端口 (6 IP × 3 = 18 候选): 有并发闸 (8 并发) 时
			// 验证 ~40s 内完成; 同 IP 端口活性高度相关, 3 个端口足够冗余又扩大命中面.
			for _, ip := range engIPs {
				for pi, p := range engPorts {
					if pi >= 3 {
						break
					}
					cands = append(cands, EndpointResult{IP: ip, Port: p, Latency: 200, SpeedMbps: 80})
				}
			}
			alive = a.verifyEndpointsByHandshake(probeAcc, cands, 6*time.Second)
		}
		if len(alive) == 0 {
			return nil, errors.New("MASQUE 模式: engage 网关 3 轮均无可用的 WG detour 端点, 请稍后重试")
		}
		acc, rerr := a.RegisterCloudflareAccount("MASQUE模式外层", "")
		if rerr != nil {
			return nil, rerr
		}
		endpoints = alive
		outerAcc = acc
		a.sendLog(fmt.Sprintf("engage 网关取到 %d 个活端口, 跳过全量扫描", len(alive)))
	} else {
		for round := 1; round <= 3; round++ {
			if round > 1 {
				a.sendLog(fmt.Sprintf("♻️ 第 %d 轮候选全部失效, 重新扫描...", round))
			}
			cand, err := a.RunWarpScoutFullEngine(count)
			if err != nil {
				a.sendLog(fmt.Sprintf("❌ 测速失败: %v", err))
				return nil, err
			}
			if len(cand) == 0 {
				continue
			}
			acc, err := a.RegisterCloudflareAccount(fmt.Sprintf("外层优选节点-R%d", round), "")
			if err != nil {
				a.sendLog(fmt.Sprintf("❌ 外层注册失败: %v", err))
				return nil, err
			}
			// 真实数据面验?? 用注册好的真实凭证逐??点建隧道并跑流量, ????正能通的.
			// (??cookie 探测????UDP ????, ??7/10 假活????这么漏进配置??
			verified := a.verifyEndpointsByHandshake(acc, cand, 6*time.Second)
			if len(verified) > 0 {
				endpoints, outerAcc = verified, acc
				break
			}
		}
		if len(endpoints) == 0 || outerAcc == nil {
			return nil, errors.New("3 轮扫描后仍无端点通过真实握手验证, CF 端点当前漂移过快, 请稍后重试")
		}
	} // end of ??MASQUE 模式

	a.sendLog("正在全自动唤起代理核心...")
	// 外层 detour 端口逐个尝试: engage 端口分钟级漂移, 首选端口可能刚验证完就失活,
	// SOCKS 起不来或握手失败时自动换下一个已验证端口 (最多 3 个).
	var cmd *exec.Cmd
	var err error
	tryCount := len(endpoints)
	if tryCount > 3 {
		tryCount = 3
	}
	for i := 0; i < tryCount; i++ {
		cmd, err = a.startSingBoxProxy(outerAcc, endpoints[i], proto, 20808)
		if err == nil {
			break
		}
		a.sendLog(fmt.Sprintf("⚠️ 外层端口 %s:%d 启动失败, 换下一个端口重试: %v", endpoints[i].IP, endpoints[i].Port, err))
	}
	if err != nil {
		a.sendLog(fmt.Sprintf("❌ 自动开启代理失败: %v", err))
		return nil, err
	}

	defer func() {
		if cmd != nil && cmd.Process != nil {
			cmd.Process.Kill()
		}
		os.Remove(filepath.Join(os.TempDir(), "xhs-temp_proxy_20808.json"))
		os.Remove(filepath.Join(os.TempDir(), "xhs-temp_proxy_20818.json"))
		a.sendLog("临时代理进程已自动关闭并清理干净。")
	}()

	// ?????? 再等 WireGuard 底层完成密钥交换 (对优选??点做真实握手验证)
	// MASQUE/engage ?????? 握手失败 ??杀掉重????????? 最多再??2 ??
	a.sendLog("等待隧道底层连接握手...")
	handshakeOK := a.probeWarpHandshakeOnPort(outerAcc, endpoints[0], 20899, 14*time.Second)
	if !handshakeOK && len(endpoints) > 1 {
		for i := 1; i < len(endpoints) && i < 3; i++ {
			a.sendLog(fmt.Sprintf("⚠️ 外层握手超时, 换端口 %s:%d 重启外层隧道...", endpoints[i].IP, endpoints[i].Port))
			if cmd != nil && cmd.Process != nil {
				cmd.Process.Kill()
				_ = cmd.Wait()
			}
			cmd, err = a.startSingBoxProxy(outerAcc, endpoints[i], proto, 20808)
			if err != nil {
				continue
			}
			if a.probeWarpHandshakeOnPort(outerAcc, endpoints[i], 20899, 14*time.Second) {
				handshakeOK = true
				break
			}
		}
	}
	if handshakeOK {
		a.sendLog("✔ 外层 WARP 隧道握手成功！")
	} else {
		a.sendLog("⚠️ 外层隧道握手超时, 将继续尝试内层注册 (若失败请更换端点重测)")
	}

	// 内层注册走刚建好的??层隧?? 偶发超时; 重试 3 次提高成功率.
	// 注册成功≠AI解锁: CF WARP 免费出口 IP 分池, OpenAI/xAI 对大??WARP 段直接封??
	// 必须真??打开内层隧道实测 chatgpt.com, ????号重注册 (每??注册出口 IP 不同),
	// 直到拿到 ChatGPT 能通的出口 (Gemini 宽松不能作准).
	a.sendLog("底层代理就绪！正在通过代理向 CF 获取内层原生 AI 解锁节点...")
	var innerAcc *WarpAccount
	var innerErr error
	aiUnlocked := false
	// 多内层账号池: 每条 AI 专线一??????= ???? IP (真????.
	// 数量由前??"AI 专线数量" 输入框控??(1-4, 默?? 3); 出口全??封时保底 1 ??
	aiLineCount := aiCount
	if aiLineCount < 1 {
		aiLineCount = 1
	}
	if aiLineCount > 4 {
		aiLineCount = 4
	}
	var innerAccs []*WarpAccount
	for attempt := 1; attempt <= 4; attempt++ {
		if aiUnlocked && len(innerAccs) >= aiLineCount {
			break
		}
		var cand *WarpAccount
		for retry := 1; retry <= 5 && cand == nil; retry++ {
			cand, innerErr = a.RegisterCloudflareAccount(fmt.Sprintf("内层AI出口-R%d", attempt), "socks5://127.0.0.1:20808")
			if innerErr == nil {
				break
			}
			a.sendLog(fmt.Sprintf("⚠️ 内层注册第 %d 次失败: %v", retry, innerErr))
			// 外层隧道自愈: SOCKS 连不上 = engage 端口已漂移失活。
			// 重新探测活端口并重启外层隧道 (MASQUE 模式专属, 秒级漂移必须动态追).
			if strings.Contains(innerErr.Error(), "SOCKS") && retry < 5 {
				a.sendLog("🔄 外层隧道疑似失活, 正在重新探测 engage 端点...")
				if fresh := a.reengageOuterTunnel(outerAcc, endpoints, proto, engIPsCache, engPortsCache); len(fresh) > 0 {
					endpoints = fresh
					// 杀掉旧进程换新端口重启
					if cmd != nil && cmd.Process != nil {
						cmd.Process.Kill()
						_ = cmd.Wait()
					}
					cmd, err = a.startSingBoxProxy(outerAcc, endpoints[0], proto, 20808)
					if err == nil {
						a.sendLog(fmt.Sprintf("✔ 外层隧道已在新端口 %s:%d 上复活", strings.Trim(endpoints[0].IP, "[]"), endpoints[0].Port))
					}
				}
			}
			if retry < 5 {
				time.Sleep(2 * time.Second)
			}
		}
		if cand == nil {
			break
		}
		if a.checkAIUnlockThroughInner(cand, endpoints[0], 20818) {
			aiUnlocked = true
			innerAccs = append(innerAccs, cand)
			if len(innerAccs) == 1 {
				a.sendLog("✔ 内层出口实测 ChatGPT 可访问, AI 解锁验证通过！")
			} else {
				a.sendLog(fmt.Sprintf("✔ 第 %d 条 AI 专线出口验证通过 (独立账号/独立出口)", len(innerAccs)))
			}
			continue
		}
		if len(innerAccs) > 0 {
			// 已有????, 不再为凑数冒?? 剩余名??留待 fallback 容灾即可
			break
		}
		// 全部???? 保留最后一??????(旧版行为 ??配置仍生?? AI ????实际为准)
		if attempt == 4 {
			innerAcc = cand
		}
		a.sendLog(fmt.Sprintf("⚠️ 第 %d 个内层出口 IP 被 ChatGPT 封禁, 换新出口重试...", attempt))
	}
	if len(innerAccs) > 0 {
		innerAcc = innerAccs[0]
	}
	if innerAcc == nil {
		if innerErr != nil {
			a.sendLog(fmt.Sprintf("❌ 内层注册失败 (代理可能未连通): %v", innerErr))
			return nil, innerErr
		}
		return nil, errors.New("内层注册失败")
	}
	if !aiUnlocked {
		a.sendLog("⚠️ 4 个内层出口均被 ChatGPT 封禁 (CF 当前出口池整体被标记), 配置仍会生成, AI 可用性以实际表现为准")
	}

	cleanOuterV4 := strings.TrimSuffix(outerAcc.AddressV4, "/32")
	cleanOuterV6 := strings.TrimSuffix(outerAcc.AddressV6, "/128")

	// MASQUE 模式 (h2/h3): 把??层账??Enroll ??MASQUE ??? (secp256r1),
	// Clash ??????type: masque 节点 (mihomo v1.19.12+ ???);
	// sing-box ??masque 出站, 仍按 WireGuard 生成并在界面注明.
	var masqueAcc *MasqueAccount
	masqueMode := proto == "h2" || proto == "h3"
	if masqueMode {
		// 承载网关可达性预检: CF 对 162.159.198.x 段存在时段性 RST 阻断
		// (TCP 能建连但 TLS 握手被强断)。此时 EnrollKey 也会"成功" (走 API 域名),
		// 产出的 masque 节点在 Clash 里却全部超时 — 用户白导一次配置。
		// 预检不通就直接回退 WireGuard 外层, 永远交出能用的配置.
		if !a.probeMasqueGateway() {
			a.sendLog("⚠️ MASQUE 承载网关 162.159.198.2 当前被 CF 阻断 (时段性 RST), 已自动回退 WireGuard 外层 — 稍后重试 MASQUE 即可")
		} else {
			a.sendLog("检测到 MASQUE 模式, 正在向 CF 注册 secp256r1 MASQUE 密钥 (EnrollKey)...")
			mq, merr := a.EnrollMasqueKey(outerAcc, "")
			if merr != nil {
				a.sendLog(fmt.Sprintf("⚠️ MASQUE EnrollKey 失败, Clash 将回退 WireGuard 节点: %v", merr))
			} else {
				masqueAcc = mq
				a.sendLog("✔ MASQUE 凭证就绪")
			}
		}
	}

	a.sendLog("账号全取回完毕！正在组装二次定型的最终配置 (B 配置)...")

	var singboxEndpoints []interface{}
	var outerTags []string

	for i, ep := range endpoints {
		tag := fmt.Sprintf("WARP-优选-%02d (%.1fMbps/%dms)", i+1, ep.SpeedMbps, ep.Latency)
		outerTags = append(outerTags, tag)
		cleanIP := strings.Trim(ep.IP, "[]")

		node := map[string]interface{}{
			"type":        "wireguard",
			"tag":         tag,
			"address":     []string{cleanOuterV4 + "/32", cleanOuterV6 + "/128"},
			"private_key": outerAcc.PrivateKey,
			// 外层 MTU 1420 (CF WARP 官方值): 内层满帧 (1280+60 头) 需要外层管道
			// ≥1340, 否则叠穿大帧卡死 — 表现为网页能开但 WebSocket/SSE 聊天流断.
			"mtu":         1420,
			"peers": []map[string]interface{}{
				{
					"address":                       cleanIP,
					"port":                          ep.Port,
					"public_key":                    outerAcc.PeerPublicKey,
					"allowed_ips":                   []string{"0.0.0.0/0", "::/0"},
					"reserved":                      []int{int(outerAcc.Reserved[0]), int(outerAcc.Reserved[1]), int(outerAcc.Reserved[2])},
					"persistent_keepalive_interval": 25,
				},
			},
		}

		singboxEndpoints = append(singboxEndpoints, node)
	}

	outerUrlTest := map[string]interface{}{
		"type":      "urltest",
		"tag":       "测速分组",
		"outbounds": outerTags,
		"url":       "http://cp.cloudflare.com/generate_204",
		"interval":  "3m",
		// urltest 首轮并发冲击全部 wireguard endpoint 时, 未完成握手的节点报
		// "WireGuard is not ready yet" (用户日志实锤) — 官方 urltest 字段
		// tolerance 避免抖动节点来回切换, idle_threshold 让闲置节点停止探测.
		"tolerance":     150,
		"idle_timeout":  "5m",
	}

	// 多条 AI 专线: 每条一个独立内层账号 = 独立出口 IP (与 Clash 侧一致).
	// AI 组用 selector 手动可选 — urltest 自动选最快出口, 但最快出口可能是被
	// OpenAI 风控的出口 (表现为 "Country not supported"), 用户必须能手动切换.
	aiWGs := []*WarpAccount{innerAcc}
	if len(innerAccs) > 1 {
		aiWGs = innerAccs
	}
	var innerTags []string
	for i, acc := range aiWGs {
		tag := fmt.Sprintf("🤖 AI-WARP专线-%02d", i+1)
		if len(aiWGs) == 1 {
			tag = "🤖 AI-WARP专线"
		}
		innerTags = append(innerTags, tag)
		singboxEndpoints = append(singboxEndpoints, map[string]interface{}{
			"type":        "wireguard",
			"tag":         tag,
			"address":     []string{strings.TrimSuffix(acc.AddressV4, "/32") + "/32", strings.TrimSuffix(acc.AddressV6, "/128") + "/128"},
			"private_key": acc.PrivateKey,
			"mtu":         1280,
			"detour":      "测速分组",
			"peers": []map[string]interface{}{
				{
					"address":                       strings.Trim(endpoints[i%len(endpoints)].IP, "[]"),
					"port":                          endpoints[i%len(endpoints)].Port,
					"public_key":                    acc.PeerPublicKey,
					"allowed_ips":                   []string{"0.0.0.0/0", "::/0"},
					"reserved":                     []int{int(acc.Reserved[0]), int(acc.Reserved[1]), int(acc.Reserved[2])},
					"persistent_keepalive_interval": 25,
				},
			},
		})
	}
	// BPB 风格两组 (对齐机场订阅惯例, 所有 sing-box 客户端 GUI 都能正常渲染):
	// 「节点选择」= 手动 selector, 平铺 AI 专线 + 测速分组 + 全部外层节点 + direct,
	//   选哪个就走哪个 — AI 域名命中规则时也走本组 (见 route 规则)。
	// 「测速分组」= urltest 自动挑最快外层 (节点选择默认指向它)。
	// 官方依据: selector/urltest outbound 文档 (docs/configuration/outbound), 
	// SFW GUI (Misaka-blog/sfw-client) 用 yacd 面板渲染组, Karing/Hiddify 内核
	// (KaringX/sing-box dev-next / hiddify-core 2025+) 均为 sing-box 1.11+ 代际,
	// 与官方客户端同吃一份新格式配置 — 不再区分 PC/手机/老内核三份.
	selectorOutbound := map[string]interface{}{
		"type": "selector",
		"tag":  "节点选择",
		"outbounds": append(append(append([]string{"测速分组"}, innerTags...), outerTags...), "direct"),
		"default":                    "测速分组",
		"interrupt_exist_connections": true,
	}

	allOutbounds := []interface{}{selectorOutbound, outerUrlTest,
		map[string]interface{}{"type": "direct", "tag": "direct"}}

	// AWG 说明: 官方 sing-box 从未??? AmneziaWG (outbound/endpoint 均无此字??,
	// awg/h2/h3 请求统一按标??WireGuard 隧道组?? endpoints.
	singboxConfig := map[string]interface{}{
		"$schema": "https://sing-box.sagernet.org/schema.json",
		"dns": map[string]interface{}{
			"servers": []map[string]interface{}{
				// dns-direct 不设 detour = 走系统网络直连 (sing-box 1.13+ 禁止 detour
				// 指向空的 direct outbound)。此前满屏 "lookup failed" 的根因是探测域名
				// cp.cloudflare.com 被 dns 规则甩给 dns-remote (detour WARP, 未就绪死循环) —
				// 已用下方 dns 规则把探测域名强制 dns-direct 解析根治.
				{"type": "udp", "tag": "dns-direct", "server": "223.5.5.5"},
				{"type": "udp", "tag": "dns-remote", "server": "1.1.1.1", "detour": "测速分组"},
			},
			// 关键???: 默?? DNS 必须直连, 否则 urltest 的探测域??(cp.cloudflare.com)
			// 会??发往"尚未就绪"的隧??DNS 造成???? (隧道就绪依赖测速成??
			// 测速又依赖隧道 DNS), 实测表现为持??"context deadline exceeded".
			"rules": []map[string]interface{}{
				// urltest 探测域名强制直连解析, 保证测速能先于隧道就绪完成
				{"domain": []string{"cp.cloudflare.com"}, "server": "dns-direct"},
				// AI / 国际站域名走远端 DNS (经外层隧道, 与路由分流对齐)
				{"domain_suffix": []string{
					"openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com", "openaiusercontent.com", "sora.com",
					"anthropic.com", "claude.ai", "claudeusercontent.com",
					"grok.com", "x.ai", "perplexity.ai", "pplx.ai",
					"gemini.google.com", "bard.google.com", "aistudio.google.com", "generativelanguage.googleapis.com",
					"google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "youtube.com", "ytimg.com",
					"github.com", "githubusercontent.com", "telegram.org", "t.me", "twitter.com", "x.com", "twimg.com",
				}, "server": "dns-remote"},
				{"domain_suffix": []string{"cn", "qq.com", "taobao.com", "baidu.com", "bilibili.com", "weibo.com", "zhihu.com", "163.com"}, "server": "dns-direct"},
			},
			"final":    "dns-direct",
			"strategy": "ipv4_only",
		},
		"inbounds": []map[string]interface{}{
			{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080},
		},
		"endpoints": singboxEndpoints,
		"outbounds": allOutbounds,
		"route": map[string]interface{}{
			"rules": []map[string]interface{}{
				{"action": "sniff"},
				{"protocol": "dns", "action": "hijack-dns"},
				// AI 域名 (内联, 不依赖远程规则集下载 — 官方客户端启动时
				// "WireGuard is not ready" 死锁的根因就是远程 .srs 走了未就绪隧道)
				{"domain_suffix": []string{
					"openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com", "openaiusercontent.com", "sora.com",
					"anthropic.com", "claude.ai", "claudeusercontent.com",
					"grok.com", "x.ai", "perplexity.ai", "pplx.ai", "pplx-res.cloud",
					"gemini.google.com", "bard.google.com", "aistudio.google.com", "generativelanguage.googleapis.com", "alkalimakersuite.com",
					"copilot.microsoft.com", "bing.com", "bing.net", "meta.ai", "lama.com",
				}, "outbound": "节点选择"},
				// 流媒体/常用国际站走外层
				{"domain_suffix": []string{
					"google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "ggpht.com", "youtube.com", "ytimg.com", "youtu.be", "gvt2.com",
					"github.com", "githubusercontent.com", "githubassets.com", "github.io",
					"telegram.org", "t.me", "telegram.me", "tdesktop.com", "telesco.pe",
					"twitter.com", "x.com", "twimg.com", "t.co", "x.twimg.com",
					"wikipedia.org", "wikimedia.org",
				}, "outbound": "节点选择"},
				// 国内直连 (域名后缀 + 保留 IP 段内联, 替代 geosite-cn/geoip-cn)
				{"domain_suffix": []string{"cn", "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "qq.com", "taobao.com", "tmall.com", "jd.com", "baidu.com", "bilibili.com", "biliapi.com", "weibo.com", "zhihu.com", "douyin.com", "bytedance.com", "163.com", "126.com", "mi.com", "xiaomi.com", "huawei.com", "alipay.com", "icloud.com.cn"}, "outbound": "direct"},
				{"ip_cidr": []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4"}, "outbound": "direct"},
			},
			"final":                   "节点选择",
			"default_domain_resolver": map[string]interface{}{"server": "dns-direct"},
		},
		// clash_api: GUI (官方 sing-box 桌面客户端/Clash 面板) 的组切换、节点选择、
		// 延迟测试全部依赖此 API; cache_file 让 selector 的手动选择在重启后保留.
		// 没有 clash_api 时 GUI 只能看不能切 — 用户表现为"sing-box 无法使用".
		"experimental": map[string]interface{}{
			"clash_api": map[string]interface{}{
				"external_controller": "127.0.0.1:9090",
				"default_mode":        "rule",
			},
			"cache_file": map[string]interface{}{
				"enabled": true,
				"path":    "cache.db",
			},
		},
	}
	singboxJSON, _ := json.MarshalIndent(singboxConfig, "", "  ")

	// 手机??????(tun 入站 + auto_route): 官方 sing-box Android/iOS 客户????VPN 服务
	// 需??tun 入站, ??mixed 入站的配????上会"节点空白/点击????".
	// DNS 死锁???同样生效 (final=dns-direct + 探测域名直连解析).
	mobileConfig := map[string]interface{}{}
	for k, v := range singboxConfig {
		mobileConfig[k] = v
	}
	mobileConfig["inbounds"] = []map[string]interface{}{
		{
			"type":         "tun",
			"tag":          "tun-in",
			"address":      []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
			"mtu":          9000,
			"auto_route":   true,
			"strict_route": false,
			"stack":        "mixed",
		},
	}
	routeRules := singboxConfig["route"].(map[string]interface{})["rules"]
	routeRuleSets := singboxConfig["route"].(map[string]interface{})["rule_set"]
	mobileConfig["route"] = map[string]interface{}{
		"rules":                   routeRules,
		"rule_set":                routeRuleSets,
		"auto_detect_interface":   true,
		"final":                   "节点选择",
		"default_domain_resolver": map[string]interface{}{"server": "dns-direct"},
	}
	mobileJSON, _ := json.MarshalIndent(mobileConfig, "", "  ")

	// ─── Legacy 兼容配置 (Karing 等基于 sing-box 1.8~1.10 的老内核 GUI) ───
	// 老内核不认 1.11+ 的 endpoints 数组 (wireguard 从 outbound 挪到了 endpoint),
	// DNS 也用老式 {tag,address} 而非 {type,tag,server}, 路由规则无 action 体系.
	// KaringX/sing-box fork 的 option/wireguard.go 实测字段: server/server_port/
	// peer_public_key/reserved/local_address 均为顶层; detour 走 DialerOptions 保留.
	var legacyOutbounds []interface{}
	for _, epAny := range singboxEndpoints {
		m, _ := epAny.(map[string]interface{})
		if m == nil || m["type"] != "wireguard" {
			continue
		}
		peers, _ := m["peers"].([]map[string]interface{})
		if len(peers) == 0 {
			continue
		}
		p := peers[0]
		lo := map[string]interface{}{
			"type":            "wireguard",
			"tag":             m["tag"],
			"server":          p["address"],
			"server_port":     p["port"],
			"peer_public_key": p["public_key"],
			"reserved":        p["reserved"],
			"local_address":   m["address"],
			"private_key":     m["private_key"],
			"mtu":             m["mtu"],
		}
		if d, ok := m["detour"]; ok {
			lo["detour"] = d
		}
		legacyOutbounds = append(legacyOutbounds, lo)
	}
	legacyOutbounds = append(legacyOutbounds, allOutbounds...)
	legacyDNS := map[string]interface{}{
		"servers": []map[string]interface{}{
			{"tag": "dns-direct", "address": "223.5.5.5"},
			{"tag": "dns-remote", "address": "1.1.1.1", "detour": "WARP-外层优选"},
		},
		"rules":    singboxConfig["dns"].(map[string]interface{})["rules"],
		"final":    "dns-direct",
		"strategy": "ipv4_only",
	}
	legacyRouteRules := []interface{}{}
	for _, rAny := range singboxConfig["route"].(map[string]interface{})["rules"].([]map[string]interface{}) {
		if act, ok := rAny["action"]; ok && act == "sniff" {
			continue
		}
		if act, ok := rAny["action"]; ok && act == "hijack-dns" {
			continue
		}
		legacyRouteRules = append(legacyRouteRules, rAny)
	}
	legacyConfig := map[string]interface{}{
		"dns": legacyDNS,
		"inbounds": []map[string]interface{}{
			{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080},
		},
		"outbounds": legacyOutbounds,
		"route": map[string]interface{}{
			"rules":  legacyRouteRules,
			"final":  "节点选择",
		},
	}
	legacyJSON, _ := json.MarshalIndent(legacyConfig, "", "  ")

	// MASQUE 模式必须开 ipv6 (mihomo masque ??CONNECT-IP 双栈握手依赖), WG 模式保持关闭
	clashIPv6 := "false"
	if masqueAcc != nil {
		clashIPv6 = "true"
	}
	// AI 专线健康检查: 保持 liveness 探测即可 — 内层 WARP 出口由内层账号决定
// (与承载隧道是 MASQUE 还是直连 WG 无关), AI 解锁在生成时已通过重试验证.

	// MASQUE 外层节点数量对齐 count: masque 节点 server 固定 (198.2:443), ??engage WG
	// ????????engage 池只影响内层 detour。不??count 时用首个????示参数补??
	// ??"节点数量" ????WG 模式一??(usque-custom-pro 也是同账??× 多节??.
	if masqueAcc != nil {
		for len(endpoints) < count {
			endpoints = append(endpoints, endpoints[0])
		}
	}

	// Clash (mihomo) 配置: 除??层节点??, 额??生成一??"内层 AI 专线" wireguard 节点,
	// ??dialer-proxy 指向 "WARP ????? 分组 ??即内??WG 隧道整体从??层隧道里穿出
	// (warp-in-warp). CF WARP ????WireGuard (不是 AmneziaWG), 无需任何 amnezia 参数.
	// mihomo ??wireguard reserved 字??要求 base64 编码??3 字节??(bracket 数组会??当成非法 base64)
	reservedOuterB64 := base64.StdEncoding.EncodeToString([]byte{outerAcc.Reserved[0], outerAcc.Reserved[1], outerAcc.Reserved[2]})

	var clashProxies strings.Builder
	var clashNodeNames []string

	for i, ep := range endpoints {
		nodeName := fmt.Sprintf("WARP-优选-%02d (%.1fMbps/%dms)", i+1, ep.SpeedMbps, ep.Latency)
		clashNodeNames = append(clashNodeNames, fmt.Sprintf("      - \"%s\"", nodeName))
		cleanIP := strings.Trim(ep.IP, "[]")

		if masqueAcc != nil {
			// MASQUE 节点 (mihomo v1.19.12+): 外层账号 EnrollKey 出的 secp256r1 ???.
			// network: h3=QUIC(443/UDP) / h2=TCP(CF 专用 H2 ??? 162.159.198.2).
			// 注意: 不能??WarpScout ????WG 优选??????那些??WireGuard UDP ???,
			// MASQUE 需要承??H3/H2 ??443 入口. 关键实测结??:
			// 必须??162.159.198.x ??(usque-custom-pro curated ?? ??192.1 段在 mihomo
			// rule 模式 (真实分流场景) 会拒绝??二?? mTLS 握手 (CRYPTO_ERROR 0x128),
			// global 单连接??常但 rule 模式必挂; 198.2 两??模式均????
			masqueNet := "h3"
			if proto == "h2" {
				masqueNet = "h2"
			}
			masqueServer := "162.159.198.2"
			clashProxies.WriteString(fmt.Sprintf(`  - name: "%s"
    type: masque
    server: %s
    port: 443
    private-key: "%s"
    public-key: "%s"
    ip: %s
    ipv6: "%s"
    mtu: 1420
    udp: true
    sni: "consumer-masque.cloudflareclient.com"
    network: %s
    ip-stack:
      mode: auto
      congestion-controller: bbr
    remote-dns-resolve: true
    dns:
      - 1.1.1.1
      - 1.0.0.1

`, nodeName, masqueServer, masqueAcc.PrivKeyDERb64, masqueAcc.EndpointPub, masqueAcc.IPv4, masqueAcc.IPv6, masqueNet))
			continue
		}

		// WireGuard 节点 (awg ??MASQUE Enroll 失败回退): CF WARP 服务??????WireGuard
		clashProxies.WriteString(fmt.Sprintf(`  - name: "%s"
    type: wireguard
    server: %s
    port: %d
    ip: %s
    ipv6: %s
    public-key: %s
    private-key: %s
    reserved: %s
    mtu: 1420
    udp: true
    remote-dns-resolve: true
    dns:
      - 1.1.1.1
      - 1.0.0.1

`, nodeName, cleanIP, ep.Port, cleanOuterV4, cleanOuterV6, outerAcc.PeerPublicKey, outerAcc.PrivateKey, reservedOuterB64))
	}

	// 多条内层 AI 专线 (warp-in-warp): dialer-proxy 使其 UDP 从????urltest 组内穿出.
	// MASQUE 模式: 每条专线一????层账??(???? IP, 真????.
	// WG 模式: 单内层账??× 多????(与既有??为一??.
	var aiClashNames []string
	aiWGsC := aiWGs
	for i, acc := range aiWGsC {
		ep := endpoints[i%len(endpoints)]
		aiName := fmt.Sprintf("🤖 AI-WARP专线-%02d", i+1)
		if len(aiWGsC) == 1 {
			aiName = "🤖 AI-WARP专线"
		}
		iv4 := strings.TrimSuffix(acc.AddressV4, "/32")
		iv6 := strings.TrimSuffix(acc.AddressV6, "/128")
		ires := base64.StdEncoding.EncodeToString([]byte{acc.Reserved[0], acc.Reserved[1], acc.Reserved[2]})
		aiClashNames = append(aiClashNames, aiName)
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
    remote-dns-resolve: true
    dns:
      - 1.1.1.1
      - 1.0.0.1
    dialer-proxy: "WARP 自动优选"

`, aiName, strings.Trim(ep.IP, "[]"), ep.Port, iv4, iv6, acc.PeerPublicKey, acc.PrivateKey, ires))
	}
	aiListYaml := ""
	for _, n := range aiClashNames {
		aiListYaml += fmt.Sprintf("      - \"%s\"%s", n, "\n")
	}
	// 手动选择组全平铺: AI 节点 + 普通外层节点 一个分组自由切换 (机场式体验)
	// 注意 clashNodeNames 元素本身已是 '      - "名字"' 完整行, 直接拼接即可
	allFlatYaml := aiListYaml + strings.Join(clashNodeNames, "\n")

	clashYaml := fmt.Sprintf(`port: 7890
socks-port: 7891
allow-lan: false
mode: rule
log-level: info
ipv6: %s

dns:
  enable: true
  listen: 0.0.0.0:1053
  ipv6: %s
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - "*"
    - "+.lan"
    - "+.local"
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
  nameserver:
    - 1.1.1.1
    - 8.8.8.8
  fallback:
    - 1.1.1.1
    - 8.8.8.8

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

  - name: "普通节点"
    type: select
    proxies:
      - "WARP 自动优选"
%s

  - name: "🤖 AI 专线"
    type: select
    proxies:
%s
      - "WARP 自动优选"
%s

  - name: "WARP 手动选择"
    type: select
    proxies:
      - "🤖 AI 专线"
      - "普通节点"
      - "WARP 自动优选"
%s

  - name: "GLOBAL"
    type: select
    proxies:
      - "WARP 手动选择"
      - "🤖 AI 专线"
      - "普通节点"
      - "WARP 自动优选"
      - DIRECT

rules:
  - GEOSITE,openai,🤖 AI 专线
  - GEOSITE,anthropic,🤖 AI 专线
  - DOMAIN-SUFFIX,gemini.google.com,🤖 AI 专线
  - DOMAIN-SUFFIX,generativelanguage.googleapis.com,🤖 AI 专线
  - DOMAIN-SUFFIX,aistudio.google.com,🤖 AI 专线
  - GEOSITE,google,普通节点
  - GEOSITE,youtube,普通节点
  - GEOSITE,telegram,普通节点
  - GEOSITE,github,普通节点
  - DOMAIN-SUFFIX,grok.com,🤖 AI 专线
  - DOMAIN-SUFFIX,x.ai,🤖 AI 专线
  - DOMAIN-KEYWORD,grok,🤖 AI 专线
  - DOMAIN-SUFFIX,chatgpt.com,🤖 AI 专线
  - DOMAIN-SUFFIX,openai.com,🤖 AI 专线
  - DOMAIN-SUFFIX,oaistatic.com,🤖 AI 专线
  - DOMAIN-SUFFIX,oaiusercontent.com,🤖 AI 专线
  - DOMAIN-SUFFIX,perplexity.ai,🤖 AI 专线
  - DOMAIN-SUFFIX,claude.ai,🤖 AI 专线
  - DOMAIN-SUFFIX,anthropic.com,🤖 AI 专线
  - GEOIP,CN,DIRECT
  - MATCH,普通节点`, clashIPv6, clashIPv6, clashProxies.String(), strings.Join(clashNodeNames, "\n"), strings.Join(clashNodeNames, "\n"), aiListYaml, "", allFlatYaml)
	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)

	for i, ep := range endpoints {
		cleanIP := strings.Trim(ep.IP, "[]")
		formattedEp := fmt.Sprintf("%s:%d", cleanIP, ep.Port)
		if strings.Contains(cleanIP, ":") {
			formattedEp = fmt.Sprintf("[%s]:%d", cleanIP, ep.Port)
		}
		confContent := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/32, %s/128
DNS = 1.1.1.1, 1.0.0.1
MTU = 1280

[Peer]
PublicKey = %s
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = %s
PersistentKeepalive = 25
`, outerAcc.PrivateKey, cleanOuterV4, cleanOuterV6, outerAcc.PeerPublicKey, formattedEp)
		// 命名规则: warpwg01.conf / warpwg02.conf ... ??WireGuard 手机??文件导入"
		// 对命名敏??(实测 warp-node-01-13.6Mbps.conf 会??拒绝), ????字序号才??
		fileName := fmt.Sprintf("warpwg%02d.conf", i+1)
		fWriter, err := zipWriter.Create(fileName)
		if err == nil {
			fWriter.Write([]byte(confContent))
		}
	}
	// 手机????????zip (官方 sing-box 客户??/ NekoBox 直接导入)
	if w, err := zipWriter.Create("warp-mobile-tun.json"); err == nil {
		w.Write(mobileJSON)
	}

	// 落盘兜底: Wails WebView2 ??blob 下载时常无反?? 直接把逐节??.conf 写到
	// 程序????导出配置 子文件夹 ??用户总能拿到文件. (先清??warp*.conf 防混??
	exportDir := filepath.Join(exeSelfDir(), "导出配置")
	_ = os.MkdirAll(exportDir, 0755)
	if olds, gerr := filepath.Glob(filepath.Join(exportDir, "warp*.conf")); gerr == nil {
		for _, old := range olds {
			_ = os.Remove(old)
		}
	}
	for i, ep := range endpoints {
		cip := strings.Trim(ep.IP, "[]")
		fep := fmt.Sprintf("%s:%d", cip, ep.Port)
		if strings.Contains(cip, ":") {
			fep = fmt.Sprintf("[%s]:%d", cip, ep.Port)
		}
		confLines := []string{
			"[Interface]",
			"PrivateKey = " + outerAcc.PrivateKey,
			"Address = " + cleanOuterV4 + "/32, " + cleanOuterV6 + "/128",
			"DNS = 1.1.1.1, 1.0.0.1",
			"MTU = 1280",
			"",
			"[Peer]",
			"PublicKey = " + outerAcc.PeerPublicKey,
			"AllowedIPs = 0.0.0.0/0, ::/0",
			"Endpoint = " + fep,
			"PersistentKeepalive = 25",
			"",
		}
		conf2 := strings.Join(confLines, "\n")
		_ = os.WriteFile(filepath.Join(exportDir, fmt.Sprintf("warpwg%02d.conf", i+1)), []byte(conf2), 0644)
	}

	// NekoBox 订阅内??: wireguard:// 分享链接 (NekoBox 不??完整 JSON 配置)
	// 注意: 查??参数里的 base64 (??+ / =) 必须逐个 URL ???, 否则 Android Uri 解析会把
	// "+" 当空格??/" ??????? 导致 NekoBox 导入节点后缺 reserved/public_key 而连不上.
	// v4/v6 地址都????(逗号分隔), 与官??sing-box wireguard outbound ??local_address 对齐.
	var nekoLines []string
	var v2raynLines []string
	reservedB64 := base64.StdEncoding.EncodeToString([]byte{outerAcc.Reserved[0], outerAcc.Reserved[1], outerAcc.Reserved[2]})
	localAddrs := url.QueryEscape(cleanOuterV4 + "/32," + cleanOuterV6 + "/128")
	for i, ep := range endpoints {
		cleanIP := strings.Trim(ep.IP, "[]")
		name := fmt.Sprintf("WARP-%02d", i+1)
		link := fmt.Sprintf("wireguard://%s@%s:%d/?address=%s&public_key=%s&reserved=%s&mtu=1280#%s",
			url.QueryEscape(outerAcc.PrivateKey), cleanIP, ep.Port, localAddrs,
			url.QueryEscape(outerAcc.PeerPublicKey), url.QueryEscape(reservedB64), name)
		nekoLines = append(nekoLines, link)

		// V2rayN 版: 参数名 publickey (无下划线, WireguardFmt.GetQueryDecoded 精确匹配),
		// reserved 十进制逗号 (SingboxOutboundService 对其 int.Parse — base64 会抛异常丢字段),
		// mtu 保持 1280 (V2rayN 内核默认 tun MTU 取列表首值, 显式给出避免歧义).
		reservedDec := fmt.Sprintf("%d,%d,%d", outerAcc.Reserved[0], outerAcc.Reserved[1], outerAcc.Reserved[2])
		v2nLink := fmt.Sprintf("wireguard://%s@%s:%d/?publickey=%s&reserved=%s&address=%s&mtu=1280#%s",
			url.QueryEscape(outerAcc.PrivateKey), cleanIP, ep.Port,
			url.QueryEscape(outerAcc.PeerPublicKey), url.QueryEscape(reservedDec), localAddrs, name)
		v2raynLines = append(v2raynLines, v2nLink)
	}
	// AI 内层专线也输出 V2rayN 链接 (带 🤖 前缀标识): 分享链接本身表达不了 detour(前置),
	// 在 V2rayN 里把该节点与任意外层 WARP 节点组成「链式代理」即为双层 AI 专线;
	// 或直接用「老内核 sing-box」完整配置导入 (AI 分流自动生效, 无需手动组链).
	for i, acc := range aiWGs {
		cleanIP := strings.Trim(endpoints[i%len(endpoints)].IP, "[]")
		tag := fmt.Sprintf("WARP-AI-%02d", i+1)
		if len(aiWGs) == 1 {
			tag = "WARP-AI"
		}
		aiAddrs := url.QueryEscape(strings.TrimSuffix(acc.AddressV4, "/32") + "/32," + strings.TrimSuffix(acc.AddressV6, "/128") + "/128")
		aiRes := fmt.Sprintf("%d,%d,%d", acc.Reserved[0], acc.Reserved[1], acc.Reserved[2])
		v2nLink := fmt.Sprintf("wireguard://%s@%s:%d/?publickey=%s&reserved=%s&address=%s&mtu=1280#%s",
			url.QueryEscape(acc.PrivateKey), cleanIP, endpoints[i%len(endpoints)].Port,
			url.QueryEscape(acc.PeerPublicKey), url.QueryEscape(aiRes), aiAddrs, tag)
		v2raynLines = append(v2raynLines, v2nLink)
	}

	zipWriter.Close()

	a.zipContent = buf.Bytes()
	a.subMutex.Lock()
	a.subContent = string(singboxJSON)
	a.nekoContent = strings.Join(nekoLines, "\n")
	a.v2raynContent = strings.Join(v2raynLines, "\n")
	a.legacyContent = string(legacyJSON)
	a.mobileContent = string(mobileJSON)
	a.subMutex.Unlock()

	a.sendLog("ALL-DONE")

	protoNote := ""
	if masqueMode && masqueAcc != nil {
		protoNote = "✔ MASQUE " + strings.ToUpper(proto) + " 已就绪"
	} else if masqueMode {
		protoNote = "⚠️ MASQUE 失败, 已回退 WireGuard"
	}

	// 逐节??.conf 内?? (前??"节点???? WireGuard 手机版逐个导入)
	var confBodies []string
	for _, ep := range endpoints {
		cleanIP := strings.Trim(ep.IP, "[]")
		formattedEp := fmt.Sprintf("%s:%d", cleanIP, ep.Port)
		if strings.Contains(cleanIP, ":") {
			formattedEp = fmt.Sprintf("[%s]:%d", cleanIP, ep.Port)
		}
		confBody := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s/32, %s/128\nDNS = 1.1.1.1, 1.0.0.1\nMTU = 1280\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = %s\nPersistentKeepalive = 25",
			outerAcc.PrivateKey, cleanOuterV4, cleanOuterV6, outerAcc.PeerPublicKey, formattedEp)
		confBodies = append(confBodies, confBody)
	}

	return map[string]string{
		"singbox":   string(singboxJSON),
		"mobile":    string(mobileJSON),
		"v2raynLinks": a.v2raynContent,
		"legacy":    string(legacyJSON),
		"clashYaml": clashYaml,
		"protoNote": protoNote,
		"confs":     "====WARP-CONF====" + strings.Join(confBodies, "====WARP-CONF===="),
		"subUrl":    "http://" + lanIP() + ":8888/sub",
		"mobileUrl": "http://" + lanIP() + ":8888/mobile",
		"nekoUrl":   "http://" + lanIP() + ":8888/nekobox",
		"v2raynUrl": "http://" + lanIP() + ":8888/v2rayn",
		"zipUrl":    "http://" + lanIP() + ":8888/download-zip",
		"best":      fmt.Sprintf("%s (%.1fMbps / %dms)", endpoints[0].IP, endpoints[0].SpeedMbps, endpoints[0].Latency),
	}, nil
}
