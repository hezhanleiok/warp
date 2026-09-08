# WarpScout-Chain

极简单文件 Windows GUI 客户端，硬编码 **Warp-on-Warp（双层 WARP 嵌套链式代理）**，解决中国大陆网络环境下直连 WARP 被封锁以及出口 IP 位于国内/香港导致 AI 平台被拒的问题。

## 架构原理
- **外层隧道 (Outer Tunnel)**: AmneziaWG (AWG) 或 MASQUE (H2/H3 CONNECT-UDP)，直连大陆低延迟 Cloudflare Anycast 边缘 IP，突破 GFW 阻断。
- **内层隧道 (Inner Tunnel)**: Standard WireGuard，在外层加密安全管道中向 Cloudflare 发起二次握手，分配海外纯净出口 IP（美/日/新等），解锁 OpenAI / Claude / Gemini。

## 目录结构
```
warpscout-chain/
├── .github/workflows/build.yml   # GitHub Actions 自动化 Windows 单文件编译
├── frontend/
│   └── index.html                # 现代暗黑响应式 GUI 界面 (无额外 npm 编译依赖)
├── main.go                       # Wails v2 应用程序入口
├── app.go                        # 核心控制器：扫描测速、双账号注册、链式组装与本地订阅
├── go.mod                        # Go 模块定义
├── wails.json                    # Wails 项目配置文件
└── README.md                     # 说明文档
```

## 云端零环境打包 (GitHub Actions)
1. 将本项目所有代码上传至 GitHub 仓库。
2. 进入仓库页面的 **Actions** 标签页。
3. 选择 **Build Windows Exe** 工作流，点击 **Run workflow**。
4. 编译完成后，在 **Artifacts** 区域即可直接下载打包好的单文件 `WarpScoutChain.exe`。
