# Proxy Connector Stack Contract

本文件是 Ant Browser 代理連接棧的 normative contract。所有瀏覽器實例啟動、测速、真实连通性、IP 健康、預熱及代理下載都必須帶入同一個明確的 connector stack。不得因協議、內核缺失或暫時錯誤，自動切換到另一套 stack。

## 1. Connector 定義

### `xray`：Xray + sing-box 組合棧

`browser.default_connector_type=xray` 代表組合棧，而不是「所有代理都由 Xray 處理」：

- Xray 負責 vmess、vless、trojan、shadowsocks 及鏈式代理等協議。
- sing-box 負責 hysteria2、tuic、anytls 等協議。
- 組合棧內的 Xray 與 sing-box 是允許的協議分工；Mihomo 不屬於此 stack。
- 若協議沒有明確的組合棧實作，必須回傳 unsupported，而不是猜測或 fallback。

### `mihomo`：獨立 Mihomo 棧

`browser.default_connector_type=mihomo` 代表獨立 Mihomo 棧：

- 代理解析、設定產生、bridge 啟動及所有驗證均由 Mihomo 完成。
- 不得呼叫 Xray 或 sing-box 作為 fallback，也不得因 Mihomo binary 暫時不可用而改用其他 core。
- Mihomo 不支援的協議必須 fail closed。

### 直連與非法值

- `direct://` 是明確的無代理例外，不屬於任何 connector stack。
- 除 `direct://` 外，任何 proxy config 都必須經選定 stack 建立 bridge 或 stack-owned client。
- 空值、未知 connector、未知協議、stack 不支援的協議、缺失 binary、bridge 啟動失敗及 policy conflict 均必須 fail closed。
- `PreferredKernel` 只能在所選 stack 內生效；跨 stack 的 preference 必須拒絕，不能靜默覆寫。

## 2. 禁止混用矩陣

| 操作 | `xray` 組合棧允許 | `mihomo` 獨立棧允許 | 明確禁止 |
| --- | --- | --- | --- |
| Instance launch | vmess/vless/trojan/ss/chain → Xray；hysteria2/tuic/anytls → sing-box；最後只交給 Chrome 本機 bridge | 所有 Mihomo 支援的協議 → Mihomo 本機 bridge | Xray stack 使用 Mihomo；Mihomo stack 使用 Xray/sing-box；代理 URI credentials 直接放入 Chrome args |
| Speed test | `SpeedTestWithConnector(..., "xray")`，使用相同協議分工 | `SpeedTestWithConnector(..., "mihomo")`，只建立 Mihomo client/bridge | 測速 resolver 忽略 connector、缺 core 時換另一 stack |
| Real connectivity | `TestRealConnectivityWithRuntimeConfig` 使用 `xray` 並沿用同一 bridge policy | 同一 API 使用 `mihomo` | generic auto resolver、不同於 instance launch 的 kernel、native proxy 旁路 |
| IP health | IP health client 使用 `xray` 組合棧 | IP health client 使用 `mihomo` | 用另一 stack 的出口或未帶 connector 的 diagnostics/client |
| Warmup | 預熱必須帶入 `xray`，只預熱 Xray/sing-box 組合棧需要的 bridge | 預熱必須帶入 `mihomo`，只預熱 Mihomo bridge | warmup 呼叫 `ResolveProxyKernel(..., "")` 或因 bridge 失敗改用其他 stack |
| Proxy download | subscription/core download 的 HTTP client 必須由 `xray` stack 建立 | subscription/core download 的 HTTP client 必須由 `mihomo` stack 建立 | 自行建立未經 connector 的 `http.Transport`、system proxy、另一 stack 或未授權的 native fallback |

對所有操作適用以下硬規則：

1. connector type 必須在 operation boundary 正規化並傳入 resolver/client；不能只依賴全域 mutable state。
2. resolver 的輸出必須包含 selected stack、selected engine、protocol 及 policy decision，供後續 operation 驗證；缺少或不一致時拒絕執行。
3. stack 內的協議分工只能是明確白名單。Xray stack 的 sing-box 協議不是「Xray 不支援」而改用 Mihomo。
4. binary missing、設定預檢失敗、port bind 失敗、健康檢查失敗都只回傳錯誤；不得跨 stack retry。
5. 同一 proxy 的 launch、speed、connectivity、IP health、warmup、download 必須使用同一 stack policy，不能各自 auto-select。

## 3. Secure writer 與 credentials 邊界

所有 Xray、sing-box、Mihomo runtime config 都可能含 proxy credentials，必須由共用 secure writer 產生：

- Unix runtime directory 使用 0700，config/log/stderr file 使用 0600；採 atomic write，避免先以寬鬆 mode 建檔。
- Windows 使用 owner-only DACL；單純 `os.WriteFile` mode 不足以滿足要求。
- Chrome command line、一般 log、error response、diagnostic payload 不得出現完整 proxy URI、password、token 或 credential-bearing args。
- stop、bridge release、startup orphan sweep 必須刪除或安全回收 credentials-bearing config；留下的 audit metadata 不得含 secret。
- secure writer 只能寫入被選定 stack 的 schema，不得讓一個 stack 的設定檔被另一個 manager 重用。

## 4. 目前 code path 與差距

目前 Browser launch 的主路徑是：

```text
BrowserInstanceStart
  → browserInstanceStartInternal
  → prepareBrowserStartPlan
  → resolveBrowserStartProxy
  → ResolveProxyKernelForConnector
  → XrayManager / SingBoxManager / ClashManager
  → Chrome --remote-debugging-port + local proxy bridge
```

主要位置：

- `backend/app_instance_start.go`
- `backend/app_instance_start_prepare.go`
- `backend/app_instance_start_proxy.go`
- `backend/app_instance_start_execute.go`
- `backend/internal/proxy/kernel_resolver.go`

已知差距：

| 位置 | 現況 | 差距 |
| --- | --- | --- |
| `backend/internal/proxy/kernel_resolver.go` | `ResolveProxyKernelForConnector` 最終仍呼叫通用 `ResolveProxyKernel`；`mihomo` 主要是 preference | connector 不是 hard boundary，可能自動選出另一 stack；需改為 policy-aware、fail-closed resolver |
| `backend/app_instance_start_proxy.go` | launch 讀取 default connector，並可啟動三種 manager | 不能保證組合棧排除 Mihomo；raw `profile_proxy_config`、`temporary_proxy_config`、`resolved_proxy_config` 會寫入 log |
| `backend/app_proxy_query.go:104-115` | `warmupProxyBridge` 使用 `ResolveProxyKernel(src, proxies, proxyId, "")` | 完全忽略 current connector，違反 warmup 矩陣 |
| `backend/internal/proxy/page_probe.go:41-54` | page probe hardcode `BrowserConnectorXray` | 不是 stack-neutral，也不能測試 Mihomo stack 的真實出口 |
| `backend/internal/proxy/diagnostics.go` | 使用 generic resolver | diagnostics 可能觀察到與實際 operation 不同的 kernel |
| `backend/app_proxy_import.go` | subscription fetch 已有 connector-aware client 路徑 | 需補 hard-boundary assertion 與錯誤時禁止 fallback |
| `backend/app_proxy_core_download_http.go`、`backend/internal/browser/download_core_task.go` | 部分 core download 使用自建 transport/`url.Parse` | 可繞過 active connector stack，需統一經 stack-owned download client |
| `backend/internal/proxy/xray_runtime_config.go` | dir 0755、config 0644 | 不符合 secure writer 的 0700/0600 |
| `backend/internal/proxy/singbox_runtime_helpers.go` | dir 0755、config 0644 | 不符合 secure writer 的 0700/0600 |
| `backend/internal/proxy/mihomo_bridge.go` | dir 0755、config 0644 | 不符合 secure writer 的 0700/0600 |
| `backend/app_instance_start_execute.go` | log `proxy` 與完整 Chrome args | 可能洩漏 native proxy credentials 或 credential-bearing args |

## 5. 驗收測試

### 5.1 Policy/unit tests

新增或擴充 `backend/internal/proxy/connector_policy_test.go`，至少覆蓋：

- `xray` + vmess/vless/trojan/ss/chain → Xray。
- `xray` + hysteria2/tuic/anytls → sing-box。
- `xray` 對 Mihomo-only protocol、Mihomo preference、缺失 core → 拒絕，不能 fallback。
- `mihomo` 對所有支援協議 → Mihomo；Xray/sing-box preference → 拒絕。
- unknown connector、unknown protocol、empty config、missing binary、bridge failure → fail closed。
- `direct://` 僅走明確 direct exception。

既有相關測試入口：

- `backend/internal/proxy/kernel_resolver_test.go`
- `backend/internal/proxy/mihomo_protocol_test.go`
- `backend/internal/proxy/protocol_regression_test.go`
- `backend/internal/proxy/singbox_anytls_test.go`
- `backend/internal/proxy/singbox_tuic_test.go`
- `backend/internal/proxy/xray_chain_test.go`

### 5.2 Operation matrix tests

對兩套 connector 各自建立 launch、speed、real connectivity、IP health、warmup、proxy download 的 table-driven matrix。每個 test 都應斷言：

- selected connector 與 requested connector 相同。
- selected engine 屬於該 stack 的白名單。
- fallback 到另一 stack 時 operation 失敗且回傳可判斷的 policy error。
- 同一 proxy 在六個 operation 使用相同 stack decision。

應補測 `warmupProxyBridge`、page probe、diagnostics、subscription/core download，避免只測 Browser launch。

### 5.3 Secure writer tests

- Unix：assert directory mode 0700、config/log/stderr mode 0600、atomic replacement 及 cleanup。
- Windows：real Windows runner 驗證 owner-only DACL、non-owner read denied。
- log capture：完整 proxy URI、password、token、Chrome args 均不可出現。
- orphan sweep：程序異常退出後 config 可安全回收，且 audit metadata 不含 secret。

### 5.4 Integration/E2E

在真實 Xray、sing-box、Mihomo binaries 和真實 Chrome 上執行：

1. 建立代理 bridge。
2. 啟動 Chrome。
3. 以 loopback endpoint 做真實 connectivity/IP assertion。
4. 驗證六類 operation 均未跨 stack。
5. 驗證 core 缺失、bridge crash、port collision 時不會改用另一 stack。

目前 repo 尚無完整 connector matrix、secure writer 或 farm/CDP gateway E2E；`go test ./...` 需在 Go toolchain 安裝後執行。

## 6. Toolchain 前置條件

`go.mod` 宣告：

```text
go 1.22.0
```

目前沒有 `toolchain` directive，且執行環境沒有 `go`。最安全的取得方式是：

1. 依 repository 的 `go 1.22.0` 選定並 pin 一個 Go 1.22 patch release，不直接使用會漂移的 `brew install go` latest。
2. 從官方 Go distribution 下載與 host OS/arch 相符的 archive，核對官方 SHA256；在團隊 CI 以同一 checksum/cache 重用。
3. 使用 `GOTOOLCHAIN=local`，避免測試時自動下載或自動升級 toolchain；先驗證 `go version`、`go env GOTOOLCHAIN`、`go mod verify`。
4. 在 macOS 另確認 Xcode Command Line Tools/clang；Farm E2E 另需真實 Windows、Linux、macOS runner 及對應 Chrome、Xray、sing-box、Mihomo binaries。
5. Toolchain ready 後先跑 `go test ./...`，再跑 connector matrix、secure writer platform tests 及 real-core E2E。
