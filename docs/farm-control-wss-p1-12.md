# BF-P1.12 outbound Control WSS

`NewFarmControlWSSClient(config, adapter)` 提供 Wails-free production Agent transport；adapter 必須由現有 `NewFarmRuntimeControlAdapter(sharedFarmService)` 建立，node UID 必須一致。已配置的 P1.6 Ed25519 key 只在記憶體使用，`Connect(ctx)` 完成 challenge/prove 及 authenticated ack 後才 dispatch。

跨主機連線必須 `wss://` 並驗證 server TLS；僅 loopback 測試允許 `ws://`。64 KiB message limit、最多 16 個 in-flight commands、handshake/command/heartbeat deadlines 都會 fail closed。`Close()` 與 context cancellation 可並行，客戶端不可重複 Connect；此 gate 不自動 reconnect。`Done()` 表示通道已結束，`Err()` 回傳原因。

斷線停止命令等待及後續 dispatch，遲到的 shared service 結果不回送。已進入 shared service 的 bounded lifecycle operation 仍由既有 process owner 負責，persistent Chrome 留給後續 inventory/reconcile；通道關閉不會呼叫全域 Shutdown。P1.12 沒有 proxy、CDP tunnel、gateway 或 relay。

驗證依序執行，勿同時跑普通及 race suite：

```sh
go test ./backend -run 'TestFarm(ControlWSSClient|Runtime|Attestation)' -count=1
go test -race ./backend -run 'TestFarm(ControlWSSClient|Runtime|Attestation)' -count=1
P112_CROSS_REPO_REAL_CHROME=1 P112_SERVER_REPO=/path/to/auto-scraper go test ./backend -run '^TestFarmRuntimeP112CrossRepoRealChrome$' -count=1 -v
```

真 Chrome 預設在 `/Applications` 找 core，可設 `P112_REAL_CHROME_CORE`。跨 repo fixture 是 Server 的 `輔助程式/p1_12_control_wss_fixture.py`；使用真 TLS、正式 Python ControlWSS handler、Ed25519 auth、production readiness orchestrator 與正式 Go client。只有 store/key/profile 是隔離測試資源。Agent applied fields 源自實際 shared launch plan 和 owned runtime snapshot；空 locale/timezone 表示未配置 override。no-proxy 旗標由正式 shared launch builder 產生。

2026-09-07：focused ordinary/race PASS；真跨 repo Chrome E2E PASS，完整命令結果由 `-v` 輸出供稽核。E2E 確認 ensure → verify attestation → idle/debug_ready status → strict stop、process reap、debug port 關閉。這是 P1.12 readiness 證據，不包含 live Control DB、authenticated proxy 或 CDP attach 驗收。
