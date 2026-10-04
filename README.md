# NyaPassword 桌面端（desktop）

NyaPassword 的桌面客户端：Tauri 2 外壳 + 共享界面（`../common/web`，`vite --mode desktop` 构建）+ 原生客户端核心（`npw-core`，本地副本存 SQLite）。Windows 为主；macOS / Linux 同时构建，没有实机测试，标“实验性”。

设计见 [../common/docs/设计方案.md](../common/docs/设计方案.md)（§4.5 本地解锁、§8.6 离线导出、§10.3 桌面端），进度见 [../common/docs/开发计划.md](../common/docs/开发计划.md)。

## 功能

- **完整的密码库界面**：与网页版同一套界面（登录 / 注册、三栏主界面、编辑、生成器、TOTP、附件、导入导出、安全检查、设置），核心在本机原生运行（Argon2 比 WASM 快）。离线也能用主密码解锁。
- **本地副本**：`<本地应用数据>/app.nya.password/replica.sqlite3`（Windows：`%LOCALAPPDATA%\app.nya.password\`），只有密文。保护 Secret Key 和会话的设备密钥（32 字节随机数）存在系统凭据存储：Windows 凭据管理器 / macOS 钥匙串 / Linux Secret Service；系统凭据存储不可用时退回到同目录的 `device-key.bin`（设置页会提示）。
- **Windows Hello 快速解锁**：在“设置 → 解锁与锁定”开启。开启时 Windows Hello 创建密钥 `NyaPassword.<账户 ID>` 并对随机 32 字节挑战签名，签名经 HKDF-SHA256 得到包装密钥，包装账户密钥后与挑战一起存到 `quick-unlock.json`。规则：每次启动应用后第一次必须输入主密码；距上次输入主密码超过 14 天也必须输入；Windows Hello 密钥失效（重置 PIN 等）时自动关闭。关闭时删除系统中的密钥和文件。macOS（Touch ID）/ Linux 暂不支持。
- **托盘与后台**：关闭窗口只是隐藏到托盘；托盘菜单：显示 / 隐藏、锁定、立即同步、退出。单实例（再次启动只会把已有窗口调到前面）。可设置开机启动（直接最小化到托盘）。
- **自动锁定**：空闲超时（界面设置）、系统锁屏 / 注销 / 切换用户 / 休眠时立即锁定（Windows：WTS 会话通知 + 电源广播）。锁定会清掉解密数据和尚未确认的导入。
- **剪贴板**：复制的密码 90 秒后（若剪贴板里仍是它）以及退出应用时清除；Windows 上同时设置 `ExcludeClipboardContentFromMonitorProcessing`、`CanIncludeInClipboardHistory = 0`、`CanUploadToCloudClipboard = 0`，不进剪贴板历史、不上传云剪贴板。
- **定期离线导出**（见下）。
- **自更新**（见下）。

尚未实现（后续阶段）：全局快捷键快捷搜索 / 自动输入、SSH agent、浏览器扩展联动（Native Messaging）、Windows passkey 提供程序；macOS Touch ID、macOS / Linux 锁屏检测。

### 定期离线导出

“设置 → 定期离线导出”：选择文件夹、间隔（默认每周）、格式（原生加密 `.npwexport` 和 / 或 KDBX `.kdbx`）、保留份数（默认 8）。文件名 `NyaPassword-<日期>.npwexport` / `NyaPassword-<日期>.kdbx`，每种格式只保留最近 N 份；文件夹里其他文件不会被动。

导出需要主密码，而本应用**从不保存主密码**，所以做法是“到期提醒 + 一键完成”：

- 到期后，下一次**用主密码解锁**（或登录）时，应用趁这次解锁调用里主密码本来就在内存中，在后台完成导出，完成后立即丢弃；界面会提示成功或失败。用 Windows Hello 解锁时没有主密码，不会导出——但每次启动后第一次总是要输入主密码，所以不会拖太久。
- 也可以在设置里输入主密码“立即导出”。
- 原生格式需要主密码 + Secret Key 才能打开（无损，可再导入 NyaPassword）；KDBX 只用主密码保护，KeePassXC 可直接打开，是“软件都不在了”时的逃生通道。导出文件夹建议放在加密盘或离线介质上。

### 自更新

“设置 → 更新”检查 GitHub Releases 的最新正式版（也可以每天自动检查）。Windows 安装版可一键更新：下载 `NyaPassword_<版本>_x64-setup.exe`，先用内置的 minisign 公钥校验 `SHA256SUMS.minisig`，再核对安装包的 SHA-256，**签名或校验和不对就拒绝更新**；通过后静默运行安装程序（`/S /UPDATE /R`，装完自动重新打开）并退出。便携版、macOS、Linux 只提示新版本并打开发布页。

更新仓库和公钥在构建时编译进程序：`NPW_UPDATE_REPO`（默认 `example/NyaPassword-desktop`，发版 workflow 设为当前仓库）、`NPW_UPDATE_PUBKEY`（minisign 公钥的 base64 行；没有则此版本不自动更新）。

## 仓库关系

和 `../common` 并列检出：`src-tauri` 通过 path 依赖使用 common 的 `npw-core`、`npw-store-sqlite`、`npw-crypto` 等；界面来自 `../common/web`（`npm --prefix ../common/web run build:desktop` 输出到 `../common/web/dist-desktop`，不需要 WASM）。共享 `../target` 输出目录（`.cargo/config.toml`，Windows 静态链接 CRT）。发版时 `COMMON_REF` 固定 common 的提交。

```
desktop/
├─ src-tauri/            Tauri 应用（crate nyapassword-desktop）
│  └─ src/
│     ├─ commands.rs     与界面 Bridge 接口一一对应的命令 + 桌面端设置 / 导出 / 更新
│     ├─ pure.rs         同步函数（TOTP、生成器、强度……）走 npwsync: 协议
│     ├─ quick_unlock.rs 快速解锁的密钥包装与规则
│     ├─ export.rs       定期离线导出与清理
│     ├─ updater.rs      自更新（minisign + SHA-256）
│     ├─ device_key.rs   设备密钥
│     └─ platform/       Windows / macOS / Linux 实现（凭据存储、快速解锁、剪贴板、锁屏、开机启动）
├─ tools/update-sign/    生成更新签名密钥、签名 SHA256SUMS（minisign 格式）
└─ scripts/              release.ps1、new-update-key.ps1
```

## 开发

需要 Rust（stable）、Node.js 24；Windows 需要 VS Build Tools 和 WebView2（Windows 11 自带）；Linux 需要 `libwebkit2gtk-4.1-dev` 等（见 `.github/workflows/ci.yml`）。

```powershell
npm ci --prefix ..\common\web
npm ci
npm run dev                  # vite --mode desktop（5180 端口）+ tauri dev
npm run web                  # 只构建界面（cargo build / test 前需要它，Rust 会把界面嵌入程序）
cargo test --workspace       # 单元测试：快速解锁包装、导出清理、更新签名校验、设备密钥……
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check            # 不要加 --all：那会连 ../common 的 path 依赖一起格式化
```

本地测试服务端：在 `../server` 里 `cargo run -- --data .\data`（监听 `127.0.0.1:8087`），桌面端登录界面的服务器填 `http://127.0.0.1:8087`（http 只允许 localhost）。

## 构建

```powershell
npm run build                # = tauri build：先构建界面，再出安装包
npx tauri build --bundles nsis
```

Windows 安装包在 `..\target\release\bundle\nsis\NyaPassword_<版本>_x64-setup.exe`（按当前用户安装，不需要管理员权限）。

## 发布

```powershell
.\scripts\release.ps1 0.1.0          # 改 VERSION / Cargo.toml / package.json / tauri.conf.json、写 COMMON_REF、提交并打 tag
git push origin HEAD v0.1.0
```

推送 tag 后 GitHub Actions 用固定的 common 提交测试并构建：`NyaPassword_<版本>_x64-setup.exe`、`NyaPassword_<版本>_windows_x64.zip`（便携版）、`NyaPassword_<版本>_macos_arm64.dmg`、`NyaPassword_<版本>_macos_x64.dmg`、`NyaPassword_<版本>_linux_x64.AppImage`、`NyaPassword_<版本>_linux_x64.deb`，再生成 `SHA256SUMS` 并签名为 `SHA256SUMS.minisig`，发布 Release（带后缀的版本为预发布）。macOS 版没有 Apple 公证，首次打开需在“系统设置 → 隐私与安全性”里放行。

仓库 secrets：

| secret | 用途 |
|---|---|
| `COMMON_DEPLOY_KEY` | 检出私有的 common 仓库（只读部署密钥） |
| `NPW_UPDATE_PRIVATE_KEY` | 更新签名私钥（minisign，无口令），签 `SHA256SUMS` |
| `NPW_UPDATE_PUBKEY` | 对应公钥的 base64 行，编译进程序 |

生成更新签名密钥（只需一次，私钥放在仓库之外的 `..\signing\`，并离线备份）：

```powershell
.\scripts\new-update-key.ps1                    # 生成 ..\signing\nyapassword-update.key / .pub
.\scripts\new-update-key.ps1 -SetGitHubSecrets  # 用 gh 设置上面两个 secret（沿用已生成的密钥）
```

更换密钥后，旧版本只信任旧公钥，用户需要手动安装一次新版本。
