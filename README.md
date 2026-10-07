# NyaPassword 桌面端（desktop）

NyaPassword 的桌面客户端：Tauri 2 外壳 + 共享界面（`../common/web`，`vite --mode desktop` 构建）+ 原生客户端核心（`npw-core`，本地副本存 SQLite）。Windows 为主；macOS / Linux 同时构建，没有实机测试，标“实验性”。

设计见 [../common/docs/设计方案.md](../common/docs/设计方案.md)（§4.5 本地解锁、§8.6 离线导出、§10.3 桌面端），进度见 [../common/docs/开发计划.md](../common/docs/开发计划.md)。

## 功能

- **完整的密码库界面**：与网页版同一套界面（登录 / 注册、三栏主界面、编辑、生成器、TOTP、附件、导入导出、安全检查、设置），核心在本机原生运行（Argon2 比 WASM 快）。离线也能用主密码解锁。
- **本地副本**：`<本地应用数据>/app.nya.password/replica.sqlite3`（Windows：`%LOCALAPPDATA%\app.nya.password\`），只有密文。保护 Secret Key 和会话的设备密钥（32 字节随机数）存在系统凭据存储：Windows 凭据管理器 / macOS 钥匙串 / Linux Secret Service；系统凭据存储不可用时退回到同目录的 `device-key.bin`（设置页会提示）。
- **Windows Hello 快速解锁**：在“设置 → 解锁与锁定”开启。开启时 Windows Hello 创建密钥 `NyaPassword.<账户 ID>` 并对随机 32 字节挑战签名，签名经 HKDF-SHA256 得到包装密钥，包装账户密钥后与挑战一起存到 `quick-unlock.json`。“启动时可直接用生物识别解锁”（默认开）：应用重启后也可以直接用 Windows Hello；关掉则每次启动后第一次要输入主密码。Windows Hello 密钥不见了（重置 Windows Hello）或解不开包装时自动关闭并要求主密码。关闭时删除系统中的密钥和文件。macOS（Touch ID）/ Linux 暂不支持。
- **PIN 解锁**：“设置 → 解锁与锁定 → PIN 解锁”设置 / 修改 / 删除。PIN 至少 4 个字符（任意字符）；核心用 `Argon2id(NFKD(PIN), 随机盐, 账户的 KDF 参数)` 包装账户密钥，结果和尝试次数一起存进 Windows 凭据管理器（条目 `app.nya.password` / `unlock-guard`，DPAPI 保护，不在任何文件里，不上传）。每次尝试前先把次数写回，连续 5 次错误删除 PIN；锁屏的 PIN 输入框显示剩余次数。设备密钥退回到 `device-key.bin` 文件时不能设置 PIN。重启后可用。
- **14 天规则**：Windows Hello 和 PIN 都只在距上次在本机输入主密码不到 14 天时可用，到期后暂停（锁屏会说明原因），输入主密码即恢复。上次输入主密码的时间和 PIN 在同一条凭据存储记录里，改 `settings.json` 不能延长；系统时间比应用见过的最晚时间早 10 分钟以上也会暂停。在本机修改主密码后，Windows Hello 和 PIN 都被清除，需要重新设置。规格见 [加密规格.md](../common/docs/加密规格.md) §4.4、§4.5，风险见 [威胁模型.md](../common/docs/威胁模型.md) §3.8.2。
- **托盘与后台**：关闭窗口只是隐藏到托盘；托盘菜单：显示 / 隐藏、锁定、立即同步、退出。单实例（再次启动只会把已有窗口调到前面）。可设置开机启动（直接最小化到托盘）。
- **自动锁定**：空闲超时（界面设置）、系统锁屏 / 注销 / 切换用户 / 休眠时立即锁定（Windows：WTS 会话通知 + 电源广播）。锁定会清掉解密数据和尚未确认的导入。
- **剪贴板**：复制的密码 90 秒后（若剪贴板里仍是它）以及退出应用时清除；Windows 上同时设置 `ExcludeClipboardContentFromMonitorProcessing`、`CanIncludeInClipboardHistory = 0`、`CanUploadToCloudClipboard = 0`，不进剪贴板历史、不上传云剪贴板。
- **使用前需要验证**：条目设置了“使用前需要验证”（编辑页勾选；从 Bitwarden 导入的“主密码重新提示”自动转换）时，密码库在验证前只显示标题、用户名和网址；查看、复制、编辑前输入主密码、PIN 或使用 Windows Hello。开启了 Windows Hello 快速解锁时用同一个 Hello 密钥签名并核对账户密钥，否则只做 Windows Hello 在场确认；PIN 由核心核对，输错同样计入 5 次；PIN 和 Hello 受 14 天规则约束，主密码总是可用。验证只对当前打开的条目有效，换条目或锁定后失效。快捷搜索、SSH agent 见下。说明见 [威胁模型.md](../common/docs/威胁模型.md) §3.8.1。
- **右键菜单与链接**：条目列表和字段右键是应用自己的菜单（复制、打开网站、编辑、收藏、归档、删除等），不显示 WebView 的网页菜单（输入框和选中文字保留剪切 / 复制 / 粘贴）。链接用系统默认浏览器打开（只允许 http / https）。
- **快捷搜索与自动输入**、**SSH agent**、**浏览器扩展联动**（见下，都在“设置”里开关）。
- **定期离线导出**（见下）。
- **自更新**（见下）。

尚未实现（后续阶段）：Windows passkey 提供程序；macOS Touch ID、macOS / Linux 锁屏检测；macOS / Linux 的自动输入。

### 快捷搜索与自动输入

在任意程序里按全局快捷键（默认 `Ctrl+Shift+Alt+Space`，“设置 → 快捷搜索与自动输入”可改，写法如 `Ctrl+Alt+K`；旧版本的默认 `Ctrl+Shift+Space` 与 IDE 的参数提示和部分输入法冲突，已保存过的设置保持不变；快捷键被其他程序占用时设置页会显示）弹出搜索框：

- 打开前记下当前前台窗口（标题 + 进程名），先列出与它匹配的条目：条目网址的主机名 / 可注册域名出现在窗口标题里、条目标题出现在窗口标题里，或程序名（如 `WeChat.exe`）与条目标题相同。输入关键词则搜索全部条目（支持拼音 / 首字母）。
- **Enter**：切回那个窗口，按条目的“自动输入序列”输入，默认 `{USERNAME}{TAB}{PASSWORD}{ENTER}`。序列在条目编辑页“自动输入”里设置（存为条目的 `autofill.auto_type`，见条目格式.md），可用 `{USERNAME}` `{PASSWORD}` `{TOTP}` `{URL}` `{TITLE}` `{S:字段名}`、按键 `{TAB}` `{ENTER}` `{SPACE}` `{BS}` `{DEL}` `{ESC}` `{UP}` `{DOWN}` `{LEFT}` `{RIGHT}` `{HOME}` `{END}`、`{DELAY 500}`，`{{}` / `{}}` 表示花括号，其他文字原样输入。
- **Ctrl+U / Ctrl+P / Ctrl+T**：复制用户名 / 密码 / 验证码（秘密 90 秒后清除），Esc 关闭。
- “使用前需要验证”的条目：自动输入、复制密码 / 验证码前，在快捷搜索窗口里输入主密码、PIN 或使用 Windows Hello；一次验证只放行一次。
- Windows 用 `SendInput` + `KEYEVENTF_UNICODE` 逐字输入，与键盘布局、输入法无关（中文、emoji 都可以）；输入前等 Ctrl / Shift / Alt 松开，**每个字符前都确认目标窗口仍在前台**，焦点变了立即停止。以管理员身份运行的程序会拦截普通程序的输入（UIPI），这时会提示。
- macOS（CGEvent）/ Linux（X11 XTest）的自动输入**尚未实现**：快捷搜索可以用，只能复制，界面会说明。

### SSH agent

“设置 → SSH agent”开启后，桌面端用 OpenSSH agent 协议提供保险库中 **SSH 密钥**条目的私钥（解锁的所有保险库；条目编辑页可取消“提供给桌面端的 SSH agent”）。不能通过协议添加密钥。

- **每次签名都弹出确认窗口**：密钥名、用途（SSH 登录的用户名和服务器主机密钥指纹 / Git 提交签名）、请求的程序（及其父进程，如 `ssh-keygen.exe（git.exe）`）。可选“允许一次”“锁定前都允许”“拒绝”；关窗口或 60 秒不处理 = 拒绝。条目关闭“每次签名都确认”时，每次解锁只确认一次。
- 条目设置了“使用前需要验证”的密钥：每次签名都要在确认窗口里输入主密码、PIN 或使用 Windows Hello，没有“锁定前都允许”，也不受“每次签名都确认”关闭的影响。
- 锁定时收到请求：弹出主窗口提示解锁，最多等 60 秒。
- 签名算法：Ed25519、ECDSA（P-256 / P-384）、RSA（`rsa-sha2-256` / `rsa-sha2-512`；不做 SHA-1 的 `ssh-rsa`）。

**Windows**：默认监听 `\\.\pipe\openssh-ssh-agent`，Windows 自带的 `ssh`、`ssh-add`、`ssh-keygen` 直接可用。这个管道可能已被占用：

- Windows 的 **OpenSSH Authentication Agent** 服务（`ssh-agent`）：设置页会显示它的状态。可以停用它（管理员 PowerShell：`Stop-Service ssh-agent; Set-Service ssh-agent -StartupType Disabled`），或者
- 其他密码管理器的 agent（例如 Bitwarden 桌面端）：设置页会显示占用的程序名。

不想停用它们时，在设置里填其他管道名（如 `nyapassword-ssh-agent`），然后让客户端用它：

```powershell
[Environment]::SetEnvironmentVariable('SSH_AUTH_SOCK', '\\.\pipe\nyapassword-ssh-agent', 'User')   # 之后新开的终端生效
```

或在 `~/.ssh/config` 里：

```
Host *
    IdentityAgent //./pipe/nyapassword-ssh-agent
```

管道的访问控制只允许当前用户，拒绝远程客户端。

**Git 提交签名**（SSHSIG）：

```powershell
git config --global gpg.format ssh
git config --global user.signingkey "C:/Users/<你>/.ssh/id_ed25519.pub"     # 保险库里那把密钥的公钥（文件里只需公钥）
git config --global gpg.ssh.program "C:/Windows/System32/OpenSSH/ssh-keygen.exe"
git config --global commit.gpgsign true
# 验证：gpg.ssh.allowedSignersFile 指向“邮箱 namespaces="git" 公钥”格式的文件，然后 git log --show-signature
```

Git for Windows 自带的 `ssh` / `ssh-keygen`（MSYS 版）不认识 Windows 命名管道，所以 `gpg.ssh.program` 和 `core.sshCommand`（`C:/Windows/System32/OpenSSH/ssh.exe`）都要指向 Windows 的 OpenSSH。

**WSL**：WSL 里的 ssh 用 Unix socket，需要一个桥接到 Windows 命名管道的转发程序，常用 [npiperelay](https://github.com/jstarks/npiperelay)（Windows 侧）+ `socat`（WSL 侧）：

```bash
# WSL 里（先 sudo apt install socat，并把 npiperelay.exe 放到 Windows 的 PATH 中）
export SSH_AUTH_SOCK=$HOME/.ssh/agent.sock
if ! ss -a | grep -q "$SSH_AUTH_SOCK"; then
  rm -f "$SSH_AUTH_SOCK"
  (setsid socat UNIX-LISTEN:"$SSH_AUTH_SOCK",fork EXEC:"npiperelay.exe -ei -s //./pipe/openssh-ssh-agent",nofork &) >/dev/null 2>&1
fi
```

写进 `~/.bashrc`；用了其他管道名就把 `openssh-ssh-agent` 换掉。也可以用 [wsl-ssh-agent](https://github.com/rupor-github/wsl-ssh-agent) 等同类工具。确认窗口里的程序会显示为 `npiperelay.exe`。

**macOS / Linux（实验性）**：监听 `<应用数据目录>/ssh-agent.sock`（权限 0600；macOS 为 `~/Library/Application Support/app.nya.password/ssh-agent.sock`，Linux 为 `~/.local/share/app.nya.password/ssh-agent.sock`），可在设置里改路径。设置 `export SSH_AUTH_SOCK="<路径>"` 或 `IdentityAgent`。Linux 上确认窗口能显示请求的程序，macOS 上不能。

### 浏览器扩展联动（Native Messaging）

配对后：

- 桌面端已解锁时，扩展打开弹窗 / 内联菜单即可解锁，不用再输主密码。
- 桌面端锁定时，在扩展里**打开弹窗**或**点输入框里的 NyaPassword 按钮**（以及菜单里的“用桌面端解锁”），桌面端会把自己的主窗口（正常的解锁界面）调到前台并聚焦，界面上注明是哪个浏览器在请求；用主密码、Windows Hello 或 PIN 解锁后，扩展也跟着解锁。最多等 2 分钟，同一时间只等一个请求；扩展在等待时显示“请在 NyaPassword 桌面端完成解锁”，主密码输入框照常可用。内联菜单自己弹出、页面加载时不会把桌面端弹出来（只在桌面端已解锁时顺带解锁）。
- 桌面端没有运行时，上面的明确操作会让 Native Messaging 宿主以普通方式启动桌面端（单实例），再转发这次请求；其他请求只回答“桌面端没有运行”。
- 桌面端锁定时，已连接的扩展跟着锁定；桌面端解锁时，已连接的扩展也会解锁。

1. 扩展弹窗 ⚙ → 打开“由桌面端解锁”（浏览器会请求 `nativeMessaging` 权限），复制显示的**扩展 ID**。
2. 桌面端“设置 → 浏览器扩展联动”：填入扩展 ID（每行一个，Chrome 和 Edge 的 ID 不同时都填），开启。桌面端注册 Native Messaging 宿主：清单写到 `<应用数据目录>\native-messaging\app.nya.password.json`（`allowed_origins` = 这些扩展），注册表 `HKCU\Software\Google\Chrome\NativeMessagingHosts\app.nya.password`、`HKCU\Software\Microsoft\Edge\...`、`HKCU\Software\Chromium\...` 指向它；macOS / Linux（实验性）写到各浏览器的 `NativeMessagingHosts` 目录。关闭时删除注册；卸载程序也会删除（NSIS 钩子 `src-tauri/windows/hooks.nsh`）；应用每次启动会重新注册，保证指向当前程序。
3. 扩展弹窗 ⚙ → “与桌面端配对”：扩展和桌面端弹窗显示**同一个 6 位数字**，在桌面端点“允许配对”。扩展和桌面端必须登录同一个账户（同一服务器）。


注意：**不要从打包应用（MSIX / 应用商店应用，例如 Claude 桌面版的终端）里启动桌面端来测试联动。** Windows 会把这类进程对 `HKCU` 注册表和 `AppData` 的写入重定向到那个应用包的私有副本（`%LOCALAPPDATA%\Packages\<包名>\LocalCache`），浏览器看不到这里的注册，配对会报“找不到 NyaPassword 桌面端”（Edge / Chrome 日志：`Can't find manifest for native messaging host app.nya.password`）。用安装包安装后从开始菜单启动即可。
扩展 ID：商店发布的 ID 固定；“加载已解压的扩展程序”时 ID 由所在路径决定（manifest 里没有 `key`），换目录加载后要重新填写和配对。

原理：宿主就是桌面端程序本身——浏览器以 `nyapassword-desktop.exe chrome-extension://<ID>/` 启动它，它不开窗口，只把消息转发到正在运行的应用（只对当前用户开放的本地管道 `\\.\pipe\app.nya.password.browser-bridge.<用户 SID>`；macOS / Linux 为应用数据目录下的 `browser-bridge.sock`）。应用没运行时扩展会提示。扩展保存一对 P-256 密钥（私钥是不可导出的 WebCrypto 密钥），桌面端只保存公钥；解锁时桌面端把账户密钥用一次性的 ECDH + HKDF-SHA256 + AES-256-GCM 封装给扩展（绑定账户 ID 和扩展给的随机数），扩展解开后调用 `unlockWithKey`，核心会校验这把密钥。安全分析见 [威胁模型.md](../common/docs/威胁模型.md) §3.9.1。取消配对：桌面端设置里的配对列表，或扩展弹窗 ⚙。

### 定期离线导出

“设置 → 定期离线导出”：选择文件夹、间隔（默认每周）、格式（原生加密 `.npwexport` 和 / 或 KDBX `.kdbx`）、保留份数（默认 8）。文件名 `NyaPassword-<日期>.npwexport` / `NyaPassword-<日期>.kdbx`，每种格式只保留最近 N 份；文件夹里其他文件不会被动。

导出需要主密码，而本应用**从不保存主密码**，所以做法是“到期提醒 + 一键完成”：

- 到期后，下一次**用主密码解锁**（或登录）时，应用趁这次解锁调用里主密码本来就在内存中，在后台完成导出，完成后立即丢弃；界面会提示成功或失败。用 Windows Hello 或 PIN 解锁时没有主密码，不会导出——但至少每 14 天要输入一次主密码，所以不会拖太久（想准时导出就在设置里“立即导出”）。
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
│     ├─ quick_unlock.rs Windows Hello 快速解锁的密钥包装
│     ├─ local_unlock.rs 14 天规则、PIN 材料与尝试次数（存在系统凭据存储）
│     ├─ verify.rs       使用前需要验证：主密码 / PIN / Windows Hello 再次验证（不改变锁定状态）
│     ├─ export.rs       定期离线导出与清理
│     ├─ updater.rs      自更新（minisign + SHA-256）
│     ├─ device_key.rs   设备密钥
│     ├─ ssh_agent.rs    SSH agent（npw-ssh 协议 + 确认 + 锁定时等待解锁）
│     ├─ quick.rs        快捷搜索窗口与全局快捷键
│     ├─ autotype.rs     自动输入序列、窗口匹配
│     ├─ browser_bridge.rs 浏览器扩展联动：协议、配对、封装、宿主模式
│     ├─ prompts.rs      确认窗口（SSH 签名、扩展配对）
│     ├─ ipc.rs          只对当前用户开放的命名管道 / Unix socket
│     └─ platform/       Windows / macOS / Linux 实现（凭据存储、快速解锁、剪贴板、锁屏、开机启动、前台窗口与自动输入、OpenSSH 服务状态、宿主注册）
│  └─ windows/hooks.nsh  NSIS 卸载钩子（删除 Native Messaging 注册）
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
cargo test --workspace       # 单元测试：快速解锁包装、14 天规则与 PIN 计数、扩展联动的等待解锁 / 启动桌面端、导出清理、更新签名校验、设备密钥……
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check            # 不要加 --all：那会连 ../common 的 path 依赖一起格式化
```

界面里桌面端专用的小窗口（快捷搜索、确认窗口）是 `../common/web/desktop.html`（只在 `--mode desktop` 构建）。

只在调试版（`debug_assertions`）里有效的测试开关，发布版不包含：`NPW_TEST_AUTO_APPROVE=1`（确认窗口一律“允许一次”，用于用真实 OpenSSH 工具自动测试 agent）、`NPW_TEST_WEBVIEW_ARGS=--remote-debugging-port=<端口>`（给所有 WebView2 窗口加参数，测试可经 CDP 操作窗口）。`cargo test -- --ignored native_host` 会真实写入并删除 HKCU 的宿主注册。

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
