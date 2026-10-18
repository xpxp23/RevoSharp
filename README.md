# 🚀 RevoSharp v2.4 Pro

<p align="center">
  <b>现代化、深度逆向扫描的 Windows 强力软件卸载、安装监控与系统清理工具</b><br>
  <i>基于 .NET 8 + WPF-UI (Fluent Design) 深度打造，全面对标 Revo Uninstaller Pro / Geek Uninstaller / BCUninstaller</i>
</p>

---

## ✨ 核心特性 (v2.4 Pro 深度进化与引擎升级)

### 1. ⚡ NTFS MFT / USN Journal 极速全盘残留搜索引擎 (`NtfsMftScanner`)
- **Everything 级底层卷流式检索**：在 `Advanced` 高级模式下，通过 P/Invoke (`FSCTL_QUERY_USN_JOURNAL` / `FSCTL_ENUM_USN_DATA`) 直接读取 NTFS 卷的 USN 记录并在内存中极速重构 FRN (`FileReferenceNumber`) 父子目录树，在 **300ms 内**完成全盘散落程序文件夹与 `Windows\Prefetch` (`.pf`) 执行痕迹检索。

### 2. 🛡️ 基于数字签名 (`WinVerifyTrust` / `Authenticode`) 与白名单的防误删护栏 (`AuthenticodeVerifier`)
- **离线证书链与签名发行商校验**：在深度特征词模糊匹配与全盘 MFT 扫描时，自动通过 `wintrust.dll` (`WTD_CACHE_ONLY_URL_RETRIEVAL` 零网络阻塞) 校验候选目录内 `.exe` / `.dll` 的数字签名与 X.509 颁发者信息，自动保护微软、NVIDIA、Intel、AMD、Apple 等第三方受信任签名目录不被模糊词根误伤。

### 3. 🌐 浏览器多 Profile 扩展、本地存储与自定义 URL 协议深度清理
- **全 Profile 扩展与数据库检索**：自动遍历 Chrome / Edge / Brave / Vivaldi 的 `Default` 与 `Profile *` 目录，解析 `Extensions\*\manifest.json` 定位配套插件，并联动清理对应的 `Local Extension Settings` 与 `IndexedDB` 存储。
- **自定义 `URL Protocol` 协议死链清理**：深度扫描 `HKCU\Software\Classes` 与 `HKLM\SOFTWARE\Classes` 下指向已卸载软件的自定义协议处理器（如 `vscode://`、`zoommtg://` 等）。

### 4. 🚫 卸载后调查问卷网页弹窗自动拦截 (`UninstallerRunner`)
- **智能阻断卸载问卷弹窗**：卸载期间实时监测原厂卸载器进程树衍生的浏览器或 `rundll32 url.dll` / `cmd /c start http` 子进程，精准拦截卸载退场时弹出的调查问卷网页，同时绝不干扰用户已打开的正常浏览器会话。

### 5. ⚙️ 配置持久化 (`settings.json`)、系统右键菜单集成与 CLI 无头自动化模式
- **全状态本地持久化 (`SettingsSerializer`)**：自动保存主题模式（深色/浅色/跟随系统）、默认扫描深度、窗口尺寸、引擎开关及自定义目录白名单至 `%LOCALAPPDATA%\RevoSharp\settings.json`。
- **资源管理器右键菜单一键集成 (`ShellContextMenuService`)**：支持为 `.lnk` 快捷方式、`.exe` 程序及文件夹一键注册「使用 RevoSharp 强力卸载」系统右键菜单。
- **CLI 命令行无头自动化模式**：
  ```bash
  RevoSharp.App.exe --cli --list
  RevoSharp.App.exe --cli --scan "AppName" --mode Advanced --clean
  RevoSharp.App.exe --cli --uninstall "AppName" --silent --clean --mode Moderate
  ```

### 6. 🔓 两阶段分层 Restart Manager 极速占用解除与原位合成 `.reg` 备份
- **两阶段粗细粒度分层探测 (`FileLockUnlocker`)**：以 20 项为单位进行粗粒度单会话探测，无锁批次 1 次 `RmGetList` 瞬间通过，残留扫描尾声提速 **50～100 倍**。
- **零阻塞树形三态联动 (`TreeSelectionSyncScope`)**：消除树形视图父子级联勾选的 $O(N^2)$ 事件风暴，支持真正的三态半选（`-`）视觉指示、`IsDemotedByChildUncheck` 精准防误删、节点大小/置信度/占用徽章展示以及清理完成汇总报告。

---

## 📦 编译与运行

```bash
dotnet build RevoSharp.sln -c Release
```
