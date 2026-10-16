# 🚀 RevoSharp v2.1 Pro

<p align="center">
  <b>现代化、深度逆向扫描的 Windows 强力软件卸载、安装监控与系统清理工具</b><br>
  <i>基于 .NET 8 + WPF-UI (Fluent Design) 深度打造，全面对标 Revo Uninstaller Pro / Geek Uninstaller / BCUninstaller</i>
</p>

---

## ✨ 核心特性 (v2.1 Pro 全量升级)

### 1. 🔍 Revo Pro 级别逆向引用残留扫描引擎 (Deep Residual Scanner)
- **COM / CLSID 逆向挖掘与外壳扩展联动**：跨 64/32 位视图扫描 `HKLM/HKCU\...\Classes\CLSID` 中指向目标目录的 `InprocServer32`、`LocalServer32` 死链，并将命中的 CLSID 自动关联至 `Shell Extensions\Approved` 与 `HKCR\*\shellex\ContextMenuHandlers` 右键菜单扩展清理。
- **Windows 服务安全停止与清理**：智能检测遗留服务，清理前自动通过 SCM (`sc stop` / `sc delete`) 停止并注销服务，再清理注册表。
- **计划任务与 MSI 元数据安全清理**：深度检索 `System32\Tasks` 遗留计划任务，清理前自动备份任务 XML 并通过 `schtasks.exe /Delete` 注销系统调度器缓存；完整覆盖 `Installer\Folders` 与 `App Paths`（64/32 位双视图）。
- **扁平明细 / 树形层级双视图审查**：支持一键切换“扁平明细列表（单击直接勾选）”与“注册表 + 文件系统分栏树形视图（支持父子节点三态双向级联勾选）”。
- **防同系列版本连坐误删与共享目录护栏**：内置同系列独立版本（如 Beta / Canary / Code / Studio / Runtime）智能降级识别，严格保护桌面、下载及大厂共享根目录。

### 2. 🛠️ 强制卸载向导、分类秒筛与批量静默卸载 (Forced & Batch Uninstall)
- **快速分类筛选与新装高亮**：主界面内置“全部 / 近期新装 / 已追踪日志 / 桌面软件 / 商店应用”胶囊筛选，自动高亮近 14 天内新安装软件，并在后台异步回填缺失的磁盘真实占用大小。
- **强制卸载向导 (Forced Uninstall)**：支持直接输入名称或选择残留 `.exe` / `.lnk` 快捷方式（自动穿透解析快捷方式真实目标路径与 `FileVersionInfo` 元数据）发起深度逆向猎杀。
- **多选批量队列与静默汇总清理 (Batch Queue)**：支持随时中止后续队列；在多选静默快卸模式下，自动创建单次全局还原点、批量执行静默卸载并合并汇总所有残留项一键审查清理。

### 3. 🎯 猎犬模式 2.0 (Hunter Mode - HWND 缓存零卡顿瞄准与快捷方式拖入)
- **零自遮挡穿透准星与 120FPS 丝滑拖拽**：拖拽期间动态启用 `WS_EX_TRANSPARENT` 穿透与 HWND 句柄级缓存，避免高频重复磁盘/COM I/O；支持右键长按拖动或 `Shift+左键` 调整准星停靠位置。
- **支持桌面快捷方式 (`.lnk`) 拖入猎杀**：除拖拽瞄准活动窗口外，支持直接将桌面快捷方式或可执行文件拖入准星（或通过右键菜单选择）解析背后程序并执行强力清理。

### 4. 📡 ETW 内核安装监控与首次启动捕获 (Real-Time Install Monitor)
- **KCB 句柄映射与注册表键/值全量捕获**：结合 `RegistryKCBCreate` / `RegistryKCBRundown` 还原内核相对路径，同时捕获新建注册表键（`RegistryCreate`）与修改键值（`RegistrySetValue`），并支持追踪 `msiexec.exe` 服务进程。
- **首次运行配置捕获向导**：内置“试运行新软件 (捕获首次启动配置)”按钮，引导用户在保存日志前拉起一次新装软件，将其首次运行生成的 `AppData` 与注册表配置一并记入 `.revolog.json.gz`。
- **轻量级日志索引缓存 (`trace_index.json`)**：主界面启动秒级匹配监控日志，无需全量解压 GZip 档案；支持日志导入共享与导出可读 `.txt` 报告。

### 5. 🛡️ 多级安全备份与附加系统工具箱 (Multi-Level Backup & Toolkit)
- **全类型精确 `.reg` 导出与后序重启删除**：清理单值残留前直接读取真实注册表数据与 `RegistryValueKind`（支持 `REG_SZ`、`REG_DWORD`、`REG_QWORD`、`REG_BINARY`、`REG_EXPAND_SZ`、`REG_MULTI_SZ`）生成标准 `.reg` 备份；针对被占用目录采用“文件 ➔ 深层子目录 ➔ 根目录”后序遍历注册 `MoveFileEx` 重启删除。
- **内置系统工具箱 (`ToolkitDialog`)**：
  1. **开机自启动管理器 (Autorun Manager)**：覆盖注册表 `Run/RunOnce`、启动文件夹与第三方计划任务自启，支持与 Windows 任务管理器同步的 **`StartupApproved` 无损启用/禁用切换** 及自动归档备份移除。
  2. **多级备份还原中心 (Backup Manager)**：统一管理卸载残留与自启动项备份清单，支持一键导入还原注册表与计划任务备份。
  3. **已追踪安装日志库 (Traced Programs)**：支持导入外部日志、导出可读文本报告及随时基于日志执行反向清理。

---

## 📦 编译与运行

```bash
dotnet build RevoSharp.sln -c Release
```
