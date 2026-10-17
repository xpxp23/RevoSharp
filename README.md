# 🚀 RevoSharp v2.2 Pro

<p align="center">
  <b>现代化、深度逆向扫描的 Windows 强力软件卸载、安装监控与系统清理工具</b><br>
  <i>基于 .NET 8 + WPF-UI (Fluent Design) 深度打造，全面对标 Revo Uninstaller Pro / Geek Uninstaller / BCUninstaller</i>
</p>

---

## ✨ 核心特性 (v2.2 Pro 深度重构升级)

### 1. 🔍 Revo Pro 级别逆向引用残留扫描引擎 (Deep Residual Scanner)
- **COM / CLSID 逆向挖掘与外壳扩展联动**：跨 64/32 位视图扫描 `HKLM/HKCU\...\Classes\CLSID` 中指向目标目录的 `InprocServer32`、`LocalServer32` 死链，并将命中的 CLSID 自动关联至 `Shell Extensions\Approved` 与 `HKCR\*\shellex\ContextMenuHandlers` 右键菜单扩展清理。
- **跨目录零误伤安全护栏**：当目标软件具备明确安装目录时，严格限制反向引用路径前缀匹配；无安装目录回退匹配主程序名时自动校验磁盘死链状态，杜绝误伤其他正常软件。
- **Windows 服务“先备份后注销”安全清理**：清理遗留服务前，先完整导出 `HKLM\SYSTEM\CurrentControlSet\Services\<Name>` 为 `.reg` 备份，再通过 SCM (`sc stop` / `sc delete`) 安全停止并注销服务。
- **扁平明细（分段语法高亮） / 树形层级（单击直切三态级联）双视图**：扁平列表支持路径前缀、叶子名与注册表键值分段高亮展示；树形视图支持单击直接勾选/取消，并在半选状态下自动保护父节点避免连坐误删未勾选子项。

### 2. 🛠️ 强制卸载向导、底部详情检视栏与批量汇总卸载 (Forced & Batch Uninstall)
- **快速分类筛选与底部详情检视栏 (Inspector Bar)**：主界面内置“全部 / 近期新装 / 已追踪日志 / 桌面软件 / 商店应用”矢量图标胶囊筛选，底部内置可折叠详情检视栏，直观展示安装目录、注册表路径与卸载命令行。
- **强制卸载向导 (Forced Uninstall)**：支持直接输入名称或选择残留 `.exe` / `.lnk` 快捷方式（自动穿透解析快捷方式真实目标路径与 `FileVersionInfo` 元数据）发起深度逆向猎杀。
- **多选批量队列与来源归属标记 (Batch Queue)**：支持随时中止后续队列；多选卸载完成后自动合并汇总所有残留项，并通过归属标签清晰标注每条残留对应的源软件。

### 3. 🎯 猎犬模式 2.2 (Hunter Mode - 跨屏混合 DPI 精确校准与自动归位)
- **零自遮挡穿透准星与自动停靠归位**：拖拽期间动态启用 `WS_EX_TRANSPARENT` 穿透与 HWND 句柄级缓存，松手锁定目标或按 `Esc` 取消瞄准后准星自动归位至停靠角，绝不遮挡目标窗口或控制面板。
- **多显示器 Per-Monitor DPI 像素级对齐**：采用矩阵设备坐标逆变换与 Win32 物理坐标直接定位高亮框，支持桌面快捷方式 (`.lnk`) 拖入猎杀与计划任务自启联动清除。

### 4. 📡 ETW 内核安装监控与 180ms 批量节流控制台 (Real-Time Install Monitor)
- **原生 `.msi` / `.msp` 安装包与 `msiserver` 服务追踪**：自动封装 `msiexec.exe /i` 启动并在安装期间动态关联 `msiserver` 工作进程，结合 `RegistryKCB` 句柄还原完整捕获 MSI 与 EXE 安装全过程。
- **180ms 异步队列节流与实时四维遥测卡片**：内置并发队列与后台节流定时器，彻底消除大型软件解压数万文件时的 UI 线程阻塞；支持实时事件搜索过滤、暂停滚动与首次运行配置捕获。

### 5. 🛡️ 多级原位备份还原与系统工具箱 (Multi-Level Backup & Toolkit)
- **32/64 位视图感知 `.reg` 备份与全量原位还原**：精准处理 `WOW6432Node` 与 `/reg:32` / `/reg:64` 视图映射，保存计划任务原始调度器路径及启动文件夹快捷方式快照副本，支持在备份中心一键原位还原注册表、计划任务与启动文件。
- **内置系统工具箱 (`ToolkitDialog`)**：
  1. **开机自启动管理器 (Autorun Manager)**：覆盖注册表 `Run/RunOnce`、启动文件夹与校验包含 `LogonTrigger` / `BootTrigger` 的第三方计划任务自启，支持实时搜索与 **`StartupApproved` 无损启用/禁用切换**。
  2. **多级备份还原中心 (Backup Manager)**：支持直接预览每个备份包内的注册表键、计划任务与文件明细，并一键原位还原。
  3. **已追踪安装日志库 (Traced Programs)**：支持导入外部日志、导出可读文本报告及随时基于日志执行反向清理。

---

## 📦 编译与运行

```bash
dotnet build RevoSharp.sln -c Release
```
