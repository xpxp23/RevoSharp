# 🚀 RevoSharp v2.0 Pro

<p align="center">
  <b>现代化、深度逆向扫描的 Windows 强力软件卸载、安装监控与系统清理工具</b><br>
  <i>基于 .NET 8 + WPF-UI (Fluent Design) 深度打造，全面对标 Revo Uninstaller Pro</i>
</p>

---

## ✨ 核心特性 (v2.0 Pro 全量升级)

### 1. 🔍 Revo Pro 级别逆向引用残留扫描引擎 (Deep Residual Scanner)
- **COM / CLSID 逆向挖掘**：跨 64/32 位视图扫描 `HKLM/HKCU\...\Classes\CLSID` 中指向目标目录的 `InprocServer32`、`LocalServer32` 死链。
- **Windows 服务安全停止与清理**：智能检测遗留服务，清理前自动通过 SCM (`sc stop` / `sc delete`) 停止并注销服务，再清理注册表。
- **计划任务与 MSI 元数据扫描**：深度检索 `System32\Tasks` 遗留计划任务、`Installer\Folders` 及 `Shell Extensions\Approved` 外壳扩展。
- **系统层痕迹与快捷方式清理**：覆盖 `App Paths`、Windows 防火墙规则、`MuiCache`、桌面/开始菜单/任务栏固定栏 `.lnk` 快捷方式死链（含 COM 句柄零泄漏释放）。
- **智能共享目录与厂商根目录防误删护栏**：内置系统目录、桌面、下载目录及多产品大厂根目录（Adobe、JetBrains、Apple、Tencent 等）防连坐保护机制。

### 2. 🛠️ 强制卸载向导与批量队列卸载 (Forced & Batch Uninstall)
- **强制卸载向导 (Forced Uninstall)**：针对已通过常规方式卸载但遗留垃圾、卸载器损坏或未登记的软件，支持直接输入名称或指定残留路径发起深度逆向猎杀。
- **多选批量队列卸载 (Batch Queue)**：主界面支持 Ctrl/Shift 多选应用，按队列依次执行标准卸载或静默快卸（自动将 MSI `/I{GUID}` 转换为 `/X{GUID} /qn`）。
- **卸载取消智能识别**：原厂卸载进程退出后自动校验注册表状态，若用户在原厂向导中点击了“取消”，自动拦截并弹窗提醒，防止误删仍在使用的软件。
- **Windows 现代商店应用支持 (UWP / MSIX)**：支持一键勾选扫描并卸载 Windows 商店应用。

### 3. 🎯 猎犬模式 2.0 (Hunter Mode - 鼠标穿透瞄准与多屏适配)
- **零自遮挡穿透准星**：拖拽瞄准期间动态启用 `WS_EX_TRANSPARENT` 鼠标穿透，解决准星窗口自遮挡问题，64x64 霓虹准星置于 96x96 抗裁切画布中央。
- **多显示器 DPI 自适应定位**：基于 Win32 `MonitorFromPoint` 动态获取当前屏幕工作区，完美支持副屏与负坐标多显示器环境。
- **核心进程与桌面文件夹保护**：严格保护 `explorer.exe` 及 `C:\Windows` 全目录；对存放在桌面或下载目录的独立单文件程序仅清理程序本体，绝不误伤所在共享文件夹。

### 4. 📡 ETW 内核安装监控与注册表快照差分 (Real-Time Install Monitor)
- **先监听后启动零漏捕架构**：先完成 ETW 内核会话就绪握手，再拉起安装程序及其子进程树。
- **精准过滤只读系统文件**：结合 `FileIOWrite` 与文件创建时间戳过滤安装器读取的系统 DLL，并通过 `QueryDosDevice` 精准映射 `\Device\HarddiskVolumeX` 到真实盘符（C:/D:/E:）。
- **注册表快照自动关联**：安装前后自动对比 `Uninstall` 注册表快照，自动识别新安装软件的真实 `DisplayName` 并绑定 `.revolog.json.gz` 追踪日志。

### 5. 🛡️ 多级安全备份与附加系统工具箱 (Multi-Level Backup & Toolkit)
- **多级安全防护网**：支持清理前创建 **Windows 系统还原点 (WMI SystemRestore)**、毫秒级唯一序号导出 `.reg` 备份（含注册表键与单值备份）、文件移入回收站、以及**被占用文件重启后自动删除 (`MoveFileEx`)**。
- **内置系统工具箱 (`ToolkitDialog`)**：
  1. **开机自启动管理器 (Autorun Manager)**：集中管理 `HKCU/HKLM Run`、`RunOnce` 及启动文件夹 `.lnk` 驻留项。
  2. **多级备份还原中心 (Backup Manager)**：可视化查看所有历史卸载备份档案，支持**一键导入还原注册表备份**。
  3. **已追踪安装日志库 (Traced Programs)**：集中查看并管理所有 ETW 安装监控日志，支持随时基于日志执行反向清理。

---

## 📦 编译与运行

```bash
dotnet build RevoSharp.sln -c Release
```
