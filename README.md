# 🚀 RevoSharp

<p align="center">
  <b>现代化、深度逆向扫描的 Windows 强力软件卸载与残留清理工具</b><br>
  <i>基于 .NET 8 + WPF-UI (Fluent Design) 深度打造，对标并超越 Revo Uninstaller Pro</i>
</p>

---

## ✨ 核心特性

### 1. 🔍 Revo Pro 级别逆向引用残留扫描引擎 (Deep Residual Scanner)
- **COM / CLSID 逆向挖掘**：扫描 `HKCR\CLSID` 中指向目标目录的 `InprocServer32`、`LocalServer32` 及 ProgID 深度残留。
- **Windows 服务与驱动残留**：智能检测指向目标目录的遗留 Windows 服务、驱动及关联配置项。
- **系统层痕迹清理**：覆盖 `App Paths`、Windows 防火墙规则、`MuiCache`、自启动项 (`Run`/`RunOnce`)、文件关联与无用注册表键值。
- **快捷方式靶向追踪**：全盘扫描 Desktop 与 Start Menu 中的 `.lnk` 快捷方式并解析其目标路径。

### 2. 🎯 猎犬模式 (Hunter Mode - 靶心瞄准与流氓软件克星)
- **桌面置顶准星靶标**：极简科技感半透明发光靶标，随时待命。
- **全局动态高亮视框**：拖动准星拖拽到任意窗口、任务栏图标或桌面图标时，实时以 Fluent 霓虹蓝光勾勒目标边界（系统关键进程显示警示红光）。
- **流氓弹窗与免安装便携软件现场逆向建档**：对于未在 Windows 注册表安装列表登记的弹窗广告、单文件程序，现场反推产品元数据，派生专属虚拟档案并直接调用全强度逆向残留扫描！
- **Fluent 浮动 Action HUD 核心动作**：
  1. **卸载并清理残留**：原厂卸载 + 进程树追踪 + 逆向残留深度扫描。
  2. **强力终止并清除残留**：专杀顽固弹窗与无卸载器程序，瞬间结束进程树并直接清理全部残留。
  3. **立即终止进程**：强杀目标全链路进程树。
  4. **终止并禁用自启动**：扫描并抹除 `Run`、`RunOnce` 及 `Startup` 目录下的所有自启项。
  5. **打开所在目录**：在资源管理器中精准定位主执行文件。
  6. **进程安全情报搜索**：一键在浏览器中检索进程安全性分析。
- **系统关键进程安全防护围栏**：严格拦截对 `csrss.exe`、`dwm.exe`、`lsass.exe`、`services.exe` 等核心组件的破坏性操作。

### 3. ⚡ 单页全景直览与零阻塞清理体验
- **告别繁琐多层级树状结构**：平铺直览 `DataGrid` 展现所有残留项（分类徽标、路径/键名、命中原因、文件大小），点击深度降为 0。
- **多维分类筛选**：支持「全部 / 注册表 / 文件与目录 / 快捷方式」一键切换与实时关键词模糊检索。
- **静默安全删除**：
  - 注册表残留删除前，自动导出 `.reg` 备份至 `%LocalAppData%\RevoSharp\Backups\`。
  - 文件与目录调用 Win32 `SHFileOperation` 静默移入 Windows 回收站，绝不硬删除。
  - 清理完毕后自动流转退出，无冗余多重弹窗干扰。

### 4. 🔄 进程树全生命周期追踪 (Process Tree Tracker)
- 基于 Win32 `Toolhelp32Snapshot` 快照机制，持续轮询并追踪 Uninstaller 衍生出的所有子进程（如 Bootstrapper、自解压外壳、MSI 执行体）。
- 确保原厂卸载程序真正退出后再启动残留扫描，彻底杜绝扫描窗口过早弹出的尴尬。

### 5. 📂 智能物理路径解析 (Smart Location Resolver)
- 针对许多应用注册表缺失 `InstallLocation` 的痛点，自动从 `DisplayIcon`、`UninstallString` 中智能提取与规范化程序真实目录，精准支持各类绿色与打包软件。

---

## 🛠️ 技术架构

- **运行时环境**：.NET 8.0 (Windows x64)
- **界面架构**：WPF + WPF-UI 4.3.0 (Fluent Design System)
- **核心模块**：
  - `RevoSharp.Core`：跨层实体模型、枚举与公共契约
  - `RevoSharp.Engine`：Win32 API Interop、逆向扫描引擎、ETW 监听、进程树追踪、猎犬引擎
  - `RevoSharp.App`：现代 Fluent 桌面应用界面、MVVM (CommunityToolkit.Mvvm)

---

## 📦 编译与运行

### 源码构建
```bash
git clone https://github.com/xpxp23/RevoSharp.git
cd RevoSharp
dotnet build RevoSharp.sln -c Release
```

### 单文件/便携式发布
```bash
dotnet publish src/RevoSharp.App/RevoSharp.App.csproj -c Release -r win-x64 --self-contained false -o publish
```

---

## 📄 开源许可证

本项目基于 [MIT License](LICENSE) 开源。仅供学习交流与个人研究使用。
