namespace RevoSharp.Core.Enums;

public enum ScanMode
{
    Safe,       // 安全模式：仅扫描原安装主目录、Uninstall 键名、完全匹配 GUID
    Moderate,   // 中等模式 (默认)：Safe + 反向引用 (COM/CLSID/服务/防火墙/快捷方式) + 常见 AppData 目录
    Advanced    // 高级模式：Moderate + 深层全量注册表/文件模糊遍历
}
