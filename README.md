# Win_Security_Inspect

![License](https://img.shields.io/badge/License-MIT-blue.svg)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20Server-0078D6.svg?logo=windows)
![Version](https://img.shields.io/badge/Version-1.0-green.svg)

**Windows Server 安全加固巡检脚本** — 一键生成 HTML 安全报告，覆盖 15 大检查模块，自动评分。

## 报告预览

<p align="center">
  <img src="auto_img.jpeg" alt="巡检报告预览" width="700">
</p>

## 功能概览

PowerShell 编写的 Windows Server 安全加固巡检工具，覆盖 **15 大检查模块**，自动评估并生成带安全评分的 HTML 报告。

| 模块 | 检查内容 |
|------|---------|
| 系统基本信息 | 主机名、IP、系统版本、运行时间、域/工作组 |
| 账户与密码策略 | 密码长度、复杂度、期限、锁定阈值 |
| 本地用户与组 | 用户列表、Guest 风险、Administrators 成员 |
| 审计策略配置 | 8 项审计策略 + 关联事件实况数据 |
| 事件日志配置 | 日志容量、保留方式、7天安全事件统计 |
| 登录失败分析 | 来源 IP 统计、暴力破解检测 |
| 端口与防火墙 | 监听端口、高风险端口标记、防火墙配置 |
| 高风险服务检查 | 15 个高风险服务运行状态 |
| RDP 远程桌面安全 | NLA、端口、加密级别 |
| SMB 文件共享安全 | SMBv1、签名、加密、共享审计 |
| Windows Update | 补丁安装时间、最近补丁列表 |
| 注册表安全加固 | 10 项关键安全注册表配置 |
| 计划任务审计 | 非系统任务、SYSTEM 身份任务标记 |
| 网络连接分析 | TCP 状态统计、出站 IP Top10 |
| 安全加固建议 | 6 大类 30+ 条加固清单 |

## 适用系统

- Windows Server 2016
- Windows Server 2019
- Windows Server 2022
- Windows Server 2025
- Windows 10 / 11（部分功能）

## 快速使用

### 1. 下载脚本

```powershell
git clone https://github.com/Aidan-996/Win_Security_Inspect.git
```

或直接下载 `Win_Security_Inspect.ps1` 文件。

### 2. 运行巡检

以 **管理员身份** 打开 PowerShell，执行：

```powershell
# 允许执行脚本（仅当前会话）
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

# 运行巡检
.\Win_Security_Inspect.ps1
```

### 3. 查看报告

脚本执行完毕后会输出报告路径：

```
========================================
  安全加固巡检完成: WIN-SERVER-01
  时间: 2026-04-08 10:30:00
  通过: 25  警告: 6  严重: 1
  安全评分: 78%
  报告: C:\Users\xxx\AppData\Local\Temp\security_inspect\security_inspect_xxx.html
  耗时: 12.3 秒
========================================
```

用浏览器打开生成的 `.html` 文件即可查看报告。

## 自定义参数

```powershell
.\Win_Security_Inspect.ps1 `
    -ReportDir "D:\Reports" `
    -MinPwdLength 14 `
    -MaxPwdAgeDays 60 `
    -LockoutThreshold 3 `
    -LockoutDuration 30 `
    -SecurityLogMinKB 409600 `
    -SystemLogMinKB 131072 `
    -AppLogMinKB 131072
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-ReportDir` | `$env:TEMP\security_inspect` | 报告输出目录 |
| `-MinPwdLength` | 12 | 最小密码长度建议值 |
| `-MaxPwdAgeDays` | 90 | 最大密码期限建议值（天） |
| `-LockoutThreshold` | 5 | 账户锁定阈值建议值 |
| `-LockoutDuration` | 30 | 锁定持续时间建议值（分钟） |
| `-SecurityLogMinKB` | 204800 | 安全日志最小容量（KB） |
| `-SystemLogMinKB` | 65536 | 系统日志最小容量（KB） |
| `-AppLogMinKB` | 65536 | 应用日志最小容量（KB） |

## 定时巡检

创建 Windows 计划任务，每天自动巡检：

```powershell
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-ExecutionPolicy Bypass -File C:\Scripts\Win_Security_Inspect.ps1 -ReportDir D:\Reports"
$Trigger = New-ScheduledTaskTrigger -Daily -At "08:00"
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
Register-ScheduledTask -TaskName "SecurityInspect" -Action $Action -Trigger $Trigger -Principal $Principal
```

## 批量巡检

通过 PowerShell Remoting 远程巡检多台服务器：

```powershell
$Servers = @("192.168.1.10", "192.168.1.11", "192.168.1.12")
$Credential = Get-Credential

foreach ($srv in $Servers) {
    Invoke-Command -ComputerName $srv -Credential $Credential `
        -FilePath ".\Win_Security_Inspect.ps1"
}
```

## 退出码

| 退出码 | 含义 |
|--------|------|
| 0 | 巡检完成，无严重项 |
| 1 | 巡检完成，存在严重安全风险 |

可用于自动化流水线中的条件判断。

## 文件说明

| 文件 | 说明 |
|------|------|
| `Win_Security_Inspect.ps1` | 巡检脚本主文件 |
| `LICENSE` | 许可证文件 |
| `README.md` | 本文档 |

## License

本项目采用 **MIT License** 开源，你可以自由使用、修改和分发，但请遵守以下约定：

1. **保留版权信息** — 在脚本文件头部保留原始作者信息，不得删除或篡改
2. **标注修改出处** — 如果你对脚本进行了修改或二次开发，请在显著位置注明：
   - 原项目地址：`https://github.com/Aidan-996/Win_Security_Inspect`
   - 原作者：Aidan-996
   - 你所做的修改内容
3. **禁止冒充原创** — 不得将本项目或其衍生作品声称为自己的原创作品
4. **商业使用需注明来源** — 用于商业用途（培训、付费文章、产品集成等）时，须注明本项目出处

**简单来说：免费用，随便改，但请尊重原作者，改了请说明。**

详见 [LICENSE](LICENSE) 文件。
