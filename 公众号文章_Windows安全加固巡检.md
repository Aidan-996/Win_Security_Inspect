# 一键搞定！Windows Server 安全加固巡检脚本，运维人必备神器

> 服务器安全加固还在对着等保清单一项项手动查？这篇文章给你一个开箱即用的 PowerShell 巡检脚本，跑完自动生成高颜值 HTML 报告，安全评分一目了然。

---

## 为什么需要安全加固巡检？

做运维的都知道，Windows Server 的安全加固是绑在脑门上的紧箍咒：

- 等保测评、安全审计一来，手忙脚乱翻策略
- 密码策略、审计策略、端口管控... 检查项几十上百条
- 服务器多的时候，一台台敲命令能敲到天亮
- 出了安全事件才发现，RDP 裸奔了三个月...

**一个好的安全巡检脚本 = 省时间 + 不遗漏 + 自动出报告 + 量化评分**

---

## 这个脚本能干啥？

一个 **PowerShell 安全加固巡检脚本**，覆盖 **15 大检查维度**，一条命令跑完，自动生成 HTML 报告 + 安全评分。

### 检查维度一览

| # | 模块 | 检查内容 |
|---|------|---------|
| 1 | **系统基本信息** | 主机名、IP、系统版本、运行时间、域/工作组、CPU/内存、BIOS |
| 2 | **账户与密码策略** | 最小密码长度、最大期限、复杂度、历史记录、锁定阈值/时长 |
| 3 | **本地用户与组** | 用户列表、启停状态、密码过期、Administrators 组成员 |
| 4 | **审计策略配置** | 登录事件、账户管理、策略更改、特权使用、进程跟踪等 8 项 |
| 5 | **事件日志配置** | 安全/系统/应用日志容量、保留方式 + 7天安全事件统计 |
| 6 | **登录失败分析** | Top 10 失败IP、失败次数、暴力破解检测、最近失败记录 |
| 7 | **端口与防火墙** | 监听端口清单、高风险端口标记、防火墙配置、入站规则审计 |
| 8 | **高风险服务检查** | 15 个高风险服务状态：Telnet/FTP/远程注册表/SNMP 等 |
| 9 | **RDP 远程桌面安全** | 启用状态、NLA认证、端口是否默认、加密级别 |
| 10 | **SMB 文件共享安全** | SMBv1 禁用、签名要求、加密、非默认共享 |
| 11 | **Windows Update** | 最近补丁安装时间、距今天数、最近10个补丁列表 |
| 12 | **注册表安全加固** | 10 项关键安全注册表：匿名访问、LM认证、UAC、NTLM 等 |
| 13 | **计划任务审计** | 非系统计划任务、SYSTEM身份运行的任务标记 |
| 14 | **网络连接分析** | TCP 连接状态统计、出站 IP Top10、可疑连接 |
| 15 | **安全加固建议** | 6 大类 30+ 条加固建议清单 |

---

## 报告长啥样？

报告采用现代化卡片式设计，顶部 5 个核心指标一目了然：

```
 ┌──────────┬──────┬──────┬──────┬──────┐
 │ 安全评分 │ 通过 │ 警告 │ 严重 │ 总数 │
 │   78%    │  25  │   6  │   1  │  32  │
 └──────────┴──────┴──────┴──────┴──────┘
```

### 评分机制

脚本会对每个检查项进行自动评估，最终计算安全评分：

- **通过（绿色）** = 符合安全基线
- **警告（橙色）** = 存在风险，建议加固
- **严重（红色）** = 必须立即修复

**安全评分 = 通过项 / 总检查项 × 100%**

- **>= 80%** → 安全状况良好（绿色）
- **60% - 79%** → 存在风险（橙色）
- **< 60%** → 安全隐患较多（红色）

报告包含 **可点击的目录导航**，15 个模块一键跳转，专业、直观。

---

## 详细检查项说明

### 密码策略检查

密码策略是最基础的安全防线。脚本通过 `secedit` 导出本地安全策略进行检查：

| 检查项 | 建议值 | 说明 |
|--------|--------|------|
| 最小密码长度 | >= 12 位 | 防止弱口令 |
| 密码复杂度 | 已启用 | 必须包含大小写+数字+特殊字符 |
| 最大密码期限 | <= 90 天 | 定期强制更换密码 |
| 密码历史 | >= 5 个 | 防止重复使用旧密码 |
| 账户锁定阈值 | <= 5 次 | 防暴力破解 |
| 锁定持续时间 | >= 30 分钟 | 锁定后的等待时间 |

### 高风险端口识别

脚本内置高风险端口库，自动标记风险：

| 端口 | 服务 | 风险级别 |
|------|------|---------|
| 21 | FTP | **严重** - 明文传输 |
| 23 | Telnet | **严重** - 明文传输 |
| 135 | RPC | 警告 - 常被利用 |
| 139 | NetBIOS | 警告 - SMB 相关 |
| 445 | SMB | 警告 - 勒索病毒常用 |
| 1433 | SQL Server | 警告 - 数据库暴露 |
| 3389 | RDP | 警告 - 远程桌面 |
| 5985/5986 | WinRM | 警告 - 远程管理 |

### 注册表安全加固

10 项关键安全注册表配置，直接对标等保和 CIS Benchmark：

| 注册表项 | 建议值 | 说明 |
|---------|--------|------|
| RestrictAnonymous | 1 | 限制匿名访问 |
| RestrictAnonymousSAM | 1 | 限制匿名枚举 SAM |
| LmCompatibilityLevel | 5 | 仅允许 NTLMv2 |
| NoLMHash | 1 | 禁止存储 LM Hash |
| EnableLUA | 1 | 启用 UAC |
| ConsentPromptBehaviorAdmin | 2 | 安全桌面提示 |
| AutoShareServer | 0 | 禁用管理共享 |
| fDisableCdm | 1 | RDP 禁止驱动映射 |
| NtlmMinServerSec | 537395200 | NTLMv2 + 128bit |
| LegalNoticeText | 非空 | 登录法律声明 |

### 登录失败分析

暴力破解是 Windows Server 最常见的攻击方式。脚本自动分析最近 7 天的 4625 事件：

- **按 IP 统计**：快速定位攻击来源
- **按用户统计**：发现被针对的账户
- **风险等级**：>= 100 次标记为严重，>= 20 次标记为警告
- **最近记录**：展示最新 10 条失败详情

### 15 个高风险服务

脚本检测以下服务的运行状态：

| 风险级别 | 服务 |
|---------|------|
| **严重** | Telnet、FTP (FTPSVC/MSFTPSVC)、Remote Registry、Simple TCP/IP |
| **警告** | RDP (TermService)、WinRM、SNMP、SSDP、UPnP、Computer Browser、NetBIOS Helper、ICS |
| **信息** | IIS (W3SVC)、RAS 连接管理器 |

---

## 快速使用

### 1. 下载脚本

把 `Win_Security_Inspect.ps1` 上传到目标服务器。

### 2. 管理员运行

```powershell
# 以管理员身份打开 PowerShell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
.\Win_Security_Inspect.ps1
```

### 3. 查看报告

脚本执行完会输出报告路径：

```
========================================
  安全加固巡检完成: WIN-SERVER-01
  时间: 2026-04-08 10:30:00
  通过: 25  警告: 6  严重: 1
  安全评分: 78%
  报告: C:\Users\xxx\AppData\Local\Temp\security_inspect\security_inspect_WIN-SERVER-01_20260408_103000.html
  耗时: 12.3 秒
========================================
```

把 HTML 文件下载到本地，浏览器打开即可。

### 4. 自定义参数

```powershell
# 自定义报告目录和阈值
.\Win_Security_Inspect.ps1 `
    -ReportDir "D:\Reports" `
    -MinPwdLength 14 `
    -MaxPwdAgeDays 60 `
    -LockoutThreshold 3 `
    -SecurityLogMinKB 409600
```

---

## 脚本技术细节

### 数据采集方式

| 数据源 | 采集方式 |
|--------|---------|
| 密码策略 | `secedit /export` 导出本地安全策略 |
| 审计策略 | `auditpol /get /category:*` |
| 用户信息 | `Get-LocalUser` / `Get-LocalGroupMember` |
| 事件日志 | `Get-WinEvent` 过滤 EventID |
| 网络连接 | `Get-NetTCPConnection` |
| 端口监听 | `Get-NetTCPConnection -State Listen` |
| 防火墙 | `Get-NetFirewallProfile` / `Get-NetFirewallRule` |
| 服务状态 | `Get-Service` / `Get-CimInstance Win32_Service` |
| 注册表 | `Get-ItemProperty` 读取关键注册表路径 |
| 补丁信息 | `Get-HotFix` |
| 计划任务 | `Get-ScheduledTask` |
| SMB配置 | `Get-SmbServerConfiguration` / `Get-SmbShare` |

### 兼容性

- Windows Server 2016 ✅
- Windows Server 2019 ✅
- Windows Server 2022 ✅
- Windows Server 2025 ✅
- Windows 10/11 (部分功能) ✅

### 退出码

- **0** = 无严重项
- **1** = 存在严重项（方便自动化脚本判断）

---

## 进阶玩法

### 定时巡检 + 邮件通知

配合 Windows 计划任务，每天自动巡检：

```powershell
# 创建每日巡检计划任务
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-ExecutionPolicy Bypass -File C:\Scripts\Win_Security_Inspect.ps1 -ReportDir D:\Reports"
$Trigger = New-ScheduledTaskTrigger -Daily -At "08:00"
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
Register-ScheduledTask -TaskName "SecurityInspect" -Action $Action -Trigger $Trigger -Principal $Principal
```

巡检完发送邮件：

```powershell
# 追加到巡检脚本后面，或单独封装
$report = Get-ChildItem "D:\Reports\*.html" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Send-MailMessage -From "server@company.com" -To "admin@company.com" `
    -Subject "$env:COMPUTERNAME 安全巡检报告 - $(Get-Date -Format 'yyyy-MM-dd')" `
    -Body "巡检报告见附件" -Attachments $report.FullName `
    -SmtpServer "smtp.company.com"
```

### 批量巡检

用 PowerShell Remoting 一次巡检多台服务器：

```powershell
# batch_inspect.ps1
$Servers = @("192.168.1.10", "192.168.1.11", "192.168.1.12")
$Credential = Get-Credential

foreach ($srv in $Servers) {
    Write-Host "=== 巡检: $srv ===" -ForegroundColor Cyan
    Invoke-Command -ComputerName $srv -Credential $Credential `
        -FilePath "C:\Scripts\Win_Security_Inspect.ps1"
    # 拉取报告
    $session = New-PSSession -ComputerName $srv -Credential $Credential
    $remotePath = Invoke-Command -Session $session -ScriptBlock {
        Get-ChildItem "$env:TEMP\security_inspect\*.html" |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName
    }
    Copy-Item -Path $remotePath -Destination "D:\Reports\$srv\" -FromSession $session
    Remove-PSSession $session
}
```

### 集成企业微信/钉钉通知

在脚本末尾加上 webhook 推送：

```powershell
# 企业微信通知
if ($script:CriticalCount -gt 0) {
    $body = @{
        msgtype = "markdown"
        markdown = @{
            content = @"
## Windows 安全巡检告警
> 主机: $env:COMPUTERNAME
> 评分: ${scorePercent}%
> 通过: $($script:PassCount) | 警告: $($script:WarnCount) | 严重: $($script:CriticalCount)
> **存在严重安全风险，请立即处理！**
"@
        }
    } | ConvertTo-Json -Depth 3

    Invoke-RestMethod -Uri "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=YOUR_KEY" `
        -Method POST -ContentType "application/json" -Body $body
}
```

### 对标等保/CIS Benchmark

脚本的检查项覆盖了以下标准的核心要求：

| 标准 | 覆盖范围 |
|------|---------|
| **等保 2.0** | 身份鉴别、访问控制、安全审计、入侵防范 |
| **CIS Benchmark** | 密码策略、审计策略、网络安全、注册表加固 |
| **STIG** | 账户管理、服务加固、日志配置 |

---

## 与 Linux 版的对比

| 特性 | Linux 版 | Windows 版 |
|------|----------|-----------|
| 语言 | Bash | PowerShell |
| 侧重点 | 系统性能巡检 | 安全加固检查 |
| 检查维度 | 20+ 项 | 15 大模块 |
| 安全评分 | 无 | 有 (百分制) |
| 密码策略 | SSH 配置检查 | 完整密码策略审计 |
| 端口检查 | 监听端口 | 监听端口 + 风险标记 |
| 日志分析 | 系统日志关键字 | 安全事件 ID 精确分析 |
| 登录分析 | 失败记录 | IP 统计 + 暴力破解检测 |
| 注册表 | N/A | 10 项关键安全注册表 |
| 报告样式 | 蓝色系 | 红色系(安全主题) |

**两个脚本配合使用，Linux + Windows 全覆盖！**

---

## 脚本亮点总结

| 特性 | 说明 |
|------|------|
| **零依赖** | 纯 PowerShell 编写，无需安装任何额外模块 |
| **15 大模块** | 覆盖安全加固的方方面面 |
| **一键执行** | 管理员身份运行即可，无需配置 |
| **HTML 报告** | 现代卡片式设计 + 目录导航 |
| **安全评分** | 量化安全状态，直观展示 |
| **暴力破解检测** | 自动分析 4625 事件，定位攻击源 |
| **等保对标** | 覆盖等保 2.0 / CIS 核心检查项 |
| **高风险标记** | 端口、服务、配置自动标红 |
| **参数可调** | 密码长度、日志大小等阈值自定义 |
| **退出码支持** | 方便集成到自动化流水线 |
| **批量巡检** | 支持 PS Remoting 远程执行 |
| **多版本兼容** | 2016/2019/2022/2025 全兼容 |

---

## 写在最后

安全加固是运维工作中最容易被忽视、但最不能忽视的环节。一个好的巡检脚本，能让你从繁琐的手动检查中解放出来，把精力放在真正需要关注的安全问题上。

后面我还会继续分享：

- **VMware ESXi 巡检脚本（PowerCLI 版）**
- **Citrix 环境巡检脚本**
- **如何搭建轻量级巡检平台**

如果觉得有用，**点赞 + 收藏 + 转发**，你的支持是我持续更新的动力！

有问题欢迎在评论区交流，也可以私信我获取完整脚本源码。

---

*本文脚本已在生产环境验证，如有问题欢迎反馈。*
