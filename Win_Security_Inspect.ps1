#Requires -RunAsAdministrator
###############################################################################
# Windows Server 安全加固巡检脚本 v1.0
# 功能：一键采集安全配置、端口状态、日志审计等关键指标，生成 HTML 巡检报告
# 适用：Windows Server 2016 / 2019 / 2022 / 2025
# 用法：以管理员身份运行 PowerShell → .\Win_Security_Inspect.ps1
# 作者：运维团队
# 日期：2026-04-08
###############################################################################

param(
    [string]$ReportDir = "$env:TEMP\security_inspect",
    # 密码策略建议值
    [int]$MinPwdLength       = 12,
    [int]$MaxPwdAgeDays      = 90,
    [int]$LockoutThreshold   = 5,
    [int]$LockoutDuration    = 30,
    # 日志大小建议值 (KB)
    [int]$SecurityLogMinKB   = 204800,
    [int]$SystemLogMinKB     = 65536,
    [int]$AppLogMinKB        = 65536
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# ======================== 初始化 ========================
$ScriptVersion = "1.0"
$StartTime     = Get-Date
$Hostname      = $env:COMPUTERNAME
$ReportFile    = Join-Path $ReportDir "security_inspect_${Hostname}_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"

if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null }

# 计数器
$script:WarnCount     = 0
$script:CriticalCount = 0
$script:PassCount     = 0

# ======================== 工具函数 ========================
function Add-Pass     { $script:PassCount++ }
function Add-Warn     { $script:WarnCount++ }
function Add-Critical { $script:CriticalCount++ }

function Get-StatusBadge {
    param([string]$Status)
    switch ($Status) {
        'pass'     { '<span class="badge ok">通过</span>' }
        'warn'     { Add-Warn; '<span class="badge warning">警告</span>' }
        'critical' { Add-Critical; '<span class="badge critical">严重</span>' }
        'info'     { '<span class="badge info">信息</span>' }
        default    { '<span class="badge info">信息</span>' }
    }
}

function ConvertTo-HtmlTable {
    param(
        [string[]]$Headers,
        [System.Collections.ArrayList]$Rows
    )
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append('<table><thead><tr>')
    foreach ($h in $Headers) { [void]$sb.Append("<th>$h</th>") }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($row in $Rows) {
        [void]$sb.Append('<tr>')
        foreach ($cell in $row) { [void]$sb.Append("<td>$cell</td>") }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table>')
    return $sb.ToString()
}

function Write-Section {
    param([string]$Title, [string]$Icon, [string]$Content)
    return @"
<div class="section">
  <h2>$Icon $Title</h2>
  $Content
</div>
"@
}

Write-Host "[INFO] 开始安全加固巡检: $Hostname - $($StartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Green

# ======================== HTML 报告头 ========================
$htmlHead = @'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Windows Server 安全加固巡检报告</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, "Microsoft YaHei", "Segoe UI", sans-serif; background: #f0f2f5; color: #333; line-height: 1.6; }
  .container { max-width: 1000px; margin: 20px auto; padding: 0 16px; }
  .header { background: linear-gradient(135deg, #e74c3c, #c0392b); color: #fff; padding: 30px; border-radius: 12px; margin-bottom: 20px; text-align: center; }
  .header h1 { font-size: 24px; margin-bottom: 8px; }
  .header p { opacity: 0.9; font-size: 14px; }
  .summary { display: flex; gap: 12px; margin-bottom: 20px; flex-wrap: wrap; }
  .summary-card { flex: 1; min-width: 130px; background: #fff; border-radius: 10px; padding: 16px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.06); }
  .summary-card .num { font-size: 28px; font-weight: bold; }
  .summary-card .label { font-size: 12px; color: #888; margin-top: 4px; }
  .num.green { color: #52c41a; }
  .num.orange { color: #fa8c16; }
  .num.red { color: #f5222d; }
  .num.blue { color: #1890ff; }
  .section { background: #fff; border-radius: 10px; padding: 24px 28px; margin-bottom: 18px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); }
  .section h2 { font-size: 17px; color: #c0392b; border-left: 4px solid #e74c3c; padding-left: 12px; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 1px solid #f5f5f5; }
  .section h3 { font-size: 15px; color: #444; margin: 24px 0 12px; padding: 10px 14px; background: linear-gradient(135deg, #fff5f5, #fff0ed); border-radius: 8px; border-left: 3px solid #e74c3c; }
  .section h3:first-of-type { margin-top: 18px; }
  .section h4 { font-size: 13px; color: #666; margin: 18px 0 8px; padding-left: 4px; border-bottom: 1px dashed #e8e8e8; padding-bottom: 6px; }
  .section p { font-size: 13px; color: #888; margin: 6px 0 10px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; margin-bottom: 16px; }
  th { background: #fafafa; text-align: left; padding: 10px 12px; border-bottom: 2px solid #e8e8e8; white-space: nowrap; font-size: 12px; color: #666; text-transform: uppercase; letter-spacing: 0.3px; }
  td { padding: 10px 12px; border-bottom: 1px solid #f0f0f0; word-break: break-all; line-height: 1.5; }
  tr:hover { background: #fafbff; }
  td:first-child { font-weight: 500; }
  .badge { display: inline-block; padding: 3px 10px; border-radius: 10px; font-size: 11px; font-weight: 600; letter-spacing: 0.3px; }
  .badge.ok { background: #f6ffed; color: #389e0d; border: 1px solid #b7eb8f; }
  .badge.warning { background: #fff7e6; color: #d46b08; border: 1px solid #ffd591; }
  .badge.critical { background: #fff1f0; color: #cf1322; border: 1px solid #ffa39e; }
  .badge.info { background: #e6f7ff; color: #096dd9; border: 1px solid #91d5ff; }
  .info-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 8px; }
  .info-item { display: flex; padding: 6px 0; border-bottom: 1px dashed #f0f0f0; overflow: hidden; }
  .info-item .key { color: #888; min-width: 100px; width: 100px; flex-shrink: 0; font-size: 13px; }
  .info-item .val { font-weight: 500; font-size: 13px; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .info-item .val:hover { white-space: normal; word-break: break-all; }
  pre { background: #f8f9fa; padding: 14px 16px; border-radius: 8px; font-size: 12px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; max-height: 300px; overflow-y: auto; border: 1px solid #e8e8e8; line-height: 1.8; margin: 10px 0 16px; }
  code { font-size: 11px; background: #f0f0f0; padding: 2px 7px; border-radius: 3px; font-family: Consolas, "Courier New", monospace; }
  .footer { text-align: center; color: #aaa; font-size: 12px; padding: 20px 0; }
  .checklist-pass { color: #52c41a; }
  .checklist-fail { color: #f5222d; }
  .toc { background: #fff; border-radius: 10px; padding: 20px 24px; margin-bottom: 16px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); }
  .toc h3 { font-size: 16px; color: #333; margin-bottom: 14px; border-bottom: 2px solid #f0f0f0; padding-bottom: 10px; }
  .toc-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; }
  .toc-item { display: flex; align-items: center; gap: 8px; padding: 10px 14px; background: #f9fafb; border-radius: 8px; text-decoration: none; color: #333; font-size: 13px; border: 1px solid #f0f0f0; transition: all 0.2s; }
  .toc-item:hover { background: #fff1f0; border-color: #e74c3c; color: #c0392b; transform: translateY(-1px); box-shadow: 0 2px 6px rgba(231,76,60,0.12); }
  .toc-num { display: inline-flex; align-items: center; justify-content: center; width: 22px; height: 22px; background: #e74c3c; color: #fff; border-radius: 50%; font-size: 11px; font-weight: bold; flex-shrink: 0; }
  .toc-icon { font-size: 16px; flex-shrink: 0; }
  .toc-label { white-space: nowrap; }
  @media (max-width: 768px) { .toc-grid { grid-template-columns: repeat(2, 1fr); } }
  @media (max-width: 480px) { .toc-grid { grid-template-columns: 1fr; } }
</style>
</head>
<body>
<div class="container">
'@

# ======================== 1. 基本信息 ========================
Write-Host "[INFO] 采集系统基本信息..." -ForegroundColor Green

$osInfo       = Get-CimInstance Win32_OperatingSystem
$csInfo       = Get-CimInstance Win32_ComputerSystem
$biosInfo     = Get-CimInstance Win32_BIOS
$cpuInfo      = Get-CimInstance Win32_Processor | Select-Object -First 1
$netAdapters  = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
$primaryIP    = ($netAdapters | Select-Object -First 1).IPAddress | Where-Object { $_ -match '^\d+\.\d+' } | Select-Object -First 1

$sysInfoHtml = @"
<div class="info-grid">
  <div class="info-item"><span class="key">主机名</span><span class="val">$Hostname</span></div>
  <div class="info-item"><span class="key">IP 地址</span><span class="val">$primaryIP</span></div>
  <div class="info-item"><span class="key">操作系统</span><span class="val">$($osInfo.Caption)</span></div>
  <div class="info-item"><span class="key">系统版本</span><span class="val">$($osInfo.Version) Build $($osInfo.BuildNumber)</span></div>
  <div class="info-item"><span class="key">安装日期</span><span class="val">$($osInfo.InstallDate.ToString('yyyy-MM-dd'))</span></div>
  <div class="info-item"><span class="key">最后启动</span><span class="val">$($osInfo.LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss'))</span></div>
  <div class="info-item"><span class="key">运行时间</span><span class="val">$([math]::Round(((Get-Date) - $osInfo.LastBootUpTime).TotalDays, 1)) 天</span></div>
  <div class="info-item"><span class="key">域/工作组</span><span class="val">$(if($csInfo.PartOfDomain){"域: $($csInfo.Domain)"}else{"工作组: $($csInfo.Workgroup)"})</span></div>
  <div class="info-item"><span class="key">CPU</span><span class="val">$($cpuInfo.Name)</span></div>
  <div class="info-item"><span class="key">CPU 核数</span><span class="val">$($csInfo.NumberOfLogicalProcessors) 逻辑核 / $($csInfo.NumberOfProcessors) 物理</span></div>
  <div class="info-item"><span class="key">总内存</span><span class="val">$([math]::Round($csInfo.TotalPhysicalMemory / 1GB, 1)) GB</span></div>
  <div class="info-item"><span class="key">BIOS</span><span class="val">$($biosInfo.Manufacturer) $($biosInfo.SMBIOSBIOSVersion)</span></div>
  <div class="info-item"><span class="key">序列号</span><span class="val">$($biosInfo.SerialNumber)</span></div>
  <div class="info-item"><span class="key">时区</span><span class="val">$((Get-TimeZone).DisplayName)</span></div>
</div>
"@

$section1 = Write-Section -Title "系统基本信息" -Icon "&#128187;" -Content $sysInfoHtml

# ======================== 2. 账户与密码策略 ========================
Write-Host "[INFO] 检查账户与密码策略..." -ForegroundColor Green

# 导出本地安全策略
$secEditFile = Join-Path $env:TEMP "secpol_export.inf"
secedit /export /cfg $secEditFile /quiet 2>$null
$secContent = if (Test-Path $secEditFile) { Get-Content $secEditFile -Raw } else { "" }

function Get-SecPolValue {
    param([string]$Key)
    if ($secContent -match "$Key\s*=\s*(.+)") { return $Matches[1].Trim() }
    return "N/A"
}

$minPwdLen       = Get-SecPolValue "MinimumPasswordLength"
$maxPwdAge       = Get-SecPolValue "MaximumPasswordAge"
$minPwdAge       = Get-SecPolValue "MinimumPasswordAge"
$pwdHistory      = Get-SecPolValue "PasswordHistorySize"
$pwdComplexity   = Get-SecPolValue "PasswordComplexity"
$lockoutBad      = Get-SecPolValue "LockoutBadCount"
$lockoutDuration = Get-SecPolValue "ResetLockoutCount"
$lockoutWindow   = Get-SecPolValue "LockoutDuration"

$pwdRows = [System.Collections.ArrayList]::new()

# 最小密码长度
$pwdLenStatus = if ($minPwdLen -ne "N/A" -and [int]$minPwdLen -ge $MinPwdLength) { Add-Pass; "pass" } else { "critical" }
[void]$pwdRows.Add(@("最小密码长度", $minPwdLen, ">= $MinPwdLength", (Get-StatusBadge $pwdLenStatus)))

# 最大密码使用期限
$maxPwdStatus = if ($maxPwdAge -ne "N/A" -and [int]$maxPwdAge -le $MaxPwdAgeDays -and [int]$maxPwdAge -gt 0) { Add-Pass; "pass" } else { "warn" }
[void]$pwdRows.Add(@("最大密码期限(天)", $maxPwdAge, "<= $MaxPwdAgeDays", (Get-StatusBadge $maxPwdStatus)))

# 密码复杂度
$complexStatus = if ($pwdComplexity -eq "1") { Add-Pass; "pass" } else { "critical" }
[void]$pwdRows.Add(@("密码复杂度要求", $(if($pwdComplexity -eq "1"){"已启用"}else{"未启用"}), "已启用", (Get-StatusBadge $complexStatus)))

# 密码历史
$histStatus = if ($pwdHistory -ne "N/A" -and [int]$pwdHistory -ge 5) { Add-Pass; "pass" } else { "warn" }
[void]$pwdRows.Add(@("密码历史记录", $pwdHistory, ">= 5", (Get-StatusBadge $histStatus)))

# 最小密码期限
$minAgeStatus = if ($minPwdAge -ne "N/A" -and [int]$minPwdAge -ge 1) { Add-Pass; "pass" } else { "warn" }
[void]$pwdRows.Add(@("最小密码期限(天)", $minPwdAge, ">= 1", (Get-StatusBadge $minAgeStatus)))

# 账户锁定阈值
$lockBadStatus = if ($lockoutBad -ne "N/A" -and [int]$lockoutBad -gt 0 -and [int]$lockoutBad -le $LockoutThreshold) { Add-Pass; "pass" } elseif ($lockoutBad -eq "0" -or $lockoutBad -eq "N/A") { "critical" } else { "warn" }
[void]$pwdRows.Add(@("账户锁定阈值", $lockoutBad, "<= $LockoutThreshold 且 > 0", (Get-StatusBadge $lockBadStatus)))

# 锁定持续时间
$lockDurStatus = if ($lockoutWindow -ne "N/A" -and [int]$lockoutWindow -ge $LockoutDuration) { Add-Pass; "pass" } else { "warn" }
[void]$pwdRows.Add(@("锁定持续时间(分)", $lockoutWindow, ">= $LockoutDuration", (Get-StatusBadge $lockDurStatus)))

$pwdTable = ConvertTo-HtmlTable -Headers @("检查项","当前值","建议值","状态") -Rows $pwdRows
$section2 = Write-Section -Title "账户与密码策略" -Icon "&#128274;" -Content $pwdTable

# ======================== 3. 本地用户与组 ========================
Write-Host "[INFO] 检查本地用户与组..." -ForegroundColor Green

$localUsers = Get-LocalUser
$userRows = [System.Collections.ArrayList]::new()

foreach ($u in $localUsers) {
    $enabled = if ($u.Enabled) { "启用" } else { "禁用" }
    $lastLogon = if ($u.LastLogon) { $u.LastLogon.ToString('yyyy-MM-dd HH:mm') } else { "从未" }
    $pwdExpires = if ($u.PasswordExpires) { $u.PasswordExpires.ToString('yyyy-MM-dd') } else { "永不过期" }
    $pwdChangeable = if ($u.PasswordLastSet) { $u.PasswordLastSet.ToString('yyyy-MM-dd') } else { "N/A" }

    # 检查风险
    $status = "info"
    if ($u.Enabled -and $u.Name -eq "Administrator") { $status = "warn" }
    if ($u.Enabled -and $u.Name -eq "Guest") { $status = "critical" }
    if ($u.Enabled -and $pwdExpires -eq "永不过期" -and $u.Name -ne "DefaultAccount") { $status = "warn" }

    [void]$userRows.Add(@($u.Name, $enabled, $lastLogon, $pwdChangeable, $pwdExpires, (Get-StatusBadge $status)))
}

$userTable = ConvertTo-HtmlTable -Headers @("用户名","状态","最后登录","密码设置时间","密码过期","风险") -Rows $userRows

# 管理员组成员
$adminMembers = Get-LocalGroupMember -Group "Administrators" 2>$null
$adminList = if ($adminMembers) { ($adminMembers | ForEach-Object { $_.Name }) -join ", " } else { "N/A" }

$userContent = @"
<h3>本地用户列表</h3>
$userTable
<h3>Administrators 组成员</h3>
<pre>$adminList</pre>
"@

$section3 = Write-Section -Title "本地用户与组" -Icon "&#128101;" -Content $userContent

# ======================== 4. 审计策略 ========================
Write-Host "[INFO] 检查审计策略..." -ForegroundColor Green

$auditRows = [System.Collections.ArrayList]::new()

# 使用 auditpol 获取审计策略
$auditOutput = auditpol /get /category:* 2>$null
$auditPolicies = @(
    @{
        Name     = "登录事件"
        Keywords = @("Logon", "登录")
        EventIDs = "4624/4625/4634/4647"
        Desc     = "记录用户登录和注销行为，是检测暴力破解、异常登录的核心数据源"
        Risk     = "未启用将无法追踪谁在何时登录了服务器，暴力破解攻击不可见"
        FixCmd   = "auditpol /set /subcategory:`"Logon`" /success:enable /failure:enable"
    },
    @{
        Name     = "账户登录事件"
        Keywords = @("Credential Validation", "凭据验证")
        EventIDs = "4774/4775/4776/4777"
        Desc     = "记录凭据验证过程（NTLM 认证），用于检测域/本地账户的认证请求"
        Risk     = "未启用将无法发现密码喷洒、Pass-the-Hash 等凭据攻击"
        FixCmd   = "auditpol /set /subcategory:`"Credential Validation`" /success:enable /failure:enable"
    },
    @{
        Name     = "对象访问"
        Keywords = @("File System", "文件系统")
        EventIDs = "4656/4658/4660/4663"
        Desc     = "记录文件、注册表等对象的访问操作，配合 SACL 使用可精确审计敏感文件"
        Risk     = "未启用将无法追踪敏感文件被谁读取、修改或删除"
        FixCmd   = "auditpol /set /subcategory:`"File System`" /success:enable /failure:enable"
    },
    @{
        Name     = "策略更改"
        Keywords = @("Audit Policy Change", "审核策略更改")
        EventIDs = "4719/4739/4904/4905"
        Desc     = "记录审计策略自身的变更，防止攻击者关闭审计后清除痕迹"
        Risk     = "未启用将无法发现攻击者篡改审计策略的行为（反取证手段）"
        FixCmd   = "auditpol /set /subcategory:`"Audit Policy Change`" /success:enable /failure:enable"
    },
    @{
        Name     = "账户管理"
        Keywords = @("User Account Management", "用户帐户管理")
        EventIDs = "4720/4722/4723/4724/4725/4726/4738"
        Desc     = "记录用户账户的创建、删除、启用、禁用、密码重置等操作"
        Risk     = "未启用将无法发现后门账户创建、权限提升等恶意行为"
        FixCmd   = "auditpol /set /subcategory:`"User Account Management`" /success:enable /failure:enable"
    },
    @{
        Name     = "特权使用"
        Keywords = @("Sensitive Privilege Use", "敏感权限使用")
        EventIDs = "4672/4673/4674"
        Desc     = "记录敏感特权的使用，如 SeDebugPrivilege、SeTakeOwnershipPrivilege 等"
        Risk     = "未启用将无法检测提权攻击和管理员特权滥用"
        FixCmd   = "auditpol /set /subcategory:`"Sensitive Privilege Use`" /success:enable /failure:enable"
    },
    @{
        Name     = "系统事件"
        Keywords = @("Security State Change", "安全状态更改")
        EventIDs = "4608/4616/4621/1102"
        Desc     = "记录系统启动/关闭、时间修改、日志清除等关键系统级事件"
        Risk     = "未启用将无法发现系统时间篡改、安全日志被清除等行为"
        FixCmd   = "auditpol /set /subcategory:`"Security State Change`" /success:enable /failure:enable"
    },
    @{
        Name     = "进程跟踪"
        Keywords = @("Process Creation", "进程创建")
        EventIDs = "4688/4689"
        Desc     = "记录进程创建和退出，是检测恶意软件执行、横向移动的关键日志"
        Risk     = "未启用将无法追踪恶意程序的执行链（如 PowerShell 攻击、木马启动）"
        FixCmd   = "auditpol /set /subcategory:`"Process Creation`" /success:enable /failure:enable"
    }
)

foreach ($ap in $auditPolicies) {
    $found = $false
    foreach ($kw in $ap.Keywords) {
        $line = $auditOutput | Where-Object { $_ -match $kw }
        if ($line) {
            $setting = ($line -split '\s{2,}')[-1].Trim()
            $status = if ($setting -match "Success and Failure|成功和失败") { Add-Pass; "pass" }
                      elseif ($setting -match "Success|成功") { "warn" }
                      elseif ($setting -match "No Auditing|无审核|未配置") { "critical" }
                      else { "info" }
            [void]$auditRows.Add(@($ap.Name, $ap.EventIDs, $ap.Desc, $setting, "成功和失败", (Get-StatusBadge $status)))
            $found = $true
            break
        }
    }
    if (-not $found) {
        [void]$auditRows.Add(@($ap.Name, $ap.EventIDs, $ap.Desc, "未检测到", "成功和失败", (Get-StatusBadge "warn")))
    }
}

$auditTable = ConvertTo-HtmlTable -Headers @("审计策略","关联事件ID","说明","当前设置","建议设置","状态") -Rows $auditRows

# ---- 各审计策略关联事件实况 ----
Write-Host "[INFO] 采集各审计策略关联事件数据..." -ForegroundColor Green
$auditEventDays = 7
$auditEventStart = (Get-Date).AddDays(-$auditEventDays)

# --- 4.1 登录事件实况 ---
$auditLoginHtml = "<h3>&#128205; 登录事件实况（最近 ${auditEventDays} 天）</h3>"

# 成功登录统计
$loginSuccessEvts = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=$auditEventStart} -MaxEvents 10000 2>$null
$loginSuccessCount = ($loginSuccessEvts | Measure-Object).Count

# 按登录类型分组
$logonTypeNames = @{ 2="交互式(本地)"; 3="网络"; 4="批处理"; 5="服务"; 7="解锁"; 8="网络明文"; 10="远程桌面(RDP)"; 11="缓存凭据" }
$logonTypeStats = @{}
foreach ($evt in $loginSuccessEvts) {
    $xml = [xml]$evt.ToXml()
    $lt = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'LogonType' }).'#text'
    if ($lt) {
        $ltName = if ($logonTypeNames.ContainsKey([int]$lt)) { "$lt - $($logonTypeNames[[int]$lt])" } else { "$lt - 其他" }
        if ($logonTypeStats.ContainsKey($ltName)) { $logonTypeStats[$ltName]++ } else { $logonTypeStats[$ltName] = 1 }
    }
}
$ltRows = [System.Collections.ArrayList]::new()
foreach ($entry in ($logonTypeStats.GetEnumerator() | Sort-Object Value -Descending)) {
    $ltStatus = if ($entry.Key -match "^8 ") { "critical" } elseif ($entry.Key -match "^10 ") { "warn" } else { "info" }
    [void]$ltRows.Add(@($entry.Key, $entry.Value, (Get-StatusBadge $ltStatus)))
}
$auditLoginHtml += "<h4>成功登录按类型分布（共 $loginSuccessCount 次）</h4>"
$auditLoginHtml += ConvertTo-HtmlTable -Headers @("登录类型","次数","评估") -Rows $ltRows

# 成功登录来源 IP Top 10
$loginSrcIPs = @{}
foreach ($evt in $loginSuccessEvts) {
    $xml = [xml]$evt.ToXml()
    $ip = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
    $lt = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'LogonType' }).'#text'
    if ($ip -and $ip -ne '-' -and $ip -ne '127.0.0.1' -and $ip -ne '::1' -and $lt -notin @('5','0')) {
        if ($loginSrcIPs.ContainsKey($ip)) { $loginSrcIPs[$ip]++ } else { $loginSrcIPs[$ip] = 1 }
    }
}
$srcRows = [System.Collections.ArrayList]::new()
foreach ($entry in ($loginSrcIPs.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10)) {
    [void]$srcRows.Add(@($entry.Key, $entry.Value, (Get-StatusBadge "info")))
}
if ($srcRows.Count -gt 0) {
    $auditLoginHtml += "<h4>成功登录来源 IP Top 10</h4>"
    $auditLoginHtml += ConvertTo-HtmlTable -Headers @("来源 IP","登录次数","评估") -Rows $srcRows
}

# 失败登录统计
$loginFailEvts = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$auditEventStart} -MaxEvents 10000 2>$null
$loginFailCount = ($loginFailEvts | Measure-Object).Count

$failIpUser = @{}
foreach ($evt in $loginFailEvts) {
    $xml = [xml]$evt.ToXml()
    $ip  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
    $usr = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
    $sub = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'SubStatus' }).'#text'
    if ($ip -and $ip -ne '-') {
        $key = "$ip"
        if (-not $failIpUser.ContainsKey($key)) { $failIpUser[$key] = @{ Count=0; Users=@{}; SubStatus=$sub; LastTime=$evt.TimeCreated } }
        $failIpUser[$key].Count++
        $failIpUser[$key].Users[$usr] = $true
        if ($evt.TimeCreated -gt $failIpUser[$key].LastTime) { $failIpUser[$key].LastTime = $evt.TimeCreated }
    }
}

$subStatusNames = @{
    "0xC0000064" = "用户名不存在"
    "0xC000006A" = "密码错误"
    "0xC0000234" = "账户已锁定"
    "0xC0000072" = "账户已禁用"
    "0xC000006F" = "非允许时间登录"
    "0xC0000070" = "非允许工作站"
    "0xC0000071" = "密码已过期"
    "0xC0000133" = "时钟偏差过大"
    "0xC0000224" = "必须更改密码"
}

$failRows2 = [System.Collections.ArrayList]::new()
foreach ($entry in ($failIpUser.GetEnumerator() | Sort-Object { $_.Value.Count } -Descending | Select-Object -First 15)) {
    $targetUsers = ($entry.Value.Users.Keys | Select-Object -First 5) -join ", "
    $extraUsers = if ($entry.Value.Users.Count -gt 5) { " (+$($entry.Value.Users.Count - 5))" } else { "" }
    $subName = if ($subStatusNames.ContainsKey($entry.Value.SubStatus)) { $subStatusNames[$entry.Value.SubStatus] } else { $entry.Value.SubStatus }
    $fStatus = if ($entry.Value.Count -ge 100) { "critical" } elseif ($entry.Value.Count -ge 20) { "warn" } else { "info" }
    $verdict = if ($entry.Value.Count -ge 100) { "疑似暴力破解" } elseif ($entry.Value.Count -ge 20) { "频繁失败" } else { "少量失败" }
    [void]$failRows2.Add(@($entry.Key, "$($entry.Value.Count) 次", "${targetUsers}${extraUsers}", $subName, $entry.Value.LastTime.ToString('MM-dd HH:mm'), $verdict, (Get-StatusBadge $fStatus)))
}

$auditLoginHtml += "<h4>失败登录来源分析（共 $loginFailCount 次）</h4>"
if ($failRows2.Count -gt 0) {
    $auditLoginHtml += ConvertTo-HtmlTable -Headers @("来源 IP","失败次数","尝试用户名","失败原因","最后尝试","判定","状态") -Rows $failRows2
} else {
    $auditLoginHtml += '<p style="color:#52c41a;">最近 ' + $auditEventDays + ' 天无登录失败记录</p>'
}

# 最近 10 条登录失败明细
if ($loginFailEvts -and $loginFailCount -gt 0) {
    $recentFailRows = [System.Collections.ArrayList]::new()
    foreach ($evt in ($loginFailEvts | Select-Object -First 10)) {
        $xml = [xml]$evt.ToXml()
        $ip  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
        $usr = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
        $dom = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetDomainName' }).'#text'
        $sub = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'SubStatus' }).'#text'
        $lt  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'LogonType' }).'#text'
        $subName = if ($subStatusNames.ContainsKey($sub)) { $subStatusNames[$sub] } else { $sub }
        $ltName  = if ($logonTypeNames.ContainsKey([int]$lt)) { $logonTypeNames[[int]$lt] } else { $lt }
        [void]$recentFailRows.Add(@($evt.TimeCreated.ToString('MM-dd HH:mm:ss'), "$dom\$usr", $ip, $ltName, $subName))
    }
    $auditLoginHtml += "<h4>最近 10 条失败登录明细</h4>"
    $auditLoginHtml += ConvertTo-HtmlTable -Headers @("时间","目标账户","来源IP","登录类型","失败原因") -Rows $recentFailRows
}

# --- 4.2 账户管理事件实况 ---
$auditAcctHtml = "<h3>&#128205; 账户管理事件实况（最近 ${auditEventDays} 天）</h3>"
$acctEventIds = @(4720, 4722, 4723, 4724, 4725, 4726, 4738, 4732, 4733, 4756, 4757)
$acctEventNames = @{
    4720 = "创建用户账户"; 4722 = "启用用户账户"; 4723 = "用户尝试更改密码"
    4724 = "重置用户密码"; 4725 = "禁用用户账户"; 4726 = "删除用户账户"
    4738 = "修改用户账户"; 4732 = "成员添加到本地组"; 4733 = "成员从本地组移除"
    4756 = "成员添加到通用组"; 4757 = "成员从通用组移除"
}
$acctEvts = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$acctEventIds; StartTime=$auditEventStart} -MaxEvents 500 2>$null
$acctCount = ($acctEvts | Measure-Object).Count

if ($acctEvts -and $acctCount -gt 0) {
    $acctRows = [System.Collections.ArrayList]::new()
    foreach ($evt in ($acctEvts | Select-Object -First 20)) {
        $xml = [xml]$evt.ToXml()
        $targetUser = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
        $operator   = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
        $evtName    = if ($acctEventNames.ContainsKey($evt.Id)) { $acctEventNames[$evt.Id] } else { "事件 $($evt.Id)" }
        $aStatus    = if ($evt.Id -in @(4720, 4726, 4732)) { "warn" } else { "info" }
        [void]$acctRows.Add(@($evt.TimeCreated.ToString('MM-dd HH:mm:ss'), $evt.Id, $evtName, $targetUser, $operator, (Get-StatusBadge $aStatus)))
    }
    $auditAcctHtml += "<p>共 $acctCount 条账户管理事件</p>"
    $auditAcctHtml += ConvertTo-HtmlTable -Headers @("时间","事件ID","操作","目标账户","操作者","评估") -Rows $acctRows
} else {
    $auditAcctHtml += '<p style="color:#52c41a;">最近 ' + $auditEventDays + ' 天无账户管理变更事件</p>'
}

# --- 4.3 策略更改事件实况 ---
$auditPolHtml = "<h3>&#128205; 策略更改事件实况（最近 ${auditEventDays} 天）</h3>"
$polEventIds = @(4719, 4739, 4904, 4905, 4906, 4907)
$polEventNames = @{
    4719 = "系统审计策略更改"; 4739 = "域策略更改"; 4904 = "注册安全事件源"
    4905 = "注销安全事件源"; 4906 = "CrashOnAuditFail 值更改"; 4907 = "审计设置更改"
}
$polEvts = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$polEventIds; StartTime=$auditEventStart} -MaxEvents 200 2>$null
$polCount = ($polEvts | Measure-Object).Count

if ($polEvts -and $polCount -gt 0) {
    $polRows = [System.Collections.ArrayList]::new()
    foreach ($evt in ($polEvts | Select-Object -First 15)) {
        $xml = [xml]$evt.ToXml()
        $operator = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
        $evtName  = if ($polEventNames.ContainsKey($evt.Id)) { $polEventNames[$evt.Id] } else { "事件 $($evt.Id)" }
        [void]$polRows.Add(@($evt.TimeCreated.ToString('MM-dd HH:mm:ss'), $evt.Id, $evtName, $operator, (Get-StatusBadge "warn")))
    }
    $auditPolHtml += "<p>共 $polCount 条策略更改事件</p>"
    $auditPolHtml += ConvertTo-HtmlTable -Headers @("时间","事件ID","操作","操作者","评估") -Rows $polRows
} else {
    $auditPolHtml += '<p style="color:#52c41a;">最近 ' + $auditEventDays + ' 天无策略更改事件</p>'
}

# --- 4.4 特权使用事件实况 ---
$auditPrivHtml = "<h3>&#128205; 特权使用事件实况（最近 ${auditEventDays} 天）</h3>"
$privEvts = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4672; StartTime=$auditEventStart} -MaxEvents 5000 2>$null
$privCount = ($privEvts | Measure-Object).Count

$privUserStats = @{}
foreach ($evt in $privEvts) {
    $xml = [xml]$evt.ToXml()
    $usr = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
    if ($usr -and $usr -ne 'SYSTEM' -and $usr -notmatch '\$$') {
        if ($privUserStats.ContainsKey($usr)) { $privUserStats[$usr]++ } else { $privUserStats[$usr] = 1 }
    }
}

if ($privUserStats.Count -gt 0) {
    $privRows = [System.Collections.ArrayList]::new()
    foreach ($entry in ($privUserStats.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10)) {
        $pStatus = if ($entry.Value -ge 500) { "warn" } else { "info" }
        [void]$privRows.Add(@($entry.Key, "$($entry.Value) 次", (Get-StatusBadge $pStatus)))
    }
    $auditPrivHtml += "<p>共 $privCount 次特权分配事件（已排除 SYSTEM 和计算机账户）</p>"
    $auditPrivHtml += ConvertTo-HtmlTable -Headers @("用户","特权使用次数","评估") -Rows $privRows
} else {
    $auditPrivHtml += '<p style="color:#888;">最近 ' + $auditEventDays + ' 天无非系统账户的特权使用记录（或审计未开启）</p>'
}

# --- 4.5 系统事件实况 ---
$auditSysHtml = "<h3>&#128205; 系统关键事件实况（最近 ${auditEventDays} 天）</h3>"
$sysEvtChecks = @(
    @{ Id = 1102; Label = "安全日志被清除"; Level = "critical" },
    @{ Id = 4608; Label = "Windows 启动"; Level = "info" },
    @{ Id = 4616; Label = "系统时间被修改"; Level = "warn" },
    @{ Id = 6005; Label = "事件日志服务启动"; Level = "info" },
    @{ Id = 6006; Label = "事件日志服务停止"; Level = "info" },
    @{ Id = 6008; Label = "系统异常关机"; Level = "warn" },
    @{ Id = 6009; Label = "系统引导信息"; Level = "info" },
    @{ Id = 1074; Label = "系统关机/重启"; Level = "info" }
)

$sysEvtRows = [System.Collections.ArrayList]::new()
foreach ($sc in $sysEvtChecks) {
    $logNames = @('Security', 'System')
    $totalCount = 0
    $lastTime = $null
    foreach ($logName in $logNames) {
        $sevts = Get-WinEvent -FilterHashtable @{LogName=$logName; Id=$sc.Id; StartTime=$auditEventStart} -MaxEvents 100 2>$null
        if ($sevts) {
            $totalCount += $sevts.Count
            $first = $sevts | Select-Object -First 1
            if (-not $lastTime -or $first.TimeCreated -gt $lastTime) { $lastTime = $first.TimeCreated }
        }
    }
    $lastStr = if ($lastTime) { $lastTime.ToString('MM-dd HH:mm:ss') } else { "-" }
    $sLevel = if ($totalCount -gt 0 -and $sc.Level -ne "info") { $sc.Level } elseif ($totalCount -gt 0) { "info" } else { "pass" }
    [void]$sysEvtRows.Add(@($sc.Id, $sc.Label, "$totalCount 次", $lastStr, (Get-StatusBadge $sLevel)))
}

$auditSysHtml += ConvertTo-HtmlTable -Headers @("事件ID","事件描述","发生次数","最后发生","评估") -Rows $sysEvtRows

# --- 4.6 进程创建事件实况 ---
$auditProcHtml = "<h3>&#128205; 进程创建事件实况（最近 ${auditEventDays} 天）</h3>"
$procEvts = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=$auditEventStart} -MaxEvents 5000 2>$null
$procCount = ($procEvts | Measure-Object).Count

$suspiciousProcs = @('powershell.exe','cmd.exe','wscript.exe','cscript.exe','mshta.exe','certutil.exe',
    'bitsadmin.exe','regsvr32.exe','rundll32.exe','msiexec.exe','net.exe','net1.exe','whoami.exe',
    'nltest.exe','psexec.exe','wmic.exe','schtasks.exe')

$procStats = @{}
foreach ($evt in $procEvts) {
    $xml = [xml]$evt.ToXml()
    $newProc = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'NewProcessName' }).'#text'
    if ($newProc) {
        $procName = Split-Path $newProc -Leaf
        $procNameLower = $procName.ToLower()
        if ($procNameLower -in $suspiciousProcs) {
            if ($procStats.ContainsKey($procName)) { $procStats[$procName].Count++ }
            else { $procStats[$procName] = @{ Count=1; FullPath=$newProc } }
        }
    }
}

if ($procStats.Count -gt 0) {
    $procRows = [System.Collections.ArrayList]::new()
    foreach ($entry in ($procStats.GetEnumerator() | Sort-Object { $_.Value.Count } -Descending)) {
        $prStatus = if ($entry.Key.ToLower() -in @('certutil.exe','bitsadmin.exe','mshta.exe','psexec.exe','wmic.exe')) { "warn" } else { "info" }
        [void]$procRows.Add(@($entry.Key, $entry.Value.FullPath, "$($entry.Value.Count) 次", (Get-StatusBadge $prStatus)))
    }
    $auditProcHtml += "<p>共 $procCount 条进程创建记录，以下为高关注进程统计：</p>"
    $auditProcHtml += ConvertTo-HtmlTable -Headers @("进程名","完整路径","执行次数","评估") -Rows $procRows
} else {
    if ($procCount -gt 0) {
        $auditProcHtml += "<p style=`"color:#52c41a;`">共 $procCount 条进程创建记录，未发现高关注进程</p>"
    } else {
        $auditProcHtml += '<p style="color:#888;">无进程创建记录（审计可能未开启）</p>'
    }
}

# ---- 组装审计策略完整内容 ----

# 风险说明 + 加固命令
$auditDetailHtml = '<h3>风险说明与加固命令</h3><table><thead><tr><th>审计策略</th><th>未启用的风险</th><th>加固命令</th></tr></thead><tbody>'
foreach ($ap in $auditPolicies) {
    $auditDetailHtml += "<tr><td>$($ap.Name)</td><td style=`"color:#e74c3c;`">$($ap.Risk)</td><td><code style=`"font-size:11px;background:#f5f5f5;padding:2px 6px;border-radius:3px;word-break:break-all;`">$($ap.FixCmd)</code></td></tr>"
}
$auditDetailHtml += '</tbody></table>'

# 一键加固脚本提示
$auditFixAllHtml = @"
<h3>一键开启全部审计（管理员 PowerShell）</h3>
<pre>auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable</pre>
"@

$auditContent = $auditTable + $auditLoginHtml + $auditAcctHtml + $auditPolHtml + $auditPrivHtml + $auditSysHtml + $auditProcHtml + $auditDetailHtml + $auditFixAllHtml
$section4 = Write-Section -Title "审计策略配置" -Icon "&#128203;" -Content $auditContent

# ======================== 5. 事件日志配置 ========================
Write-Host "[INFO] 检查事件日志配置..." -ForegroundColor Green

$logRows = [System.Collections.ArrayList]::new()
$logChecks = @(
    @{ Name = "Security";    Label = "安全日志";   MinKB = $SecurityLogMinKB },
    @{ Name = "System";      Label = "系统日志";   MinKB = $SystemLogMinKB },
    @{ Name = "Application"; Label = "应用程序日志"; MinKB = $AppLogMinKB }
)

foreach ($lc in $logChecks) {
    $log = Get-WinEvent -ListLog $lc.Name 2>$null
    if ($log) {
        $maxSizeKB   = [math]::Round($log.MaximumSizeInBytes / 1KB)
        $currentKB   = [math]::Round($log.FileSize / 1KB)
        $retention   = $log.LogMode
        $sizeStatus  = if ($maxSizeKB -ge $lc.MinKB) { Add-Pass; "pass" } else { "warn" }
        $retStatus   = if ($retention -eq "Circular") { Add-Pass; "pass" } else { "info" }
        [void]$logRows.Add(@($lc.Label, "${maxSizeKB} KB", "$($lc.MinKB) KB", $retention, "${currentKB} KB", (Get-StatusBadge $sizeStatus)))
    } else {
        [void]$logRows.Add(@($lc.Label, "N/A", "$($lc.MinKB) KB", "N/A", "N/A", (Get-StatusBadge "critical")))
    }
}

$logTable = ConvertTo-HtmlTable -Headers @("日志名称","最大容量","建议容量","保留方式","当前大小","状态") -Rows $logRows

# 最近安全事件统计
$recentDays = 7
$startDate = (Get-Date).AddDays(-$recentDays)

$loginSuccess = (Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=$startDate} -MaxEvents 10000 2>$null | Measure-Object).Count
$loginFailed  = (Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$startDate} -MaxEvents 10000 2>$null | Measure-Object).Count
$acctChanged  = (Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720,4722,4723,4724,4725,4726; StartTime=$startDate} -MaxEvents 10000 2>$null | Measure-Object).Count
$policyChanged = (Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4719,4739; StartTime=$startDate} -MaxEvents 1000 2>$null | Measure-Object).Count
$logCleared   = (Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102; StartTime=$startDate} -MaxEvents 100 2>$null | Measure-Object).Count

$logClearStatus = if ($logCleared -gt 0) { "critical" } else { Add-Pass; "pass" }

$eventStatsHtml = @"
<h3>最近 ${recentDays} 天安全事件统计</h3>
<div class="info-grid">
  <div class="info-item"><span class="key">成功登录 (4624)</span><span class="val">$loginSuccess 次</span></div>
  <div class="info-item"><span class="key">失败登录 (4625)</span><span class="val">$loginFailed 次 $(if($loginFailed -gt 100){Get-StatusBadge 'warn'})</span></div>
  <div class="info-item"><span class="key">账户变更 (4720-4726)</span><span class="val">$acctChanged 次</span></div>
  <div class="info-item"><span class="key">策略变更 (4719/4739)</span><span class="val">$policyChanged 次</span></div>
  <div class="info-item"><span class="key">日志清除 (1102)</span><span class="val">$logCleared 次 $(Get-StatusBadge $logClearStatus)</span></div>
</div>
"@

$logContent = $logTable + $eventStatsHtml
$section5 = Write-Section -Title "事件日志配置与统计" -Icon "&#128218;" -Content $logContent

# ======================== 6. 登录失败详情 (Top 10 IP) ========================
Write-Host "[INFO] 分析登录失败事件..." -ForegroundColor Green

$failedEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$startDate} -MaxEvents 5000 2>$null

$failedContent = ""
if ($failedEvents -and $failedEvents.Count -gt 0) {
    # 按 IP 统计
    $ipStats = @{}
    foreach ($evt in $failedEvents) {
        $xml = [xml]$evt.ToXml()
        $ip  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
        $usr = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
        if ($ip -and $ip -ne '-') {
            $key = "$ip|$usr"
            if ($ipStats.ContainsKey($key)) { $ipStats[$key]++ } else { $ipStats[$key] = 1 }
        }
    }

    $failRows = [System.Collections.ArrayList]::new()
    $top10 = $ipStats.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10
    foreach ($entry in $top10) {
        $parts = $entry.Key -split '\|'
        $fStatus = if ($entry.Value -ge 100) { "critical" } elseif ($entry.Value -ge 20) { "warn" } else { "info" }
        [void]$failRows.Add(@($parts[0], $parts[1], $entry.Value, (Get-StatusBadge $fStatus)))
    }
    $failedContent = ConvertTo-HtmlTable -Headers @("来源 IP","目标用户","失败次数","风险") -Rows $failRows

    # 最近 10 条失败记录
    $recentFails = $failedEvents | Select-Object -First 10
    $recentRows = [System.Collections.ArrayList]::new()
    foreach ($evt in $recentFails) {
        $xml = [xml]$evt.ToXml()
        $ip  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
        $usr = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
        $reason = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'FailureReason' }).'#text'
        [void]$recentRows.Add(@($evt.TimeCreated.ToString('MM-dd HH:mm:ss'), $usr, $ip, $reason))
    }
    $failedContent += "<h3>最近 10 条失败记录</h3>"
    $failedContent += ConvertTo-HtmlTable -Headers @("时间","用户","来源IP","失败原因") -Rows $recentRows
} else {
    $failedContent = '<p style="color:#52c41a;">最近 ' + $recentDays + ' 天无登录失败记录</p>'
}

$section6 = Write-Section -Title "登录失败分析" -Icon "&#128683;" -Content $failedContent

# ======================== 7. 端口与防火墙 ========================
Write-Host "[INFO] 检查端口与防火墙..." -ForegroundColor Green

# 监听端口
$listeners = Get-NetTCPConnection -State Listen 2>$null | Sort-Object LocalPort
$portRows = [System.Collections.ArrayList]::new()

$knownRiskyPorts = @{
    21  = "FTP (明文传输)"
    23  = "Telnet (明文传输)"
    135 = "RPC (常被利用)"
    139 = "NetBIOS (SMB 相关)"
    445 = "SMB (勒索病毒常用)"
    1433 = "SQL Server"
    3389 = "RDP 远程桌面"
    5985 = "WinRM HTTP"
    5986 = "WinRM HTTPS"
}

$displayedPorts = @{}
foreach ($l in $listeners) {
    $port = $l.LocalPort
    if ($displayedPorts.ContainsKey($port)) { continue }
    $displayedPorts[$port] = $true

    $procId  = $l.OwningProcess
    $proc    = Get-Process -Id $procId 2>$null
    $pName   = if ($proc) { $proc.ProcessName } else { "N/A" }
    $localAddr = "$($l.LocalAddress):$port"

    $riskNote = ""
    $pStatus  = "info"
    if ($knownRiskyPorts.ContainsKey([int]$port)) {
        $riskNote = $knownRiskyPorts[[int]$port]
        $pStatus = if ($port -in @(21, 23)) { "critical" } else { "warn" }
    }

    [void]$portRows.Add(@($localAddr, "TCP", $pName, "(PID: $procId)", $riskNote, (Get-StatusBadge $pStatus)))
}

$portTable = ConvertTo-HtmlTable -Headers @("监听地址","协议","进程名","PID","风险说明","状态") -Rows $portRows

# 防火墙状态
$fwProfiles = Get-NetFirewallProfile 2>$null
$fwRows = [System.Collections.ArrayList]::new()
if ($fwProfiles) {
    foreach ($fw in $fwProfiles) {
        $fwEnabled = if ($fw.Enabled) { "已启用" } else { "未启用" }
        $fwStatus  = if ($fw.Enabled) { Add-Pass; "pass" } else { "critical" }
        $inbound   = $fw.DefaultInboundAction
        $outbound  = $fw.DefaultOutboundAction
        [void]$fwRows.Add(@($fw.Name, $fwEnabled, $inbound, $outbound, (Get-StatusBadge $fwStatus)))
    }
}

$fwTable = ConvertTo-HtmlTable -Headers @("配置文件","状态","入站默认","出站默认","评估") -Rows $fwRows

# 高风险入站规则
$riskyRules = Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow 2>$null |
    Where-Object { $_.Profile -match 'Any|Public' } |
    Select-Object -First 20
$ruleRows = [System.Collections.ArrayList]::new()
foreach ($r in $riskyRules) {
    $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r 2>$null
    $rPort = if ($portFilter.LocalPort -and $portFilter.LocalPort -ne 'Any') { $portFilter.LocalPort -join ',' } else { "所有" }
    $rProto = if ($portFilter.Protocol) { $portFilter.Protocol } else { "Any" }
    [void]$ruleRows.Add(@($r.DisplayName, $rProto, $rPort, $r.Profile, (Get-StatusBadge "info")))
}
$ruleTable = if ($ruleRows.Count -gt 0) {
    "<h3>公开配置的入站允许规则(前20)</h3>" + (ConvertTo-HtmlTable -Headers @("规则名称","协议","端口","配置文件","状态") -Rows $ruleRows)
} else { "" }

$portContent = @"
<h3>防火墙配置</h3>
$fwTable
<h3>监听端口列表</h3>
$portTable
$ruleTable
"@

$section7 = Write-Section -Title "端口与防火墙" -Icon "&#128737;" -Content $portContent

# ======================== 8. 服务安全检查 ========================
Write-Host "[INFO] 检查系统服务..." -ForegroundColor Green

$riskyServices = @(
    @{ Name = "TermService";   Label = "远程桌面服务(RDP)";     Risk = "warn" },
    @{ Name = "RemoteRegistry"; Label = "远程注册表";            Risk = "critical" },
    @{ Name = "TlntSvr";       Label = "Telnet 服务";           Risk = "critical" },
    @{ Name = "FTPSVC";         Label = "FTP 服务";              Risk = "critical" },
    @{ Name = "SNMP";           Label = "SNMP 服务";             Risk = "warn" },
    @{ Name = "W3SVC";          Label = "IIS Web 服务";          Risk = "info" },
    @{ Name = "WinRM";          Label = "Windows 远程管理";      Risk = "warn" },
    @{ Name = "SSDPSRV";        Label = "SSDP 发现服务";         Risk = "warn" },
    @{ Name = "upnphost";       Label = "UPnP 设备主机";         Risk = "warn" },
    @{ Name = "Browser";        Label = "Computer Browser";       Risk = "warn" },
    @{ Name = "lmhosts";        Label = "TCP/IP NetBIOS Helper"; Risk = "warn" },
    @{ Name = "SharedAccess";   Label = "Internet 连接共享";     Risk = "warn" },
    @{ Name = "RasMan";         Label = "远程访问连接管理器";     Risk = "info" },
    @{ Name = "MSFTPSVC";       Label = "Microsoft FTP";          Risk = "critical" },
    @{ Name = "simptcp";        Label = "Simple TCP/IP Services"; Risk = "critical" }
)

$svcRows = [System.Collections.ArrayList]::new()
foreach ($rs in $riskyServices) {
    $svc = Get-Service -Name $rs.Name 2>$null
    if ($svc) {
        $running = $svc.Status -eq 'Running'
        $startType = (Get-CimInstance Win32_Service -Filter "Name='$($rs.Name)'" 2>$null).StartMode
        $sStatus = if ($running -and $rs.Risk -eq "critical") { "critical" }
                   elseif ($running -and $rs.Risk -eq "warn") { "warn" }
                   elseif ($running) { "info" }
                   else { Add-Pass; "pass" }
        $statusText = if ($running) { "运行中" } else { "已停止" }
        [void]$svcRows.Add(@($rs.Label, $rs.Name, $statusText, $startType, (Get-StatusBadge $sStatus)))
    }
}

$svcTable = ConvertTo-HtmlTable -Headers @("服务说明","服务名","状态","启动类型","评估") -Rows $svcRows
$section8 = Write-Section -Title "高风险服务检查" -Icon "&#9881;" -Content $svcTable

# ======================== 9. 远程桌面 (RDP) 安全 ========================
Write-Host "[INFO] 检查 RDP 配置..." -ForegroundColor Green

$rdpRows = [System.Collections.ArrayList]::new()

# RDP 是否启用
$rdpEnabled = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections 2>$null).fDenyTSConnections
$rdpStatus = if ($rdpEnabled -eq 0) { "warn" } else { Add-Pass; "pass" }
[void]$rdpRows.Add(@("RDP 远程桌面", $(if($rdpEnabled -eq 0){"已启用"}else{"已禁用"}), "按需启用", (Get-StatusBadge $rdpStatus)))

# NLA (网络级别认证)
$nla = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication 2>$null).UserAuthentication
$nlaStatus = if ($nla -eq 1) { Add-Pass; "pass" } else { "critical" }
[void]$rdpRows.Add(@("网络级别认证(NLA)", $(if($nla -eq 1){"已启用"}else{"未启用"}), "已启用", (Get-StatusBadge $nlaStatus)))

# RDP 端口
$rdpPort = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name PortNumber 2>$null).PortNumber
$rdpPortStatus = if ($rdpPort -and $rdpPort -ne 3389) { Add-Pass; "pass" } else { "warn" }
[void]$rdpRows.Add(@("RDP 端口", $rdpPort, "非默认端口(非3389)", (Get-StatusBadge $rdpPortStatus)))

# RDP 加密级别
$rdpEncrypt = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name MinEncryptionLevel 2>$null).MinEncryptionLevel
$encLevel = switch ($rdpEncrypt) { 1 {"Low"} 2 {"Client Compatible"} 3 {"High"} 4 {"FIPS"} default {"未配置"} }
$encStatus = if ($rdpEncrypt -ge 3) { Add-Pass; "pass" } else { "warn" }
[void]$rdpRows.Add(@("RDP 加密级别", $encLevel, "High 或 FIPS", (Get-StatusBadge $encStatus)))

$rdpTable = ConvertTo-HtmlTable -Headers @("检查项","当前值","建议值","状态") -Rows $rdpRows
$section9 = Write-Section -Title "远程桌面(RDP)安全" -Icon "&#128421;" -Content $rdpTable

# ======================== 10. SMB 安全 ========================
Write-Host "[INFO] 检查 SMB 配置..." -ForegroundColor Green

$smbRows = [System.Collections.ArrayList]::new()

# SMBv1
$smb1 = (Get-SmbServerConfiguration 2>$null).EnableSMB1Protocol
$smb1Status = if ($smb1 -eq $false) { Add-Pass; "pass" } else { "critical" }
[void]$smbRows.Add(@("SMBv1 协议", $(if($smb1){"已启用"}else{"已禁用"}), "已禁用", (Get-StatusBadge $smb1Status)))

# SMB 签名
$smbSign = (Get-SmbServerConfiguration 2>$null).RequireSecuritySignature
$signStatus = if ($smbSign -eq $true) { Add-Pass; "pass" } else { "warn" }
[void]$smbRows.Add(@("SMB 签名要求", $(if($smbSign){"已启用"}else{"未启用"}), "已启用", (Get-StatusBadge $signStatus)))

# SMB 加密
$smbEncrypt = (Get-SmbServerConfiguration 2>$null).EncryptData
$smbEncStatus = if ($smbEncrypt -eq $true) { Add-Pass; "pass" } else { "warn" }
[void]$smbRows.Add(@("SMB 加密", $(if($smbEncrypt){"已启用"}else{"未启用"}), "已启用", (Get-StatusBadge $smbEncStatus)))

# 共享列表
$shares = Get-SmbShare 2>$null | Where-Object { $_.Name -notmatch '^\$' -and $_.Name -ne 'IPC$' }
$shareInfo = if ($shares) { ($shares | ForEach-Object { "$($_.Name) → $($_.Path)" }) -join "<br>" } else { "无自定义共享" }
[void]$smbRows.Add(@("非默认共享", $shareInfo, "仅保留必要共享", (Get-StatusBadge "info")))

$smbTable = ConvertTo-HtmlTable -Headers @("检查项","当前值","建议值","状态") -Rows $smbRows
$section10 = Write-Section -Title "SMB 文件共享安全" -Icon "&#128193;" -Content $smbTable

# ======================== 11. Windows Update ========================
Write-Host "[INFO] 检查 Windows Update..." -ForegroundColor Green

$updateRows = [System.Collections.ArrayList]::new()

# 最后安装的补丁
$hotfixes = Get-HotFix 2>$null | Sort-Object InstalledOn -Descending | Select-Object -First 10
$lastPatch = if ($hotfixes) { $hotfixes[0].InstalledOn.ToString('yyyy-MM-dd') } else { "未知" }
$daysSincePatch = if ($hotfixes -and $hotfixes[0].InstalledOn) { ((Get-Date) - $hotfixes[0].InstalledOn).Days } else { 999 }
$patchStatus = if ($daysSincePatch -le 30) { Add-Pass; "pass" } elseif ($daysSincePatch -le 90) { "warn" } else { "critical" }
[void]$updateRows.Add(@("最近补丁安装", $lastPatch, "30 天内", "$daysSincePatch 天前", (Get-StatusBadge $patchStatus)))

$patchRows = [System.Collections.ArrayList]::new()
foreach ($hf in $hotfixes) {
    $instDate = if ($hf.InstalledOn) { $hf.InstalledOn.ToString('yyyy-MM-dd') } else { "未知" }
    [void]$patchRows.Add(@($hf.HotFixID, $hf.Description, $instDate, $hf.InstalledBy))
}

$updateContent = ConvertTo-HtmlTable -Headers @("检查项","当前值","建议值","详情","状态") -Rows $updateRows
$updateContent += "<h3>最近安装的补丁(Top 10)</h3>"
$updateContent += ConvertTo-HtmlTable -Headers @("补丁编号","类型","安装日期","安装者") -Rows $patchRows

$section11 = Write-Section -Title "Windows Update 补丁" -Icon "&#128295;" -Content $updateContent

# ======================== 12. 注册表安全加固 ========================
Write-Host "[INFO] 检查注册表安全配置..." -ForegroundColor Green

$regRows = [System.Collections.ArrayList]::new()

$regChecks = @(
    @{
        Path  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        Name  = 'RestrictAnonymous'
        Label = '限制匿名访问'
        Good  = 1
        Suggest = '1 (限制)'
    },
    @{
        Path  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        Name  = 'RestrictAnonymousSAM'
        Label = '限制匿名枚举 SAM 账户'
        Good  = 1
        Suggest = '1 (限制)'
    },
    @{
        Path  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        Name  = 'LmCompatibilityLevel'
        Label = 'LAN Manager 认证级别'
        Good  = 5
        Suggest = '5 (仅NTLMv2)'
    },
    @{
        Path  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        Name  = 'NoLMHash'
        Label = '禁止存储 LM Hash'
        Good  = 1
        Suggest = '1 (禁止)'
    },
    @{
        Path  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        Name  = 'EnableLUA'
        Label = 'UAC 启用状态'
        Good  = 1
        Suggest = '1 (启用)'
    },
    @{
        Path  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        Name  = 'ConsentPromptBehaviorAdmin'
        Label = 'UAC 管理员提示行为'
        Good  = 2
        Suggest = '2 (安全桌面提示)'
    },
    @{
        Path  = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        Name  = 'AutoShareServer'
        Label = '禁止管理共享(C$/D$)'
        Good  = 0
        Suggest = '0 (禁用)'
    },
    @{
        Path  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
        Name  = 'fDisableCdm'
        Label = 'RDP 禁止驱动器映射'
        Good  = 1
        Suggest = '1 (禁止)'
    },
    @{
        Path  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
        Name  = 'NtlmMinServerSec'
        Label = 'NTLM 最低服务器安全'
        Good  = 537395200
        Suggest = '537395200 (NTLMv2 128bit)'
    },
    @{
        Path  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        Name  = 'LegalNoticeText'
        Label = '登录法律声明'
        Good  = $null
        Suggest = '已配置警告文本'
    }
)

foreach ($rc in $regChecks) {
    $val = (Get-ItemProperty -Path $rc.Path -Name $rc.Name 2>$null)."$($rc.Name)"
    $current = if ($null -ne $val) { $val } else { "未配置" }

    if ($rc.Name -eq 'LegalNoticeText') {
        $rStatus = if ($val -and $val.Length -gt 0) { Add-Pass; "pass" } else { "warn" }
        $current = if ($val -and $val.Length -gt 0) { "已配置 ($($val.Length) 字符)" } else { "未配置" }
    } else {
        $rStatus = if ($null -ne $val -and $val -ge $rc.Good) { Add-Pass; "pass" } else { "warn" }
    }

    [void]$regRows.Add(@($rc.Label, $current, $rc.Suggest, (Get-StatusBadge $rStatus)))
}

$regTable = ConvertTo-HtmlTable -Headers @("检查项","当前值","建议值","状态") -Rows $regRows
$section12 = Write-Section -Title "注册表安全加固" -Icon "&#128736;" -Content $regTable

# ======================== 13. 计划任务审计 ========================
Write-Host "[INFO] 检查计划任务..." -ForegroundColor Green

$tasks = Get-ScheduledTask 2>$null | Where-Object {
    $_.State -eq 'Ready' -and
    $_.TaskPath -notmatch '^\\Microsoft\\' -and
    $_.TaskPath -ne '\'
} | Select-Object -First 30

$taskRows = [System.Collections.ArrayList]::new()
foreach ($t in $tasks) {
    $tInfo = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath 2>$null
    $lastRun = if ($tInfo.LastRunTime -and $tInfo.LastRunTime.Year -gt 1999) { $tInfo.LastRunTime.ToString('yyyy-MM-dd HH:mm') } else { "从未" }
    $action = ($t.Actions | ForEach-Object { $_.Execute }) -join "; "
    $runAs = $t.Principal.UserId
    $tStatus = if ($runAs -match 'SYSTEM|LocalSystem') { "warn" } else { "info" }
    [void]$taskRows.Add(@($t.TaskName, $t.TaskPath, $action, $runAs, $lastRun, (Get-StatusBadge $tStatus)))
}

$taskContent = if ($taskRows.Count -gt 0) {
    ConvertTo-HtmlTable -Headers @("任务名","路径","执行命令","运行身份","最后执行","评估") -Rows $taskRows
} else {
    "<p>无自定义计划任务</p>"
}

$section13 = Write-Section -Title "计划任务审计" -Icon "&#9200;" -Content $taskContent

# ======================== 14. 网络连接分析 ========================
Write-Host "[INFO] 分析网络连接..." -ForegroundColor Green

$tcpConns = Get-NetTCPConnection 2>$null
$established = ($tcpConns | Where-Object State -eq 'Established' | Measure-Object).Count
$timeWait    = ($tcpConns | Where-Object State -eq 'TimeWait' | Measure-Object).Count
$closeWait   = ($tcpConns | Where-Object State -eq 'CloseWait' | Measure-Object).Count
$listenCount = ($tcpConns | Where-Object State -eq 'Listen' | Measure-Object).Count

$connStatsHtml = @"
<div class="info-grid">
  <div class="info-item"><span class="key">ESTABLISHED</span><span class="val">$established</span></div>
  <div class="info-item"><span class="key">TIME_WAIT</span><span class="val">$timeWait</span></div>
  <div class="info-item"><span class="key">CLOSE_WAIT</span><span class="val">$closeWait $(if($closeWait -gt 50){Get-StatusBadge 'warn'})</span></div>
  <div class="info-item"><span class="key">LISTEN</span><span class="val">$listenCount</span></div>
</div>
"@

# 外连 IP Top 10
$outbound = $tcpConns | Where-Object { $_.State -eq 'Established' -and $_.RemoteAddress -notmatch '^(127\.|0\.|::)' }
$ipCount = @{}
foreach ($c in $outbound) {
    $rip = $c.RemoteAddress
    if ($ipCount.ContainsKey($rip)) { $ipCount[$rip]++ } else { $ipCount[$rip] = 1 }
}

$outRows = [System.Collections.ArrayList]::new()
$topIPs = $ipCount.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10
foreach ($entry in $topIPs) {
    $sample = $outbound | Where-Object { $_.RemoteAddress -eq $entry.Key } | Select-Object -First 1
    $pName = (Get-Process -Id $sample.OwningProcess 2>$null).ProcessName
    [void]$outRows.Add(@($entry.Key, $sample.RemotePort, $entry.Value, $pName, (Get-StatusBadge "info")))
}

$outTable = if ($outRows.Count -gt 0) {
    "<h3>出站连接 Top 10 IP</h3>" + (ConvertTo-HtmlTable -Headers @("远程IP","端口","连接数","进程","状态") -Rows $outRows)
} else { "" }

$connContent = $connStatsHtml + $outTable
$section14 = Write-Section -Title "网络连接分析" -Icon "&#127760;" -Content $connContent

# ======================== 15. 安全加固建议汇总 ========================
Write-Host "[INFO] 生成加固建议..." -ForegroundColor Green

$recommendations = @(
    @{ Cat = "密码策略"; Items = @(
        "设置最小密码长度 >= 12 位",
        "启用密码复杂度要求",
        "设置密码最大使用期限 <= 90 天",
        "密码历史记录 >= 5 个",
        "配置账户锁定阈值 <= 5 次"
    )},
    @{ Cat = "访问控制"; Items = @(
        "禁用 Guest 账户",
        "重命名默认 Administrator 账户",
        "定期清理不活跃用户账户",
        "遵循最小权限原则分配权限",
        "启用 UAC 并保持默认配置"
    )},
    @{ Cat = "网络安全"; Items = @(
        "禁用 SMBv1 协议",
        "修改 RDP 默认端口(3389)",
        "启用 NLA 网络级别认证",
        "关闭不必要的服务和端口",
        "启用 Windows 防火墙所有配置文件",
        "禁用 Telnet/FTP 等明文协议"
    )},
    @{ Cat = "日志审计"; Items = @(
        "安全日志最大容量 >= 200MB",
        "启用登录/注销审计(成功和失败)",
        "启用账户管理审计(成功和失败)",
        "启用策略更改审计(成功和失败)",
        "启用进程创建审计",
        "定期检查日志清除事件(ID 1102)"
    )},
    @{ Cat = "补丁更新"; Items = @(
        "及时安装安全更新(30天内)",
        "启用 Windows Update 自动检查",
        "定期进行漏洞扫描",
        "关注微软安全公告(MSRC)"
    )},
    @{ Cat = "其他加固"; Items = @(
        "启用 BitLocker 磁盘加密",
        "配置登录法律声明(Legal Notice)",
        "限制匿名访问(RestrictAnonymous=1)",
        "设置 LAN Manager 认证级别为 NTLMv2",
        "禁止存储 LM Hash",
        "启用 SMB 签名和加密",
        "审计计划任务中的可疑条目",
        "禁用管理默认共享(C$, D$)"
    )}
)

$recHtml = ""
foreach ($r in $recommendations) {
    $items = ($r.Items | ForEach-Object { "<li>$_</li>" }) -join ""
    $recHtml += "<h3>$($r.Cat)</h3><ul style='margin:0 0 12px 20px;font-size:13px;'>$items</ul>"
}

$section15 = Write-Section -Title "安全加固建议清单" -Icon "&#9989;" -Content $recHtml

# ======================== 组装报告 ========================
Write-Host "[INFO] 生成 HTML 报告..." -ForegroundColor Green

$totalChecks = $script:PassCount + $script:WarnCount + $script:CriticalCount
$scorePercent = if ($totalChecks -gt 0) { [math]::Round($script:PassCount / $totalChecks * 100) } else { 0 }
$scoreColor = if ($scorePercent -ge 80) { "green" } elseif ($scorePercent -ge 60) { "orange" } else { "red" }

$htmlHeader = @"
<div class="header">
  <h1>&#128737; Windows Server 安全加固巡检报告</h1>
  <p>$Hostname | $primaryIP | $($osInfo.Caption) | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
</div>
<div class="summary">
  <div class="summary-card"><div class="num $scoreColor">${scorePercent}%</div><div class="label">安全评分</div></div>
  <div class="summary-card"><div class="num green">$($script:PassCount)</div><div class="label">通过项</div></div>
  <div class="summary-card"><div class="num orange">$($script:WarnCount)</div><div class="label">警告项</div></div>
  <div class="summary-card"><div class="num red">$($script:CriticalCount)</div><div class="label">严重项</div></div>
  <div class="summary-card"><div class="num blue">$totalChecks</div><div class="label">检查总数</div></div>
</div>
<div class="toc">
  <h3>&#128204; 检查目录（共 15 项）</h3>
  <div class="toc-grid">
    <a href="#s1" class="toc-item"><span class="toc-num">1</span><span class="toc-icon">&#128187;</span><span class="toc-label">系统基本信息</span></a>
    <a href="#s2" class="toc-item"><span class="toc-num">2</span><span class="toc-icon">&#128274;</span><span class="toc-label">账户与密码策略</span></a>
    <a href="#s3" class="toc-item"><span class="toc-num">3</span><span class="toc-icon">&#128101;</span><span class="toc-label">本地用户与组</span></a>
    <a href="#s4" class="toc-item"><span class="toc-num">4</span><span class="toc-icon">&#128203;</span><span class="toc-label">审计策略配置</span></a>
    <a href="#s5" class="toc-item"><span class="toc-num">5</span><span class="toc-icon">&#128218;</span><span class="toc-label">事件日志与统计</span></a>
    <a href="#s6" class="toc-item"><span class="toc-num">6</span><span class="toc-icon">&#128683;</span><span class="toc-label">登录失败分析</span></a>
    <a href="#s7" class="toc-item"><span class="toc-num">7</span><span class="toc-icon">&#128737;</span><span class="toc-label">端口与防火墙</span></a>
    <a href="#s8" class="toc-item"><span class="toc-num">8</span><span class="toc-icon">&#9881;</span><span class="toc-label">高风险服务检查</span></a>
    <a href="#s9" class="toc-item"><span class="toc-num">9</span><span class="toc-icon">&#128421;</span><span class="toc-label">RDP 远程桌面安全</span></a>
    <a href="#s10" class="toc-item"><span class="toc-num">10</span><span class="toc-icon">&#128193;</span><span class="toc-label">SMB 文件共享安全</span></a>
    <a href="#s11" class="toc-item"><span class="toc-num">11</span><span class="toc-icon">&#128295;</span><span class="toc-label">Windows Update</span></a>
    <a href="#s12" class="toc-item"><span class="toc-num">12</span><span class="toc-icon">&#128736;</span><span class="toc-label">注册表安全加固</span></a>
    <a href="#s13" class="toc-item"><span class="toc-num">13</span><span class="toc-icon">&#9200;</span><span class="toc-label">计划任务审计</span></a>
    <a href="#s14" class="toc-item"><span class="toc-num">14</span><span class="toc-icon">&#127760;</span><span class="toc-label">网络连接分析</span></a>
    <a href="#s15" class="toc-item"><span class="toc-num">15</span><span class="toc-icon">&#9989;</span><span class="toc-label">安全加固建议</span></a>
  </div>
</div>
"@

# 给 section 加锚点
$sections = @(
    @{Id="s1";  Html=$section1},
    @{Id="s2";  Html=$section2},
    @{Id="s3";  Html=$section3},
    @{Id="s4";  Html=$section4},
    @{Id="s5";  Html=$section5},
    @{Id="s6";  Html=$section6},
    @{Id="s7";  Html=$section7},
    @{Id="s8";  Html=$section8},
    @{Id="s9";  Html=$section9},
    @{Id="s10"; Html=$section10},
    @{Id="s11"; Html=$section11},
    @{Id="s12"; Html=$section12},
    @{Id="s13"; Html=$section13},
    @{Id="s14"; Html=$section14},
    @{Id="s15"; Html=$section15}
)

$bodyHtml = ""
foreach ($s in $sections) {
    $bodyHtml += $s.Html -replace '<div class="section">', "<div class=`"section`" id=`"$($s.Id)`">"
}

$endTime = Get-Date
$duration = ($endTime - $StartTime).TotalSeconds

$htmlFooter = @"
<div class="footer">
  <p>Windows Server 安全加固巡检报告 v$ScriptVersion | 巡检耗时: $([math]::Round($duration,1)) 秒 | 生成时间: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
</div>
</div>
</body>
</html>
"@

$fullHtml = $htmlHead + $htmlHeader + $bodyHtml + $htmlFooter
$fullHtml | Out-File -FilePath $ReportFile -Encoding UTF8

# 清理临时文件
Remove-Item $secEditFile -Force 2>$null

# ======================== 输出结果 ========================
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  安全加固巡检完成: $Hostname" -ForegroundColor Cyan
Write-Host "  时间: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "  通过: $($script:PassCount)  警告: $($script:WarnCount)  严重: $($script:CriticalCount)" -ForegroundColor Cyan
Write-Host "  安全评分: ${scorePercent}%" -ForegroundColor $(if($scorePercent -ge 80){"Green"}elseif($scorePercent -ge 60){"Yellow"}else{"Red"})
Write-Host "  报告: $ReportFile" -ForegroundColor Cyan
Write-Host "  耗时: $([math]::Round($duration,1)) 秒" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# 如果有严重项，返回非零退出码（方便自动化判断）
if ($script:CriticalCount -gt 0) { exit 1 } else { exit 0 }
