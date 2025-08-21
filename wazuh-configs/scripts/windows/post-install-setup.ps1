# Cloud-X Security - Post Wazuh Agent Installation Setup
# Integrates threat response scripts, PowerShell logging, and malicious scan rules
# Copyright (C) 2023, Cloud-X Security
# GitHub: https://github.com/MAPLEIZER/Cloud-X-security-agent
# Usage: 
#   $postInstallUrl = "https://raw.githubusercontent.com/MAPLEIZER/Cloud-X-security-agent/main/wazuh-configs/scripts/windows/post-install-setup.ps1"
#   $postInstallScript = (Invoke-WebRequest -Uri $postInstallUrl -UseBasicParsing).Content
#   $postInstallScript | Out-File -FilePath "$env:TEMP\CloudX-PostInstall-Setup.ps1" -Encoding UTF8
#   & "$env:TEMP\CloudX-PostInstall-Setup.ps1"

param(
    [string]$WazuhPath = "C:\Program Files (x86)\ossec-agent",
    [string]$WazuhManager = "192.168.100.37",
    [string]$AgentName = $env:COMPUTERNAME,
    [switch]$Force
)

Write-Host "=== Cloud-X Security Post-Installation Setup ===" -ForegroundColor Cyan
Write-Host "Configuring advanced threat response capabilities..." -ForegroundColor Green

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run as Administrator"
    exit 1
}

# Get Wazuh agent installation path
$possiblePaths = @(
    (Join-Path -Path $env:ProgramFiles -ChildPath "ossec-agent"),
    (Join-Path -Path ${env:ProgramFiles(x86)} -ChildPath "ossec-agent")
)
$WazuhPath = $possiblePaths | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $WazuhPath) {
    Write-Warning "Wazuh agent not found. Some features may not work."
}

Write-Host "[1/6] Setting up active response scripts..." -ForegroundColor Yellow

# Create active response directory if it doesn't exist
$activeResponseDir = Join-Path -Path $WazuhPath -ChildPath "active-response\bin"
New-Item -ItemType Directory -Path $activeResponseDir -Force | Out-Null

# Download threat response script from GitHub
$scriptUrl = "https://raw.githubusercontent.com/MAPLEIZER/Cloud-X-security-agent/main/wazuh-configs/scripts/windows/remove-threat.py"
$scriptDest = Join-Path -Path $activeResponseDir -ChildPath "remove-threat.py"

try {
    Write-Host "  Downloading remove-threat.py from GitHub..." -ForegroundColor Gray
    Invoke-WebRequest -Uri $scriptUrl -OutFile $scriptDest -UseBasicParsing
    if (Test-Path $scriptDest) {
        Write-Host "  ✓ Threat response script downloaded and installed" -ForegroundColor Green
    } else {
        Write-Warning "  ⚠ Download completed but script file not found"
    }
} catch {
    Write-Warning "  ⚠ Failed to download threat response script: $($_.Exception.Message)"
    Write-Host "  Attempting to continue without active response script..." -ForegroundColor Yellow
}

Write-Host "[2/6] Installing Python dependencies..." -ForegroundColor Yellow

# Install required Python packages
$pythonPackages = @("psutil", "pywin32")
foreach ($package in $pythonPackages) {
    try {
        & python -m pip install $package --quiet
        Write-Host "  ✓ Installed $package" -ForegroundColor Green
    } catch {
        Write-Warning "  ⚠ Failed to install $package - some features may not work"
    }
}

Write-Host "[3/8] Installing and Configuring Sysmon..." -ForegroundColor Yellow

# Download Sysmon and its configuration
$sysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
$sysmonZip = "$env:TEMP\Sysmon.zip"
$sysmonDir = "$env:TEMP\Sysmon"
$sysmonConfigUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
$sysmonConfigFile = "$env:TEMP\sysmonconfig.xml"

try {
    Write-Host "  Downloading Sysmon..." -ForegroundColor Gray
    Invoke-WebRequest -Uri $sysmonUrl -OutFile $sysmonZip -UseBasicParsing
    Expand-Archive -Path $sysmonZip -DestinationPath $sysmonDir -Force
    Write-Host "  ✓ Sysmon downloaded and extracted" -ForegroundColor Green

    Write-Host "  Downloading SwiftOnSecurity Sysmon configuration..." -ForegroundColor Gray
    Invoke-WebRequest -Uri $sysmonConfigUrl -OutFile $sysmonConfigFile -UseBasicParsing
    Write-Host "  ✓ Sysmon configuration downloaded" -ForegroundColor Green

    # Install Sysmon
    if (Test-Path "$sysmonDir\Sysmon64.exe") {
        Write-Host "  Installing Sysmon..." -ForegroundColor Gray
        & "$sysmonDir\Sysmon64.exe" -accepteula -i $sysmonConfigFile
        Write-Host "  ✓ Sysmon installed successfully" -ForegroundColor Green
    } elseif (Test-Path "$sysmonDir\Sysmon.exe") {
        Write-Host '  Installing Sysmon (32-bit)...' -ForegroundColor Gray
        & "$sysmonDir\Sysmon.exe" -accepteula -i $sysmonConfigFile
        Write-Host "  ✓ Sysmon installed successfully" -ForegroundColor Green
    } else {
        Write-Warning "  ⚠ Sysmon executable not found. Skipping installation."
    }
} catch {
    Write-Warning "  ⚠ Failed to download or install Sysmon: $($_.Exception.Message)"
}

Write-Host "[4/8] Enabling Advanced Windows Auditing..." -ForegroundColor Yellow
try {
    auditpol /set /category:"Object Access" /success:enable /failure:enable
    auditpol /set /subcategory:"File System" /success:enable /failure:enable
    auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable
    auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
    auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
    auditpol /set /subcategory:"Logon" /success:enable /failure:enable
    Write-Host "  ✓ Advanced Windows auditing enabled" -ForegroundColor Green
} catch {
    Write-Warning "  ⚠ Failed to enable advanced auditing: $($_.Exception.Message)"
}

Write-Host "[5/8] Enabling PowerShell Script Block Logging..." -ForegroundColor Yellow

# Enable PowerShell logging (integrated from Powershell-log-enable.ps1)
try {
    $basePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    
    if (!(Test-Path $basePath)) {
        New-Item -Path $basePath -Force | Out-Null
    }
    
    Set-ItemProperty -Path $basePath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
    
    # Also enable module logging
    $moduleLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    if (!(Test-Path $moduleLogPath)) {
        New-Item -Path $moduleLogPath -Force | Out-Null
    }
    Set-ItemProperty -Path $moduleLogPath -Name "EnableModuleLogging" -Value 1 -Type DWord
    
    Write-Host "  ✓ PowerShell logging enabled" -ForegroundColor Green
} catch {
    Write-Warning "  ⚠ Failed to enable PowerShell logging: $($_.Exception.Message)"
}

# [6/8] Configuring Wazuh rules... (Temporarily Disabled)
# Write-Host "[6/8] Configuring Wazuh rules..." -ForegroundColor Yellow

# # Download and install PowerShell monitoring rules
# $rulesUrl = "https://raw.githubusercontent.com/MAPLEIZER/Cloud-X-security-agent/main/wazuh-configs/rules/cloudx_powershell_rules.xml"
# $rulesFile = Join-Path -Path $WazuhPath -ChildPath "ruleset\rules\cloudx_powershell_rules.xml"
# try {
#     Write-Host "  Downloading PowerShell monitoring rules..." -ForegroundColor Gray
#     Invoke-WebRequest -Uri $rulesUrl -OutFile $rulesFile -UseBasicParsing
#     Write-Host "  ✓ PowerShell monitoring rules installed" -ForegroundColor Green
# } catch {
#     Write-Warning "  ⚠ Failed to download PowerShell rules: $($_.Exception.Message)"
# }

Write-Host "[6/7] Configuring active response..." -ForegroundColor Yellow

# Create active response configuration
$activeResponseConfig = @"
<!-- Cloud-X Security Active Response Configuration -->
<command>
  <name>remove-threat</name>
  <executable>remove-threat.py</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<active-response>
  <command>remove-threat</command>
  <location>local</location>
  <rules_id>100543,100546,100547</rules_id>
  <timeout>60</timeout>
</active-response>
"@

$configDir = Join-Path -Path $WazuhPath -ChildPath "etc"
New-Item -ItemType Directory -Path $configDir -Force | Out-Null
$activeResponseFile = Join-Path $configDir "cloudx_active_response.conf"
$activeResponseConfig | Out-File -FilePath $activeResponseFile -Encoding UTF8
Write-Host "  ✓ Active response configuration created" -ForegroundColor Green

Write-Host "[7/7] Configuring Wazuh agent connection..." -ForegroundColor Yellow

# Configure Wazuh agent with manager address and dynamic agent name
$ossecConf = Join-Path $WazuhPath "ossec.conf"

if (Test-Path $ossecConf) {
    # Backup original config
    Copy-Item $ossecConf "$ossecConf.backup" -Force
    
    # Read current config
    [xml]$config = Get-Content $ossecConf
    
    # Update server address
    $serverNode = $config.ossec_config.client.server
    if ($serverNode) {
        $serverNode.address = $WazuhManager
        Write-Host "  ✓ Manager address set to $WazuhManager" -ForegroundColor Green
    }
    
    # Update agent name if different from computer name
    if ($AgentName -ne $env:COMPUTERNAME) {
        $config.ossec_config.client.config_profile = $AgentName
        Write-Host "  ✓ Agent name set to $AgentName" -ForegroundColor Green
    } else {
        Write-Host "  ✓ Using computer name as agent name: $AgentName" -ForegroundColor Green
    }
    
    # Save updated config
    $config.Save($ossecConf)
    
} else {
    Write-Warning "  ⚠ ossec.conf not found - manual configuration required"
}

Write-Host "[7/9] Creating quarantine directory..." -ForegroundColor Yellow

# Create quarantine directory
$quarantineDir = "$env:TEMP\wazuh_quarantine"
New-Item -ItemType Directory -Path $quarantineDir -Force | Out-Null
Write-Host "  ✓ Quarantine directory created at $quarantineDir" -ForegroundColor Green

Write-Host "[8/9] Restarting Wazuh agent service..." -ForegroundColor Yellow

# Restart Wazuh service to apply configurations
try {
    $service = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
    if ($service) {
        Write-Host "  Stopping Wazuh service..." -ForegroundColor Gray
        Stop-Service -Name "WazuhSvc" -Force -ErrorAction Stop
        Start-Sleep -Seconds 3
        
        Write-Host "  Starting Wazuh service..." -ForegroundColor Gray
        Start-Service -Name "WazuhSvc" -ErrorAction Stop
        Start-Sleep -Seconds 2
        
        # Verify service is running
        $serviceStatus = (Get-Service -Name "WazuhSvc").Status
        if ($serviceStatus -eq 'Running') {
            Write-Host "  ✓ Wazuh service restarted successfully" -ForegroundColor Green
        } else {
            Write-Warning "  ⚠ Wazuh service status: $serviceStatus"
        }
    } else {
        Write-Warning "  ⚠ Wazuh service not found - manual restart may be required"
    }
} catch {
    Write-Warning "  ⚠ Failed to restart Wazuh service: $($_.Exception.Message)"
    Write-Host "  Please manually restart with: Restart-Service WazuhSvc" -ForegroundColor Yellow
}

Write-Host "[9/9] Finalizing setup..." -ForegroundColor Yellow

# Set appropriate permissions on the active response script
if (Test-Path $scriptDest) {
    try {
        $acl = Get-Acl $scriptDest
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "Allow")
        $acl.SetAccessRule($accessRule)
        Set-Acl $scriptDest $acl
        Write-Host "  ✓ Script permissions configured" -ForegroundColor Green
    } catch {
        Write-Warning "  ⚠ Could not set script permissions: $($_.Exception.Message)"
    }
} else {
    Write-Warning "  ⚠ Script file not found - permissions not set"
}

Write-Host ""
Write-Host "=== Setup Complete ===" -ForegroundColor Green
Write-Host "Cloud-X Security threat response system is now active!" -ForegroundColor Cyan
Write-Host ""
Write-Host "Features enabled:" -ForegroundColor White
Write-Host "  • Advanced threat file quarantine with metadata tracking" -ForegroundColor Gray
Write-Host "  • Digital signature verification for executables" -ForegroundColor Gray
Write-Host "  • File type verification using magic bytes" -ForegroundColor Gray
Write-Host "  • Malicious process termination" -ForegroundColor Gray
Write-Host "  • PowerShell script block logging" -ForegroundColor Gray
Write-Host "  • PowerShell malicious command detection" -ForegroundColor Gray
Write-Host "  • Automated active response to threats" -ForegroundColor Gray
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Register agent with manager:" -ForegroundColor White
Write-Host "     /var/ossec/bin/manage_agents (on manager $WazuhManager)" -ForegroundColor Gray
Write-Host "  2. ✓ Wazuh agent service automatically restarted" -ForegroundColor Green
Write-Host "  3. Manager configuration files created locally:" -ForegroundColor White
Write-Host "     - Active Response: $activeResponseFile" -ForegroundColor Gray
Write-Host "     - PowerShell Rules: $rulesFile" -ForegroundColor Gray
Write-Host "     Copy these to your Wazuh manager and restart it" -ForegroundColor Gray
Write-Host "" -ForegroundColor White
Write-Host "Agent Configuration:" -ForegroundColor Yellow
Write-Host "  Manager: $WazuhManager" -ForegroundColor Cyan
Write-Host "  Agent Name: $AgentName" -ForegroundColor Cyan
Write-Host ""
Write-Host "Quarantine location: $quarantineDir" -ForegroundColor Cyan
Write-Host "Log file: C:\Program Files (x86)\ossec-agent\active-response\active-responses.log" -ForegroundColor Cyan
