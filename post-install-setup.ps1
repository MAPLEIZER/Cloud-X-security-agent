# Cloud-X Security - Post Wazuh Agent Installation Setup
# Integrates threat response scripts, PowerShell logging, and malicious scan rules
# Copyright (C) 2023, Cloud-X Security
# GitHub: https://github.com/MAPLEIZER/Cloud-X-security-agent
# Usage: 
#   $postInstallUrl = "https://raw.githubusercontent.com/MAPLEIZER/Cloud-X-security-agent/main/post-install-setup.ps1"
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

# Verify Wazuh agent is installed
if (-not (Test-Path $WazuhPath)) {
    Write-Error "Wazuh agent not found at $WazuhPath"
    exit 1
}

Write-Host "[1/6] Setting up active response scripts..." -ForegroundColor Yellow

# Create active response directory if it doesn't exist
$activeResponseDir = Join-Path $WazuhPath "active-response\bin"
New-Item -ItemType Directory -Path $activeResponseDir -Force | Out-Null

# Download threat response script from GitHub
$scriptUrl = "https://raw.githubusercontent.com/MAPLEIZER/Cloud-X-security-agent/main/wazuh-configs/scripts/remove-threat.py"
$scriptDest = Join-Path $activeResponseDir "remove-threat.py"

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

Write-Host "[3/6] Enabling PowerShell Script Block Logging..." -ForegroundColor Yellow

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

Write-Host "[4/6] Configuring Wazuh rules..." -ForegroundColor Yellow

# Create custom rules directory
$rulesDir = Join-Path $WazuhPath "ruleset\rules"
New-Item -ItemType Directory -Path $rulesDir -Force | Out-Null

# Create PowerShell malicious scan rules (integrated from XML)
$powershellRules = @"
<!-- Cloud-X Security PowerShell Monitoring Rules -->
<group name="windows,powershell,cloudx">
  <!-- General PowerShell Events -->
  <rule id="100535" level="3">
    <if_sid>60009</if_sid>
    <field name="win.system.providerName">^(PowerShell|Microsoft-Windows-PowerShell)$</field>
    <field name="win.system.severityValue">INFO|VERBOSE|WARNING|ERROR|CRITICAL</field>
    <mitre>
      <id>T1059.001</id>
    </mitre>
    <options>no_full_log</options>
    <description>PowerShell EventLog Monitoring - Cloud-X Security</description>
  </rule>

  <!-- Frequency-based alert: multiple errors in short time -->
  <rule id="100539" level="12" frequency="8" timeframe="60">
    <if_matched_sid>100535</if_matched_sid>
    <field name="win.system.severityValue">ERROR|CRITICAL</field>
    <description>Multiple PowerShell errors detected - Possible attack</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
    <options>no_full_log</options>
    <group>pci_dss_10.6.1,attack_execution,</group>
  </rule>

  <!-- Script execution monitoring -->
  <rule id="100541" level="3">
    <if_sid>91802</if_sid>
    <field name="win.system.severityValue">VERBOSE|INFO</field>
    <description>PowerShell script executed: `$(win.eventdata.scriptBlockText)`</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
    <options>no_full_log</options>
  </rule>

  <!-- Malicious PowerShell command detection -->
  <rule id="100543" level="12">
    <if_sid>100541</if_sid>
    <pcre2>(?i)(invoke-expression|iex|downloadstring|downloadfile|bypass|hidden|encodedcommand|invoke-shellcode|invoke-mimikatz)</pcre2>
    <description>Malicious PowerShell command detected: `$(win.eventdata.scriptBlockText)`</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
    <options>no_full_log</options>
    <group>windows_powershell_highrisk,attack_execution,</group>
  </rule>

  <!-- Detect PowerShell Obfuscation -->
  <rule id="100546" level="13">
    <if_sid>61605</if_sid>
    <field name="win.system.eventID">^4688$</field>
    <pcre2>(?i)powershell.+(-e|-en|-enc|-enco|-encod|-encode|-encoded|-encodedc|-encodedco|-encodedcom|-encodedcomm|-encodedcomma|-encodedcomman|-encodedcommand)\s+\w+</pcre2>
    <description>Suspicious PowerShell execution with encoded command detected</description>
    <mitre>
      <id>T1027</id>
    </mitre>
    <group>windows_powershell_highrisk,technique_obfuscation,</group>
  </rule>

  <!-- Detect In-memory Download and Execution -->
  <rule id="100547" level="12">
    <if_sid>100541</if_sid>
    <field name="win.eventdata.scriptBlockText" type="pcre2">(?i)IEX.*New-Object.*Net\.WebClient.*DownloadString</field>
    <description>Malicious PowerShell script detected: In-memory download and execution</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
    <group>windows_powershell_highrisk,attack_execution,</group>
  </rule>
</group>
"@

$rulesFile = Join-Path $rulesDir "cloudx_powershell_rules.xml"
$powershellRules | Out-File -FilePath $rulesFile -Encoding UTF8
Write-Host "  ✓ PowerShell monitoring rules installed" -ForegroundColor Green

Write-Host "[5/6] Configuring active response..." -ForegroundColor Yellow

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

$configDir = Join-Path $WazuhPath "etc"
New-Item -ItemType Directory -Path $configDir -Force | Out-Null
$activeResponseFile = Join-Path $configDir "cloudx_active_response.conf"
$activeResponseConfig | Out-File -FilePath $activeResponseFile -Encoding UTF8
Write-Host "  ✓ Active response configuration created" -ForegroundColor Green

Write-Host "[6/7] Configuring Wazuh agent connection..." -ForegroundColor Yellow

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

Write-Host "[7/7] Finalizing setup..." -ForegroundColor Yellow

# Create quarantine directory
$quarantineDir = "$env:TEMP\wazuh_quarantine"
New-Item -ItemType Directory -Path $quarantineDir -Force | Out-Null
Write-Host "  ✓ Quarantine directory created at $quarantineDir" -ForegroundColor Green

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
Write-Host "  2. Restart the Wazuh agent service:" -ForegroundColor White
Write-Host "     Restart-Service WazuhSvc" -ForegroundColor Gray
Write-Host "  3. Update your Wazuh manager configuration to include:" -ForegroundColor White
Write-Host "     - Include the cloudx_active_response.conf file" -ForegroundColor Gray
Write-Host "     - Include the cloudx_powershell_rules.xml file" -ForegroundColor Gray
Write-Host "" -ForegroundColor White
Write-Host "Agent Configuration:" -ForegroundColor Yellow
Write-Host "  Manager: $WazuhManager" -ForegroundColor Cyan
Write-Host "  Agent Name: $AgentName" -ForegroundColor Cyan
Write-Host ""
Write-Host "Quarantine location: $quarantineDir" -ForegroundColor Cyan
Write-Host "Log file: C:\Program Files (x86)\ossec-agent\active-response\active-responses.log" -ForegroundColor Cyan
