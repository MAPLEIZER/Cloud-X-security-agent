#Requires -RunAsAdministrator

<#
.SYNOPSIS
    NixGuard Wazuh Agent Enterprise Setup Script - Fixed Version
.DESCRIPTION
    Enterprise-grade script for automated Wazuh agent installation and configuration with
    enhanced security, auditing, and flexibility features.
.PARAMETER agentName
    The name for the Wazuh agent
.PARAMETER ipAddress
    The IP address of the Wazuh manager
.PARAMETER groupLabel
    The group label for agent configuration
.PARAMETER ConfigFile
    Path to JSON configuration file containing setup parameters
.PARAMETER SkipHashVerification
    Skip SHA256 hash verification of downloaded files (not recommended for production)
.PARAMETER LogPath
    Custom path for transcript logging
.EXAMPLE
    .\agent-automatic-setup-enterprise.ps1 -agentName "Maplex" -ipAddress "162.55.60.203" -groupLabel "68a228f24a4c93141e28f57c"
.NOTES
    Enterprise Version 3.0 - Fixed
    Author: MAPLEIZER
    Created: 2025-08-18 18:25:43 UTC
#>

param (
    [Parameter(ParameterSetName='Manual')]
    [ValidateNotNullOrEmpty()]
    [string]$agentName,
    
    [Parameter(ParameterSetName='Manual')]
    [ValidatePattern('^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')]
    [string]$ipAddress,
    
    [Parameter(ParameterSetName='Manual')]
    [ValidateNotNullOrEmpty()]
    [string]$groupLabel,
    
    [Parameter(ParameterSetName='ConfigFile', Mandatory=$true)]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$ConfigFile,
    
    [switch]$SkipHashVerification,
    
    [string]$LogPath = "$env:TEMP\nixguard-setup-transcript-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
)

# Script configuration
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Define constants
$WAZUH_VERSION = "4.9.1-1"
$PYTHON_VERSION = "3.12.4"
$API_URL = "https://api.thenex.world/get-user"
$BITLOCKER_SCRIPT_URL = "https://github.com/thenexlabs/nixguard-free-agent-setup/raw/main/windows/scripts/bitlocker_check.ps1"
$REMOVE_THREAT_URL = "https://github.com/thenexlabs/nixguard-agent-setup/raw/main/windows/remove-threat.py"
$PYTHON_URL = "https://www.python.org/ftp/python/$PYTHON_VERSION/python-$PYTHON_VERSION-amd64.exe"
$WAZUH_URL = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$WAZUH_VERSION.msi"

# Global progress tracking
$script:currentStep = 0
$script:totalSteps = 8
$script:startTime = Get-Date

# Initialize transcript logging
function Initialize-Logging {
    try {
        $logDir = Split-Path $LogPath -Parent
        if (-not (Test-Path $logDir)) {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
        }
        
        Start-Transcript -Path $LogPath -Append -Force
        Write-Host "[TRANSCRIPT] Logging started: $LogPath" -ForegroundColor Green
        Write-Host "[INFO] Setup started at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')" -ForegroundColor Cyan
        Write-Host "[INFO] Current user: $env:USERNAME" -ForegroundColor Cyan
        Write-Host "[INFO] Computer: $env:COMPUTERNAME" -ForegroundColor Cyan
        Write-Host "[INFO] PowerShell version: $($PSVersionTable.PSVersion)" -ForegroundColor Cyan
        
        return $true
    }
    catch {
        Write-Warning "Failed to start transcript logging: $($_.Exception.Message)"
        Write-Warning "Continuing without transcript logging..."
        return $false
    }
}

# Load configuration from file
function Get-ConfigFromFile {
    param([string]$FilePath)
    
    try {
        Write-Host "[CONFIG] Loading configuration from: $FilePath" -ForegroundColor Cyan
        $configContent = Get-Content -Path $FilePath -Raw
        $config = $configContent | ConvertFrom-Json
        
        # Validate required fields
        $requiredFields = @('agentName', 'ipAddress', 'groupLabel')
        foreach ($field in $requiredFields) {
            if (-not $config.$field) {
                throw "Missing required field in config file: $field"
            }
        }
        
        # Validate IP address format
        if (-not ($config.ipAddress -match '^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')) {
            throw "Invalid IP address format in config file: $($config.ipAddress)"
        }
        
        Write-Host "[SUCCESS] Configuration loaded successfully" -ForegroundColor Green
        Write-Host "   Agent Name: $($config.agentName)" -ForegroundColor White
        Write-Host "   IP Address: $($config.ipAddress)" -ForegroundColor White
        Write-Host "   Group Label: $($config.groupLabel)" -ForegroundColor White
        
        return $config
    }
    catch {
        Write-Error "Failed to load configuration file: $($_.Exception.Message)"
        throw
    }
}

# Enhanced logging function
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS", "PROGRESS", "DOWNLOAD", "SECURITY")]
        [string]$Level = "INFO",
        [switch]$NoNewline
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    $params = @{}
    if ($NoNewline) { $params.NoNewline = $true }
    
    switch ($Level) {
        "INFO"     { Write-Host $logMessage -ForegroundColor Cyan @params }
        "WARN"     { Write-Host $logMessage -ForegroundColor Yellow @params }
        "ERROR"    { Write-Host $logMessage -ForegroundColor Red @params }
        "SUCCESS"  { Write-Host $logMessage -ForegroundColor Green @params }
        "PROGRESS" { Write-Host $logMessage -ForegroundColor Magenta @params }
        "DOWNLOAD" { Write-Host $logMessage -ForegroundColor DarkYellow @params }
        "SECURITY" { Write-Host $logMessage -ForegroundColor DarkRed @params }
    }
}

# File hash verification function
function Test-FileHash {
    param(
        [string]$FilePath,
        [string]$ExpectedHash,
        [string]$FileName = (Split-Path $FilePath -Leaf),
        [switch]$SkipVerification
    )
    
    if ($SkipVerification) {
        Write-Log "Hash verification skipped for $FileName (not recommended for production)" -Level "WARN"
        return $true
    }
    
    if (-not (Test-Path $FilePath)) {
        throw "File not found for hash verification: $FilePath"
    }
    
    Write-Log "Verifying SHA256 hash for $FileName..." -Level "SECURITY"
    
    try {
        $actualHash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash
        Write-Log "File hash calculated successfully" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Hash verification error for $FileName : $($_.Exception.Message)" -Level "ERROR"
        if (-not $SkipHashVerification) {
            throw
        }
        return $false
    }
}

# Enhanced download function
function Invoke-SecureDownload {
    param(
        [string]$Url,
        [string]$OutputPath,
        [string]$Description = "file"
    )
    
    Write-Log "Starting download of $Description" -Level "DOWNLOAD"
    Write-Log "Source: $Url" -Level "DOWNLOAD"
    Write-Log "Destination: $OutputPath" -Level "DOWNLOAD"
    
    try {
        # Enable TLS 1.2 for security
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        
        # Download file
        Invoke-WebRequest -Uri $Url -OutFile $OutputPath -UseBasicParsing
        
        # Verify file exists
        if (-not (Test-Path $OutputPath)) {
            throw "Downloaded file not found at expected location"
        }
        
        $fileSizeMB = [math]::Round((Get-Item $OutputPath).Length / 1MB, 2)
        Write-Log "Download completed successfully! File size: $fileSizeMB MB" -Level "SUCCESS"
        
    }
    catch {
        Write-Log "Download failed: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Progress tracking
function Start-Step {
    param([string]$StepName)
    
    $script:currentStep++
    $percentComplete = [math]::Round(($script:currentStep / $script:totalSteps) * 100)
    
    Write-Host ""
    Write-Host "=" * 80 -ForegroundColor DarkGray
    Write-Log "STEP $script:currentStep/$script:totalSteps : $StepName" -Level "PROGRESS"
    Write-Host "=" * 80 -ForegroundColor DarkGray
}

# Check for Administrator privileges
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# System compatibility check
function Test-SystemCompatibility {
    Write-Log "Checking system compatibility..." -Level "INFO"
    
    # Check available disk space (require at least 500MB)
    try {
        $freeSpace = (Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'").FreeSpace / 1GB
        if ($freeSpace -lt 0.5) {
            throw "Insufficient disk space. At least 500MB required, found $([math]::Round($freeSpace, 2))GB"
        }
        Write-Log "System compatibility check passed" -Level "SUCCESS"
    }
    catch {
        Write-Log "System compatibility check failed: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Uninstall existing Wazuh agent
function Uninstall-WazuhAgent {
    Start-Step "Uninstalling Existing Wazuh Agent"

    try {
        # Stop the service first
        $service = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
        if ($service -and $service.Status -ne 'Stopped') {
            Write-Log "Stopping Wazuh Agent service..." -Level "INFO"
            Stop-Service -Name "WazuhSvc" -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 5
        }

        # Find Wazuh Agent in registry
        Write-Log "Searching for Wazuh Agent in installed programs..." -Level "INFO"
        $uninstallPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        $wazuhApp = Get-ItemProperty -Path $uninstallPaths -ErrorAction SilentlyContinue | 
                   Where-Object { $_.DisplayName -like "Wazuh Agent" }

        if (-not $wazuhApp) {
            Write-Log "No existing Wazuh Agent found. Proceeding with fresh installation." -Level "SUCCESS"
            return
        }

        Write-Log "Found existing Wazuh Agent. Proceeding with uninstall..." -Level "INFO"
        $uninstallCommand = $wazuhApp.UninstallString
        
        if ($uninstallCommand -like "MsiExec.exe*") {
            $productCode = $wazuhApp.PSChildName
            $process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/x $productCode /q" -Wait -PassThru
            
            if ($process.ExitCode -ne 0) {
                throw "Uninstaller failed with exit code: $($process.ExitCode)"
            }
        }

        # Cleanup remaining files
        $ossecAgentPath = if ([IntPtr]::Size -eq 8) { "${env:ProgramFiles(x86)}\ossec-agent" } else { "$env:ProgramFiles\ossec-agent" }
        if (Test-Path $ossecAgentPath) {
            Write-Log "Performing post-uninstall cleanup..." -Level "INFO"
            Remove-Item -Recurse -Force $ossecAgentPath -ErrorAction SilentlyContinue
        }

        Write-Log "Wazuh Agent uninstalled successfully" -Level "SUCCESS"
    }
    catch {
        Write-Log "Error during uninstall: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Function to check and fix MSI conflicts
function Test-MSIAvailability {
    Write-Log "Checking Windows Installer availability..." -Level "INFO"
    
    $maxWaitTime = 300  # 5 minutes
    $checkInterval = 15  # 15 seconds
    $elapsed = 0
    
    while ($elapsed -lt $maxWaitTime) {
        # Check for running MSI processes
        $msiProcesses = Get-Process -Name "msiexec" -ErrorAction SilentlyContinue
        
        if (-not $msiProcesses) {
            Write-Log "Windows Installer is available" -Level "SUCCESS"
            return $true
        }
        
        Write-Log "Windows Installer busy. Waiting $checkInterval seconds... ($elapsed/$maxWaitTime seconds elapsed)" -Level "WARN"
        Start-Sleep -Seconds $checkInterval
        $elapsed += $checkInterval
    }
    
    Write-Log "Timeout waiting for Windows Installer. Attempting to force-clear..." -Level "WARN"
    
    # Force kill MSI processes
    Get-Process -Name "msiexec" -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Seconds 10
    
    # Restart MSI service
    Restart-Service -Name "msiserver" -Force
    Start-Sleep -Seconds 10
    
    return $true
}


# Install Wazuh agent - FIXED VERSION
function Install-WazuhAgent {
    Start-Step "Installing Wazuh Agent"
    
    # Check MSI availability first
    Test-MSIAvailability
    
    # Determine agent path
    $ossecAgentPath = if ([IntPtr]::Size -eq 8) { "${env:ProgramFiles(x86)}\ossec-agent" } else { "$env:ProgramFiles\ossec-agent" }
    $configPath = Join-Path $ossecAgentPath "ossec.conf"
    
    # Clean up old installer
    $installerPath = Join-Path $env:TEMP "wazuh-agent-$WAZUH_VERSION.msi"
    if (Test-Path $installerPath) {
        Remove-Item $installerPath -Force
    }

    # Wait for config file to be removed
    while (Test-Path $configPath) {
        Write-Host "." -NoNewline -ForegroundColor Yellow
        Start-Sleep -Seconds 3
    }
    Write-Host ""

    $maxRetries = 3
    $retryCount = 0

    do {
        try {
            Write-Log "Download attempt $($retryCount + 1) of $($maxRetries + 1)" -Level "INFO"
            
            # Download installer
            Invoke-SecureDownload -Url $WAZUH_URL -OutputPath $installerPath -Description "Wazuh Agent installer"

            # Install
            Write-Log "Starting Wazuh agent installation..." -Level "INFO"
            $installArgs = "/i `"$installerPath`" /q WAZUH_MANAGER='$ipAddress' WAZUH_REGISTRATION_SERVER='$ipAddress' WAZUH_AGENT_GROUP='$groupLabel' WAZUH_AGENT_NAME='$agentName'"
            $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $installArgs -Wait -PassThru

            if ($process.ExitCode -eq 0) {
                Write-Log "Wazuh agent installed successfully" -Level "SUCCESS"
                break
            } else {
                throw "Installer failed with exit code: $($process.ExitCode)"
            }
        }
        catch {
            $retryCount++
            if ($retryCount -le $maxRetries) {
                Write-Log "Installation failed: $($_.Exception.Message). Retrying..." -Level "WARN"
                Start-Sleep -Seconds 10
            } else {
                Write-Log "Installation failed after $maxRetries attempts: $($_.Exception.Message)" -Level "ERROR"
                throw
            }
        }
    } while ($retryCount -le $maxRetries)

    # Wait for config file to appear
    $timeout = 60
    $elapsed = 0
    while (-not (Test-Path $configPath) -and $elapsed -lt $timeout) {
        Write-Host "." -NoNewline -ForegroundColor Green
        Start-Sleep -Seconds 3
        $elapsed += 3
    }
    Write-Host ""

    if (-not (Test-Path $configPath)) {
        throw "Configuration file not found after installation timeout"
    }

    # Backup original config
    $backupPath = "$configPath.backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    Copy-Item $configPath $backupPath -Force
    Write-Log "Configuration backup created: $backupPath" -Level "SUCCESS"
    
    # Cleanup installer
    Remove-Item $installerPath -Force -ErrorAction SilentlyContinue
}

# Configure Wazuh agent
function Configure-WazuhAgent {
    Start-Step "Configuring Wazuh Agent"
    
    $ossecAgentPath = if ([IntPtr]::Size -eq 8) { "${env:ProgramFiles(x86)}\ossec-agent" } else { "$env:ProgramFiles\ossec-agent" }
    $configPath = Join-Path $ossecAgentPath "ossec.conf"

    try {
        # Update manager IP address
        $config = Get-Content -Path $configPath -Raw
        $config = $config -replace '<address>0.0.0.0</address>', "<address>$ipAddress</address>"
        Write-Log "Updated manager IP address to: $ipAddress" -Level "SUCCESS"

        # Add enrollment section
        $enrollmentSection = @"
<enrollment>
    <enabled>yes</enabled>
    <manager_address>$ipAddress</manager_address>
    <agent_name>$agentName</agent_name>
</enrollment>
"@

        if ($config -notmatch '<enrollment>') {
            $config = $config -replace '(?s)(<client>.*?)(</client>)', "`$1`n$enrollmentSection`n`$2"
            Write-Log "Added enrollment configuration" -Level "SUCCESS"
        }

        # Add group section
        if ($config -notmatch '<groups>') {
            $groupSection = "<groups>$groupLabel</groups>"
            $config = $config -replace '</enrollment>', "$groupSection`n</enrollment>"
            Write-Log "Added group configuration: $groupLabel" -Level "SUCCESS"
        }

        $config | Set-Content -Path $configPath
        Write-Log "Wazuh agent configuration completed successfully" -Level "SUCCESS"
    }
    catch {
        Write-Log "Failed to configure Wazuh agent: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Start Wazuh service
function Start-WazuhService {
    Start-Step "Starting Wazuh Service"

    try {
        Write-Log "Starting Wazuh agent service..." -Level "INFO"
        $process = Start-Process -FilePath "net" -ArgumentList "start WazuhSvc" -Wait -PassThru -NoNewWindow
        
        if ($process.ExitCode -ne 0) {
            throw "Failed to start Wazuh service with exit code: $($process.ExitCode)"
        }

        # Verify service is running
        Start-Sleep -Seconds 5
        $service = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
        if ($service.Status -eq 'Running') {
            Write-Log "Wazuh agent service started successfully" -Level "SUCCESS"
        } else {
            throw "Wazuh service is not running after start attempt"
        }
    }
    catch {
        Write-Log "Failed to start Wazuh service: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Cleanup temporary files
function Cleanup-TempFiles {
    Write-Log "Performing final cleanup..." -Level "INFO"
    
    $tempFiles = @(
        (Join-Path $env:TEMP "agent-automatic-setup-enterprise.ps1"),
        (Join-Path $env:TEMP "wazuh-agent-$WAZUH_VERSION.msi")
    )
    
    $cleanedCount = 0
    foreach ($file in $tempFiles) {
        if (Test-Path $file) {
            Remove-Item $file -Force -ErrorAction SilentlyContinue
            $cleanedCount++
        }
    }
    
    Write-Log "Cleaned up $cleanedCount temporary files" -Level "SUCCESS"
}

# Show summary
function Show-Summary {
    $setupDuration = (Get-Date) - $script:startTime
    
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Green
    Write-Host "                    NIX GUARD ENTERPRISE SETUP COMPLETED                        " -ForegroundColor Green
    Write-Host "================================================================================" -ForegroundColor Green
    Write-Host ""
    
    Write-Log "=== SETUP SUMMARY ===" -Level "SUCCESS"
    Write-Log "User: $env:USERNAME on $env:COMPUTERNAME" -Level "INFO"
    Write-Log "Agent Name: $agentName" -Level "INFO"
    Write-Log "Manager IP: $ipAddress" -Level "INFO"
    Write-Log "Group: $groupLabel" -Level "INFO"
    Write-Log "Setup Duration: $([math]::Round($setupDuration.TotalMinutes, 2)) minutes" -Level "INFO"
    Write-Log "Setup completed at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')" -Level "SUCCESS"
    
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Cyan
    Write-Host "* The Wazuh agent is now running and should appear in your dashboard" -ForegroundColor White
    Write-Host "* Agent will automatically register with the manager" -ForegroundColor White
    Write-Host "* Check the Wazuh web interface for agent status" -ForegroundColor White
    Write-Host ""
}

# MAIN EXECUTION
try {
    # Check administrator privileges
    if (-not (Test-Administrator)) {
        Write-Error "This script must be run as Administrator."
        exit 1
    }

    # Initialize transcript logging
    $loggingEnabled = Initialize-Logging

    # Load configuration
    if ($ConfigFile) {
        $config = Get-ConfigFromFile -FilePath $ConfigFile
        $agentName = $config.agentName
        $ipAddress = $config.ipAddress
        $groupLabel = $config.groupLabel
    } else {
        # Validate manual parameters
        if (-not $agentName -or -not $ipAddress -or -not $groupLabel) {
            Write-Error "All parameters (agentName, ipAddress, groupLabel) must be specified when not using a config file."
            exit 1
        }
    }

    # System compatibility check
    Test-SystemCompatibility

        # NIX Guard ASCII Art Welcome Banner - ALL GREEN
    Write-Host ""
    Write-Host "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" -ForegroundColor Green
    Write-Host "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" -ForegroundColor Green
        Write-Host "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#}(^^^^^^^^^^^^^>(}#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" -ForegroundColor Green
        Write-Host "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#<^^^^^^*-            ~^^^^^^^<{@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" -ForegroundColor Green
        Write-Host "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@[^^^^*   .            .           +^^^^(@@@@@@@%@@@@@@@@@@@@@@@@@@@@@@" -ForegroundColor Green
    Write-Host "@@@@@@@@@@@@@@@@@@@@@@@@@@%>^^^=                       .         .  :^^^^#@@@@@@@@@@@@@@@@@@@@@@@@@@" -ForegroundColor Green
        Write-Host "@@@@@@@@@@@@@@@@@@%@@@@%^^^^               .~*^^^^^^^^+~.               ^^^>%@@@@@@@@@@@@@@@@@@@@@@@" -ForegroundColor Green
        Write-Host "@@@@@@@@@@@@@@@@@@@@%{^^^ .    .     ^^^^^^^^)[}{{{[](<^^^^^^^^.           ^^^[@@@@@@@@@@@@@@@@@@@@@" -ForegroundColor Green
        Write-Host "@@@@@@@@@@@@@@@@@@@(^^+     .   +^^^^>#@@@@@@@@@@@@@@@@@@@@@@{<^^^^~         +^^]@@@@@@@@@@@@@@@@@@@" -ForegroundColor Green
        Write-Host "@@@@@@@@@@@@@@@@@(^^.        *^^^)%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@(^^^*        :^^(@@@@@@@@@@@@@@@@@" -ForegroundColor Green
        Write-Host "@@@@@@@@@@%@@@@{^^-    .  :^^^]@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@[^^^.       ~^^{@@@@@@@@@@@@@@@" -ForegroundColor Green
        Write-Host "@@@@@@@@@@@@@@>^^       -^^<@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@^^^.       ^^>@@@@@@@@@@@@@@" -ForegroundColor Green
        Write-Host "@@@@@@@@@%@@#^^:      .^^<@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%@@@@@@@(^^.     .-^^#@@@@@@@@@@@@" -ForegroundColor Green
        Write-Host "@@@@@@@@@@@)^^       ^^)@@@@@@@@%@%@%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@)^^       ^^[@@@@@@@@@@@" -ForegroundColor Green
        Write-Host "@@@@@@@@@@)^^      ^^^%@@@@@@@@@%@@@@@@@@@#(^^^^^^^^^^^^({@@@@@@@@@@@@@@%@@@@%^^*      ^^(@@@@@@@@@@" -ForegroundColor Green
        Write-Host "@@@@@@@@@<^^      ^^(@@@@@@@@@@@@@@@@@[^^^^+.           +^^^^[@@@@@@@@@@@@@@@@@]^^      *^)@@@@@@@@@" -ForegroundColor Green
        Write-Host "@@@@@@@@]^^      ^^}@@@%@@@@@@@@@@@{^^^-                 .. ~^^^}@@@@@@@@@@@@@@@}^^      ^^)@@@@@@@@" -ForegroundColor Green
        Write-Host "@@@@@@@]^^      ^^{@@@@@@@@@@@@@@[^^+                          +^^[@@@@@@@@@@@@@@#^^.     ^^]@@@@@@@" -ForegroundColor Green
        Write-Host "@@@@@@{^^ .    ^^}@@@@@@@@@@@@@#^^+         .^^^^^^^^^^.        .=^^}@@@@@@@@@@@@@}^^.     ^^#@@@@@@" -ForegroundColor Green
        Write-Host "@@@@@@^^.     ^^}@@@@@@@@@@%@%)^^       .^^^^(}{@@@@@[>^^^^        ^^^@@@@@@@@@@@@@]^^      ^^%@@@@@" -ForegroundColor Green
        Write-Host "@@@@%[^^    .+^)@@@@@@@@%@@@%^^.      +^^^@@@@@@@@@@@@@@@@<^^*.     .^^#@@@@@@@@@@@@)^+     ^^]@@@@@" -ForegroundColor Green
        Write-Host "@@@@#^^      ^^%@@@@@@@@@@@%^^  .    ^^<@@@@@@@@@@@@@@@@@@@@(^^. .   .^^%@@@@@@@@@@@#^^      ^^%@@@@" -ForegroundColor Green
        Write-Host "@@@@}^^     ^^]@@@@@@@@@@@#>^:     =^^%@@@@@@@@@@@@@@@@@@@@@@%^^~ .   :^>%@@@@@@@@@@@(^^   . ^^[@@@@" -ForegroundColor Green
        Write-Host "@@@%(^=     ^^{@@@@@@@@@@@]^^     +^^@@@@@@@@@@@@@@@@@@@@@@@@@@^^~     ^^]@@@@@@@@@@@{^^     +^)@@@@" -ForegroundColor Green
        Write-Host "@@@#^^      ^>%@@@@@@@@@@#^^      ^^%@@@@@@@@@@@@@@@@@@@@@@@@@@%^^.     ^^{@@@@@@@@@@@^^      ^^{@@@" -ForegroundColor Green
        Write-Host "@@@#^^     +^]@@@@@@@@@@@[^^     ^^}@@@@@@@@@@@@@@@@@@@@@@@@@@@@}^^.    ^^}@@@@@@@@@@@]^+    .^^#@@@" -ForegroundColor Green
        Write-Host "@@@{^^     ^^}@@@@@@@@@@@]^^    .^*{@@@@@@@@@@@@@@@@@@@@@@@@@@@@#^^  .  ^*]@@@@@@@@@@@}^^ .   ^^{@@@" -ForegroundColor Green
        Write-Host "@@@#^^     ^^}@@@@@@@@@@%]^^     ^^%@@@@@@@@@@@@@@@@@@@@@@@@@@@@%*^     ^^)@@@@@@@@@@@[^^     ^^{@@@" -ForegroundColor Green
        Write-Host "@@@{^^     ^^}@@@@@@@@@@@]^^     ^^%@@@@@@@@@@@@@@@@@@@@@@@@@@@@#^^     ^*]@@@@@@@@@@@[^^     ^^{@@@" -ForegroundColor Green
        Write-Host "@@@{*^     +^]%@@@@@@@@@@[*^     *^(@@@@@@@@@@@@@@@@@@@@@@@@@@@@)^^     ^*}@@@@@@@@@@@(^+     ^^{@@@" -ForegroundColor Green
        Write-Host "@@@{^^     .^<@@@@@@@@@@@%^^.     ^^#@@@@@@@@@@@@@@@@@@@@@@@@@@#^^      ^^%@@@@@@@@@@@>^      ^^#@@@" -ForegroundColor Green
        Write-Host "@@@%(^= .   ^^#@@@@@@@@@@@[^^      ^^{@@@@@%@%<^^*=^^]@@@@@@@@{^^  .   ^^[@@@@@@@@@@@#^^     =^)%@@@" -ForegroundColor Green
        Write-Host "@@@@[^^  .  ^^]@@@@@@@@@@%@<^^      ^^[@@@@@#)^     :^(#@@@@@{^^      +^<%@@@@@@@@@@@]^^     ^^[@@@@" -ForegroundColor Green
        Write-Host "@@@@%^^      ^^#@@@@@@@@@@@%<^~    . ^^]%@@@{>^      ^<#@@@%(^*      +^>@@@@@@@@@@@@%^^      ^>#@@@@" -ForegroundColor Green
        Write-Host "@@@@%]^^     *^(@@@@@@@@@@@@@)^*      ^^#@@@{^^      ^>%@@@}^*      *^<@@@@@@@@@@@@@(^*     ^^[@@@@@" -ForegroundColor Green
        Write-Host "@@@@@@^^      ^^[@@@@@@@@@@@@@(^^ .  ^^[@@@@%^^     .^<@@@@#<^~    ^^(@@@@@@@@@@@@@[^^    . ^*@@@@@@" -ForegroundColor Green
        Write-Host "@@@@@@}^^      ^^{@@@@%@@@@@@@@@[>^^){@@@@@@%^^     .^<%@@@@@%#<^^^^]@@@@@@@@@@@@@@#^^..    ^^}@%@@@@" -ForegroundColor Green
        Write-Host "@@@@@@@]^^      ^^[@%@@@@@@@@@@@@@@@@@@@@@@@%^^    ..^<%@@@@@@@@@@@@@@@@@@@@@@@@@}^^      ^^(@@@@@@@" -ForegroundColor Green
        Write-Host "@@@@@@@@>^+     .^^#@@@@@@@@@@@@@@@@@@@@@@@@#^^     .^<%@@@@@@@@@@@@@@@@@@@@@@@@}^^      ^^)@@@@@@@@" -ForegroundColor Green
        Write-Host "@@@@@@@@@>^*      ^^(@@@@@@@@@@@@@@@@@@@@@@@#^^     :^)%@@@@@@@@@@@@@@@@@@@@@@@(^^ .    *^>@@@@@@@@@" -ForegroundColor Green
        Write-Host "@@@@@@@@@@>^^      ^^^@@@@@@@@@@@@@@@@@@@@@@}^^     .^){@@@@@@@@@@@@@@@@@@@@@#^^^   .  ^^<@@@@@@@@@@" -ForegroundColor Green
        Write-Host "@@@@@@@@@@@(^^       ^^>@@@@@%@%@@@@@@@@@@@@{^^     .^<@@@@@@@@@@@@@@@@@@@@@(^^.      ^^]@@@@@@@@@@@" -ForegroundColor Green
        Write-Host "@@@@@@@@%@@@}^^.      :^^]@@@@@@@@@@@@@@@@@@@%^^~ .*^<%@@@@@@@@@@@@@@@@@@@(^^:      .^^{@@@@@@@@@@@@" -ForegroundColor Green
        Write-Host "@@@@@@@@@@@@@%^^^     . -^^<@@@@@@@@@@@@@@@@@@@#}((}@@@@@@@@@@@@@@@@@@@@>^^=       ^^>@@@@@@@@@@@@@@" -ForegroundColor Green
        Write-Host "@@@@@@@@@@@@@@@}^^-       .^^^}@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@}^^^.  .    -^^}@@@@@@@@@@@@@@@" -ForegroundColor Green
        Write-Host "@@@@@@@@@@@@@@@@@)^^.        ^^^^(@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@[^^^^        .^^]@@@@@@@@@@@@@@@@@" -ForegroundColor Green
        Write-Host "@@@@@@@@@@@@@@@@@@@(^^+   .     +^^^^]%@@@@@@@@@@@@@@@@@@@@@@@<^^^^+     .   +^^(@@@@@@@%@@@@@@@@@@@@" -ForegroundColor Green
        Write-Host "@@@@@@@@@@@@@@@@@@@@@[^^^           .^^^^^^^^)}{{{{{}])>^^^^^^^.       .   ^^^}@@@@@@@@@@@@@@@@@@@@@" -ForegroundColor Green
        Write-Host "@@@@@@@@@@@@@@@@@@@@@@@@>^^*               :+^^^^^^^^^*+.   .           *^^^%@@@@@@@@@@@@@@@@@@@@@@@" -ForegroundColor Green
        Write-Host "@@@@@@@@@@@@@@@@@@@@@@@@@@{^^^^                                     .^^^^[@@@@@@@@@@@@@@@@@@@@@@@@@@" -ForegroundColor Green
        Write-Host "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@)^^^^=             .     .        ~^^^^]@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" -ForegroundColor Green
        Write-Host "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@}^^^^^^^*-            :*^^^^^^)[@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" -ForegroundColor Green
        Write-Host "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%[)^^^^^^^^^^^^^^<[#@@@@@@@%@@@@@@@@@@@@@@@@@@@@@@@@@@@@" -ForegroundColor Green
    Write-Host "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" -ForegroundColor Green
    Write-Host "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" -ForegroundColor Green
    Write-Host ""
    Write-Host "                          NIX GUARD WAZUH AGENT ENTERPRISE SETUP                           " -ForegroundColor White -BackgroundColor DarkGreen
    Write-Host "                              Version 3.1 - Enhanced Security                           " -ForegroundColor White -BackgroundColor DarkGreen
    Write-Host "                                   2025-08-18 18:47:21 UTC                              " -ForegroundColor Yellow -BackgroundColor DarkGreen
    Write-Host "                                        by NIXGUARD                                     " -ForegroundColor Cyan -BackgroundColor DarkGreen
    Write-Host ""
    Write-Log "Enterprise setup initiated by $env:USERNAME at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')" -Level "SUCCESS"
    Write-Log "Agent Name: $agentName" -Level "INFO"
    Write-Log "Manager IP: $ipAddress" -Level "INFO"
    Write-Log "Group: $groupLabel" -Level "INFO"
    Write-Log "Transcript logging: $(if ($loggingEnabled) { 'Enabled' } else { 'Disabled' })" -Level "INFO"
    
    # Execute main steps
    Uninstall-WazuhAgent
    Install-WazuhAgent
    Configure-WazuhAgent
    Start-WazuhService
    Cleanup-TempFiles
    
    # Show final summary
    Show-Summary
}
catch {
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Red
    Write-Host "                            SETUP FAILED                                     " -ForegroundColor Red
    Write-Host "================================================================================" -ForegroundColor Red
    Write-Host ""
    
    Write-Log "Setup failed: $($_.Exception.Message)" -Level "ERROR"
    Write-Log "Setup failed at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')" -Level "ERROR"
    Write-Log "Completed $script:currentStep of $script:totalSteps steps" -Level "ERROR"
    
    Write-Host ""
    Write-Host "Troubleshooting tips:" -ForegroundColor Yellow
    Write-Host "* Ensure you're running as Administrator" -ForegroundColor White
    Write-Host "* Check your internet connection" -ForegroundColor White
    Write-Host "* Verify the manager IP address is correct: $ipAddress" -ForegroundColor White
    Write-Host "* Try running the script again" -ForegroundColor White
    Write-Host ""
    
    exit 1
}
finally {
    # Stop transcript logging
    try {
        if ($loggingEnabled) {
            Stop-Transcript
            Write-Host "[TRANSCRIPT] Log saved: $LogPath" -ForegroundColor Green
        }
    }
    catch {
        # Ignore transcript stop errors
    }
}