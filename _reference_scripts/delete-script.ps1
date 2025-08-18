#Requires -RunAsAdministrator

<#
.SYNOPSIS
    MAPLEX Wazuh Agent Complete Uninstaller
.DESCRIPTION
    Comprehensive script to completely remove Wazuh agent from Windows systems
    Handles registry cleanup, service removal, file cleanup, and system restoration
.PARAMETER Force
    Force removal without confirmation prompts
.PARAMETER KeepLogs
    Keep log files during uninstallation
.EXAMPLE
    .\wazuh-agent-uninstaller.ps1
.EXAMPLE
    .\wazuh-agent-uninstaller.ps1 -Force -KeepLogs
.NOTES
    MAPLEX Uninstaller Version 1.0
    Author: MAPLEIZER
    Created: 2025-08-18 19:01:33 UTC
#>

param (
    [switch]$Force,
    [switch]$KeepLogs
)

# Script configuration
$ErrorActionPreference = "Continue"  # Continue on errors for cleanup
$ProgressPreference = "SilentlyContinue"

# Global tracking
$script:startTime = Get-Date
$script:removedItems = @()
$script:errors = @()

# Enhanced logging function
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS", "PROGRESS", "CLEANUP")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "INFO"     { Write-Host $logMessage -ForegroundColor Cyan }
        "WARN"     { Write-Host $logMessage -ForegroundColor Yellow }
        "ERROR"    { Write-Host $logMessage -ForegroundColor Red }
        "SUCCESS"  { Write-Host $logMessage -ForegroundColor Green }
        "PROGRESS" { Write-Host $logMessage -ForegroundColor Magenta }
        "CLEANUP"  { Write-Host $logMessage -ForegroundColor DarkYellow }
    }
}

# Check for Administrator privileges
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# MAPLEX ASCII Banner for Uninstaller
function Show-UninstallBanner {
    Write-Host ""
    Write-Host "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" -ForegroundColor Red
    Write-Host "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" -ForegroundColor Red
    Write-Host "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" -ForegroundColor Red
    Write-Host "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" -ForegroundColor Red
    Write-Host ""
    Write-Host "                    MAPLEX WAZUH AGENT COMPLETE UNINSTALLER                   " -ForegroundColor White -BackgroundColor DarkRed
    Write-Host "                            Version 1.0 - MAPLEIZER                          " -ForegroundColor White -BackgroundColor DarkRed
    Write-Host "                              2025-08-18 19:01:33 UTC                        " -ForegroundColor Yellow -BackgroundColor DarkRed
    Write-Host ""
}

# Safe item removal with logging
function Remove-ItemSafe {
    param(
        [string]$Path,
        [string]$Description,
        [switch]$Recurse
    )
    
    try {
        if (Test-Path $Path) {
            Write-Log "Removing $Description : $Path" -Level "CLEANUP"
            
            if ($Recurse) {
                Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
            } else {
                Remove-Item -Path $Path -Force -ErrorAction Stop
            }
            
            $script:removedItems += "$Description : $Path"
            Write-Log "Successfully removed $Description" -Level "SUCCESS"
            return $true
        } else {
            Write-Log "$Description not found: $Path" -Level "INFO"
            return $true
        }
    }
    catch {
        $errorMsg = "Failed to remove $Description : $($_.Exception.Message)"
        Write-Log $errorMsg -Level "ERROR"
        $script:errors += $errorMsg
        return $false
    }
}

# Stop Wazuh services
function Stop-WazuhServices {
    Write-Log "Stopping Wazuh services..." -Level "PROGRESS"
    
    $services = @("WazuhSvc", "Wazuh", "OssecSvc")
    $stopped = 0
    
    foreach ($serviceName in $services) {
        try {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service) {
                Write-Log "Found service: $serviceName (Status: $($service.Status))" -Level "INFO"
                
                if ($service.Status -ne 'Stopped') {
                    Write-Log "Stopping service: $serviceName" -Level "CLEANUP"
                    Stop-Service -Name $serviceName -Force -ErrorAction Stop
                    
                    # Wait for service to stop
                    $timeout = 30
                    $elapsed = 0
                    while ((Get-Service -Name $serviceName).Status -ne 'Stopped' -and $elapsed -lt $timeout) {
                        Start-Sleep -Seconds 2
                        $elapsed += 2
                        Write-Host "." -NoNewline -ForegroundColor Yellow
                    }
                    Write-Host ""
                    
                    if ((Get-Service -Name $serviceName).Status -eq 'Stopped') {
                        Write-Log "Service $serviceName stopped successfully" -Level "SUCCESS"
                        $stopped++
                    } else {
                        Write-Log "Service $serviceName did not stop within timeout" -Level "WARN"
                    }
                } else {
                    Write-Log "Service $serviceName already stopped" -Level "INFO"
                    $stopped++
                }
            }
        }
        catch {
            Write-Log "Error handling service $serviceName : $($_.Exception.Message)" -Level "ERROR"
        }
    }
    
    Write-Log "Service stop operation completed ($stopped services processed)" -Level "SUCCESS"
}

# Kill Wazuh processes
function Stop-WazuhProcesses {
    Write-Log "Terminating Wazuh processes..." -Level "PROGRESS"
    
    $processNames = @("*wazuh*", "*ossec*", "agent*")
    $killed = 0
    
    foreach ($processPattern in $processNames) {
        try {
            $processes = Get-Process -Name $processPattern -ErrorAction SilentlyContinue
            if ($processes) {
                foreach ($process in $processes) {
                    Write-Log "Terminating process: $($process.Name) (PID: $($process.Id))" -Level "CLEANUP"
                    $process | Stop-Process -Force -ErrorAction Stop
                    $killed++
                }
            }
        }
        catch {
            Write-Log "Error terminating processes: $($_.Exception.Message)" -Level "ERROR"
        }
    }
    
    if ($killed -gt 0) {
        Write-Log "Terminated $killed Wazuh processes" -Level "SUCCESS"
        Start-Sleep -Seconds 5  # Wait for processes to fully terminate
    } else {
        Write-Log "No Wazuh processes found running" -Level "INFO"
    }
}

# Uninstall via Windows Installer
function Uninstall-WazuhMSI {
    Write-Log "Attempting MSI uninstallation..." -Level "PROGRESS"
    
    # Search for Wazuh in installed programs
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    
    $wazuhApps = @()
    foreach ($path in $uninstallPaths) {
        try {
            $apps = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | 
                   Where-Object { $_.DisplayName -like "*Wazuh*" -or $_.DisplayName -like "*OSSEC*" }
            $wazuhApps += $apps
        }
        catch {
            Write-Log "Error searching registry path $path : $($_.Exception.Message)" -Level "WARN"
        }
    }
    
    if ($wazuhApps.Count -eq 0) {
        Write-Log "No Wazuh applications found in Windows Programs registry" -Level "INFO"
        return $true
    }
    
    foreach ($app in $wazuhApps) {
        try {
            Write-Log "Found installed application: $($app.DisplayName) (Version: $($app.DisplayVersion))" -Level "INFO"
            
            $productCode = $app.PSChildName
            Write-Log "Uninstalling product code: $productCode" -Level "CLEANUP"
            
            # Enhanced uninstall command
            $uninstallArgs = @("/x", $productCode, "/q", "/norestart", "/L*V", "`"$env:TEMP\wazuh-uninstall-$productCode.log`"")
            $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $uninstallArgs -Wait -PassThru -NoNewWindow
            
            Write-Log "MSI uninstall exit code: $($process.ExitCode)" -Level "INFO"
            
            if ($process.ExitCode -eq 0 -or $process.ExitCode -eq 3010) {
                Write-Log "Successfully uninstalled: $($app.DisplayName)" -Level "SUCCESS"
            } else {
                Write-Log "MSI uninstall failed with exit code: $($process.ExitCode)" -Level "WARN"
            }
        }
        catch {
            Write-Log "Error during MSI uninstall: $($_.Exception.Message)" -Level "ERROR"
        }
    }
    
    return $true
}

# Remove registry entries
function Remove-WazuhRegistry {
    Write-Log "Cleaning Wazuh registry entries..." -Level "PROGRESS"
    
    $registryPaths = @(
        "HKLM:\SOFTWARE\WOW6432Node\Wazuh",
        "HKLM:\SOFTWARE\Wazuh",
        "HKLM:\SOFTWARE\WOW6432Node\ossec",
        "HKLM:\SOFTWARE\ossec",
        "HKLM:\SYSTEM\CurrentControlSet\Services\WazuhSvc",
        "HKLM:\SYSTEM\CurrentControlSet\Services\OssecSvc",
        "HKLM:\SYSTEM\CurrentControlSet\Services\Wazuh"
    )
    
    $removed = 0
    foreach ($regPath in $registryPaths) {
        if (Remove-ItemSafe -Path $regPath -Description "Registry key" -Recurse) {
            $removed++
        }
    }
    
    Write-Log "Registry cleanup completed ($removed entries processed)" -Level "SUCCESS"
}

# Remove installation directories
function Remove-WazuhDirectories {
    Write-Log "Removing Wazuh installation directories..." -Level "PROGRESS"
    
    $installPaths = @(
        "${env:ProgramFiles}\ossec-agent",
        "${env:ProgramFiles(x86)}\ossec-agent",
        "${env:ProgramFiles}\Wazuh Agent",
        "${env:ProgramFiles(x86)}\Wazuh Agent",
        "${env:ProgramData}\ossec",
        "${env:ProgramData}\Wazuh"
    )
    
    if (-not $KeepLogs) {
        $installPaths += @(
            "${env:ProgramData}\ossec-agent",
            "${env:ProgramData}\Wazuh Agent"
        )
    }
    
    $removed = 0
    foreach ($path in $installPaths) {
        if (Remove-ItemSafe -Path $path -Description "Installation directory" -Recurse) {
            $removed++
        }
    }
    
    if ($KeepLogs) {
        Write-Log "Log directories preserved as requested" -Level "INFO"
    }
    
    Write-Log "Directory cleanup completed ($removed directories processed)" -Level "SUCCESS"
}

# Remove Windows services
function Remove-WazuhServices {
    Write-Log "Removing Wazuh Windows services..." -Level "PROGRESS"
    
    $serviceNames = @("WazuhSvc", "OssecSvc", "Wazuh")
    $removed = 0
    
    foreach ($serviceName in $serviceNames) {
        try {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service) {
                Write-Log "Removing Windows service: $serviceName" -Level "CLEANUP"
                
                # Use sc.exe for reliable service deletion
                $result = & sc.exe delete $serviceName
                if ($LASTEXITCODE -eq 0) {
                    Write-Log "Successfully removed service: $serviceName" -Level "SUCCESS"
                    $removed++
                } else {
                    Write-Log "Failed to remove service $serviceName : $result" -Level "ERROR"
                }
            }
        }
        catch {
            Write-Log "Error removing service $serviceName : $($_.Exception.Message)" -Level "ERROR"
        }
    }
    
    Write-Log "Service removal completed ($removed services removed)" -Level "SUCCESS"
}

# Clean temporary files
function Remove-TempFiles {
    Write-Log "Cleaning temporary Wazuh files..." -Level "PROGRESS"
    
    $tempPatterns = @(
        "$env:TEMP\*wazuh*",
        "$env:TEMP\*ossec*",
        "$env:TEMP\agent-automatic-setup*",
        "$env:TEMP\nixguard-setup*"
    )
    
    $cleaned = 0
    foreach ($pattern in $tempPatterns) {
        try {
            $files = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                if (Remove-ItemSafe -Path $file.FullName -Description "Temporary file") {
                    $cleaned++
                }
            }
        }
        catch {
            Write-Log "Error cleaning temp pattern $pattern : $($_.Exception.Message)" -Level "WARN"
        }
    }
    
    Write-Log "Temporary file cleanup completed ($cleaned files removed)" -Level "SUCCESS"
}

# Verify complete removal
function Test-WazuhRemoval {
    Write-Log "Verifying complete Wazuh removal..." -Level "PROGRESS"
    
    $remainingItems = @()
    
    # Check services
    $services = Get-Service -Name "*wazuh*", "*ossec*" -ErrorAction SilentlyContinue
    if ($services) {
        $remainingItems += "Services: $($services.Name -join ', ')"
    }
    
    # Check processes
    $processes = Get-Process -Name "*wazuh*", "*ossec*" -ErrorAction SilentlyContinue
    if ($processes) {
        $remainingItems += "Processes: $($processes.Name -join ', ')"
    }
    
    # Check main installation directories
    $dirs = @("${env:ProgramFiles}\ossec-agent", "${env:ProgramFiles(x86)}\ossec-agent")
    foreach ($dir in $dirs) {
        if (Test-Path $dir) {
            $remainingItems += "Directory: $dir"
        }
    }
    
    if ($remainingItems.Count -eq 0) {
        Write-Log "Verification PASSED: Wazuh completely removed from system" -Level "SUCCESS"
        return $true
    } else {
        Write-Log "Verification WARNING: Some items may remain:" -Level "WARN"
        foreach ($item in $remainingItems) {
            Write-Log "  - $item" -Level "WARN"
        }
        return $false
    }
}

# Show final summary
function Show-UninstallSummary {
    $duration = (Get-Date) - $script:startTime
    
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Red
    Write-Host "                         MAPLEX UNINSTALL COMPLETED                          " -ForegroundColor Red
    Write-Host "================================================================================" -ForegroundColor Red
    Write-Host ""
    
    Write-Log "=== UNINSTALL SUMMARY ===" -Level "SUCCESS"
    Write-Log "User: $env:USERNAME on $env:COMPUTERNAME" -Level "INFO"
    Write-Log "Items Removed: $($script:removedItems.Count)" -Level "INFO"
    Write-Log "Errors Encountered: $($script:errors.Count)" -Level "INFO"
    Write-Log "Duration: $([math]::Round($duration.TotalMinutes, 2)) minutes" -Level "INFO"
    Write-Log "Completed at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')" -Level "SUCCESS"
    
    if ($script:removedItems.Count -gt 0) {
        Write-Host ""
        Write-Host "Removed Items:" -ForegroundColor Green
        foreach ($item in $script:removedItems) {
            Write-Host "  ✓ $item" -ForegroundColor White
        }
    }
    
    if ($script:errors.Count -gt 0) {
        Write-Host ""
        Write-Host "Errors Encountered:" -ForegroundColor Yellow
        foreach ($error in $script:errors) {
            Write-Host "  ✗ $error" -ForegroundColor Red
        }
    }
    
    Write-Host ""
    Write-Host "System is now clean and ready for fresh Wazuh installation if needed." -ForegroundColor Cyan
    Write-Host ""
}

# MAIN EXECUTION
try {
    # Check administrator privileges
    if (-not (Test-Administrator)) {
        Write-Error "This uninstaller must be run as Administrator."
        exit 1
    }

    # Show banner
    Show-UninstallBanner

    Write-Log "MAPLEX Wazuh Agent Uninstaller started by $env:USERNAME at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')" -Level "SUCCESS"
    Write-Log "Force mode: $(if ($Force) { 'Enabled' } else { 'Disabled' })" -Level "INFO"
    Write-Log "Keep logs: $(if ($KeepLogs) { 'Yes' } else { 'No' })" -Level "INFO"
    
    # Confirmation prompt (unless Force mode)
    if (-not $Force) {
        Write-Host ""
        Write-Host "This will completely remove Wazuh Agent from your system." -ForegroundColor Yellow
        Write-Host "This action cannot be undone." -ForegroundColor Red
        Write-Host ""
        $confirmation = Read-Host "Are you sure you want to continue? (Type 'YES' to confirm)"
        
        if ($confirmation -ne "YES") {
            Write-Log "Uninstallation cancelled by user" -Level "WARN"
            exit 0
        }
    }
    
    Write-Host ""
    Write-Log "Starting comprehensive Wazuh removal process..." -Level "PROGRESS"
    
    # Execute uninstall steps
    Stop-WazuhServices
    Stop-WazuhProcesses
    Uninstall-WazuhMSI
    Remove-WazuhServices
    Remove-WazuhRegistry
    Remove-WazuhDirectories
    Remove-TempFiles
    
    # Verify removal
    $removalSuccess = Test-WazuhRemoval
    
    # Show final summary
    Show-UninstallSummary
    
    if ($removalSuccess) {
        Write-Host "🎉 UNINSTALL COMPLETED SUCCESSFULLY! 🎉" -ForegroundColor Green
        exit 0
    } else {
        Write-Host "⚠️  UNINSTALL COMPLETED WITH WARNINGS ⚠️" -ForegroundColor Yellow
        exit 1
    }
}
catch {
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Red
    Write-Host "                           UNINSTALL FAILED                                  " -ForegroundColor Red
    Write-Host "================================================================================" -ForegroundColor Red
    Write-Host ""
    
    Write-Log "Uninstall failed: $($_.Exception.Message)" -Level "ERROR"
    Write-Log "Failed at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')" -Level "ERROR"
    
    Write-Host ""
    Write-Host "Manual cleanup may be required." -ForegroundColor Yellow
    Write-Host "Check the error messages above for details." -ForegroundColor Yellow
    Write-Host ""
    
    exit 1
}