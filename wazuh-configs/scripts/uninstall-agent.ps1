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
    .\Cloud-X-Security-Wazuh-Uninstaller.ps1
.EXAMPLE
    .\Cloud-X-Security-Wazuh-Uninstaller.ps1 -Force -KeepLogs
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

# Import Modules
$modulePath = Join-Path $PSScriptRoot "Uninstaller-Modules"
Import-Module (Join-Path $modulePath "Uninstall-Display.psm1") -Force
Import-Module (Join-Path $modulePath "Uninstall-Operations.psm1") -Force
Import-Module (Join-Path $modulePath "Uninstall-Cleanup.psm1") -Force
Import-Module (Join-Path $modulePath "Uninstall-Utilities.psm1") -Force

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
    Write-Host "===============================================================================" -ForegroundColor Red
    Write-Host "                           UNINSTALL FAILED                                  " -ForegroundColor Red
    Write-Host "===============================================================================" -ForegroundColor Red
    Write-Host ""
    
    Write-Log "Uninstall failed: $($_.Exception.Message)" -Level "ERROR"
    Write-Log "Failed at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')" -Level "ERROR"
    
    Write-Host ""
    Write-Host "Manual cleanup may be required." -ForegroundColor Yellow
    Write-Host "Check the error messages above for details." -ForegroundColor Yellow
    Write-Host ""
    
    exit 1
}
