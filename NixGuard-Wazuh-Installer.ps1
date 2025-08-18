#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Automates the installation and configuration of the Wazuh agent on Windows systems.

.DESCRIPTION
    This script provides a comprehensive, modular solution for deploying the Wazuh agent.
    It handles prerequisites, downloads the installer, configures the agent, and ensures the service is running correctly.

.PARAMETER ipAddress
    The IP address of the Wazuh manager. (Used with 'Manual' parameter set)

.PARAMETER agentName
    The desired name for the Wazuh agent. (Used with 'Manual' parameter set)

.PARAMETER groupLabel
    The group label to assign to the agent in Wazuh. (Used with 'Manual' parameter set)

.PARAMETER ConfigFile
    Path to a JSON configuration file to load parameters from. (Used with 'ConfigFile' parameter set)

.PARAMETER WAZUH_VERSION
    The version of the Wazuh agent to install.

.PARAMETER SKIP_HASH_CHECK
    If specified, skips the SHA256 hash verification of the downloaded installer.

.PARAMETER LogPath
    Custom path for the transcript log file.

.EXAMPLE
    # Using manual parameters
    .\NixGuard-Wazuh-Installer.ps1 -ipAddress '192.168.1.100' -agentName 'WIN-AGENT-01' -groupLabel 'windows_servers'

.EXAMPLE
    # Using a configuration file
    .\NixGuard-Wazuh-Installer.ps1 -ConfigFile 'C:\path\to\your\config.json'

.EXAMPLE
    # Uninstall the Wazuh agent
    .\NixGuard-Wazuh-Installer.ps1 -Uninstall

.NOTES
    Author: NIXGUARD
    Version: 3.2 (Modular & Corrected)
#>

param (
    [Parameter(ParameterSetName='Manual', Mandatory=$true)]
    [string]$ipAddress,

    [Parameter(ParameterSetName='Manual', Mandatory=$true)]
    [string]$agentName,

    [Parameter(ParameterSetName='Manual', Mandatory=$true)]
    [string]$groupLabel,

    [Parameter(ParameterSetName='ConfigFile', Mandatory=$true)]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$ConfigFile,

    [Parameter(ParameterSetName='Uninstall', Mandatory=$true)]
    [switch]$Uninstall,

    [Parameter(ParameterSetName='Manual')]
    [Parameter(ParameterSetName='ConfigFile')]
    [string]$WAZUH_VERSION = '4.7.0-1',

    [Parameter(ParameterSetName='Manual')]
    [Parameter(ParameterSetName='ConfigFile')]
    [Parameter(ParameterSetName='Uninstall')]
    [switch]$SKIP_HASH_CHECK,

    [Parameter(ParameterSetName='Uninstall')]
    [switch]$KeepLogs,

    [Parameter(ParameterSetName='Manual')]
    [Parameter(ParameterSetName='ConfigFile')]
    [string]$LogPath
)

# Script configuration
$ErrorActionPreference = 'Stop'
$script:startTime = Get-Date
$script:totalSteps = 6
$script:currentStep = 0
$global:LogPath = $null
$transcriptStarted = $false

try {
    # Import Modules
    $modulePath = Join-Path $PSScriptRoot "Modules"
    Import-Module (Join-Path $modulePath "Banner.psm1") -Force
    Import-Module (Join-Path $modulePath "Logging.psm1") -Force
    Import-Module (Join-Path $modulePath "Utilities.psm1") -Force
    Import-Module (Join-Path $modulePath "WazuhOperations.psm1") -Force
    Import-Module (Join-Path $modulePath "PostInstall.psm1") -Force

    # Start Logging
    if ($PSBoundParameters.ContainsKey('LogPath')) {
        $transcriptStarted = Initialize-Logging -LogPath $LogPath
    } else {
        $transcriptStarted = Initialize-Logging
    }

    # Display Banner
    Show-Banner

    # Determine workflow: Install or Uninstall
    if ($PSCmdlet.ParameterSetName -eq 'Uninstall') {
        # --- UNINSTALL WORKFLOW ---
        Write-Log "Uninstall parameter detected. Launching the MAPLEX Uninstaller..." -Level "INFO"
        
        $uninstallerPath = Join-Path $PSScriptRoot "NixGuard-Wazuh-Uninstaller.ps1"
        if (-not (Test-Path $uninstallerPath)) {
            throw "Uninstaller script not found at: $uninstallerPath"
        }

        $uninstallArgs = @()
        if ($SKIP_HASH_CHECK) { # Re-using SKIP_HASH_CHECK as a proxy for -Force
            $uninstallArgs += "-Force"
            Write-Log "Force mode enabled for uninstaller." -Level "WARN"
        }
        if ($KeepLogs) {
            $uninstallArgs += "-KeepLogs"
            Write-Log "Keep logs mode enabled for uninstaller." -Level "INFO"
        }

        try {
            & $uninstallerPath $uninstallArgs
        }
        catch {
            throw "The uninstaller script failed to execute. Please run it directly to see detailed errors."
        }

        Write-Log "UNINSTALL PROCESS INITIATED." -Level "SUCCESS"

    } else {
        # --- INSTALL WORKFLOW ---
        Write-Log "Starting NIX Guard Wazuh Agent setup..." -Level "INFO"
        Write-Log "Parameters provided by: $PSCmdlet.ParameterSetName" -Level "INFO"

        # Load configuration from file if provided
        if ($PSCmdlet.ParameterSetName -eq 'ConfigFile') {
            Write-Log "Loading configuration from file: $ConfigFile" -Level "INFO"
            $config = Get-ConfigFromFile -FilePath $ConfigFile
            $agentName = $config.agentName
            $ipAddress = $config.ipAddress
            $groupLabel = $config.groupLabel
            if ($config.PSObject.Properties['WAZUH_VERSION']) { $WAZUH_VERSION = $config.WAZUH_VERSION }
        }

        # Main Execution
        Start-Step "Initialization and Parameter Validation"
        Write-Log "Setup initiated by user: $env:USERNAME" -Level "INFO"
        Write-Log "Parameters: IP=$ipAddress, AgentName=$agentName, Group=$groupLabel, Version=$WAZUH_VERSION" -Level "INFO"

        # Pre-flight checks
        Test-SystemCompatibility
        Test-MSIAvailability

        # Core Operations
        Uninstall-WazuhAgent
        Install-WazuhAgent -WAZUH_VERSION $WAZUH_VERSION
        Configure-WazuhAgent -ipAddress $ipAddress -agentName $agentName -groupLabel $groupLabel
        Start-WazuhService

        # Post-Install
        Start-Step "Finalizing Setup"
        Cleanup-TempFiles
    }
}
catch {
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Red
    Write-Host "                            SETUP FAILED                                     " -ForegroundColor Red
    Write-Host "================================================================================" -ForegroundColor Red
    Write-Host ""
    Write-Log "Setup failed: $($_.Exception.Message)" -Level "ERROR"
    Write-Log "Completed $script:currentStep of $script:totalSteps steps." -Level "ERROR"
    Write-Host ""
    Write-Host "Troubleshooting tips:" -ForegroundColor Yellow
    Write-Host "* Ensure you're running as Administrator." -ForegroundColor White
    Write-Host "* Check your internet connection and that the manager IP ($ipAddress) is reachable." -ForegroundColor White
    Write-Host "* Review the log file for details: $($global:LogPath)" -ForegroundColor White
    Write-Host ""
    exit 1
}
finally {
    if ($PSItem -eq $null) { # If no errors occurred
        Show-Summary -startTime $script:startTime -agentName $agentName -ipAddress $ipAddress -groupLabel $groupLabel
    }
    
    if ($transcriptStarted) {
        Stop-Transcript
    }
}