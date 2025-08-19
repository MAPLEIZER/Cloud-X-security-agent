#================================================================================
# REPOSITORY REFACTOR NOTICE (2025-08-19)
#
# This script is now part of a larger repository structure designed for
# centralized Wazuh configuration management.
#
# - All scripts and modules are located in the 'wazuh-configs/scripts' directory.
# - Agent configuration templates are in 'wazuh-configs/agents'.
# - The main installer script is now 'install-agent.ps1'.
# - The main uninstaller script is now 'uninstall-agent.ps1'.
#
# This change improves organization and scalability.
#================================================================================

#Requires -RunAsAdministrator

function Start-CloudXSecurityWazuhInstall {
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
    Start-CloudXSecurityWazuhInstall -ipAddress '192.168.1.100' -agentName 'WIN-AGENT-01' -groupLabel 'windows_servers'

.EXAMPLE
    # Using a configuration file
    Start-CloudXSecurityWazuhInstall -ConfigFile 'C:\path\to\your\config.json'

.EXAMPLE
    # Uninstall the Wazuh agent
    Start-CloudXSecurityWazuhInstall -Uninstall

.NOTES
    Author: Cloud-X Security
    Version: 3.3 (Refactored for one-liner execution)
#>
    [CmdletBinding(DefaultParameterSetName='Manual')]
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
        
        # Robust module import supporting both local script execution and web one-liner (iex)
        $modules = @("Banner.psm1","Logging.psm1","Utilities.psm1","WazuhOperations.psm1","PostInstall.psm1")
        $repoRawBase = "https://raw.githubusercontent.com/MAPLEIZER/Cloud-X-security-agent/main/wazuh-configs/scripts/Modules"

        $usingWeb = [string]::IsNullOrWhiteSpace($PSScriptRoot) -or -not (Test-Path $modulePath)
        if ($usingWeb) {
            # Running via iex: download modules to temp and import them
            $tempModulesDir = Join-Path $env:TEMP "CloudXSecurity\Modules"
            if (-not (Test-Path $tempModulesDir)) { New-Item -ItemType Directory -Path $tempModulesDir -Force | Out-Null }

            foreach ($m in $modules) {
                $url = "$repoRawBase/$m"
                $dest = Join-Path $tempModulesDir $m
                try {
                    Write-Verbose "Downloading module $m from $url"
                    Invoke-WebRequest -Uri $url -UseBasicParsing -OutFile $dest -ErrorAction Stop
                    Import-Module $dest -Force -ErrorAction Stop
                } catch {
                    throw "Failed to download/import module '$m' from '$url': $($_.Exception.Message)"
                }
            }
        } else {
            # Local execution: import modules from repository
            foreach ($m in $modules) {
                $path = Join-Path $modulePath $m
                Import-Module $path -Force -ErrorAction Stop
            }
        }

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
            
                        $uninstallerPath = Join-Path $PSScriptRoot "uninstall-agent.ps1"
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
            Write-Log "Starting Cloud-X Security Wazuh Agent setup..." -Level "INFO"
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
            Set-WazuhAgentConfiguration -ipAddress $ipAddress -agentName $agentName -groupLabel $groupLabel
            Start-WazuhService

            # Post-Install
            Start-Step "Finalizing Setup"
            Deploy-ActiveResponseScripts
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
}
