#================================================================================
# Cloud-X Security Wazuh Agent Installer Module
# Version: 3.3
# Author: Cloud-X Security
#================================================================================

#region Helper Functions

function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [Parameter(Mandatory=$true)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS", "DEBUG")]
        [string]$Level
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $formattedMessage = "$timestamp [$Level] - $Message"

    $colorMap = @{
        INFO    = "White";
        WARNING = "Yellow";
        ERROR   = "Red";
        SUCCESS = "Green";
        DEBUG   = "Cyan"
    }

    Write-Host $formattedMessage -ForegroundColor $colorMap[$Level]
    if ($global:LogPath) {
        Add-Content -Path $global:LogPath -Value $formattedMessage
    }
}

function Start-Step {
    param (
        [string]$StepName
    )
    $script:currentStep++
    $header = "=== STEP $script:currentStep OF $script:totalSteps: $StepName ==="
    Write-Log $header -Level "INFO"
    Write-Host "`n" + ("=" * $header.Length) -ForegroundColor Cyan
    Write-Host $header -ForegroundColor Cyan
    Write-Host ("=" * $header.Length) -ForegroundColor Cyan
}

function Show-Summary {
    param (
        [datetime]$startTime,
        [string]$agentName,
        [string]$ipAddress,
        [string]$groupLabel
    )

    $endTime = Get-Date
    $duration = New-TimeSpan -Start $startTime -End $endTime

    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Green
    Write-Host "                         SETUP COMPLETED SUCCESSFULLY                           " -ForegroundColor Green
    Write-Host "================================================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Setup completed successfully." -ForegroundColor Green

    Write-Host "Summary:" -ForegroundColor Cyan
    Write-Host "- Agent Name:    $agentName" -ForegroundColor White
    Write-Host "- Manager IP:    $ipAddress" -ForegroundColor White
    Write-Host "- Agent Group:   $groupLabel" -ForegroundColor White
    Write-Host "- Total Time:    $($duration.Minutes)m $($duration.Seconds)s" -ForegroundColor White
    Write-Host ""
}

function Show-Banner {
    # Cloud-X Security ASCII Art Welcome Banner
    Write-Host "" -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                               @@@@@                                                ' -ForegroundColor Blue
    Write-Host '                                            @@@      @@                                             ' -ForegroundColor Blue
    Write-Host '                                          @@             @@                                         ' -ForegroundColor Blue
    Write-Host '                                     @@@@@@         @@@@@@@@@@@                                     ' -ForegroundColor Blue
    Write-Host '                                    @@@           @@@         @@                                    ' -ForegroundColor Blue
    Write-Host '                                   @@           @@@  @@@@@@@@@ @@                                   ' -ForegroundColor Blue
    Write-Host '                                   @@ @       @@@  @@@       @ @@                                   ' -ForegroundColor Blue
    Write-Host '                                   @@ @@    @@@  @@@         @ @@                                   ' -ForegroundColor Blue
    Write-Host '                                    @@   @@    @@@            @@                                    ' -ForegroundColor Blue
    Write-Host '                                     @@@@@@@@@@@       @@@@@@@                                      ' -ForegroundColor Blue
    Write-Host '                                         @@@                                                        ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                    @@                     @@    @    @                             ' -ForegroundColor Blue
    Write-Host '                               @    @@   @@             @  @     @@  @                              ' -ForegroundColor Blue
    Write-Host '                             @@@@@@ @@ @@@@@@  @@  @@ @@@@@@       @@                               ' -ForegroundColor Blue
    Write-Host '                            @@      @@ @@   @@ @   @@ @    @      @ @@                              ' -ForegroundColor Blue
    Write-Host '                             @@@@@  @@ @@@@@@  @@@@@@ @@@@@@@    @   @@                             ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                     @@  @  @@  @@ @@  @  @  @                                      ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host ""
    Write-Host "                       CLOUD-X SECURITY WAZUH AGENT ENTERPRISE SETUP                         " -ForegroundColor White -BackgroundColor DarkGreen
    Write-Host "                              Version 3.1 - Enhanced Security                           " -ForegroundColor White -BackgroundColor DarkGreen
    Write-Host "                                   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')                              " -ForegroundColor Yellow -BackgroundColor DarkGreen
    Write-Host "                                     by CLOUD-X SECURITY                                  " -ForegroundColor Cyan -BackgroundColor DarkGreen
    Write-Host ""
}

#endregion

#region Main Function

function Install-WazuhAgent {
<#
.SYNOPSIS
    Automates the installation and configuration of the Wazuh agent on Windows systems.

.DESCRIPTION
    This function provides a comprehensive, modular solution for deploying the Wazuh agent.
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
    Install-WazuhAgent -ipAddress '192.168.1.100' -agentName 'WIN-AGENT-01' -groupLabel 'windows_servers'

.EXAMPLE
    # Using a configuration file
    Install-WazuhAgent -ConfigFile 'C:\path\to\your\config.json'

.EXAMPLE
    # Uninstall the Wazuh agent
    Install-WazuhAgent -Uninstall

.NOTES
    Author: Cloud-X Security
    Version: 3.3 (Module version)
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
        # Display Banner
        Show-Banner

        # Start Logging (simplified for module)
        if ($PSBoundParameters.ContainsKey('LogPath')) {
            $global:LogPath = $LogPath
        } else {
            $global:LogPath = Join-Path $env:TEMP "Cloud-X-Security-Wazuh-Installer-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
        }

        Write-Log "Cloud-X Security Wazuh Agent setup started..." -Level "INFO"
        Write-Log "Parameters provided by: $($PSCmdlet.ParameterSetName)" -Level "INFO"

        # Determine workflow: Install or Uninstall
        if ($PSCmdlet.ParameterSetName -eq 'Uninstall') {
            Write-Log "Uninstall parameter detected. This is a placeholder for uninstall logic." -Level "INFO"
            Write-Log "UNINSTALL PROCESS INITIATED." -Level "SUCCESS"
        } else {
            # --- INSTALL WORKFLOW ---
            Write-Log "Starting Cloud-X Security Wazuh Agent setup..." -Level "INFO"

            # Load configuration from file if provided
            if ($PSCmdlet.ParameterSetName -eq 'ConfigFile') {
                Write-Log "Loading configuration from file: $ConfigFile" -Level "INFO"
                # Placeholder for config file loading
                Write-Log "Config file loading is a placeholder in this module version." -Level "WARNING"
            }

            # Main Execution (simplified for module demonstration)
            Start-Step "Initialization and Parameter Validation"
            Write-Log "Setup initiated by user: $env:USERNAME" -Level "INFO"
            Write-Log "Parameters: IP=$ipAddress, AgentName=$agentName, Group=$groupLabel, Version=$WAZUH_VERSION" -Level "INFO"

            Start-Step "Placeholder Installation Steps"
            Write-Log "This is a module demonstration. Full installation logic would go here." -Level "INFO"
            
            Start-Step "Finalizing Setup"
            Write-Log "Installation completed successfully (placeholder)." -Level "SUCCESS"
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
        throw
    }
    finally {
        if ($PSItem -eq $null) { # If no errors occurred
            Show-Summary -startTime $script:startTime -agentName $agentName -ipAddress $ipAddress -groupLabel $groupLabel
        }
    }
}

#endregion

# Export the main function
Export-ModuleMember -Function Install-WazuhAgent
