#================================================================================
# Cloud-X Security Wazuh Agent Installer Module
# Version: 3.1
# Author: Cloud-X Security Team
# Description: Professional PowerShell module for automated Wazuh agent installation and configuration

# Import required modules
$ModulePath = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module "$ModulePath\Modules\Core\Logging.psm1" -Force
Import-Module "$ModulePath\Modules\Core\Utilities.psm1" -Force
Import-Module "$ModulePath\Modules\Installation\WazuhOperations.psm1" -Force
Import-Module "$ModulePath\Modules\Installation\PostInstall.psm1" -Force
Import-Module "$ModulePath\Modules\UI\Banner.psm1" -Force

# Constants
$WAZUH_VERSION = "4.9.1-1"

function Install-WazuhAgent {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ipAddress,
        
        [Parameter(Mandatory=$true)]
        [string]$agentName,
        
        [Parameter(Mandatory=$true)]
        [string]$groupLabel,
        
        [string]$ConfigFile = $null,
        [switch]$SKIP_HASH_CHECK,
        [switch]$KeepLogs,
        [string]$LogPath = $null
    )

    # Initialize logging and progress tracking
    $script:startTime = Get-Date
    $script:totalSteps = 8
    $script:currentStep = 0
    
    # Set up logging
    if ($LogPath) {
        $global:LogPath = $LogPath
    } else {
        $global:LogPath = Join-Path $env:TEMP "Cloud-X-Security-Wazuh-Installer-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
    }
    
    Start-Transcript -Path $global:LogPath -Append
    
    try {
        # Display banner
        Show-Banner
        
        Write-Log "Cloud-X Security Wazuh Agent setup started..." -Level "INFO"
        Write-Log "Parameters provided by: Manual" -Level "INFO"
        Write-Log "Starting Cloud-X Security Wazuh Agent setup..." -Level "INFO"

        # Load configuration from file if provided
        if ($ConfigFile -and (Test-Path $ConfigFile)) {
            Write-Log "Loading configuration from file: $ConfigFile" -Level "INFO"
            # Placeholder for config file loading
            Write-Log "Config file loading is a placeholder in this module version." -Level "WARNING"
        }

        # Main Execution
        Start-Step "Initialization and Parameter Validation"
        Write-Log "Setup initiated by user: $env:USERNAME" -Level "INFO"
        Write-Log "Parameters: IP=$ipAddress, AgentName=$agentName, Group=$groupLabel, Version=$WAZUH_VERSION" -Level "INFO"

        # Pre-flight checks
        Test-SystemCompatibility
        Test-MSIAvailability

        # Core Operations
        Uninstall-ExistingWazuhAgent
        Install-WazuhAgentMSI -ipAddress $ipAddress -agentName $agentName -groupLabel $groupLabel
        Set-WazuhAgentConfiguration -ipAddress $ipAddress -agentName $agentName -groupLabel $groupLabel
        Start-WazuhService

        # Post-Install
        Start-Step "Finalizing Setup"
        Deploy-ActiveResponseScripts
        Cleanup-TempFiles
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
        Stop-Transcript
    }
}

# Export the main function
Export-ModuleMember -Function Install-WazuhAgent
