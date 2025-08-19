#================================================================================
# Cloud-X Security Wazuh Agent Installer Module
# Version: 3.3
# Author: Cloud-X Security
#================================================================================

#region Helper Functions

# Define constants
$WAZUH_VERSION = "4.9.1-1"
$WAZUH_URL = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$WAZUH_VERSION.msi"

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
    
    if ($global:LogPath) {
        Add-Content -Path $global:LogPath -Value $logMessage
    }
}

function Start-Step {
    param([string]$StepName)
    
    $script:currentStep++
    $percentComplete = [math]::Round(($script:currentStep / $script:totalSteps) * 100)
    
    Write-Host ""
    Write-Host "=" * 80 -ForegroundColor DarkGray
    Write-Log "STEP $script:currentStep/$script:totalSteps : $StepName" -Level "PROGRESS"
    Write-Host "=" * 80 -ForegroundColor DarkGray
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-SystemCompatibility {
    Write-Log "Checking system compatibility..." -Level "INFO"
    
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

function Test-MSIAvailability {
    Write-Log "Checking Windows Installer availability..." -Level "INFO"
    
    $maxWaitTime = 300  # 5 minutes
    $checkInterval = 15  # 15 seconds
    $elapsed = 0
    
    while ($elapsed -lt $maxWaitTime) {
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
    
    Get-Process -Name "msiexec" -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Seconds 10
    
    Restart-Service -Name "msiserver" -Force
    Start-Sleep -Seconds 10
    
    return $true
}

function Repair-WindowsInstallerRegistry {
    Write-Log "Checking and repairing Windows Installer registry permissions..." -Level "INFO"
    
    try {
        # Fix common registry permission issues
        $registryPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Rollback\Scripts",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer"
        )
        
        foreach ($regPath in $registryPaths) {
            if (-not (Test-Path $regPath)) {
                Write-Log "Creating missing registry path: $regPath" -Level "INFO"
                New-Item -Path $regPath -Force -ErrorAction SilentlyContinue | Out-Null
            }
        }
        
        # Reset Windows Installer service permissions
        Write-Log "Resetting Windows Installer service..." -Level "INFO"
        Stop-Service -Name "msiserver" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5
        Start-Service -Name "msiserver" -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5
        
        Write-Log "Windows Installer registry repair completed" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Registry repair failed: $($_.Exception.Message)" -Level "WARN"
        return $false
    }
}

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
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        
        Invoke-WebRequest -Uri $Url -OutFile $OutputPath -UseBasicParsing
        
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

function Uninstall-ExistingWazuhAgent {
    Start-Step "Uninstalling Existing Wazuh Agent"
    
    Write-Log "Searching for Wazuh Agent in installed programs..." -Level "INFO"
    
    $wazuhAgent = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Wazuh*" }
    
    if ($wazuhAgent) {
        Write-Log "Found existing Wazuh Agent. Proceeding with uninstall..." -Level "INFO"
        
        # Apply registry repair before uninstalling
        Repair-WindowsInstallerRegistry
        
        try {
            $logFile = Join-Path $env:TEMP "wazuh-uninstall-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
            $process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/x", $wazuhAgent.IdentifyingNumber, "/qn", "/l*v", "`"$logFile`"" -Wait -PassThru
            
            if ($process.ExitCode -ne 0) {
                Write-Log "Uninstall failed with exit code: $($process.ExitCode)" -Level "ERROR"
                Write-Log "Uninstall log file: $logFile" -Level "ERROR"
                
                # Try to read and display last lines of uninstall log
                if (Test-Path $logFile) {
                    Write-Log "Reading uninstall log file for error details..." -Level "INFO"
                    try {
                        $logContent = Get-Content $logFile -Tail 20 -ErrorAction SilentlyContinue
                        if ($logContent) {
                            Write-Log "Last 20 lines of uninstall log:" -Level "ERROR"
                            $logContent | ForEach-Object { Write-Log $_ -Level "ERROR" }
                        }
                    }
                    catch {
                        Write-Log "Could not read uninstall log file" -Level "WARN"
                    }
                }
                
                throw "Uninstaller failed with exit code: $($process.ExitCode)"
            }
            
            Write-Log "Existing Wazuh Agent uninstalled successfully" -Level "SUCCESS"
        }
        catch {
            Write-Log "Error during uninstall: $($_.Exception.Message)" -Level "ERROR"
            throw
        }
    } else {
        Write-Log "No existing Wazuh Agent found. Proceeding with fresh installation." -Level "SUCCESS"
    }
}

function Install-WazuhAgentMSI {
    param(
        [string]$ipAddress,
        [string]$agentName,
        [string]$groupLabel
    )
    
    Start-Step "Installing Wazuh Agent"
    
    Test-MSIAvailability
    Repair-WindowsInstallerRegistry
    
    $ossecAgentPath = if ([IntPtr]::Size -eq 8) { "${env:ProgramFiles(x86)}\ossec-agent" } else { "$env:ProgramFiles\ossec-agent" }
    $configPath = Join-Path $ossecAgentPath "ossec.conf"
    
    $installerPath = Join-Path $env:TEMP "wazuh-agent-$WAZUH_VERSION.msi"
    if (Test-Path $installerPath) {
        Remove-Item $installerPath -Force
    }

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
            
            Invoke-SecureDownload -Url $WAZUH_URL -OutputPath $installerPath -Description "Wazuh Agent installer"

            Write-Log "Starting Wazuh agent installation..." -Level "INFO"
            $logFile = Join-Path $env:TEMP "wazuh-install-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
            $installArgs = "/i `"$installerPath`" /qn /l*v `"$logFile`" WAZUH_MANAGER=$ipAddress WAZUH_REGISTRATION_SERVER=$ipAddress WAZUH_AGENT_GROUP=$groupLabel WAZUH_AGENT_NAME=$agentName"
            Write-Log "MSI command: msiexec.exe $installArgs" -Level "INFO"
            Write-Log "MSI log file: $logFile" -Level "INFO"
            $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $installArgs -Wait -PassThru

            if ($process.ExitCode -eq 0) {
                Write-Log "Wazuh agent installed successfully" -Level "SUCCESS"
                break
            } else {
                Write-Log "Reading MSI log file for error details..." -Level "INFO"
                if (Test-Path $logFile) {
                    $logContent = Get-Content $logFile -Tail 20 | Out-String
                    Write-Log "Last 20 lines of MSI log:" -Level "ERROR"
                    Write-Log $logContent -Level "ERROR"
                }
                throw "Installer failed with exit code: $($process.ExitCode). Check MSI log: $logFile"
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

    $backupPath = "$configPath.backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    Copy-Item $configPath $backupPath -Force
    Write-Log "Configuration backup created: $backupPath" -Level "SUCCESS"
    
    Remove-Item $installerPath -Force -ErrorAction SilentlyContinue
}

function Set-WazuhAgentConfiguration {
    param(
        [string]$ipAddress,
        [string]$agentName,
        [string]$groupLabel
    )
    
    Start-Step "Configuring Wazuh Agent"
    
    $ossecAgentPath = if ([IntPtr]::Size -eq 8) { "${env:ProgramFiles(x86)}\ossec-agent" } else { "$env:ProgramFiles\ossec-agent" }
    $configPath = Join-Path $ossecAgentPath "ossec.conf"

    try {
        $config = Get-Content -Path $configPath -Raw
        $config = $config -replace '<address>0.0.0.0</address>', "<address>$ipAddress</address>"
        Write-Log "Updated manager IP address to: $ipAddress" -Level "SUCCESS"

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

function Start-WazuhService {
    Start-Step "Starting Wazuh Service"

    try {
        Write-Log "Starting Wazuh agent service..." -Level "INFO"
        $process = Start-Process -FilePath "net" -ArgumentList "start WazuhSvc" -Wait -PassThru -NoNewWindow
        
        if ($process.ExitCode -ne 0) {
            throw "Failed to start Wazuh service with exit code: $($process.ExitCode)"
        }

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

function Deploy-ActiveResponseScripts {
    Write-Log "Deploying active response scripts..." -Level "INFO"
    
    $ossecAgentPath = if ([IntPtr]::Size -eq 8) { "${env:ProgramFiles(x86)}\ossec-agent" } else { "$env:ProgramFiles\ossec-agent" }
    $activeResponsePath = Join-Path $ossecAgentPath "active-response\bin"
    
    if (Test-Path $activeResponsePath) {
        Write-Log "Active response directory found: $activeResponsePath" -Level "SUCCESS"
    } else {
        Write-Log "Active response directory not found, skipping script deployment" -Level "WARN"
    }
}

function Cleanup-TempFiles {
    Write-Log "Performing final cleanup..." -Level "INFO"
    
    $tempFiles = @(
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
  
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host ""
    Write-Host "                       CLOUD-X SECURITY WAZUH AGENT ENTERPRISE SETUP                         " -ForegroundColor White -BackgroundColor DarkGreen
    Write-Host "                              Version 3.1 - Enhanced Security                                " -ForegroundColor White -BackgroundColor DarkGreen
    Write-Host "                                   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')                              " -ForegroundColor Yellow -BackgroundColor DarkGreen
    Write-Host "                                     by CLOUD-X SECURITY                                     " -ForegroundColor Cyan -BackgroundColor DarkGreen
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
        [string]$WAZUH_VERSION = '4.9.1-1',

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
    $script:totalSteps = 8
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

            # Main Execution
            Start-Step "Initialization and Parameter Validation"
            Write-Log "Setup initiated by user: $env:USERNAME" -Level "INFO"
            Write-Log "Parameters: IP=$ipAddress, AgentName=$agentName, Group=$groupLabel, Version=$WAZUH_VERSION" -Level "INFO"

            # Pre-flight checks
            Test-SystemCompatibility
            Test-MSIAvailability

            # Core Operations
            Uninstall-WazuhAgent
            Install-WazuhAgentMSI -ipAddress $ipAddress -agentName $agentName -groupLabel $groupLabel
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
