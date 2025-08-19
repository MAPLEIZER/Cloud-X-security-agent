#region WazuhOperations

function Uninstall-ExistingWazuhAgent {
    Start-Step "Uninstalling Existing Wazuh Agent (if any)"

    # Attempt to stop the service first to release file locks.
    Write-Log "Attempting to stop the Wazuh Agent service (WazuhSvc)..." -Level "INFO"
    $service = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne 'Stopped') {
        Stop-Service -Name "WazuhSvc" -Force -ErrorAction SilentlyContinue
        Write-Log "Waiting 5 seconds for processes to terminate..." -Level "INFO"
        Start-Sleep -Seconds 5
    }

    # Find the Wazuh Agent installation by checking the registry.
    Write-Log "Searching for Wazuh Agent in installed programs..." -Level "INFO"
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $wazuhApp = Get-ItemProperty -Path $uninstallPaths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "Wazuh Agent*" }

    if (-not $wazuhApp) {
        Write-Log "Wazuh Agent not found. No uninstall needed." -Level "SUCCESS"
        return
    }

    Write-Log "Found Wazuh Agent. Running the official uninstaller silently..." -Level "INFO"
    $uninstallCommand = $wazuhApp.UninstallString
    if ($uninstallCommand -like "MsiExec.exe*") {
        $productCode = $wazuhApp.PSChildName
        $command = "msiexec.exe"
        $arguments = "/x $productCode /q"
        Write-Log "Executing: $command $arguments" -Level "INFO"
        Start-Process -FilePath $command -ArgumentList $arguments -Wait -NoNewWindow
    } else {
        Write-Log "Executing non-MSI uninstaller: $uninstallCommand /S" -Level "INFO"
        Start-Process -FilePath $uninstallCommand -ArgumentList "/S" -Wait -NoNewWindow
    }
    
    Write-Log "Uninstaller process has finished." -Level "SUCCESS"

    # Final Cleanup
    $agentDir = "C:\Program Files (x86)\ossec-agent"
    if (Test-Path $agentDir) {
        Write-Log "Performing post-uninstall cleanup of the installation directory..." -Level "INFO"
        Remove-Item -Recurse -Force $agentDir -ErrorAction SilentlyContinue
        
        if (!(Test-Path $agentDir)) {
            Write-Log "Directory successfully removed." -Level "SUCCESS"
        } else {
            Write-Log "FAILED to remove directory: $agentDir. A process may still be locking it." -Level "ERROR"
        }
    } else {
        Write-Log "Wazuh Agent uninstall complete and directory is clean." -Level "SUCCESS"
    }
}

function Install-WazuhAgent {
    Start-Step "Installing Wazuh Agent"
    
    $installerUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$($using:WAZUH_VERSION).msi"
    $installerPath = Join-Path $env:TEMP "wazuh-agent-$($using:WAZUH_VERSION).msi"

    Download-FileWithRetry -Url $installerUrl -OutputPath $installerPath
    
    Write-Log "Starting Wazuh agent installation..." -Level "INFO"
    $proc = Start-Process msiexec.exe -ArgumentList "/i `"$installerPath`" /qn" -Wait -PassThru
    if ($proc.ExitCode -ne 0) {
        throw "MSI installation failed with exit code: $($proc.ExitCode)"
    }
    Write-Log "Wazuh agent installed successfully" -Level "SUCCESS"

    # Wait for config file to be created
    $configPath = if ([IntPtr]::Size -eq 8) { "${env:ProgramFiles(x86)}\ossec-agent\ossec.conf" } else { "$env:ProgramFiles\ossec-agent\ossec.conf" }
    $timeout = 60 # seconds
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
    
    $installerPath = Join-Path $env:TEMP "wazuh-agent-$WAZUH_VERSION.msi"
    if (Test-Path $installerPath) {
        Remove-Item $installerPath -Force
    }

    while (Test-Path $configPath) {
        Write-Log "Existing configuration detected. Removing..." -Level "WARN"
        Remove-Item $configPath -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }

    $maxRetries = 3
    $retryCount = 0

    do {
        try {
            Write-Log "Download attempt $($retryCount + 1) of $($maxRetries + 1)" -Level "INFO"
            
            Invoke-SecureDownload -Url $WAZUH_URL -OutputPath $installerPath -Description "Wazuh Agent installer"

            Write-Log "Starting Wazuh agent installation..." -Level "INFO"
            $logFile = Join-Path $env:TEMP "wazuh-install-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
            $installArgs = "/i `"$installerPath`" /qn /l*v `"$logFile`" WAZUH_MANAGER=$managerIP WAZUH_REGISTRATION_SERVER=$managerIP WAZUH_AGENT_GROUP=$groupLabel WAZUH_AGENT_NAME=$agentName"
            Write-Log "MSI command: msiexec.exe $installArgs" -Level "INFO"
            Write-Log "MSI log file: $logFile" -Level "INFO"
            $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $installArgs -Wait -PassThru

            if ($process.ExitCode -eq 0) {
                Write-Log "Wazuh agent installed successfully" -Level "SUCCESS"
                break
            } else {
                Write-Log "Reading MSI log file for error details..." -Level "INFO"
                if (Test-Path $logFile) {
                    try {
                        $logContent = Get-Content $logFile -Tail 20 -ErrorAction SilentlyContinue
                        if ($logContent) {
                            Write-Log "Last 20 lines of MSI log:" -Level "ERROR"
                            $logContent | ForEach-Object { Write-Log $_ -Level "ERROR" }
                        }
                    }
                    catch {
                        Write-Log "Could not read MSI log file" -Level "WARN"
                    }
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
                Write-Log "Installation failed after $($maxRetries + 1) attempts: $($_.Exception.Message)" -Level "ERROR"
                throw
            }
        }
    } while ($retryCount -le $maxRetries)

    # Cleanup
    Remove-Item $installerPath -Force -ErrorAction SilentlyContinue
}

function Install-WazuhAgentMSI {
    param(
        [string]$ipAddress,
        [string]$agentName,
        [string]$groupLabel
    )
    
    # Determine the correct IP based on group BEFORE installation
    $managerIP = if ($groupLabel -eq "Personal") {
        "192.168.100.37"  # Internal network IP for Personal group
    } else {
        $ipAddress  # Use provided public IP for other groups
    }
    
    Write-Log "Group: $groupLabel - Using Manager IP: $managerIP" -Level "INFO"
    
    Start-Step "Installing Wazuh Agent"
    
    $ossecAgentPath = if ([IntPtr]::Size -eq 8) { "${env:ProgramFiles(x86)}\ossec-agent" } else { "$env:ProgramFiles\ossec-agent" }
    $configPath = Join-Path $ossecAgentPath "ossec.conf"
    
    if (Test-Path $configPath) {
        Write-Log "Existing configuration detected. Removing..." -Level "WARN"
        Remove-Item $configPath -Force -ErrorAction SilentlyContinue
    }

    $installerPath = Join-Path $env:TEMP "wazuh-agent-$WAZUH_VERSION.msi"
    if (Test-Path $installerPath) {
        Remove-Item $installerPath -Force
    }

    $maxRetries = 3
    $retryCount = 0

    do {
        try {
            Write-Log "Download attempt $($retryCount + 1) of $($maxRetries + 1)" -Level "INFO"
            
            Invoke-SecureDownload -Url $WAZUH_URL -OutputPath $installerPath -Description "Wazuh Agent installer"

            Write-Log "Starting Wazuh agent installation..." -Level "INFO"
            $logFile = Join-Path $env:TEMP "wazuh-install-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
            $installArgs = "/i `"$installerPath`" /qn /l*v `"$logFile`" WAZUH_MANAGER=$managerIP WAZUH_REGISTRATION_SERVER=$managerIP WAZUH_AGENT_GROUP=$groupLabel WAZUH_AGENT_NAME=$agentName"
            Write-Log "MSI command: msiexec.exe $installArgs" -Level "INFO"
            Write-Log "MSI log file: $logFile" -Level "INFO"
            $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $installArgs -Wait -PassThru

            if ($process.ExitCode -eq 0) {
                Write-Log "Wazuh agent installed successfully" -Level "SUCCESS"
                break
            } else {
                Write-Log "Reading MSI log file for error details..." -Level "INFO"
                if (Test-Path $logFile) {
                    $logContent = Get-Content $logFile -Tail 20
                    Write-Log "Last 20 lines of MSI log:" -Level "INFO"
                    $logContent | ForEach-Object { Write-Log $_ -Level "INFO" }
                }
                throw "MSI installation failed with exit code: $($process.ExitCode)"
            }
        }
        catch {
            $retryCount++
            if ($retryCount -le $maxRetries) {
                Write-Log "Installation attempt failed: $($_.Exception.Message). Retrying in 10 seconds..." -Level "WARN"
                Start-Sleep -Seconds 10
            } else {
                Write-Log "Installation failed after $($maxRetries + 1) attempts: $($_.Exception.Message)" -Level "ERROR"
                throw
            }
        }
    } while ($retryCount -le $maxRetries)

    # Cleanup
    Remove-Item $installerPath -Force -ErrorAction SilentlyContinue
}

function Set-WazuhAgentConfiguration {
    param(
        [string]$ipAddress,
        [string]$agentName,
        [string]$groupLabel
    )
    
    Start-Step "Configuring Wazuh Agent"
    
    # Determine the correct IP based on group
    $configIP = if ($groupLabel -eq "Personal") {
        "192.168.100.37"  # Internal network IP for Personal group
    } else {
        $ipAddress  # Use provided public IP for other groups
    }
    
    Write-Log "Group: $groupLabel - Using IP: $configIP" -Level "INFO"
    
    $ossecAgentPath = if ([IntPtr]::Size -eq 8) { "${env:ProgramFiles(x86)}\ossec-agent" } else { "$env:ProgramFiles\ossec-agent" }
    $configPath = Join-Path $ossecAgentPath "ossec.conf"

    try {
        $config = Get-Content -Path $configPath -Raw
        $config = $config -replace '<address>0.0.0.0</address>', "<address>$configIP</address>"
        Write-Log "Updated manager IP address to: $configIP" -Level "SUCCESS"

        $enrollmentSection = @"
<enrollment>
    <enabled>yes</enabled>
    <manager_address>$configIP</manager_address>
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
        
        if ($groupLabel -eq "Personal") {
            Write-Log "Personal group detected - configured for internal network (192.168.100.37)" -Level "INFO"
        }
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

Export-ModuleMember -Function Uninstall-ExistingWazuhAgent, Install-WazuhAgentMSI, Set-WazuhAgentConfiguration, Start-WazuhService

#endregion
