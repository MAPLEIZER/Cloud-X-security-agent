#region WazuhOperations

function Uninstall-WazuhAgent {
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
    Write-Log "Configuration backup created: $backupPath" -Level "SUCCESS"
    
    # Cleanup installer
    Remove-Item $installerPath -Force -ErrorAction SilentlyContinue
}

function Set-WazuhAgentConfiguration {
    param (
        [string]$ipAddress,
        [string]$agentName,
        [string]$groupLabel
    )

    Start-Step "Configuring Wazuh Agent from template"
    Write-Log "Configuring agent '$agentName' for manager '$ipAddress' in group '$groupLabel'" -Level "INFO"

    # The main script sets a script-level variable PSScriptRoot which we can access from the module.
    $scriptRoot = Get-Variable -Name PSScriptRoot -Scope 1 -ValueOnly
    $templatePath = Join-Path $scriptRoot "agent-template.conf"
    $agentConfPath = "${env:ProgramFiles(x86)}\ossec-agent\ossec.conf"

    if (-not (Test-Path $templatePath)) {
        throw "Agent configuration template not found at: $templatePath"
    }

    try {
        $templateContent = Get-Content -Path $templatePath -Raw
        $newConfig = $templateContent -replace 'MANAGER_IP_ADDRESS', $ipAddress `
                                    -replace 'AGENT_NAME', $agentName `
                                    -replace 'AGENT_GROUP', $groupLabel

        # Overwrite the existing ossec.conf with the new configuration
        Set-Content -Path $agentConfPath -Value $newConfig -Force

        Write-Log "Agent configuration file has been successfully generated from template." -Level "SUCCESS"
    }
    catch {
        throw "Failed to create agent configuration from template. Error: $($_.Exception.Message)"
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

Export-ModuleMember -Function Uninstall-WazuhAgent, Install-WazuhAgent, Set-WazuhAgentConfiguration, Start-WazuhService

#endregion
