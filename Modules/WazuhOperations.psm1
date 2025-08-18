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

function Configure-WazuhAgent {
    Start-Step "Configuring Wazuh Agent"
    
    $ossecAgentPath = if ([IntPtr]::Size -eq 8) { "${env:ProgramFiles(x86)}\ossec-agent" } else { "$env:ProgramFiles\ossec-agent" }
    $configPath = Join-Path $ossecAgentPath "ossec.conf"

    try {
        # Update manager IP address
        $config = Get-Content -Path $configPath -Raw
        $config = $config -replace '<address>0.0.0.0</address>', "<address>$($using:ipAddress)</address>"
        Write-Log "Updated manager IP address to: $($using:ipAddress)" -Level "SUCCESS"

        # Add enrollment section
        $enrollmentSection = "<enrollment>`n    <enabled>yes</enabled>`n    <manager_address>$($using:ipAddress)</manager_address>`n    <agent_name>$($using:agentName)</agent_name>`n</enrollment>"

        if ($config -notmatch '<enrollment>') {
            $config = $config -replace '(?s)(<client>.*?)(</client>)', "`$1`n$enrollmentSection`n`$2"
            Write-Log "Added enrollment configuration" -Level "SUCCESS"
        }

        # Add group section
        if ($config -notmatch '<groups>') {
            $groupSection = "<groups>$($using:groupLabel)</groups>"
            $config = $config -replace '</enrollment>', "$groupSection`n</enrollment>"
            Write-Log "Added group configuration: $($using:groupLabel)" -Level "SUCCESS"
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

Export-ModuleMember -Function Uninstall-WazuhAgent, Install-WazuhAgent, Configure-WazuhAgent, Start-WazuhService

#endregion
