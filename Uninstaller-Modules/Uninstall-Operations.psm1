#region Uninstall-Operations

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

Export-ModuleMember -Function Stop-WazuhServices, Stop-WazuhProcesses, Uninstall-WazuhMSI

#endregion
