#region Uninstall-Cleanup

# Remove registry entries
function Remove-WazuhRegistry {
    Write-Log "Cleaning Wazuh registry entries..." -Level "PROGRESS"
    
    $registryPaths = @(
        "HKLM:\SOFTWARE\WOW6432Node\Wazuh",
        "HKLM:\SOFTWARE\Wazuh",
        "HKLM:\SOFTWARE\WOW6432Node\ossec",
        "HKLM:\SOFTWARE\ossec",
        "HKLM:\SYSTEM\CurrentControlSet\Services\WazuhSvc",
        "HKLM:\SYSTEM\CurrentControlSet\Services\OssecSvc",
        "HKLM:\SYSTEM\CurrentControlSet\Services\Wazuh"
    )
    
    $removed = 0
    foreach ($regPath in $registryPaths) {
        if (Remove-ItemSafe -Path $regPath -Description "Registry key" -Recurse) {
            $removed++
        }
    }
    
    Write-Log "Registry cleanup completed ($removed entries processed)" -Level "SUCCESS"
}

# Remove installation directories
function Remove-WazuhDirectories {
    Write-Log "Removing Wazuh installation directories..." -Level "PROGRESS"
    
    $installPaths = @(
        "${env:ProgramFiles}\ossec-agent",
        "${env:ProgramFiles(x86)}\ossec-agent",
        "${env:ProgramFiles}\Wazuh Agent",
        "${env:ProgramFiles(x86)}\Wazuh Agent",
        "${env:ProgramData}\ossec",
        "${env:ProgramData}\Wazuh"
    )
    
    if (-not $KeepLogs) {
        $installPaths += @(
            "${env:ProgramData}\ossec-agent",
            "${env:ProgramData}\Wazuh Agent"
        )
    }
    
    $removed = 0
    foreach ($path in $installPaths) {
        if (Remove-ItemSafe -Path $path -Description "Installation directory" -Recurse) {
            $removed++
        }
    }
    
    if ($KeepLogs) {
        Write-Log "Log directories preserved as requested" -Level "INFO"
    }
    
    Write-Log "Directory cleanup completed ($removed directories processed)" -Level "SUCCESS"
}

# Remove Windows services
function Remove-WazuhServices {
    Write-Log "Removing Wazuh Windows services..." -Level "PROGRESS"
    
    $serviceNames = @("WazuhSvc", "OssecSvc", "Wazuh")
    $removed = 0
    
    foreach ($serviceName in $serviceNames) {
        try {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service) {
                Write-Log "Removing Windows service: $serviceName" -Level "CLEANUP"
                
                # Use sc.exe for reliable service deletion
                $result = & sc.exe delete $serviceName
                if ($LASTEXITCODE -eq 0) {
                    Write-Log "Successfully removed service: $serviceName" -Level "SUCCESS"
                    $removed++
                } else {
                    Write-Log "Failed to remove service $serviceName : $result" -Level "ERROR"
                }
            }
        }
        catch {
            Write-Log "Error removing service $serviceName : $($_.Exception.Message)" -Level "ERROR"
        }
    }
    
    Write-Log "Service removal completed ($removed services removed)" -Level "SUCCESS"
}

# Clean temporary files
function Remove-TempFiles {
    Write-Log "Cleaning temporary Wazuh files..." -Level "PROGRESS"
    
    $tempPatterns = @(
        "$env:TEMP\*wazuh*",
        "$env:TEMP\*ossec*",
        "$env:TEMP\agent-automatic-setup*",
        "$env:TEMP\nixguard-setup*"
    )
    
    $cleaned = 0
    foreach ($pattern in $tempPatterns) {
        try {
            $files = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                if (Remove-ItemSafe -Path $file.FullName -Description "Temporary file") {
                    $cleaned++
                }
            }
        }
        catch {
            Write-Log "Error cleaning temp pattern $pattern : $($_.Exception.Message)" -Level "WARN"
        }
    }
    
    Write-Log "Temporary file cleanup completed ($cleaned files removed)" -Level "SUCCESS"
}

Export-ModuleMember -Function Remove-WazuhRegistry, Remove-WazuhDirectories, Remove-WazuhServices, Remove-TempFiles

#endregion
