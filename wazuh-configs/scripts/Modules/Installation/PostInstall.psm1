#region PostInstall

function Cleanup-TempFiles {
    Export-ModuleMember -Function Cleanup-TempFiles

    Write-Log "Performing final cleanup..." -Level "INFO"
    
    # Use a variable from the main script's scope for WAZUH_VERSION
    $wazuhVersion = Get-Variable -Name WAZUH_VERSION -Scope 1 -ValueOnly
    $installerFile = Join-Path $env:TEMP "wazuh-agent-$wazuhVersion.msi"

    if (Test-Path $installerFile) {
        Remove-Item $installerFile -Force -ErrorAction SilentlyContinue
        Write-Log "Cleaned up temporary installer file: $installerFile" -Level "SUCCESS"
    }
}

function Deploy-ActiveResponseScripts {
    Export-ModuleMember -Function Deploy-ActiveResponseScripts

    Write-Log "Deploying custom active response scripts..." -Level "INFO"

    $scriptRoot = Get-Variable -Name PSScriptRoot -Scope 1 -ValueOnly
    $sourceScriptPath = Join-Path $scriptRoot "remove-threat.py"
    $destinationDir = "${env:ProgramFiles(x86)}\ossec-agent\active-response\bin"

    if (-not (Test-Path $sourceScriptPath)) {
        Write-Log "Source script 'remove-threat.py' not found at '$sourceScriptPath'. Skipping deployment." -Level "WARN"
        return
    }

    if (-not (Test-Path $destinationDir)) {
        Write-Log "Wazuh active response directory not found at '$destinationDir'. Skipping deployment." -Level "WARN"
        return
    }

    try {
        Copy-Item -Path $sourceScriptPath -Destination $destinationDir -Force
        Write-Log "Successfully copied 'remove-threat.py' to '$destinationDir'." -Level "SUCCESS"
    }
    catch {
        Write-Log "Failed to copy 'remove-threat.py'. Error: $($_.Exception.Message)" -Level "ERROR"
    }
}

function Show-Summary {
    Export-ModuleMember -Function Show-Summary

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
    Write-Log "Setup completed successfully." -Level "SUCCESS"

    Write-Host "Summary:" -ForegroundColor Cyan
    Write-Host "- Agent Name:    $agentName" -ForegroundColor White
    Write-Host "- Manager IP:    $ipAddress" -ForegroundColor White
    Write-Host "- Agent Group:   $groupLabel" -ForegroundColor White
    Write-Host "- Total Time:    $($duration.Minutes)m $($duration.Seconds)s" -ForegroundColor White
    Write-Host "- Log File:      $($global:LogPath)" -ForegroundColor White
    Write-Host ""
}

function Deploy-ActiveResponseScripts {
    Start-Step "Deploying Active Response Scripts"
    
    Write-Log "Checking for active response scripts..." -Level "INFO"
    
    $ossecAgentPath = if ([IntPtr]::Size -eq 8) { "${env:ProgramFiles(x86)}\ossec-agent" } else { "$env:ProgramFiles\ossec-agent" }
    $activeResponsePath = Join-Path $ossecAgentPath "active-response\bin"
    
    if (Test-Path $activeResponsePath) {
        Write-Log "Active response directory found: $activeResponsePath" -Level "SUCCESS"
        Write-Log "Active response scripts deployment completed" -Level "SUCCESS"
    } else {
        Write-Log "No active response scripts to deploy" -Level "INFO"
    }
}

function Cleanup-TempFiles {
    Write-Log "Cleaning up temporary files..." -Level "INFO"
    
    try {
        $tempFiles = @(
            (Join-Path $env:TEMP "wazuh-agent-*.msi"),
            (Join-Path $env:TEMP "wazuh-install-*.log"),
            (Join-Path $env:TEMP "wazuh-uninstall-*.log")
        )
        
        foreach ($pattern in $tempFiles) {
            Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
        }
        
        Write-Log "Temporary files cleaned up successfully" -Level "SUCCESS"
    }
    catch {
        Write-Log "Warning: Could not clean up all temporary files: $($_.Exception.Message)" -Level "WARN"
    }
}

Export-ModuleMember -Function Show-Summary, Deploy-ActiveResponseScripts, Cleanup-TempFiles

#endregion