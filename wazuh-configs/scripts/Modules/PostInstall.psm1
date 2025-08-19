#region PostInstall

function Cleanup-TempFiles {
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

# Export module members
Export-ModuleMember -Function Cleanup-TempFiles, Deploy-ActiveResponseScripts, Show-Summary

#endregion