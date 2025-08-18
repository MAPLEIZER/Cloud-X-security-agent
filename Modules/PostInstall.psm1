#region PostInstall

function Cleanup-TempFiles {
    Write-Log "Performing final cleanup..." -Level "INFO"
    
    $tempFiles = @(
        (Join-Path $env:TEMP "agent-automatic-setup-enterprise.ps1"),
        (Join-Path $env:TEMP "wazuh-agent-$($using:WAZUH_VERSION).msi")
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
    $setupDuration = (Get-Date) - $script:startTime
    
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Green
    Write-Host "                    NIX GUARD ENTERPRISE SETUP COMPLETED                        " -ForegroundColor Green
    Write-Host "================================================================================" -ForegroundColor Green
    Write-Host ""
    
    Write-Log "=== SETUP SUMMARY ===" -Level "SUCCESS"
    Write-Log "User: $env:USERNAME on $env:COMPUTERNAME" -Level "INFO"
    Write-Log "Agent Name: $($using:agentName)" -Level "INFO"
    Write-Log "Manager IP: $($using:ipAddress)" -Level "INFO"
    Write-Log "Group: $($using:groupLabel)" -Level "INFO"
    Write-Log "Setup Duration: $([math]::Round($setupDuration.TotalMinutes, 2)) minutes" -Level "INFO"
    Write-Log "Setup completed at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')" -Level "SUCCESS"
    
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Cyan
    Write-Host "* The Wazuh agent is now running and should appear in your dashboard" -ForegroundColor White
    Write-Host "* Agent will automatically register with the manager" -ForegroundColor White
    Write-Host "* Check the Wazuh web interface for agent status" -ForegroundColor White
    Write-Host ""
}

Export-ModuleMember -Function Cleanup-TempFiles, Show-Summary

#endregion