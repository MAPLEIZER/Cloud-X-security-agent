#region Uninstall-Display

# Enhanced logging function
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS", "PROGRESS", "CLEANUP")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "INFO"     { Write-Host $logMessage -ForegroundColor Cyan }
        "WARN"     { Write-Host $logMessage -ForegroundColor Yellow }
        "ERROR"    { Write-Host $logMessage -ForegroundColor Red }
        "SUCCESS"  { Write-Host $logMessage -ForegroundColor Green }
        "PROGRESS" { Write-Host $logMessage -ForegroundColor Magenta }
        "CLEANUP"  { Write-Host $logMessage -ForegroundColor DarkYellow }
    }
}

# MAPLEX ASCII Banner for Uninstaller
function Show-UninstallBanner {
    Write-Host ""
    Write-Host "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" -ForegroundColor Red
    Write-Host "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" -ForegroundColor Red
    Write-Host "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" -ForegroundColor Red
    Write-Host "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" -ForegroundColor Red
    Write-Host ""
    Write-Host "                    MAPLEX WAZUH AGENT COMPLETE UNINSTALLER                   " -ForegroundColor White -BackgroundColor DarkRed
    Write-Host "                            Version 1.0 - MAPLEIZER                          " -ForegroundColor White -BackgroundColor DarkRed
    Write-Host "                              2025-08-18 19:01:33 UTC                        " -ForegroundColor Yellow -BackgroundColor DarkRed
    Write-Host ""
}

# Show final summary
function Show-UninstallSummary {
    $duration = (Get-Date) - $script:startTime
    
    Write-Host ""
    Write-Host "===============================================================================" -ForegroundColor Red
    Write-Host "                         MAPLEX UNINSTALL COMPLETED                          " -ForegroundColor Red
    Write-Host "===============================================================================" -ForegroundColor Red
    Write-Host ""
    
    Write-Log "=== UNINSTALL SUMMARY ===" -Level "SUCCESS"
    Write-Log "User: $env:USERNAME on $env:COMPUTERNAME" -Level "INFO"
    Write-Log "Items Removed: $($script:removedItems.Count)" -Level "INFO"
    Write-Log "Errors Encountered: $($script:errors.Count)" -Level "INFO"
    Write-Log "Duration: $([math]::Round($duration.TotalMinutes, 2)) minutes" -Level "INFO"
    Write-Log "Completed at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')" -Level "SUCCESS"
    
    if ($script:removedItems.Count -gt 0) {
        Write-Host ""
        Write-Host "Removed Items:" -ForegroundColor Green
        foreach ($item in $script:removedItems) {
            Write-Host "  ✓ $item" -ForegroundColor White
        }
    }
    
    if ($script:errors.Count -gt 0) {
        Write-Host ""
        Write-Host "Errors Encountered:" -ForegroundColor Yellow
        foreach ($error in $script:errors) {
            Write-Host "  ✗ $error" -ForegroundColor Red
        }
    }
    
    Write-Host ""
    Write-Host "System is now clean and ready for fresh Wazuh installation if needed." -ForegroundColor Cyan
    Write-Host ""
}

Export-ModuleMember -Function Write-Log, Show-UninstallBanner, Show-UninstallSummary

#endregion
