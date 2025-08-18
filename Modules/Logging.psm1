#region Logging

function Initialize-Logging {
    $logDir = Join-Path $env:TEMP "NixGuard-Wazuh-Logs"
    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory | Out-Null
    }
    $global:LogPath = Join-Path $logDir "Wazuh-Agent-Setup-$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
    
    try {
        Start-Transcript -Path $global:LogPath -Append
        Write-Host "[TRANSCRIPT] Logging to: $($global:LogPath)" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Warning "Transcript logging failed to start: $($_.Exception.Message)"
        return $false
    }
}

function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [Parameter(Mandatory=$true)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS", "DEBUG")]
        [string]$Level
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $formattedMessage = "$timestamp [$Level] - $Message"

    $colorMap = @{
        INFO    = "White";
        WARNING = "Yellow";
        ERROR   = "Red";
        SUCCESS = "Green";
        DEBUG   = "Cyan"
    }

    Write-Host $formattedMessage -ForegroundColor $colorMap[$Level]
    Add-Content -Path $global:LogPath -Value $formattedMessage
}

function Start-Step {
    param (
        [string]$StepName
    )
    $script:currentStep++
    $header = "=== STEP $script:currentStep OF $script:totalSteps: $StepName ==="
    Write-Log $header -Level "INFO"
    Write-Host "`n" + ("=" * $header.Length) -ForegroundColor Cyan
    Write-Host $header -ForegroundColor Cyan
    Write-Host ("=" * $header.Length) -ForegroundColor Cyan
}

Export-ModuleMember -Function Initialize-Logging, Write-Log, Start-Step

#endregion
