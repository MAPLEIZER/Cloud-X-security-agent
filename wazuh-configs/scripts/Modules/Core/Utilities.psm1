#region Utilities

function Test-Administrator {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-SystemCompatibility {
    Write-Log "Checking system compatibility..." -Level "INFO"
    
    # Check available disk space (require at least 500MB)
    try {
        $freeSpace = (Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'").FreeSpace / 1GB
        if ($freeSpace -lt 0.5) {
            throw "Insufficient disk space. At least 500MB required, found $([math]::Round($freeSpace, 2))GB"
        }
        Write-Log "System compatibility check passed" -Level "SUCCESS"
    }
    catch {
        Write-Log "System compatibility check failed: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

function Test-MSIAvailability {
    Write-Log "Checking Windows Installer availability..." -Level "INFO"
    
    $maxWaitTime = 180  # 3 minutes
    $checkInterval = 10  # 10 seconds
    $elapsed = 0
    
    while ($elapsed -lt $maxWaitTime) {
        $msiProcesses = Get-Process -Name "msiexec" -ErrorAction SilentlyContinue
        
        if (-not $msiProcesses) {
            Write-Log "Windows Installer is available" -Level "SUCCESS"
            return $true
        }
        
        Write-Log "Windows Installer busy. Waiting $checkInterval seconds... ($elapsed/$maxWaitTime seconds elapsed)" -Level "WARN"
        Start-Sleep -Seconds $checkInterval
        $elapsed += $checkInterval
    }
    
    Write-Log "Timeout waiting for Windows Installer. Restarting MSI service..." -Level "WARN"
    Restart-MSIService
    
    return $true
}

function Restart-MSIService {
    Write-Log "Restarting Windows Installer service to free up resources..." -Level "INFO"
    
    try {
        # Kill any hanging msiexec processes
        $msiProcesses = Get-Process -Name "msiexec" -ErrorAction SilentlyContinue
        if ($msiProcesses) {
            Write-Log "Terminating $($msiProcesses.Count) msiexec process(es)..." -Level "INFO"
            $msiProcesses | Stop-Process -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 5
        }
        
        # Stop and restart the Windows Installer service
        Write-Log "Stopping Windows Installer service..." -Level "INFO"
        Stop-Service -Name "msiserver" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5
        
        Write-Log "Starting Windows Installer service..." -Level "INFO"
        Start-Service -Name "msiserver" -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 10
        
        # Verify service is running
        $service = Get-Service -Name "msiserver" -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq 'Running') {
            Write-Log "Windows Installer service restarted successfully" -Level "SUCCESS"
        } else {
            Write-Log "Warning: Windows Installer service may not be running properly" -Level "WARN"
        }
    }
    catch {
        Write-Log "Error restarting Windows Installer service: $($_.Exception.Message)" -Level "WARN"
    }
}

function Invoke-SecureDownload {
    param(
        [string]$Url,
        [string]$OutputPath,
        [string]$Description = "file"
    )
    
    Write-Log "Starting download of $Description" -Level "DOWNLOAD"
    Write-Log "Source: $Url" -Level "DOWNLOAD"
    Write-Log "Destination: $OutputPath" -Level "DOWNLOAD"
    
    try {
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($Url, $OutputPath)
        
        $fileSizeMB = [math]::Round((Get-Item $OutputPath).Length / 1MB, 2)
        Write-Log "Download completed successfully! File size: $fileSizeMB MB" -Level "SUCCESS"
        
    }
    catch {
        Write-Log "Download failed: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

function Test-MSIAvailability {
    param(
        [int]$MaxRetries = 5,
        [int]$InitialDelay = 5
    )

    Write-Log "Checking if Windows Installer service is available..." -Level "INFO"
    for ($i = 1; $i -le $MaxRetries; $i++) {
        try {
            $installer = New-Object -ComObject WindowsInstaller.Installer
            if ($installer) {
                Write-Log "Windows Installer service is available." -Level "SUCCESS"
                return
            }
        }
        catch {
            $delay = $InitialDelay * $i
            Write-Log "Windows Installer not ready. Retrying in $delay seconds... (Attempt $i of $MaxRetries)" -Level "WARNING"
            Start-Sleep -Seconds $delay
        }
    }
    throw "Windows Installer service is not available after $MaxRetries retries."
}

function Get-ConfigFromFile {
    param(
        [string]$FilePath
    )
    if (-not (Test-Path $FilePath)) {
        throw "Configuration file not found: $FilePath"
    }
    Get-Content $FilePath | ConvertFrom-Json
}

function Download-FileWithRetry {
    param(
        [string]$Url,
        [string]$OutputPath,
        [int]$MaxRetries = 3
    )

    for ($i = 1; $i -le $MaxRetries; $i++) {
        try {
            Invoke-WebRequest -Uri $Url -OutFile $OutputPath -UseBasicParsing
            Write-Log "Successfully downloaded $Url to $OutputPath" -Level "SUCCESS"
            return
        }
        catch {
            Write-Log "Failed to download $Url (Attempt $i of $MaxRetries): $($_.Exception.Message)" -Level "WARNING"
            if ($i -eq $MaxRetries) {
                throw "Failed to download file after $MaxRetries retries."
            }
            Start-Sleep -Seconds (5 * $i)
        }
    }
}

function Verify-FileHash {
    param(
        [string]$FilePath,
        [string]$ExpectedHash,
        [string]$HashAlgorithm = 'SHA256',
        [switch]$SkipHashCheck
    )

    if ($SkipHashCheck) {
        Write-Log "Skipping file hash verification for $FilePath." -Level "WARNING"
        return
    }

    Write-Log "Verifying hash for $FilePath..." -Level "INFO"
    $actualHash = (Get-FileHash -Path $FilePath -Algorithm $HashAlgorithm).Hash.ToLower()
    if ($actualHash -ne $ExpectedHash.ToLower()) {
        throw "Hash mismatch for $FilePath. Expected: $ExpectedHash, Actual: $actualHash"
    }
    Write-Log "File hash verified successfully." -Level "SUCCESS"
}

Export-ModuleMember -Function Test-Administrator, Test-SystemCompatibility, Test-MSIAvailability, Restart-MSIService, Invoke-SecureDownload, Get-ConfigFromFile, Download-FileWithRetry, Verify-FileHash

#endregion
