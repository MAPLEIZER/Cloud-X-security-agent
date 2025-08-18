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

Export-ModuleMember -Function Test-Administrator, Test-SystemCompatibility, Test-MSIAvailability, Get-ConfigFromFile, Download-FileWithRetry, Verify-FileHash

#endregion
