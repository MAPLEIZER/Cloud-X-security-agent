#region Uninstall-Utilities

# Check for Administrator privileges
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Safe item removal with logging
function Remove-ItemSafe {
    param(
        [string]$Path,
        [string]$Description,
        [switch]$Recurse
    )
    
    try {
        if (Test-Path $Path) {
            Write-Log "Removing $Description : $Path" -Level "CLEANUP"
            
            if ($Recurse) {
                Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
            } else {
                Remove-Item -Path $Path -Force -ErrorAction Stop
            }
            
            $script:removedItems += "$Description : $Path"
            Write-Log "Successfully removed $Description" -Level "SUCCESS"
            return $true
        } else {
            Write-Log "$Description not found: $Path" -Level "INFO"
            return $true
        }
    }
    catch {
        $errorMsg = "Failed to remove $Description : $($_.Exception.Message)"
        Write-Log $errorMsg -Level "ERROR"
        $script:errors += $errorMsg
        return $false
    }
}

# Verify complete removal
function Test-WazuhRemoval {
    Write-Log "Verifying complete Wazuh removal..." -Level "PROGRESS"
    
    $remainingItems = @()
    
    # Check services
    $services = Get-Service -Name "*wazuh*", "*ossec*" -ErrorAction SilentlyContinue
    if ($services) {
        $remainingItems += "Services: $($services.Name -join ', ')"
    }
    
    # Check processes
    $processes = Get-Process -Name "*wazuh*", "*ossec*" -ErrorAction SilentlyContinue
    if ($processes) {
        $remainingItems += "Processes: $($processes.Name -join ', ')"
    }
    
    # Check main installation directories
    $dirs = @("${env:ProgramFiles}\ossec-agent", "${env:ProgramFiles(x86)}\ossec-agent")
    foreach ($dir in $dirs) {
        if (Test-Path $dir) {
            $remainingItems += "Directory: $dir"
        }
    }
    
    if ($remainingItems.Count -eq 0) {
        Write-Log "Verification PASSED: Wazuh completely removed from system" -Level "SUCCESS"
        return $true
    } else {
        Write-Log "Verification WARNING: Some items may remain:" -Level "WARN"
        foreach ($item in $remainingItems) {
            Write-Log "  - $item" -Level "WARN"
        }
        return $false
    }
}

Export-ModuleMember -Function Test-Administrator, Remove-ItemSafe, Test-WazuhRemoval

#endregion
