# Cloud-X Security PowerShell Logging Enable Script
# Enables PowerShell Script Block Logging for better security monitoring

function Enable-PowerShellScriptBlockLogging {
    [CmdletBinding()]
    param(
        [switch]$Force
    )
    
    Write-Host "[INFO] Enabling PowerShell Script Block Logging..." -ForegroundColor Cyan
    
    try {
        # Check if running as administrator
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {
            Write-Warning "This script must be run as Administrator to modify registry settings."
            return
        }
        
        # Define registry paths
        $basePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        $baseUserPath = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        
        # Create registry keys if they don't exist
        if (!(Test-Path $basePath)) {
            New-Item -Path $basePath -Force | Out-Null
        }
        
        if (!(Test-Path $baseUserPath) -and $Force) {
            New-Item -Path $baseUserPath -Force | Out-Null
        }
        
        # Enable script block logging
        Set-ItemProperty -Path $basePath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
        
        if ($Force) {
            Set-ItemProperty -Path $baseUserPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
        }
        
        Write-Host "[SUCCESS] PowerShell Script Block Logging enabled successfully." -ForegroundColor Green
        Write-Host "[INFO] This will help detect malicious PowerShell activity." -ForegroundColor Cyan
        
    } catch {
        Write-Error "Failed to enable PowerShell Script Block Logging: $($_.Exception.Message)"
    }
}

# Main execution
Enable-PowerShellScriptBlockLogging
