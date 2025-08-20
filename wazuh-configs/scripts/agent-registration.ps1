# Cloud-X Security - Wazuh Agent Registration Helper
# Automates agent registration with the Wazuh manager
# Copyright (C) 2023, Cloud-X Security

param(
    [string]$WazuhManager = "192.168.100.37",
    [string]$AgentName = $env:COMPUTERNAME,
    [string]$WazuhPath = "C:\Program Files (x86)\ossec-agent"
)

Write-Host "=== Cloud-X Security Agent Registration ===" -ForegroundColor Cyan
Write-Host "Manager: $WazuhManager" -ForegroundColor Green
Write-Host "Agent Name: $AgentName" -ForegroundColor Green

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run as Administrator"
    exit 1
}

# Verify Wazuh agent is installed
if (-not (Test-Path $WazuhPath)) {
    Write-Error "Wazuh agent not found at $WazuhPath"
    exit 1
}

Write-Host "[1/3] Configuring agent connection..." -ForegroundColor Yellow

# Update ossec.conf with manager address
$ossecConf = Join-Path $WazuhPath "ossec.conf"

if (Test-Path $ossecConf) {
    # Backup original config
    Copy-Item $ossecConf "$ossecConf.backup" -Force
    
    # Read and update config
    [xml]$config = Get-Content $ossecConf
    
    # Update server address
    if ($config.ossec_config.client.server) {
        $config.ossec_config.client.server.address = $WazuhManager
        Write-Host "  ✓ Manager address configured" -ForegroundColor Green
    }
    
    # Save updated config
    $config.Save($ossecConf)
} else {
    Write-Error "ossec.conf not found"
    exit 1
}

Write-Host "[2/3] Generating agent key..." -ForegroundColor Yellow

# Generate agent authentication key request
$keyRequest = @{
    "name" = $AgentName
    "ip" = "any"
    "groups" = @("default", "cloudx-security")
}

Write-Host "  Agent registration details:" -ForegroundColor Cyan
Write-Host "    Name: $AgentName" -ForegroundColor Gray
Write-Host "    Manager: $WazuhManager" -ForegroundColor Gray
Write-Host "    Groups: default, cloudx-security" -ForegroundColor Gray

Write-Host "[3/3] Registration instructions..." -ForegroundColor Yellow

Write-Host ""
Write-Host "Manual registration required on Wazuh Manager ($WazuhManager):" -ForegroundColor Yellow
Write-Host ""
Write-Host "1. SSH to your Wazuh manager:" -ForegroundColor White
Write-Host "   ssh user@$WazuhManager" -ForegroundColor Gray
Write-Host ""
Write-Host "2. Add the agent:" -ForegroundColor White
Write-Host "   sudo /var/ossec/bin/manage_agents" -ForegroundColor Gray
Write-Host "   Select 'A' to add agent" -ForegroundColor Gray
Write-Host "   Agent name: $AgentName" -ForegroundColor Gray
Write-Host "   Agent IP: any" -ForegroundColor Gray
Write-Host ""
Write-Host "3. Extract the agent key:" -ForegroundColor White
Write-Host "   Select 'E' to extract key for agent ID" -ForegroundColor Gray
Write-Host ""
Write-Host "4. Import key on this agent:" -ForegroundColor White
Write-Host "   manage_agents.exe" -ForegroundColor Gray
Write-Host "   Select 'I' and paste the key from step 3" -ForegroundColor Gray
Write-Host ""
Write-Host "5. Start the agent service:" -ForegroundColor White
Write-Host "   Restart-Service WazuhSvc" -ForegroundColor Gray
Write-Host ""
Write-Host "Alternative: Use Wazuh API for automated registration" -ForegroundColor Cyan
Write-Host "  curl -k -X POST 'https://$WazuhManager:55000/agents' \\" -ForegroundColor Gray
Write-Host "       -H 'Authorization: Bearer <API_TOKEN>' \\" -ForegroundColor Gray
Write-Host "       -H 'Content-Type: application/json' \\" -ForegroundColor Gray
Write-Host "       -d '{\"name\":\"$AgentName\"}'" -ForegroundColor Gray
Write-Host ""
