

# Cloud-X Security Wazuh Agent Installer

Enterprise-grade Wazuh agent setup script with enhanced security, auditing, and configuration management features.

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![Windows](https://img.shields.io/badge/Windows-10%2B-green.svg)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-3.2-orange.svg)](CHANGELOG.md)

## 📋 Table of Contents

- [Features](#-features)
- [Prerequisites](#-prerequisites)
- [How to Run](#-how-to-run)
- [Configuration](#-configuration)
- [Uninstaller](#-uninstaller)
- [Troubleshooting](#-troubleshooting)
- [Repository Structure](#-repository-structure)

## 🚀 Features

### 🔒 **Secure by Design**
- **SHA256 Hash Verification** - Verifies the integrity of the downloaded Wazuh agent installer.
- **HTTPS Enforcement** - Ensures secure communications by using TLS 1.2 for all downloads.
- **Administrator Enforcement** - Scripts require elevated privileges to run, ensuring system-level changes are authorized.
- **Audit Trail Generation** - Complete PowerShell transcript logging captures all actions for security and troubleshooting.

### ⚙️ **Flexible and Modular**
- **JSON Configuration** - Use external `.json` files for consistent, repeatable, and streamlined deployments.
- **Parameter-driven** - All key settings can be passed as command-line arguments.
- **Modular Architecture** - Both the installer and uninstaller are broken into logical PowerShell modules for easy maintenance and extensibility.

### 📈 **Robust Functionality**
- **Pre-flight Checks** - Verifies system compatibility (e.g., disk space) before starting.
- **Automated Cleanup** - Removes downloaded setup files after a successful installation.
- **Color-Coded Logging** - Provides clear, real-time feedback on the script's progress.
- **Comprehensive Uninstaller** - A dedicated, modular script for removing all traces of the Wazuh agent.

### 🛡️ **Automated Threat Response**
- **Automatic Deployment** - The secure `remove-threat.py` active response script is automatically deployed to the agent during installation.
- **Enhanced Security** - The script includes critical safety features, such as a whitelist of safe directories for file removal and a `--dry-run` mode for safe testing.
- **Robust Error Handling** - Prevents crashes from malformed alerts and provides detailed logging.

## 🔧 Prerequisites

- **Operating System**: Windows 10 or Windows Server 2016+
- **PowerShell Version**: PowerShell 5.1 or higher
- **Permissions**: You must run scripts from an **elevated (Administrator)** PowerShell session.
- **Network**: Internet connectivity to download the Wazuh agent installer and connectivity to the Wazuh Manager IP.
- **Disk Space**: Minimum 500MB of free disk space.

## ⚡ Quick Start

Run the following command in an **elevated (Administrator)** PowerShell session to download and execute the installer. Replace the placeholder parameters with your specific configuration.

```powershell
# Download and execute the script in one line
$params = @{
    ipAddress  = '192.168.1.100'
    agentName  = 'WIN-AGENT-01'
    groupLabel = 'windows_servers'
}

iwr https://raw.githubusercontent.com/MAPLEIZER/Cloud-X-security-agent/main/wazuh-configs/scripts/install-agent.ps1 | iex; Start-CloudXSecurityWazuhInstall @params
```

> **Note:** The one-liner assumes the repository has been renamed to `Cloud-X-security-agent`.

## ⚙️ Configuration

This repository is designed to be a centralized location for managing your Wazuh agent configurations.

### **Agent Configuration (`/agents`)**

The `agents` directory contains templates for `ossec.conf`. You can define default configurations and create specific overrides for different operating systems or server roles.

- `agents/ossec.conf`: Default configuration for all agents.
- `agents/windows-agents/ossec.conf`: Specific overrides for Windows agents.
- `agents/linux-agents/ossec.conf`: Specific overrides for Linux agents.
- `agents/custom-groups/`: Define configurations for specific Wazuh groups (e.g., web servers, database servers).

### **Installer Parameters**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `ipAddress` | String | Yes* | IP address of your Wazuh manager. |
| `agentName` | String | Yes* | A unique name for the new agent. |
| `groupLabel` | String | Yes* | The Wazuh group to assign the agent to. |
| `ConfigFile` | String | Yes* | Path to your JSON configuration file. |
| `Uninstall` | Switch | Yes* | Runs the uninstaller instead of the installer. |
| `WAZUH_VERSION` | String | No | The Wazuh agent version to install. Defaults to `4.7.0-1`. |
| `LogPath` | String | No | Custom file path for the transcript log. |
| `SKIP_HASH_CHECK` | Switch | No | Skips SHA256 hash verification. **Not recommended.** |
| `KeepLogs` | Switch | No | Used with `-Uninstall` to preserve log directories. |

*Either `ipAddress`/`agentName`/`groupLabel`, `ConfigFile`, or `Uninstall` parameter set must be used.

## 🛡️ Uninstaller

A powerful, standalone uninstaller is included to completely and safely remove all traces of the Wazuh agent.

### **How to Run the Uninstaller**

Navigate to the `wazuh-configs/scripts` directory to run the uninstaller.

```powershell
# Option 1: Using the main installer script
.\install-agent.ps1 -Uninstall

# Option 2: Running the uninstaller script directly
.\uninstall-agent.ps1
```

### **Uninstaller Parameters**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Force` | Switch | No | Bypasses the confirmation prompt. |
| `-KeepLogs` | Switch | No | Preserves Wazuh log directories during cleanup. |

## 🚨 Troubleshooting

If the script fails, a `SETUP FAILED` message will appear.

1.  **Check Administrator Privileges**: The most common issue is not running PowerShell as an Administrator.
2.  **Check Network Connectivity**: Ensure the machine can reach the internet and that the Wazuh manager IP is correct and reachable.
3.  **Review the Log File**: The script will output the path to a transcript log (e.g., `Cloud-X-Security-Wazuh-Installer-*.log`). This file contains a complete record of the execution and will have detailed error messages.
4.  **Verify Parameters**: Double-check that all parameters are correct. If using a config file, ensure the path is correct and the JSON is valid.

## 📁 Repository Structure

```
wazuh-configs/
├── agents/
│   ├── ossec.conf                    # Default agent configuration
│   ├── linux-agents/
│   │   └── ossec.conf               # Linux-specific agent config
│   ├── windows-agents/
│   │   └── ossec.conf               # Windows-specific agent config
│   └── custom-groups/
│       ├── web-servers/
│       │   └── ossec.conf           # Web server agents config
│       └── database-servers/
│           └── ossec.conf           # Database server agents config
├── scripts/
│   ├── Modules/                      # PowerShell modules for the installer
│   ├── Uninstaller-Modules/          # PowerShell modules for the uninstaller
│   ├── install-agent.ps1             # Windows installation script
│   ├── uninstall-agent.ps1           # Windows uninstallation script
│   ├── install-agent.sh              # (Placeholder) Linux installation script
│   └── update-config.sh              # (Placeholder) Configuration update script
└── README.md
```

---

<p align="center">
  <strong>Made with ❤️ by MAPLEIZER</strong>
</p>
