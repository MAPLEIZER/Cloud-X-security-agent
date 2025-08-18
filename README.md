<p align="center">
  <img src="nextechlabs_logo.jpeg" alt="Nextech Labs Logo" width="200"/>
</p>

# NixGuard Wazuh Agent Installer

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

iwr https://raw.githubusercontent.com/MAPLEIZER/NixGuard-Wazuh-Installer/main/NixGuard-Wazuh-Installer.ps1 | iex; Start-NixGuardWazuhInstall @params
```

> **Note:** For the one-liner to work, the main logic of the installer script would need to be wrapped in a function (e.g., `Start-NixGuardWazuhInstall`). This is a recommended practice for distributable scripts.

## ⚙️ Configuration

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

You can run the uninstaller directly or via the main installer script.

```powershell
# Option 1: Using the main script
.\NixGuard-Wazuh-Installer.ps1 -Uninstall

# Option 2: Running the uninstaller script directly
.\NixGuard-Wazuh-Uninstaller.ps1
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
3.  **Review the Log File**: The script will output the path to a transcript log (e.g., `NixGuard-Wazuh-Installer-*.log`). This file contains a complete record of the execution and will have detailed error messages.
4.  **Verify Parameters**: Double-check that all parameters are correct. If using a config file, ensure the path is correct and the JSON is valid.

## 📁 Repository Structure

```
NixGuard-Wazuh-Installer/
├── Modules/                              # Installer modules
│   ├── Banner.psm1
│   ├── Logging.psm1
│   ├── PostInstall.psm1
│   ├── Utilities.psm1
│   └── WazuhOperations.psm1
├── Uninstaller-Modules/                  # Uninstaller modules
│   ├── Uninstall-Cleanup.psm1
│   ├── Uninstall-Display.psm1
│   ├── Uninstall-Operations.psm1
│   └── Uninstall-Utilities.psm1
├── _reference_scripts/                   # Archived original scripts
├── config.json.example                   # Example configuration file
├── NixGuard-Wazuh-Installer.ps1          # Main installer script
├── NixGuard-Wazuh-Uninstaller.ps1        # Main uninstaller script
└── README.md                             # This file
```

---

<p align="center">
  <strong>Made with ❤️ by MAPLEIZER</strong>
</p>
