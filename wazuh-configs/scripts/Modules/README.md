# Cloud-X Security Wazuh Agent Installer - Modules

This directory contains the modular components of the Cloud-X Security Wazuh Agent Installer. The modules are organized by functionality for better maintainability and code organization.

## Module Structure

```
Modules/
├── Core/                    # Core system functionality
│   ├── Logging.psm1        # Logging and progress tracking
│   └── Utilities.psm1      # System utilities and MSI management
├── Installation/            # Installation-specific modules
│   ├── WazuhOperations.psm1 # Wazuh agent operations
│   └── PostInstall.psm1    # Post-installation tasks
└── UI/                     # User interface components
    └── Banner.psm1         # Installation banner display
```

## Module Descriptions

### Core Modules

#### Logging.psm1
- **Purpose**: Centralized logging and progress tracking
- **Functions**:
  - `Write-Log`: Color-coded logging with multiple severity levels
  - `Start-Step`: Progress tracking with step counters
- **Features**: 
  - Console output with colors
  - File logging support
  - UTC timestamps

#### Utilities.psm1
- **Purpose**: System compatibility checks and MSI management
- **Functions**:
  - `Test-Administrator`: Check admin privileges
  - `Test-SystemCompatibility`: Verify system requirements
  - `Test-MSIAvailability`: Check Windows Installer availability
  - `Restart-MSIService`: Restart Windows Installer service
  - `Invoke-SecureDownload`: Secure file downloads
- **Features**:
  - Enhanced MSI service management
  - Automatic process cleanup
  - Robust error handling

### Installation Modules

#### WazuhOperations.psm1
- **Purpose**: Core Wazuh agent installation and configuration
- **Functions**:
  - `Uninstall-ExistingWazuhAgent`: Remove existing installations
  - `Install-WazuhAgentMSI`: Install Wazuh agent via MSI
  - `Set-WazuhAgentConfiguration`: Configure agent settings
  - `Start-WazuhService`: Start and verify Wazuh service
- **Features**:
  - Conditional IP configuration (Personal group uses internal IP)
  - Verbose MSI logging
  - Retry logic with enhanced error reporting

#### PostInstall.psm1
- **Purpose**: Post-installation tasks and cleanup
- **Functions**:
  - `Show-Summary`: Display installation summary
  - `Deploy-ActiveResponseScripts`: Deploy active response components
  - `Cleanup-TempFiles`: Clean temporary installation files
- **Features**:
  - Professional summary display
  - Automatic cleanup
  - Duration tracking

### UI Modules

#### Banner.psm1
- **Purpose**: User interface and branding
- **Functions**:
  - `Show-Banner`: Display Cloud-X Security branded banner
- **Features**:
  - ASCII art logo
  - Professional branding
  - Version information

## Key Features

### Enhanced MSI Management
- **Service Restart**: Automatically restarts Windows Installer service when busy
- **Process Cleanup**: Force-kills hanging msiexec processes
- **Timeout Handling**: 3-minute timeout with 10-second intervals
- **Verbose Logging**: Detailed MSI installation logs for troubleshooting

### Smart IP Configuration
- **Conditional Logic**: Personal group agents use internal network IP (192.168.100.37)
- **Public IP Fallback**: Other groups use provided public IP address
- **Automatic Detection**: Based on agent group assignment
- **Enhanced Logging**: Shows which IP configuration is applied

### Robust Error Handling
- **Retry Logic**: Multiple attempts for downloads and installations
- **Detailed Logging**: Last 20 lines of MSI logs on failure
- **Service Recovery**: Automatic Windows Installer service restart
- **Comprehensive Diagnostics**: Enhanced error reporting and troubleshooting

## Usage

The modules are automatically imported by the main `CloudXSecurityInstaller.psm1` file. No manual import is required when using the installer.

For development or testing individual modules:

```powershell
# Import specific module
Import-Module ".\Modules\Core\Logging.psm1" -Force

# Use module functions
Write-Log "Test message" -Level "INFO"
```

## Dependencies

- PowerShell 5.1 or higher
- Windows Administrator privileges
- .NET Framework 4.5 or higher
- Internet connectivity for downloads

## Version History

- **v3.1**: Modular architecture implementation
- **v3.0**: Enhanced MSI service management
- **v2.x**: Conditional IP configuration
- **v1.x**: Initial implementation
