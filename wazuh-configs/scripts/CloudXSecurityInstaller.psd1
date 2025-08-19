@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'CloudXSecurityInstaller.psm1'

    # Version number of this module.
    ModuleVersion = '3.3.0'

    # Supported PSEditions
    CompatiblePSEditions = @('Desktop', 'Core')

    # ID used to uniquely identify this module
    GUID = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'

    # Author of this module
    Author = 'Cloud-X Security'

    # Company or vendor of this module
    CompanyName = 'Cloud-X Security'

    # Copyright statement for this module
    Copyright = '(c) 2025 Cloud-X Security. All rights reserved.'

    # Description of the functionality provided by this module
    Description = 'Enterprise-grade Wazuh agent installer with enhanced security, auditing, and configuration management features.'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Functions to export from this module
    FunctionsToExport = @('Install-WazuhAgent')

    # Cmdlets to export from this module
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = '*'

    # Aliases to export from this module
    AliasesToExport = @()

    # Private data to pass to the module
    PrivateData = @{
        PSData = @{
            # Tags applied to this module
            Tags = @('Wazuh', 'Security', 'Agent', 'Installer', 'SIEM')

            # A URL to the license for this module.
            LicenseUri = ''

            # A URL to the main website for this project.
            ProjectUri = 'https://github.com/MAPLEIZER/Cloud-X-security-agent'

            # A URL to an icon representing this module.
            IconUri = ''

            # Release notes
            ReleaseNotes = 'Version 3.3.0 - Module conversion for better maintainability and distribution'
        }
    }
}
