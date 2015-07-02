# Update-AdfsFederationMetadata
Copyright: Sean McDougall, 2015
License: GPL v2
Version: 1.0.0

Tool to load Shibboleth (SAML) federation metadata into ADFSv3 and keep it updated.  Primarily designed for the consumption of Canadian Access Federation (https://caf-shib2ops.ca/CoreServices/index.shtml) metadata.

- Based on SILA (https://sila.codeplex.com/) with modifications to support ADFSv3 (Windows 2012 R2) and SHA-256 XML signatures.
- SILA is copyright 2012 by CNRS, licensed under CeCiLL B and GPL v2

INSTALLATION

- Create a new folder on your primary ADFS server (ie C:\ADFS) and copy in the contents of this folder.
- Download your federation's validation certificate and place within this folder.
- Modify Update-AdfsFederationMetadata.ps1 to match your configuration.
- Review ClaimProviderRules.txt and modify if needed.
- Open an Administrator Powershell window
- cd into the script directory (ie C:\ADFS)
- Run the script (.\Update-AdfsFederationMetadata.ps1) and review the output

AUTOMATION
- Once everything is running smoothly, you can add a scheduled task for this script.
- Edit Create-AdfsFederationMetadataScheduledJob.ps1 and modify the settings as needed.
- Run .\Create-AdfsFederationMetadataScheduledJob.ps1 and enter credentials for a valid admin user when prompted.
