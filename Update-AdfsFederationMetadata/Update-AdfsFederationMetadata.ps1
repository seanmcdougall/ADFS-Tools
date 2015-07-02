#requires -runasadministrator
# Update-AdfsFederationMetadata.ps1
# Copyright: Sean McDougall, 2015
# License: GPL v2
# Version: 1.0.0
# Based on SILA (https://sila.codeplex.com/) with modifications to support ADFSv3 (Windows 2012 R2) and SHA-256 XML signatures.
# SILA is copyright 2012 by CNRS, licensed under CeCiLL B and GPL v2

# Path to the location of this script
$scriptFolder = "C:\ADFS"

# Path to temporary folder
$outPath = Join-Path $scriptFolder "temp\"

# Path to log folder
$logPath = Join-Path $scriptFolder "Log\"

# Name of the federation, used to create a folder for the metadata files
$federationName = "CAF"

# Set to true in order to validate XML signatures
$checkSignature = $true

# URL for the signed federation metadata
$federationMetadataURL = "https://caf-shib2ops.ca/CoreServices/caf_metadata_signed_sha256.xml"

# Path to the PEM encoded certificate to be used for validating the federation metadata signature.
$federationValidationCert = Join-Path $scriptFolder "caf_metadata_verify.crt"

# Name of the ADFS web theme currently in use
$webTheme = "ECN-RIE"

# URL for the ADFS farm (https required)
$webServerURL = "https://fs.domain.ca"

# Path to file containing default rules to be used when adding a new claims provider
$ruleFilePath = Join-Path $scriptFolder "ClaimProviderRules.txt"

# Manually added IdPs that are not present in the federation metadata.  Anything not in here will be removed automatically.  DO NOT REMOVE AD AUTHORITY!
$adfsManualIdp = @(
    "AD AUTHORITY" # this value must remain
)

# Import functions and run the loader
cd $scriptFolder
. .\Update-AdfsFederationMetadata-Functions.ps1
loadMetadata

# Add any post-load tasks here
Set-AdfsRelyingPartyTrust -TargetName "relyingparty.domain" -ClaimsProviderName @("IdP1","IdP2","IdP3")