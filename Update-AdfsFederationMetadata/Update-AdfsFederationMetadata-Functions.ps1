# Update-AdfsFederationMetadata-Functions.ps1
# Copyright: Sean McDougall, 2015
# License: GPL v2
# Version: 1.0.0
# Based on SILA (https://sila.codeplex.com/) with modifications to support ADFSv3 (Windows 2012 R2) and SHA-256 XML signatures.
# SILA is copyright 2012 by CNRS, licensed under CeCiLL B and GPL v2
function loadMetadata() {
    [CmdletBinding()]
    param ()

	# contains the IdPs that will be added to ADFS
    $psHash = @{} 
	
	# contains IdPs in ADFS, this hash table is used to remove IdPs that are no longer in the metadata file
    $adfsHash = @{} 

	#date formats
    $isoTimeFormat ="yyyy-MM-dd HH:mm:ss"
    $isoTimeFileFormat ="yyyy-MM-dd_HHmmss"
    
	# Generate name for log file
	$logDate = get-date -format "yyyy-MM-dd_HHmmss"
    $logFile = Join-Path $logPath ($logDate + ".txt")

    # Load ADFS snapin
    Add-PSSnapin Microsoft.ADFS.PowerShell -EA 0
    
	# Start processing
    $timestamp = get-date -format $isoTimeFormat
    Log-Write "Begin : $timeStamp"

    # Fetch the federation metadata file
    Log-Write "** fetching metadata file"

    # build the metadata file path and create it as empty (removing the old version)
    $federationMetadataPath = (Join-Path -Path $outPath -ChildPath ("federationMetadata/" + $federationName + ".xml"))
    New-Item -type file -Force $federationMetadataPath > $null

    # Download the metadata file
    $webClient = new-object System.Net.WebClient 
    $webClient.DownloadFile($federationMetadataUrl, $federationMetadataPath) 

    # Make sure metadata isn't empty before processing
    if ( (get-item $federationMetadataPath).Length -eq 0) {
        Log-Write "ERROR: Metadata File $federationMetadataPath is empty"
        Exit 1
    }

	Log-Write "** validating metadata file"
    
	# Load the federation metadata xml file
    $xmldata = new-object Xml.XmlDocument
    $xmldata.PreserveWhitespace = $true
    $xmldata.Load($federationMetadataPath)

    # Make sure the metadata is still valid
    $validUntil = [DateTime]$xmldata.EntitiesDescriptor.ValidUntil
    if ($validUntil -le (Get-Date)) {
        Log-Write "ERROR: Metadata file is valid until $validUntil and we are : (Get-Date)"
        Exit 1
    }

	if ($checkSignature) {
		# Validate the signature on the metadata file
		# http://stackoverflow.com/questions/30759119/verifying-xml-signature-in-powershell-with-pem-certificate
		Add-Type -AssemblyName system
		Add-Type -AssemblyName system.security
		Add-Type @'
        public class RSAPKCS1SHA256SignatureDescription : System.Security.Cryptography.SignatureDescription
            {
                public RSAPKCS1SHA256SignatureDescription()
                {
                    base.KeyAlgorithm = "System.Security.Cryptography.RSACryptoServiceProvider";
                    base.DigestAlgorithm = "System.Security.Cryptography.SHA256Managed";
                    base.FormatterAlgorithm = "System.Security.Cryptography.RSAPKCS1SignatureFormatter";
                    base.DeformatterAlgorithm = "System.Security.Cryptography.RSAPKCS1SignatureDeformatter";
                }

                public override System.Security.Cryptography.AsymmetricSignatureDeformatter CreateDeformatter(System.Security.Cryptography.AsymmetricAlgorithm key)
                {
                    System.Security.Cryptography.AsymmetricSignatureDeformatter asymmetricSignatureDeformatter = (System.Security.Cryptography.AsymmetricSignatureDeformatter)
                        System.Security.Cryptography.CryptoConfig.CreateFromName(base.DeformatterAlgorithm);
                    asymmetricSignatureDeformatter.SetKey(key);
                    asymmetricSignatureDeformatter.SetHashAlgorithm("SHA256");
                    return asymmetricSignatureDeformatter;
                }
            }
'@
		$RSAPKCS1SHA256SignatureDescription = New-Object RSAPKCS1SHA256SignatureDescription
		[System.Security.Cryptography.CryptoConfig]::AddAlgorithm($RSAPKCS1SHA256SignatureDescription.GetType(), "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
	
		$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($federationValidationCert)
	
		$signatureNode = $xmldata.EntitiesDescriptor.Signature
		$signedXml = New-Object System.Security.Cryptography.Xml.SignedXml($xmldata)
		$signedXml.LoadXml($signatureNode)
		$isSigned = $signedXml.CheckSignature($cert,$true)

		if (! $isSigned) {
			Log-Write "ERROR: Metadata file signature is not valid !"
			Exit 1
		}
	}
	
    # Retrieve list of all current claims providers (IdPs) in ADFS
    $cps = Get-AdfsClaimsProviderTrust
    foreach ($cp in $cps) {
        $adfsHash[$cp.Identifier] = $cp.Name
    }
    foreach ($key in $adfsManualIdp) {
        $adfsHash.Remove($key)
    }

    # Process the federation metadata file, handling each IdP individually.
    Log-Write "`r`n**splitting metadata file"

    # Get all the EntityDescriptor nodes
    $entities = $xmldata.EntitiesDescriptor.EntityDescriptor

    # idpCounter to get the number of IdP record
    $idpCounter = 0

    foreach ($entity in $entities) {
	    # only process IdPs
        if ($entity.IDPSSODescriptor -ne $null) {
            $name = [string]($entity.Organization.OrganizationName | ? {$_.lang -eq 'en'}).innerXML
            $organizationName = $name.Normalize()

            if ($organizationName.Length -gt 0) {

				log-Write ("$idpCounter : $organizationName / " + $entity.entityID + " -> " +(getDomain $entity.entityID))
			
                # create the IdP metadata file path
                $metadataFileName = (getDomain $entity.entityID) + ".xml"
                $metadataFilePath = Join-Path -Path $outPath -ChildPath $metadataFileName

			    # add xml descriptor and a comment and write the file. 
                '<?xml version="1.0" encoding="UTF-8"?>' |  out-file -encoding:UTF8 $metadataFilePath
                "<!-- " + $organizationName + " -->" |  out-file -encoding:UTF8 $metadataFilePath -append

				# ADFS doesn't like multiple certificates, so do some checks and only keep the "best" one
				if ($entity.IDPSSODescriptor.KeyDescriptor.Count -gt 1) {
					$now = Get-Date
					$bestKeyCert = $null
					foreach ($keyDescriptor in $entity.IDPSSODescriptor.KeyDescriptor) {
						[byte[]]$keyCertData = [Convert]::FromBase64String($keyDescriptor.KeyInfo.X509Data.X509Certificate)
						$keyCert = [System.Security.Cryptography.X509Certificates.X509Certificate2] $keyCertData
						if ($keyCert.NotAfter -gt $now -and $keyCert.NotBefore -lt $now) {
							if ($bestKeyCert -eq $null -or $keyCert.NotAfter -gt $bestKeyCert.NotAfter) {
								$bestKeyCert = $keyCert
							} else {
								$entity.IDPSSODescriptor.RemoveChild($keyDescriptor) | Out-Null
							}
						} else {
							$entity.IDPSSODescriptor.RemoveChild($keyDescriptor) | Out-Null
						}
					}
				}
				
				# Remove other things ADFS doesn't like
				$aad = $entity.AttributeAuthorityDescriptor;
				if ($aad -ne $null) {
					$entity.RemoveChild($entity.AttributeAuthorityDescriptor) | Out-Null
				}
				foreach ($ars in $entity.IDPSSODescriptor.ArtifactResolutionService) {
					if ($ars.binding -eq "urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding") {
						$entity.IDPSSODescriptor.RemoveChild($ars) | Out-Null
					}
				}
				foreach ($slo in $entity.IDPSSODescriptor.SingleLogoutService) {
					if ($slo.binding -eq "urn:oasis:names:tc:SAML:2.0:bindings:SOAP") {
						$entity.IDPSSODescriptor.RemoveChild($slo) | Out-Null
					}
				}
				foreach ($sso in $entity.IDPSSODescriptor.SingleSignOnService) {
					if ($sso.binding -eq "urn:mace:shibboleth:1.0:profiles:AuthnRequest" -or $sso.binding -eq "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign") {
						$entity.IDPSSODescriptor.RemoveChild($sso) | Out-Null
					}
				}
				
				# Write out the cleaned IdP metadata file
                $entity.OuterXml.ToString() | out-file -encoding:UTF8 $metadataFilePath -append

                # Load the metadata file into the ADFS web theme.  Need to cheat and pretend it's a "js" file because ADFS only allows certain extensions.
				Set-ADFSWebTheme -TargetName $webTheme -AdditionalFileResource @{uri='/adfs/portal/metadata/' + (ensureFile($federationName)) + '/' + $metadataFileName + '.js';path=$metadataFilePath.ToString()}

                # store the organization name and the entity ID in hashTable for the next steps
                $psHash[$organizationName] = $entity.entityID

                # remove the organization name from $adfsHash
                if ($adfsHash.ContainsKey($entity.entityID) -and ($adfsHash[$entity.entityID] -eq $organizationName )) {
                    $adfsHash.Remove($entity.entityID)
                }

                $idpCounter ++
        
            }
            else {
                Log-Write "ERROR : entityID $entity.entityID organization name is empty !"
            }
        }
    }
    
    #
    # clean up the dictionary to only add new IdPs as trusted claims providers
    #
    Log-Write "`r`n**Cleaning up the IdP hash"

    # get all ADFS trusted Claims Providers again
    $cpNames = get-adfsClaimsProviderTrust | select name

    foreach ($cpName in $cpNames) 
	{
        # remove existing IdPs in ADFS from Federation List
        if($psHash.ContainsKey($CpName.Name)) 
		{
            $psHash.Remove($CpName.Name)
        }
    }

    # Remove old IdPs
    Log-Write "`r`n**Removing old IDPs"

    $oldIdpCounter = 0

    foreach ($key in $adfsHash.Keys) {
        Log-Write  "oldIdP : $key `t  $($adfsHash[$key])"
        Remove-ADFSClaimsProviderTrust -TargetIdentifier ($key)
        $oldIdpCounter ++
    }
	
	# Add new IdPs
    Log-Write "`r`n**Adding new IdPs"

    $newIdpCounter = 0

    foreach ($hashKey in $psHash.Keys) 
	{
		Log-Write "newIdP : $hashKey `t $($psHash[$hashKey])"
		
        # build the metadata url
	    $cpMetadataUrl = $webServerURL + '/adfs/portal/metadata/' + (ensureFile $federationName) + '/' + (getDomain $psHash[$hashKey]) + '.xml.js'

	    # add the IdP
        try 
		{
			# if the IdP changed its name but kept its entityID, we must remove it first 
			$checkEntity = Get-ADFSClaimsProviderTrust -Identifier ($psHash[$hashKey])
			if ($checkEntity -ne $null) {
				Remove-ADFSClaimsProviderTrust -TargetIdentifier ($psHash[$hashKey])
			}
        
			Add-ADFSClaimsProviderTrust –Name "$hashKey" –MetadataUrl "$cpMetadataUrl" -SignatureAlgorithm "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
			Set-ADFSClaimsProviderTrust -Targetname "$hashKey" –MonitoringEnabled $true –AutoUpdateEnabled $true -AcceptanceTransformRulesFile "$ruleFilePath"
        }
        catch 
		{
            Log-Write "ERROR adding IdP name : $hashKey `t entityID : $($psHash[$hashKey])"
            Log-Write $_
            Log-Write "Command used :"
            Log-Write "Add-ADFSClaimsProviderTrust –Name ""$hashKey"" –MetadataUrl ""$cpMetadataUrl"" -SignatureAlgorithm ""http://www.w3.org/2000/09/xmldsig#rsa-sha1"""
            Log-Write "Set-ADFSClaimsProviderTrust -Targetname ""$hashKey"" –MonitoringEnabled `$true –AutoUpdateEnabled `$true -AcceptanceTransformRulesFile ""$ruleFilePath"""
            Log-Write " "
        }
        $newIdpCounter ++
    }

	# end
    $timestamp = get-date -format $isoTimeFormat
    Log-Write "`r`nEnd : $timeStamp"

    # recap of the job
    Log-Write "------------------"
    Log-Write ("Records   :  "+ $entities.Count)
    Log-Write "IdPs      :  $idpCounter"
    Log-Write "Old IdPs  :  $oldIdpCounter"
    Log-Write "New IdPs  :  $newIdpCounter"
	
}
Function ensureFile
{
    param
    (
        [string]$file
    )

    # from http://powershell.com/cs/blogs/tips/archive/2009/06/19/removing-illegal-file-name-characters.aspx
    $pattern = "[{0}]" -f ([Regex]::Escape([String] [System.IO.Path]::GetInvalidFileNameChars()))
    $newfile = [Regex]::Replace($file, $pattern, '')
    return $newfile
}

function getDomain
{
    param
    (
        [string]$inputString
    )

    if ($inputString.StartsWith("http")) {
        $result = ($inputString.Split("/"))[2]
    }
    else {
        $result = $inputString
    }
    ensureFile ($result.Replace(":", "_"))
}

function Log-Write 
{
	param 
	(
		[string]$msg
	)
	
	Write-Host $msg
	Add-Content $logFile $msg
}