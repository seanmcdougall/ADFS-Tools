# Update to point to your script
$scriptPath = 'C:\ADFS\Update-AdfsFederationMetadata.ps1'

# Set time of day to run
$scriptTrigger = New-JobTrigger -Daily -At "03:00 AM"

# Set option to run with administrator privileges
$scriptOption = New-ScheduledJobOption –RunElevated

# User to run the script (you'll be prompted for the password)
$scriptUser = "ECN-RIE\Administrator"

# Register the job
Register-ScheduledJob -Name UpdateAdfsFederationMetadata -FilePath $scriptPath -Trigger $scriptTrigger -ScheduledJobOption $scriptOption -Credential $scriptUser