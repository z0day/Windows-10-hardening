# FIXME

$appxpackages = (
	'3DBuilder',
	'BingFinance',
	'BingSports',
	'CommsPhone',
	'ConnectivityStore',
	'GetHelp',
	'Getstarted',
	'HaloCamera',
	'HaloItemPlayerApp',
	'HaloShell',
	'Messaging',
	'Microsoft3DViewer',
	'MicrosoftOfficeHub',
	'MicrosoftSolitaireCollection',
	'Office.Sway',
	'OneConnect',
	'People',
	'Print3D',
	'SkypeApp',
	'WindowsFeedbackHub',
	'WindowsPhone',
	'Xbox.TCUI',
	'XboxApp',
	'ZuneMusic',
	'ZuneVideo',
	'windowscommunicationsapps'
)

ForEach ($package in $appxpackages)
{
	try
 {
		$packagenames = (Get-AppxProvisionedPackage -online | Where-Object { $_.DisplayName -like '*' + $package + '*' }).PackageName

		ForEach ($packagename in $packagenames)
		{
			DISM /online /remove-provisionedappxpackage /packagename:$packagename
		}
	}
	catch
 {
		Write-Host "Error: "
		Write-Host $package
	}
}

