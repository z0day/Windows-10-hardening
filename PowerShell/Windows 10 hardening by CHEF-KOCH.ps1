<#

_|          _|  _|                  _|    _|        _|    _|                            _|                      _|                          _|                        _|_|_|  _|    _|
_|          _|      _|_|_|        _|_|  _|  _|      _|    _|    _|_|_|  _|  _|_|    _|_|_|    _|_|    _|_|_|        _|_|_|      _|_|_|      _|_|_|    _|    _|      _|        _|  _|
_|    _|    _|  _|  _|    _|        _|  _|  _|      _|_|_|_|  _|    _|  _|_|      _|    _|  _|_|_|_|  _|    _|  _|  _|    _|  _|    _|      _|    _|  _|    _|      _|        _|_|
  _|  _|  _|    _|  _|    _|        _|  _|  _|      _|    _|  _|    _|  _|        _|    _|  _|        _|    _|  _|  _|    _|  _|    _|      _|    _|  _|    _|      _|        _|  _|
    _|  _|      _|  _|    _|        _|    _|        _|    _|    _|_|_|  _|          _|_|_|    _|_|_|  _|    _|  _|  _|    _|    _|_|_|      _|_|_|      _|_|_|        _|_|_|  _|    _|
                                                                                                                                    _|                      _|
                                                                                                                                _|_|                    _|_|

       Codename : Waste of time
       Author   : CHEF-KOCH
       License  : GNU General Public License v3.0
       Version  : pre 0.5 ALPHA (public version)

#>

<#
       .SYNOPSIS
           - Windows 10 hardening by CHEF-KOCH -

       .DESCRIPTION
           This PowerShell script aims to harden Windows 10 LTSB/C (EntS) & Enterprise
           in order to improve the overall OS security and data privacy.

           All tweaks are explained. I do not provide an"undo" script because I think this is not the
           "correct" way to harden something. Hardening should work for everyone and not only some individuals or for "special" SKUs.

           A registry backup will automatically stored onto your system OS drive (default C:\).

       REQUIREMENTS:

       * PowerShell execution policy must be configured to allow script execution!

       .NOTES
            -> A script integration into an ISO image is possible, however I do
                not use it because I usually apply the fixes after a fresh installation and
                some tweaks can only be applied after the OS was installed.
            -> This script has no OS SKU checks, using it on other Edition is on your own!
            -> This script IS INSECURE, because it needs higher "OS level rights" and PS rights,
                it will change and/or uninstall a lot Windows 10 internals.
            -> The script is available as "Chocolatey package" (but not yet uploaded).
            -> Some entries are duplicates (registry/GPO), this is a workaround because GPO might not show the correct value.
            -> Script provided "as-is", without warranty of any kind and used at your own risk.

       .PARAMETER Name
            Windows 10 hardening by CHEF-KOCH.ps1

       .EXAMPLE
            .\Windows 10 hardening by CHEF-KOCH.ps1

       .PARAMETER Source
           -> FIXME:

       .SUPPORTED EDITIONS
           -> No ARM!
           -> No CoreS (CoreOS)!
           -> No Government Editions!
           -> No Home/Pro Editions (workarounds are mentioned)!
           -> No SERVER OR DOMAIN (workarounds are mentioned)!
           -> No TABLETS!

       .REQUIREMENTS
           -> Intel or ARM CPU (nor ARM/MIPS)
           -> SSD, HDD will work too but you might need to enable the "Bitlocker workaround"
                because of hardware based encryption "distrust".

       .LINK
           https://github.com/CHEF-KOCH/Windows-10-hardening/blob/master/PowerShell/Windows%2010%20hardening%20by%20CHEF-KOCH.ps1

       .INPUTS
           None. Folders are defined within variables, please terminate your variables with "\"

       .OUTPUTS
           -> FIXME:

       .EXTERNALHELP
           -> FIXME:
#>

# Custom present
# FIXME:
#powershell.exe -NoProfile -ExecutionPolicy Bypass -File CK-No-Defender.ps1 EnableFirewall DisableDefender
#powershell.exe -NoProfile -ExecutionPolicy Bypass -File CK-No-Defender.ps1 -preset nodefender.txt

# We need admin rights, ask for elevated permissions first.
#Requires -RunAsAdministrator
$ErrorActionPreference = "Continue"

# Check minimum PowerShell version first.
#Requires -Version 6

# DISM
#Requires -Module Dism

# Get location of this script
#$rootDir = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path)

# Remove all text from the current PowerShell session (in case there is some)
Clear-Host
# Clear Errors
$Error.Clear()
# Log output in Unicode (UTF-8)
$OutputEncodingPrevious = $OutputEncoding
$OutputEncoding = [System.Text.ASCIIEncoding]::Unicode
#
#
# Missing variables
# IPSec default pre-shared key
$ThePreSharedKey = 'Myown-insecure0815-testpassword-replace-it-with-your-own'
# (FIXME:) New-Variables <here>
#
#
##########################################################################################
###### 		                BACKUP (Registry)                                       ######
######          Backup:     HKLM, HKCU and HKCR                                     ######
######      + check and delete existent backups                                     ######
######      Todo: Check existent keys (FIXME:) & trigger system backup              ######
# Reg backups are useless if we are unable to start at all and SysRep will fail!    ######
#                                                                                   ######
# https://github.com/PowerShell/PowerShell/issues/4878                              ######
##########################################################################################
# Turn on Windows 10 own Registry Backup function
# C:\Windows\System32\config\RegBack
# Since Windows 1803+, this is disabled by default.
Set-ItemProperty-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" -Name "EnablePeriodicBackup" -PropertyType DWord -Value 1 -Force
# First remove existing backups
#Remove-Item $env:systemroot\backup\hklm.reg | Out-Null
#Remove-Item $env:systemroot\backup\hkcu.reg | Out-Null
#Remove-Item $env:systemroot\backup\hkcr.reg | Out-Null
# Backup our current Registry Hive
reg export HKLM $env:systemroot\backup\hklm.reg | Out-Null
reg export HKCU $env:systemroot\backup\hkcu.reg | Out-Null
reg export HKCR $env:systemroot\backup\hkcr.reg | Out-Null

# Backup current user profile
# https://github.com/nickrod518/Migrate-WindowsUserProfile
# https://docs.Microsoft.com/en-us/windows-server/administration/windows-commands/robocopy
# https://windowsreport.com/corrupt-user-profile-windows-10/
# https://docs.Microsoft.com/en-us/windows/deployment/usmt/usmt-scanstate-syntax#a-href-idbkmk-useroptionsauser-options
# Backup printers
#wmic printer list brief >>PrinterList.txt
#reg export $env:systemroot\backup\%username%\MappedDrives.reg "HKCU:\Network"

# FIXME: hardcoding C: (or as search is BS because this will not work when Windows is not booted)
#Robocopy "$env:systemroot\documents and settings\%username%\application data\Microsoft\Outlook" $env:systemroot\backup\%username%\NK2 *.nk2
#Robocopy "$env:systemroot\documents and settings\%username%\application data\Microsoft\signatures" $env:systemroot\backup\%username%\signatures *.* /e
#Robocopy "$env:systemroot\documents and settings\%username%\application data\Microsoft\templates" D:\backup\%username%\templates normal.dot
#Robocopy "$env:systemroot\documents and settings\%username%\Desktop" $env:systemroot\backup\%username%\Desktop *.* /e
#Robocopy "$env:systemroot\documents and settings\%username%\Favorites" $env:systemroot\backup\%username%\Favorites *.* /e
#reg export $env:systemroot\backup\%username%\CustomDictionaries.reg "HKCU:\Software\Microsoft\Shared Tools\Proofing tools\Custom Dictionaries"


##########################################################################################
###### 			Telemetry & Feedback, Ads & Fingerprinting Migration				######
# Overview: https://docs.Microsoft.com/en-us/windows/privacy/manage-windows-1809-endpoints
# German "audit" 					https://files.catbox.moe/ugqngv.pdf			    ######
# Windows Editions Diff: 			https://en.wikipedia.org/wiki/Windows_10_editions    #
##########################################################################################
# Turn off Visual Studio Telemetry, Feedback button etc.
New-ItemProperty -Path "HKCU:\Software\Microsoft\VisualStudio\Telemetry" -Name "TurnOffSwitch" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\VisualStudio\SQM" -Name "OptIn" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" -Name "DisableFeedbackDialog" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" -Name "DisableEmailInput" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" -Name "DisableScreenshotCapture" -PropertyType DWord -Value 1 -Force
# Turn off SQL Study ID
# Windows Vista+
# Max: 65535
# Max: 256 (Corporate SQM URL)
#Set-ItemProperty-Path "HKLM:\Software\Policies\Microsoft\SQMClient\Windows" -Name "StudyId" -PropertyType DWord -Value 0 -Force
#Set-ItemProperty-Path "HKLM:\Software\Policies\Microsoft\SQMClient" -Name "CorporateSQMURL" -PropertyType DWord -Value 0 -Force
# Turn off preview builds telemetry
# By default preview builds automatically changing telemetry flag to 2 (or higher)
Set-ItemProperty-Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "CommercialId" -PropertyType DWord -Value 0
# Disallow to change the telemetry opt-in settings via GUI
# Windows 10 RS4+
Set-ItemProperty-Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "DisableTelemetryOptInSettingsUx" -PropertyType DWord -Value 1
# Disable Telemetry changed notifications
# Windows 10 RS4+
Set-ItemProperty-Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "DisableTelemetryOptInChangeNotification" -PropertyType DWord -Value 1
# Disallow to delete device via UX
# Windows 10 RS5+
Set-ItemProperty-Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "DisableDeviceDelete" -PropertyType DWord -Value 1
# Turn off DisableDiagnosticDataViewer app
# Windows 10 RS5+
# Theoretically we should enable it because auditing reasons BUT keep in mind
# Apps are disabled
# The app is for whatever reasons not "preinstalled"
Set-ItemProperty-Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "DisableDiagnosticDataViewer" -PropertyType DWord -Value 1
# Disable endpoint upload
# FIXME: Set-ItemProperty-Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "ConfigureMicrosoft365UploadEndpoint" -PropertyType DWord -Value 1
# Turn off commercial data pipeline
Set-ItemProperty-Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowCommercialDataPipeline" -PropertyType DWord -Value 0
# Disable MSDT
# https://getadmx.com/?Category=Windows_10_2016&Policy=Microsoft.Policies.MSDT::MsdtSupportProvider
Set-ItemProperty-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" -Name "DisableQueryRemoteServer" -PropertyType DWord -Value 0 -Force
# Do not allow the real device name in Telemetry
Set-ItemProperty-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowDeviceNameInTelemetry" -PropertyType DWord -Value 0 -Force
# No Cross Device Experience
# This might break StartMenu due to an bug
# https://github.com/DavidXanatos/priv10/issues/5
# KB4517389
# FIXME:
# Let apps on my other devices open apps and continue experiences on this device
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -PropertyType DWord -Value 0 -Force
# Turn off telemetry for Service Provider Foundation
# https://docs.Microsoft.com/en-us/powershell/module/spfadmin/set-scspftelemetry?view=systemcenter-ps-2019
#Set-SCSPFTelemetry -Enabled $False -ErrorAction SilentlyContinue
# SharePoint Telemetry
# https://docs.Microsoft.com/en-us/powershell/module/sharepoint-pnp/disable-pnppowershelltelemetry?view=sharepoint-ps
#Disable-PnPPowerShellTelemetry -Force
# Prevent non-administrators from using Safe Mode
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "SafeModeBlockNonAdmins" -PropertyType DWord -Value 1 -Force
# Turn off Turn Help Experience Improvement Program
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" -Name "NoImplicitFeedback" -PropertyType DWord -Value 0 -Force
# Turn off App based Customer Experience Improvement Program (CEIP)
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\AppV\CEIP" -Name "CEIPEnable" -PropertyType DWord -Value 0 -Force
# Turn off WMP Telemetry (metadata) and Auto-Updates
# WMP9+
# Vista+
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "DisableAutoUpdate" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "DisableOnline" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventCDDVDMetadataRetrieval" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventLibrarySharing" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventMusicFileMetadataRetrieval" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventRadioPresetsRetrieval" -PropertyType DWord -Value 1 -Force
# Turn off Data Collection (not needed >= 1603+)
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitEnhancedDiagnosticDataWindowsAnalytics" -PropertyType DWord -Value 1 -Force
Set-ItemProperty-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -PropertyType DWord -Value 0 -Force
Set-ItemProperty-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "MaxTelemetryAllowed" -PropertyType DWord -Value 0 -Force
Set-ItemProperty-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "MicrosoftEdgeDataOptIn" -PropertyType DWord -Value 0 -Force
# Turn off KMS Client Online AVS Validation (Telemetry)
# This will NOT break KMS activation!
# https://getadmx.com/?Category=Windows_10_2016&Policy=Microsoft.Policies.SoftwareProtectionPlatform::NoAcquireGT
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\SOFTWARE Protection Platform" -Name "NoGenTicket" -PropertyType DWord -Value 0
# Turn off "Shared Experiences"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" -Name "RomeSdkChannelUserAuthzPolicy" -PropertyType DWord -Value 0 -Force
# Turn off automatic connecting to open Wi-Fi networks
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -PropertyType DWord -Value 0 -Force
# Turn off Microsoft consumer experiences (current user)
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -PropertyType DWord -Value 1 -Force
# Turn off additional data requests from Microsoft in response to a windows error reporting event
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -PropertyType DWord -Value 1
# Turn off "Location information" usage & Sensors
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\PolicyManager\default\System\AllowLocation" -Name "value" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -PropertyType DWord -Value 1 -Force
# Turn off "Show me the Windows welcome experience after updates and occasionally when I sign in to highlight what's new and suggested"
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -PropertyType DWord -Value 0 -Force
# Turn off "File Explorer ads" (Home/Pro users only!)
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -PropertyType DWord -Value 0 -Force
# Turn off Windows Customer Experience Improvement Program
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -PropertyType DWord -Value 0 -Force
# Turn off location tracking for this device
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -PropertyType String -Value "Deny"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -PropertyType DWord -Value 0
# Turn off "Connected User Experiences and Telemetry" service (DiagTrack)
#Get-Service -Name DiagTrack | Stop-Service -Force
#Get-Service -Name DiagTrack | Set-Service -StartupType Disabled
# Migrate some attack scenarios (FIXME:)
#Get-Service -Name mrxsmb10 | Stop-Service -Force
#Get-Service -Name mrxsmb10 | Set-Service -StartupType Disabled
# Turn off the Autologger session at the next computer restart
Update-AutologgerConfig -Name "AutoLogger-Diagtrack-Listener" -Start 0
# Turn off the SQMLogger session at the next computer restart
Update-AutologgerConfig -Name "SQMLogger" -Start 0
# Set the operating system diagnostic data level to "Security" (Ent./Edu. + LTSB/LTSC only)
# 0 = Security: Security data only (CIS L1)
# 1 = Basic: Security + basic system and quality data
# 2 = Enhanced: Basic + enhanced insights and advanced reliability data
# 3 = Full: Enhanced + full diagnostics data
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -PropertyType DWord -Value 0
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "DoNotShowFeedbackNotifications" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "MaxTelemetryAllowed" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -PropertyType DWord -Value 0
# Turn off Windows Error Reporting
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "DoReport" -PropertyType DWord -Value 0 -Force
# Change Windows Feedback frequency to "Never"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -PropertyType DWord -Value 0
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds"
# Turn off tailored experiences with diagnostic data
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "PrivacyConsentPresentationVersion" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "PrivacyConsentSettingsVersion" -PropertyType DWord -Value 2 -Force
# Turn off syncing of Location (if SynMyDevice is enabled)
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Settings\FindMyDevice" -Name "LocationSyncEnabled" -PropertyType DWord -Value 0 -Force
# Turn off "Find my device"
# Windows 10+ (NOSERVER)
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\FindMyDevice" -Name "AllowFindMyDevice" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\FindMyDevice" -Name "AllowFindMyDevice" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{26EFEA11-679D-4E5F-818E-F53648139214}Machine\SOFTWARE\Policies\Microsoft\FindMyDevice" -Name "AllowFindMyDevice" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{492489E5-7203-4704-A385-3B391393C80A}Machine\SOFTWARE\Policies\Microsoft\FindMyDevice" -Name "AllowFindMyDevice" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{6162EED4-1E02-4C57-94A2-C0ED9D513A9E}Machine\SOFTWARE\Policies\Microsoft\FindMyDevice" -Name "AllowFindMyDevice" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{70155635-EC0A-4379-AF9F-F0B82188066B}Machine\SOFTWARE\Policies\Microsoft\FindMyDevice" -Name "AllowFindMyDevice" -PropertyType DWord -Value 0 -Force
# Turn off Pen training
Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\PenTraining" -Name "DisablePenTraining" -PropertyType DWord -Value 1 -Force
#New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{755B3906-A444-45F3-837B-9E7858809463}Machine\SOFTWARE\Policies\Microsoft\PenTraining" -Name "DisablePenTraining" -PropertyType DWord -Value 1 -Force


##########################################################
######   				Repair Apps    		    	######
##########################################################
# FIXME: powershell -executionpolicy remotesigned Get-AppxPackage


##########################################################
######   				Touch Input    		    	######
##########################################################
# Turn off touch support
# Windows Vista/7+
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\TabletPC" -Name "TouchInput" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\TabletPC" -Name "TurnOffPanning" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\TabletPC" -Name "TurnOffPanning" -PropertyType DWord -Value 1 -Force




##########################################################
######   				Tablet   		    	    ######
##########################################################
# Turn off Inkball
# Vista only
#Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\TabletPC" -Name "DisableInkball" -PropertyType DWord -Value 1 -Force
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\TabletPC" -Name "DisableInkball" -PropertyType DWord -Value 1 -Force
# Turn off Journal
# Vista+
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\TabletPC" -Name "DisableJournal" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\TabletPC" -Name "DisableJournal" -PropertyType DWord -Value 1 -Force
# Turn off Note Writer Printing
# Vista+
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\TabletPC" -Name "DisableNoteWriterPrinting" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\TabletPC" -Name "DisableNoteWriterPrinting" -PropertyType DWord -Value 1 -Force
# Turn off Snipping Tool
# Vista+
#Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\TabletPC" -Name "DisableSnippingTool" -PropertyType DWord -Value 1 -Force
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\TabletPC" -Name "DisableSnippingTool" -PropertyType DWord -Value 1 -Force
# Turn off Pen Feedback
# Vista - 7
#Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\TabletPC" -Name "TurnOffPenFeedback" -PropertyType DWord -Value 1 -Force
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\TabletPC" -Name "TurnOffPenFeedback" -PropertyType DWord -Value 1 -Force
# Turn off Back ESC mapping
# Vista+
#Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\TabletPC" -Name "PreventButtonBackEscapeMapping" -PropertyType DWord -Value 1 -Force
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\TabletPC" -Name "PreventButtonBackEscapeMapping" -PropertyType DWord -Value 1 -Force
# Prevent Launch App on hardware button press
# Vista+
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\TabletPC" -Name "PreventButtonApplicationLaunch" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\TabletPC" -Name "PreventButtonApplicationLaunch" -PropertyType DWord -Value 1 -Force
# Prevent Press And Hold
# Vista+
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\TabletPC" -Name "PreventButtonPressAndHold" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\TabletPC" -Name "PreventButtonPressAndHold" -PropertyType DWord -Value 1 -Force
# Turn off all Hardware Buttons
# Vista+
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\TabletPC" -Name "TurnOffButtons" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\TabletPC" -Name "TurnOffButtons" -PropertyType DWord -Value 1 -Force
# Prevent Flicks Learning Mode
# Vista - 7
#Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\TabletPC" -Name "PreventFlicksLearningMode" -PropertyType DWord -Value 1 -Force
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\TabletPC" -Name "PreventFlicksLearningMode" -PropertyType DWord -Value 1 -Force
# Prevent Flicks
# Vista - 7
#Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\TabletPC" -Name "PreventFlicks" -PropertyType DWord -Value 1 -Force
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\TabletPC" -Name "PreventFlicks" -PropertyType DWord -Value 1 -Force
# Turn off Auto completion on Tablets
# Windows Vista - 7
Set-ItemProperty -Path "HKCU:\software\policies\Microsoft\TabletTip\1.7" -Name "DisableACIntegratio" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\software\policies\Microsoft\TabletTip\1.7" -Name "DisableACIntegratio" -PropertyType DWord -Value 1 -Force
# Turn off Edge target
# Windows Vista - 7
Set-ItemProperty -Path "HKCU:\software\policies\Microsoft\TabletTip\1.7" -Name "DisableEdgeTarget" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\software\policies\Microsoft\TabletTip\1.7" -Name "DisableEdgeTarget" -PropertyType DWord -Value 1 -Force
# Tablet TIP
# Windows Vista - 7
Set-ItemProperty -Path "HKCU:\software\policies\Microsoft\TabletTip\1.7" -Name "HideIPTIPTarget" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\software\policies\Microsoft\TabletTip\1.7" -Name "HideIPTIPTarget" -PropertyType DWord -Value 1 -Force
# Tablet Touch Target
# Windows Vista - 7
Set-ItemProperty -Path "HKCU:\software\policies\Microsoft\TabletTip\1.7" -Name "HideIPTIPTouchTarget" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\software\policies\Microsoft\TabletTip\1.7" -Name "HideIPTIPTouchTarget" -PropertyType DWord -Value 1 -Force
# Password Security
# Windows Vista
# 1 = default
# 2 = Medium/Low
# 3 = Medium
# 4 = Medium/High
# 5 = High
# Set-ItemProperty -Path "HKCU:\software\policies\Microsoft\TabletTip\1.7" -Name "PasswordSecurityState" -PropertyType DWord -Value 1 -Force
# FIXME: ^^ -> Set-ItemProperty -Path "HKLM:\software\policies\Microsoft\TabletTip\1.7" -Name "PasswordSecurityState" -PropertyType DWord -Value 1 -Force
# Rare Char
# Windows Vista+
Set-ItemProperty -Path "HKCU:\software\policies\Microsoft\TabletTip\1.7" -Name "IncludeRareChar" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\software\policies\Microsoft\TabletTip\1.7" -Name "IncludeRareChar" -PropertyType DWord -Value 1 -Force
# Scatch Out
# Windows Vista only
# 1 = All
# 2 = Tolerant
# 3 = None
#Set-ItemProperty -Path "HKCU:\software\policies\Microsoft\TabletTip\1.7" -Name "ScratchOutState" -PropertyType DWord -Value 1 -Force
#Set-ItemProperty -Path "HKLM:\software\policies\Microsoft\TabletTip\1.7" -Name "ScratchOutState" -PropertyType DWord -Value 1 -Force
# Prediction
# Windows 7+
Set-ItemProperty -Path "HKCU:\software\policies\Microsoft\TabletTip\1.7" -Name "DisablePrediction" -PropertyType DWord -Value 1 -Force









##########################################################
######   		    Script Diagnostics  		  	######
###### FIXME: ... how useful is it if no understands it?
###### You better read the MS docs and check eventmgr for the ID instead
###### Validate Trust is really a critical toggle ... but breaks a lot
##########################################################
# Default script diagnostic policy
# Windows 7+
<#

Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnostics" -Name "ValidateTrust" -PropertyType DWord -Value 1 -Force
# Turn on diagnostics
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnostics" -Name "EnableDiagnostics" -PropertyType DWord -Value 1 -Force
# Turn off Query Remote Server
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" -Name "EnableDiagnostics" -PropertyType DWord -Value 1 -Force

#>

##########################################################
######   				Kerberos   		        	######
##########################################################
<#
# Vista+/7/8
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos" -Name "domain_realm_Enabled" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos" -Name "MitRealms_Enabled" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos" -Name "KdcValidation" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos" -Name "UseForestSearch" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos" -Name "ForestSearchList" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos" -Name "KdcProxyServer_Enabled" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos" -Name "NoRevocationCheck" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Name "RequireFast" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Netlogon\Parameters" -Name "CompoundIdDisabled" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Netlogon\Parameters" -Name "CompoundIdEnabled" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Name "EnableMaxTokenSize" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Name "MaxTokenSize" -PropertyType DWord -Value 2147483647 -Force
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Name "EnableCbacAndArmor" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Name "AlwaysSendCompoundId" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Name "DevicePKInitEnabled" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Name "DevicePKInitBehavior" -PropertyType DWord -Value 1 -Force

#>



##########################################################
######   		    Windows Help + Support   		######
##########################################################
# Turn off Online Tips
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HelpQualifiedRootDir" -PropertyType DWord -Value 0 -Force
# Turn off unsafe online help functions
# Internet Explorer 6 SP1+ (XP)
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "HelpQualifiedRootDir" -PropertyType hex -Value 00,00 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "HelpQualifiedRootDir" -PropertyType hex -Value 00,00 -Force
# Turn off inline Help
# Windows 7+
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DisableHHDEP" -PropertyType DWord -Value 1 -Force
# Turn off Active help
# Vista+
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Assistance\Client\1.0" -Name "Assistance" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0" -Name "NoExplicitFeedback" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0" -Name "NoImplicitFeedback" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0" -Name "NoOnlineAssist" -PropertyType DWord -Value 1 -Force





##########################################################
######   				Enhanced Storage			######
##########################################################
# Root Hub Connected Store Devices
# Windows 7+
# Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EnhancedStorageDevices" -Name "RootHubConnectedEnStorDevices" -PropertyType DWord -Value 1 -Force
# Lock Device on Machine Lock
# Windows 7+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EnhancedStorageDevices" -Name "LockDeviceOnMachineLock" -PropertyType DWord -Value 1 -Force
# Disallow Legacy Disk Devices
# Windows 7+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EnhancedStorageDevices" -Name "DisallowLegacyDiskDevices" -PropertyType DWord -Value 0 -Force
# Disable Password Authentication
# Windows 7+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EnhancedStorageDevices" -Name "DisablePasswordAuthentication" -PropertyType DWord -Value 0 -Force
# TCG Security Activation Disabled
# Windows 7+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EnhancedStorageDevices" -Name "TCGSecurityActivationDisabled" -PropertyType DWord -Value 0 -Force
# Approved Silos
# Windows 7+
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EnhancedStorageDevices" -Name "SiloAllowListPolicy" -PropertyType DWord -Value 1 -Force
# Approved Store Devices
# Windows 7+
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EnhancedStorageDevices" -Name "PolicyEnabled" -PropertyType DWord -Value 1 -Force





##########################################################
######   			    Filesystem			        ######
##########################################################
# Disable NTFS Last-Access Timestamps
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "NtfsDisableLastAccessUpdate" -PropertyType DWord -Value 1 -Force
# Symlink Evaluation
# Vista+
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Filesystems\NTFS" -Name "SymLinkState" -PropertyType DWord -Value 1 -Force
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Filesystems\NTFS" -Name "SymlinkLocalToLocalEvaluation" -PropertyType DWord -Value 1 -Force
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Filesystems\NTFS" -Name "SymlinkLocalToRemoteEvaluation" -PropertyType DWord -Value 1 -Force
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Filesystems\NTFS" -Name "SymlinkRemoteToRemoteEvaluation" -PropertyType DWord -Value 1 -Force
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Filesystems\NTFS" -Name "SymlinkRemoteToLocalEvaluation" -PropertyType DWord -Value 1 -Force
# Disable Compression
# Windows 7+
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Filesystems\NTFS" -Name "NtfsDisableCompression" -PropertyType DWord -Value 1 -Force
# Disable Encryption
# Windows 7+
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Policies" -Name "NtfsDisableEncryption" -PropertyType DWord -Value 0 -Force
# Ntfs Encrypt Paging File
# Windows 7+
# This will create overheap.
# fsutil behavior query encryptpagingfile 1
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Policies" -Name "NtfsEncryptPagingFile" -PropertyType DWord -Value 1 -Force
# NtfsDisable8dot3NameCreation
# Windows 7+
# 0 =
# 1 =
# 2 =
# 3 =
# This will be removed ?!
#Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Policies" -Name "NtfsDisable8dot3NameCreation" -PropertyType DWord -Value 1 -Force
# Disable Delete Notification
# Windows 7+
#Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Policies" -Name "DisableDeleteNotification" -PropertyType DWord -Value 0 -Force
# TxfDeprecatedFunctionality
# Windows 8+
#Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Policies" -Name "NtfsEnableTxfDeprecatedFunctionality" -PropertyType DWord -Value 1 -Force


##########################################################
###### 				    Device Setup                ######
##########################################################
# Turn off Device driver Balloon Tips
# Vista+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Settings" -Name "DisableBalloonTips" -PropertyType DWord -Value 1 -Force
# Generic Driver Send To WER
# Windows 10 RS3+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Settings" -Name "DisableSendGenericDriverNotFoundToWER" -PropertyType DWord -Value 1 -Force
# Generic Driver Send To WER
# Windows 10 RS3+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Settings" -Name "DisableSendRequestAdditionalSoftwareToWER" -PropertyType DWord -Value 1 -Force
# Driver search places
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchFloppies" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchCD" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -PropertyType DWord -Value 1 -Force
# Driver search places - Don't prompt for Windows Updates
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -PropertyType DWord -Value 1 -Force
# Default driver search order
# FIXME: Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DriverSearching" -Name "SearchOrderConfig" -PropertyType DWord -Value 1 -Force
# DriverSearchPlaces_SearchOrderConfiguration_AlwaysCheckWU
# SearchOrderConfiguration_CheckWUIfNeeded
# SearchOrderConfiguration_NeverCheckWu ^^
# Search Server Configuration
# Windows 7+
# 0 = WU
# 1 = WSUS
# 2 = Both
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DriverSearching" -Name "DriverServerSelection" -PropertyType DWord -Value 1 -Force
# Prevent Device Metadata From Network
# Windows 7+
Set-ItemProperty -Path "HKLM:\OFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -PropertyType DWord -Value 1 -Force






##########################################################
######   				Security Center				######
###### \Software\Microsoft\Windows\CurrentVersion\Explorer
##########################################################
# Turn off Security Center if Domain
# XP+
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows NT\Security Center" -Name "SecurityCenterInDomain" -PropertyType DWord -Value 0 -Force



##########################################################
######   				Explorer.exe				######
###### \Software\Microsoft\Windows\CurrentVersion\Explorer
##########################################################
# Remove "Security" Tab
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoSecurityTab" -PropertyType DWord -Value 1 -Force
# Turn on use of "Radio" Buttons
# Some OEM's preventing changing it via Windows
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\RadioManagement\SystemRadioState" -Name "(Default)" -PropertyType DWord -Value 1 -Force
# Rest Screenshot index
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ScreenshotIndex" -PropertyType DWord -Value 1 -Force
# Show NTFS files compressed in a different color
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCompColor" -PropertyType DWord -Value 0 -Force
# Admin Info URL
# Windows 7+
# FIXME: New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "AdminInfoUrl" -PropertyType DWord -Value 1 -Force
# Disable Roamed Profile
# Windows 8+
#New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "DisableRoamedProfileInit" -PropertyType DWord -Value 1 -Force
# No Heap Termination On Corruption
# Vista+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Explorer" -Name "NoHeapTerminationOnCorruption" -PropertyType DWord -Value 1 -Force
# Turn on and enforce Data Execution Prevention
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableHHDEP" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoDataExecutionPrevention" -PropertyType DWord -Value 0 -Force
# Always Show Classic Menu
# Vista+
#New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "AlwaysShowClassicMenu" -PropertyType DWord -Value 1 -Force
# Prevent Item Creation In Users Files Folder
# Vista+
#New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "PreventItemCreationInUsersFilesFolder" -PropertyType DWord -Value 1 -Force
# Turn off SPI Animations
# Vista+
#New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "TurnOffSPIAnimations" -PropertyType DWord -Value 1 -Force


# Turn off CPLS
# Windows Vista+
#New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "UseDefaultTile" -PropertyType DWord -Value 0 -Force
# No Preview Pane
# Vista+
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoPreviewPane" -PropertyType DWord -Value 1 -Force
# No Reading Pane
# Vista+
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoReadingPane" -PropertyType DWord -Value 1 -Force
# Disable Auto Suggestion in Explorer
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete" -Name "AutoSuggest" -PropertyType String -Value "no"





# Turn off Certificate Updates (DO NOT disable it!)
#New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot" -Name "DisableRootAutoUpdate" -PropertyType DWord -Value 1 -Force
# Turn off Explorer Telemetry
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "TelemetrySalt" -PropertyType DWord -Value 3 -Force
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "TelemetrySalt" -PropertyType DWord -Value 3 -Force
# Turn off connections to Web Services
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoWebServices" -PropertyType DWord -Value 1 -Force
# Turn off Jump Lists
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "EnableXamlJumpView" -PropertyType DWord -Value 1 -Force
# Turn off XAML in Start menu
#Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "EnableXamlStartMenu" -PropertyType DWord -Value 0
# Turn off Experimental Login Screen
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\TestHooks" -Name "Threshold" -PropertyType DWord -Value 1 -Force
# Turn off and hide "People Bar" in Explorer (<=1603+)
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HidePeopleBar" -PropertyType DWord -Value 1
# Hide "Remove Hardware and Eject Media" Button until next reboot
# https://superuser.com/questions/12955/how-can-i-remove-the-option-to-eject-sata-drives-from-the-windows-7-tray-icon
Set-ItemProperty -Path "KCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\SysTray called Services" -Name "Services" -PropertyType DWord -Value 29
# Turn off Thumbs.db thumbnail cache files only on network folders
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbsDBOnNetworkFolders" -PropertyType DWord -Value 1
# Turn on thumbnails
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "IconsOnly" -PropertyType DWord -Value 0
# Turn off thumbnail cache files
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbnailCache" -PropertyType DWord -Value 1
# Turn off restoring previous folder windows at logon
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "PersistBrowsers" -ErrorAction SilentlyContinue
# Turn on "Enable navigation pane expanding to current folder"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneExpandToCurrentFolder" -PropertyType DWord -Value 1
# Turn on Classic Control Panel Icons (small)
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -PropertyType DWord -Value 1
# Turn off 'How do you want to open this file?' prompt
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -PropertyType DWord -Value 1
# Turn off NumLock (usually the keyboard driver/SOFTWARE controls it)
Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -PropertyType DWord -Value 2147483648
#New-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name InitialKeyboardIndicators -PropertyType DWord -Value 2 -Force
#New-ItemProperty -Path "HKCU:\.DEFAULT\Control Panel" -Name "InitialKeyboardIndicators" -PropertyType DWord -Value 2 -Force
# Launch folder in a separate process
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SeparateProcess" -PropertyType DWord -Value 1
# Show accent color on the title bars and window borders
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\DWM" -Name "ColorPrevalence" -PropertyType DWord -Value 1
# Turn off "F1 Help"
New-ItemProperty -Path "HKCU:\SOFTWARE\Classes\Typelib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Name "(default)" -PropertyType String -Value "" -Force
# Turn off Sticky keys prompt (after pressing 5x ALT) (if not working try 506) (FIXME:)
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -PropertyType String -Value "510"
# Turn off Sharing Wizard
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SharingWizardOn" -PropertyType DWord -Value 0
# Turn off JPEG desktop wallpaper import quality compression
# %appdata%\Microsoft\Windows\Themes (transcoded wallpaper store)
New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "JPEGImportQuality" -PropertyType DWord -Value 100 -Force
# Turn on "Ribbon" in File Explorer
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Ribbon" -Name "MinimizedStateTabletModeOff" -PropertyType DWord -Value 0 -Force
# Turn on Show Control shortcut on Desktop
New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -PropertyType DWord -Value 0
# Turn off User Folder shortcut from Desktop
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -ErrorAction SilentlyContinue
# Turn off 3D Objects icon from This PC
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue
New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -PropertyType String -Value "Hide"
# Turn off Documents icon from This PC
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" -Recurse -ErrorAction SilentlyContinue
# Turn on Win32 long paths
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -PropertyType DWord -Value 1 -Force
# Turn off "The Windows Filtering Platform has blocked a connection" message
auditpol /set /subcategory:"{0CCE9226-69AE-11D9-BED3-505054503030}" /success:disable /failure:disable
# Set File Explorer to open to "This PC" by default
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -PropertyType DWord -Value 1 -Force
# Show Hidden Files, Folders and Drives
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -PropertyType DWord -Value 1 -Force
# Show Known File Extensions
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\HideFileExt" -Name "CheckedValue" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -PropertyType DWord -Value 0 -Force
# Hide Task View button on taskbar
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -PropertyType DWord -Value 0 -Force
# Show folder merge conflicts
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideMergeConflicts" -PropertyType DWord -Value 0 -Force
# Turn off "Snap Assist"
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SnapAssist" -PropertyType DWord -Value 0 -Force
# Turn off check boxes to select items
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "AutoCheckSelect" -PropertyType DWord -Value 0 -Force
# Turn off app launch tracking to improve Start menu and search results
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -PropertyType DWord -Value 0 -Force
# Turn off "This PC" on Desktop
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -ErrorAction SilentlyContinue
# Show "more details" by default in file transfer dialog
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -PropertyType DWord -Value 1 -Force
# Turn off AutoPlay for all media and devices
# Win2k+
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -PropertyType DWord -Value 255
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "DontSetAutoplayCheckbox" -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255
#Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -PropertyType DWord -Value 1
# Turn off the "- Shortcut" name extension for new shortcuts
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "link" -PropertyType Binary -Value ([byte[]](0,0,0,0))
# Turn off shortcut icon arrow
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" -Name "29" -PropertyType String -Value "%SystemRoot%\System32\imageres.dll,-1015"
#Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" -Name "29" -ErrorAction SilentlyContinue
# Remove the "Previous Versions" (ShadowCopy) tab from properties context menu
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "NoPreviousVersionsPage" -PropertyType DWord -Value 1 -Force
# Turn off tip, trick, and suggestions as you use Windows
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -PropertyType DWord -Value 0 -Force
# Delete temporary files that apps aren't using
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "04" -PropertyType DWord -Value 1 -Force
# Delete files in recycle bin if they have been there for over 7 days
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "256" -PropertyType DWord -Value 7 -Force
# Never delete files in "Downloads" folder
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "512" -PropertyType DWord -Value 0 -Force
# Turn off content suggestions in Settings.exe
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -PropertyType DWord -Value 0 -Force
# Remove 3D Objects folder in "This PC" and in the navigation pane
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -PropertyType String -Value "Hide" -Force
# Theme color (Dark) for default Windows mode
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "ColorPrevalence" -PropertyType DWord -Value 1 -Force
# Dark Theme Color for Default Windows Mode
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -PropertyType DWord -Value 0 -Force
# Turn off thumbnail cache removal (control via Storage Sense or CCleaner)
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" -Name "Autorun" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" -Name "Autorun" -PropertyType DWord -Value 0 -Force
# Change environment variable from $env:TEMP, $env:SystemDrive\Temp etc
# https://adamtheautomator.com/powershell-set-windows-environment-variables/
IF (-not (Test-Path -Path "$env:SystemDrive\Temp"))
{
	New-Item -Path "$env:SystemDrive\Temp" -ItemType Directory -Force
}
[Environment]::SetEnvironmentVariable("TMP", "$env:SystemDrive\Temp", "User")
New-ItemProperty -Path HKCU:\Environment -Name "TMP" -PropertyType ExpandString -Value "%SystemDrive%\Temp" -Force
[Environment]::SetEnvironmentVariable("TEMP", "$env:SystemDrive\Temp", "User")
New-ItemProperty -Path HKCU:\Environment -Name "TEMP" -PropertyType ExpandString -Value "%SystemDrive%\Temp" -Force
[Environment]::SetEnvironmentVariable("TMP", "$env:SystemDrive\Temp", "Machine")
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name "TMP" -PropertyType ExpandString -Value "%SystemDrive%\Temp" -Force
[Environment]::SetEnvironmentVariable("TEMP", "$env:SystemDrive\Temp", "Machine")
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name "TEMP" -PropertyType ExpandString -Value "%SystemDrive%\Temp" -Force
[Environment]::SetEnvironmentVariable("TMP", "$env:SystemDrive\Temp", "Process")
[Environment]::SetEnvironmentVariable("TEMP", "$env:SystemDrive\Temp", "Process")
# Turn off preserve zone information in file attachments
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -PropertyType DWord -Value 1 -Force
# Turn on recycle bin files delete confirmation
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ConfirmFileDelete" -PropertyType DWord -Value 1 -Force
##########################################################
###### 				Hibernation & Energy			######
##########################################################
# Turn off Hibernation
#Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernateEnabled" -PropertyType DWord -Value 0
#New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type Dword -Value 0
#powercfg /HIBERNATE OFF 2>&1 | Out-Null
# Set power management scheme for Desktop's and Laptop's.
IF ((Get-CimInstance -ClassName Win32_ComputerSystem).PCSystemType -eq 1)
{
	# Set the "High performance" power plan on a Desktop system.
	powercfg /setactive SCHEME_MIN
}
IF ((Get-CimInstance -ClassName Win32_ComputerSystem).PCSystemType -eq 2)
{
	# Enforce "Balanced" for Laptop's (workaround for a bug)!
	powercfg /setactive SCHEME_BALANCED
}
# Do not allow the PC to turn off the device in order to save power (Desktop only)
IF ((Get-CimInstance -ClassName Win32_ComputerSystem).PCSystemType -eq 1)
{
	$adapter = Get-NetAdapter -Physical | Get-NetAdapterPowerManagement
	$adapter.AllowComputerToTurnOffDevice = "Disabled"
	$adapter | Set-NetAdapterPowerManagement
}

##########################################################
###### 			  Application Diagnostics (PCA)	    ######
##########################################################
# Disable PCA UI definition
# Windows 8+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AppCompat" -Name "DisablePcaUI" -PropertyType DWord -Value 1 -Force
# Default install failure policy definition
# Windows Vista+
# FIXME:
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{acfd1ca6-18b6-4ccf-9c07-580cdb6eded4}" -Name "ScenarioExecutionEnabled" -PropertyType DWord -Value 1 -Force
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{acfd1ca6-18b6-4ccf-9c07-580cdb6eded4}" -Name "EnabledScenarioExecutionLevel" -PropertyType DWord -Value 2 -Force
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{acfd1ca6-18b6-4ccf-9c07-580cdb6eded4}" -Name "ScenarioExecutionEnabled" -PropertyType DWord -Value 1 -Force
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{acfd1ca6-18b6-4ccf-9c07-580cdb6eded4}" -Name "EnabledScenarioExecutionLevel" -PropertyType DWord -Value 2 -Force
# Update failure scenario definition
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{081D3213-48AA-4533-9284-D98F01BDC8E6}" -Name "ScenarioExecutionEnabled" -PropertyType DWord -Value 1 -Force
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{081D3213-48AA-4533-9284-D98F01BDC8E6}" -Name "EnabledScenarioExecutionLevel" -PropertyType DWord -Value 1 -Force
# Deprecated component scenario definition
# FIXME:
# 1 = Execution Policy Level Ts Only
# 2 = Execution Policy Level Resolution
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{659F08FB-2FAB-42a7-BD4F-566CFA528769}" -Name "ScenarioExecutionEnabled" -PropertyType DWord -Value 1 -Force
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{659F08FB-2FAB-42a7-BD4F-566CFA528769}" -Name "ScenarioExecutionEnabled" -PropertyType DWord -Value 1 -Force
# Deprecated COM component scenario definition
# Windows Vista+
# 1 = Execution Policy Level Ts Only
# 2 = Execution Policy Level Resolution
# FIXME:
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{88D69CE1-577A-4dd9-87AE-AD36D3CD9643}" -Name "ScenarioExecutionEnabled" -PropertyType DWord -Value 1 -Force
# Undetected installers scenario definition
# Windows Vista+
# 1 = Execution Policy Level Ts Only
# 2 = Execution Policy Level Resolution
# FIXME:
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{D113E4AA-2D07-41b1-8D9B-C065194A791D}" -Name "ScenarioExecutionEnabled" -PropertyType DWord -Value 1 -Force
# Begin blocked drivers scenario definition
# Windows Vista+
# FIXME:
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{affc81e2-612a-4f70-6fb2-916ff5c7e3f8}" -Name "ScenarioExecutionEnabled" -PropertyType DWord -Value 1 -Force
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{affc81e2-612a-4f70-6fb2-916ff5c7e3f8}" -Name "EnabledScenarioExecutionLevel" -PropertyType DWord -Value 2 -Force
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{affc81e2-612a-4f70-6fb2-916ff5c7e3f8}" -Name "ScenarioExecutionEnabled" -PropertyType DWord -Value 1 -Force
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{affc81e2-612a-4f70-6fb2-916ff5c7e3f8}" -Name "EnabledScenarioExecutionLevel" -PropertyType DWord -Value 2 -Force



##########################################################
###### 					Context Menu 				######
##########################################################
# Add a 'Take Owner' option in your right-click menu
# FIXME:
reg add "HKEY_CLASSES_ROOT\*\shell\runas" /ve /t REG_SZ /d "Take Ownership" /f
reg add "HKEY_CLASSES_ROOT\*\shell\runas" /v NoWorkingDirectory /t REG_SZ /d "" /f
reg add "HKEY_CLASSES_ROOT\*\shell\runas\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \`"%1\`" && icacls \`"%1\`" /grant administrators:F" /f
reg add "HKEY_CLASSES_ROOT\*\shell\runas\command" /v IsolatedCommand /t REG_SZ /d "cmd.exe /c takeown /f \`"%1\`" && icacls \`"%1\`" /grant administrators:F" /f
New-Item -ErrorAction SilentlyContinue -Force -Path "HKCR:\Directory\shell\runas"
New-Item -ErrorAction SilentlyContinue -Force -Path "HKCR:\Directory\shell\runas\command"
New-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKCR:\Directory\shell\runas" -Name "(Default)" -Value "Take Ownership"
New-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKCR:\Directory\shell\runas" -Name "NoWorkingDirectory" -Value ""
New-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKCR:\Directory\shell\runas\command" -Name "(Default)" -Value "cmd.exe /c takeown /f `"%1`" /r /d y && icacls `"%1`" /grant administrators:F /t"
New-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKCR:\Directory\shell\runas\command" -Name "IsolatedCommand" -Value "cmd.exe /c takeown /f `"%1`" /r /d y && icacls `"%1`" /grant administrators:F /t"
#
#
# Add "Run as Administrator" context menu for .ps1 files
New-Item -Path "Registry::HKEY_CLASSES_ROOT\Microsoft.PowershellScript.1\Shell\runas\command" -Force -Name "" -Value '"C:\windows\system32\windowspowershell\v1.0\powershell.exe" -noexit -file "%1"'
# Add Photo Viewer 'Open with...'
If (!(Test-Path "HKCR:")) {
    New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
}
New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Force | Out-Null
New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\DropTarget" -Force | Out-Null
Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open" -Name "MuiVerb" -PropertyType String -Value "@photoviewer.dll,-3043"
Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Name "(Default)" -PropertyType ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open\DropTarget" -Name "Clsid" -PropertyType String -Value "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}"
# Remove "Edit with Photos" from context menu
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellEdit" -Name "ProgrammaticAccessOnly" -PropertyType String -Value "" -Force
# Remove "Create a new video" from Context Menu
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellCreateVideo" -Name "ProgrammaticAccessOnly" -PropertyType String -Value "" -Force
# Remove "Edit" from Context Menu
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\SystemFileAssociations\image\shell\edit" -Name "ProgrammaticAccessOnly" -PropertyType String -Value "" -Force
# Remove "Print" from batch and cmd files context menu
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\batfile\shell\print" -Name "ProgrammaticAccessOnly" -PropertyType String -Value "" -Force
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\cmdfile\shell\print" -Name "ProgrammaticAccessOnly" -PropertyType String -Value "" -Force
# Remove "Compressed (zipped) Folder" from context menu
Remove-Item -Path "HKCU:\HKEY_CLASSES_ROOT\.zip\CompressedFolder\ShellNew" -Force -ErrorAction SilentlyContinue
# Remove "Rich Text Document" from context menu
Remove-Item -Path "HKCU:\HKEY_CLASSES_ROOT\.rtf\ShellNew" -Force -ErrorAction SilentlyContinue
# Remove "Bitmap image" from context menu
Remove-Item -Path "HKCU:\HKEY_CLASSES_ROOT\.bmp\ShellNew" -Force -ErrorAction SilentlyContinue
# Remove "Send to" from folder context menu
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\SendTo" -Name "(default)" -PropertyType String -Value "" -Force
# Enforce FIPS standards
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy" -Name "Enabled" -PropertyType -PropertyType DWord -Value 1 -Force
# Remove "Include in Library" from context menu
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\Folder\shellex\ContextMenuHandlers\Library Location" -Name "(default)" -PropertyType String -Value "-{3dad6c5d-2167-4cae-9914-f99e41c12cfa}" -Force
# Remove "Turn on BitLocker" from context menu because I prefer VeraCrypt (as a private person NOT in an Ent. enviorment!)
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\Drive\shell\encrypt-bde" -Name "ProgrammaticAccessOnly" -PropertyType String -Value "" -Force
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\Drive\shell\encrypt-bde-elev" -Name "ProgrammaticAccessOnly" -PropertyType String -Value "" -Force
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\Drive\shell\manage-bde" -Name "ProgrammaticAccessOnly" -PropertyType String -Value "" -Force
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\Drive\shell\resume-bde" -Name "ProgrammaticAccessOnly" -PropertyType String -Value "" -Force
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\Drive\shell\resume-bde-elev" -Name "ProgrammaticAccessOnly" -PropertyType String -Value "" -Force
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\Drive\shell\unlock-bde" -Name "ProgrammaticAccessOnly" -PropertyType String -Value "" -Force
# Remove "Edit with Paint 3D" from context menu
$exts = @(".bmp", ".gif", ".jpe", ".jpeg", ".jpg", ".png", ".tif", ".tiff")
foreach ($ext in $exts)
{
	New-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\$ext\Shell\3D Edit" -Name "ProgrammaticAccessOnly" -PropertyType String -Value "" -Force
}
# Remove "Previous Versions" from file context menu, we disabled ShadowCopy and using Macrium Reflect instead.
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{596AB062-B4D2-4215-9F74-E9109B0A8153}" -PropertyType String -Value "" -Force
# Remove "Cast to Device" from context menu
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{7AD84985-87B4-4a16-BE58-8B72A5B390F7}" -PropertyType String -Value "Play to menu" -Force
# Remove "Share" from context menu
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{E2BF9676-5F8F-435C-97EB-11607A5BEDF7}" -PropertyType String -Value "" -Force
# Make the "Open", "Print", "Edit" context menu items available, when more than 15 selected
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "MultipleInvokePromptMinimum" -PropertyType DWord -Value 300 -Force
# Turn off "Look for an app in the Microsoft Store" in "Open with" dialog
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -PropertyType DWord -Value 1
# Add "Extract" to .MSI file type context menu
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\Msi.Package\shell\Extract\Command" -Name "(default)" -PropertyType String -Value "msiexec.exe /a `"%1`" /qb TARGETDIR=`"%1 extracted`"" -Force
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\Msi.Package\shell\Extract" -Name "MUIVerb" -PropertyType String -Value "@shell32.dll,-31382" -Force
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\Msi.Package\shell\Extract" -Name "Icon" -PropertyType String -Value "shell32.dll,-16817" -Force
# Add "Run as different user" from context menu for .exe file type
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\exefile\shell\runasuser" -Name "(default)" -PropertyType String -Value "@shell32.dll,-50944" -Force
Remove-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\exefile\shell\runasuser" -Name "Extended" -Force -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\exefile\shell\runasuser" -Name "SuppressionPolicyEx" -PropertyType String -Value "{F211AA05-D4DF-4370-A2A0-9F19C09756A7}" -Force
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\exefile\shell\runasuser\command" -Name "DelegateExecute" -PropertyType String -Value "{ea72d00e-4960-42fa-ba92-7792a7944c1d}" -Force
# Add "Install" to CAB file type context menu
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\CABFolder\Shell\RunAs\Command" -Name "(default)" -PropertyType String -Value "cmd /c DISM /Online /Add-Package /PackagePath:`"%1`" /NoRestart & pause" -Force
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\CABFolder\Shell\RunAs" -Name "MUIVerb" -PropertyType String -Value "@shell32.dll,-10210" -Force
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\CABFolder\Shell\RunAs" -Name "HasLUAShield" -PropertyType String -Value "" -Force
##########################################################
######  				Printer						######
##########################################################
# Do not allow Windows 10 to manage default printer
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -Name "LegacyDefaultPrinterMode" -PropertyType DWord -Value 1 -Force
# Register Spooler Remote RPC EndPoint
#New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows NT\Printers" -Name "RegisterSpoolerRemoteRpcEndPoint" -PropertyType DWord -Value 2 -Force
# Auto publish printer
# Win2+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\Wizard" -Name "Auto Publishing" -PropertyType DWord -Value 0 -Force
# Prune Down level
# 0 = Never
# 1 = Found
# 2 = Not found
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name "PruneDownlevel" -PropertyType DWord -Value 0 -Force
# Pruning Interval Title
# 0 = Immediately
# 10 = 10 Minutes
# 30 = 30 Minutes
# 60 = 1 Hour
# 240 = 4 Hours
# 480 = 8 Hours
# 720 = 12 Hours
# 1440 = 1 Day
# 2880 = 2 Days
# 4320 = 3 Days
# 5760 = 4 Days
# 7200 = 5 Days
# 8640 = 6 Days
# 10080 = 1 Week
# 20160 = 2 Weeks
# 30240 = 3 Weeks
# 40320 = 4 Weeks
# 50400 = 5 Weeks
# 60480 = 6 Weeks
# 70560 = 7 Weeks
# 4294967295 = Never
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name "PruningIntervalTitle" -PropertyType DWord -Value 0 -Force
# Pruning Priority
# 4294967294 = Lowest
# 4294967295 = Below Normal
# 0 = Normal
# 1 = Above Normal
# 2 = Highest
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name "PruningPriority" -PropertyType DWord -Value 0 -Force
# Pruning Retries
# XP+
# 0 = 0 Retries
# 1 = 1
# 2 = 2
# 3 = 3
# 4 = 4
# 5 = 5
# 6 = 6
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\Wizard" -Name "PruningRetries" -PropertyType DWord -Value 0 -Force
# Verify Published State
# Win2k+
# 30 = 30 Minutes
# 60 = 1 Hour
# 240 = 4 Hours
# 480 = 8 Hours
# 720 = 12 Hours
# 1440 = 1 Day
# 4294967295 = Never
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\Wizard" -Name "VerifyPublishedState" -PropertyType DWord -Value 0 -Force
# Never Delete (Immortal)
# Win2k+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\Wizard" -Name "Immortal" -PropertyType DWord -Value 0 -Force

##########################################################
######  				 Taskbar			        ######
##########################################################
# Hide SCA Power (Battery Icon)
# Default 0
# Vista+
#New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAPower" -PropertyType DWord -Value 0 -Force
# Hide SCA Network (Network Icon)
# Default 0
# Vista+
#New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCANetwork" -PropertyType DWord -Value 0 -Force
# Hide SCA Volume (Volume Mixer Icon)
# Default 0
# Vista+
#New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAVolume" -PropertyType DWord -Value 0 -Force
# Hide SCA Health (Health Icon)
# Default 0
# Vista+
#New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAHealth" -PropertyType DWord -Value 0 -Force
# Hide Lock All Icons
# Default 0
# Vista+
#New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "TaskbarLockAll" -PropertyType DWord -Value 0 -Force








##########################################################
######  				 Event Log				    ######
##########################################################
# Auto backup logs
# Vista+
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application" -Name "AutoBackupLogFiles" -PropertyType DWord -Value 0 -Force
# Application logs (Channel)
# Vista+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application" -Name "ChannelAccess" -PropertyType DWord -Value 1 -Force
# Application logs (Channel)
# Vista+
# FIXME: New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application" -Name "CustomSD" -PropertyType DWord -Value 1 -Force
# Log Retention
# Vista+
# FIXME: New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application" -Name "Retention" -PropertyType DWord -Value 1 -Force
# Log File Path
# Vista+
# FIXME: New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application" -Name "File" -PropertyType DWord -Value 1 -Force
# Log Max Size
# Vista+
# Min = 1024
# Max = 2147483647
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application" -Name "MaxSize" -PropertyType DWord -Value 7483647 -Force
# AutoBackup Log Files (Security Logs)
# Vista+
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security" -Name "AutoBackupLogFiles" -PropertyType DWord -Value 0 -Force
# AutoBackup Log Files (Security Logs)
# Vista+
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security" -Name "AutoBackupLogFiles" -PropertyType DWord -Value 0 -Force
# Application logs (Security)
# Vista+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security" -Name "ChannelAccess" -PropertyType DWord -Value 0 -Force
# Application logs (Security)
# Vista+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security" -Name "CustomSD" -PropertyType DWord -Value 0 -Force
# Log Retention
# Vista+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security" -Name "Retention" -PropertyType DWord -Value 0 -Force
# Log Max Size (Security)
# Vista+
# Min = 20480
# Max = 2147483647
# FIXME: New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security" -Name "MaxSize" -PropertyType DWord -Value 20480 -Force
# Log Auto Backup (Setup)
# Vista+
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Setup" -Name "AutoBackupLogFiles" -PropertyType DWord -Value 0 -Force
# Channel Access to Setup Logs
# Vista+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Setup" -Name "ChannelAccess" -PropertyType DWord -Value 0 -Force
# File Log Access
# Vista+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Setup" -Name "CustomSD" -PropertyType DWord -Value 0 -Force
# Log File Retention
# Vista+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Setup" -Name "Retention" -PropertyType DWord -Value 0 -Force
# Turn on Setup Logs
# Default
# Vista+
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Setup" -Name "Enabled" -PropertyType DWord -Value 1 -Force
# Log File Path (Setup Logs)
# Vista+
# FIXME: New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Setup" -Name "File" -PropertyType DWord -Value 1 -Force
# Max Size (Setup Logs)
# Vista+
# Min = 1024
# Max = 2147483647
# FIXME: New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Setup" -Name "MaxSize" -PropertyType DWord -Value 1024 -Force
# Disable Auto Backup Log Files (Event Log)
# Vista+
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\System" -Name "AutoBackupLogFiles" -PropertyType DWord -Value 0 -Force
# Channel Access (Event Log)
# Vista+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\System" -Name "ChannelAccess" -PropertyType DWord -Value 0 -Force
# Channel Access (Event Log)
# Vista+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\System" -Name "CustomSD" -PropertyType DWord -Value 0 -Force
# Retention (Event Log)
# Vista+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\System" -Name "Retention" -PropertyType DWord -Value 0 -Force
# Log File Path (Event Log)
# Vista+
# FIXME: New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\System" -Name "File" -PropertyType DWord -Value 0 -Force
# Log File MAx Size (Event Log)
# Vista+
# Min = 1024
# Max = 2147483647
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\System" -Name "MaxSize" -PropertyType DWord -Value 1024 -Force









##########################################################
######  				 DMA Guard				    ######
#  DisplayName values do not match the registry values!  #
##########################################################
# Turn on Kernel DMA Protection
# Windows 10
# 0 = (option 3) -> "Block all"
# 1 = (option 2) -> "Only while logged in"
# 2 = (option 3) -> "Allow all"
# FIXME: New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Kernel DMA Protection" -Name "DeviceEnumerationPolicy" -PropertyType DWord -Value 1 -Force




##########################################################
######  				Exploit Guard				######
##########################################################
# Turn on Exploit Protection
# Windows 10 RS3+
# May length is 65535
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender ExploitGuard\Exploit Protection" -Name "ExploitProtectionSettings" -PropertyType DWord -Value 0 -Force
# You don't have to enable or change it because guess what? it's enabled by default and a hidden pref since 1809+!
# There is no suggestion from my site to set something specific there because app breakage + that's user based and biased tab in Wd.



##########################################################
###### 				    Logon                       ######
##########################################################
# Disable Blur (Acrylic) wallpaper background
# Windows 10 RS6+ (1903+)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableAcrylicBackgroundOnLogon" -PropertyType Dword -Value 1 -Force
# Disable Legacy Explorer
# Win2k+
#Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "DisableCurrentUserRun" -PropertyType Dword -Value 1 -Force
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "DisableCurrentUserRun" -PropertyType Dword -Value 1 -Force
# Disable Explorer Run Once
# Win2k+
#Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "DisableCurrentUserRunOnce" -PropertyType Dword -Value 1 -Force
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "DisableCurrentUserRunOnce" -PropertyType Dword -Value 1 -Force
# Logon Type
# XP - 7
#Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LogonType" -PropertyType Dword -Value 1 -Force
# No welcome tips
# Win2k only
#Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoWelcomeScreen" -PropertyType Dword -Value 1 -Force
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoWelcomeScreen" -PropertyType Dword -Value 1 -Force
# Sync Foreground Policy
# Windows XP+
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "SyncForegroundPolicy" -PropertyType Dword -Value 1 -Force
# Disable Status Messages
# pre Vista
#Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableStatusMessages" -PropertyType Dword -Value 1 -Force
# Hide Fast User Switching
# Vista - 7
#Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "HideFastUserSwitching" -PropertyType Dword -Value 1 -Force
# Diable Startup Sound
# Vista+
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableStartupSound" -PropertyType Dword -Value 1 -Force
# Use OEM Background
# Windows 7 only
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "UseOEMBackground" -PropertyType Dword -Value 0 -Force
# Hide the Network Selection UI
# Windows 8+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -PropertyType Dword -Value 1 -Force
# Dont Enumerate Connected Users
# Windows 8+
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DontEnumerateConnectedUsers" -PropertyType Dword -Value 1 -Force
# Block User From Showing Account Details On Signin
# Windows 10+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "BlockUserFromShowingAccountDetailsOnSignin" -PropertyType Dword -Value 1 -Force
# Turn off Lock Screen app notifications
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableLockScreenAppNotifications" -PropertyType DWord -Value 1



##########################################################
######  				LanmanWorkstation			######
##########################################################
# Turn off insecure guest logons
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -Name "AllowInsecureGuestAuth" -PropertyType DWord -Value 0 -Force
#Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\LanmanWorkstation" -Name "AllowInsecureGuestAuth" -PropertyType DWord -Value 0
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -Name "AllowInsecureGuestAuth" -PropertyType DWord -Value 0 -Force
# Default cipher suitde order
# FIXME: New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation" -Name "CipherSuiteOrder" -PropertyType DWord -Value 0 -Force
# Turn off Offline files fpr CA shares
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -Name "AllowOfflineFilesforCAShares" -PropertyType DWord -Value 1 -Force
# Turn on caching for CA files
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -Name "EnableHandleCachingForCAFiles" -PropertyType DWord -Value 1 -Force




##########################################################
######  			Folder Redirections			    ######
##########################################################
# Turn off Spotlight (not needed since 1603+)
# Windows XP
# (NOSERVER)
#New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\System\Fdeploy" -Name "DisableFRAdminPin" -PropertyType DWord -Value 1 -Force
# Localize XP Relative Path
# Vista+
#New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\System\Fdeploy" -Name "LocalizeXPRelativePaths" -PropertyType DWord -Value 1 -Force
# Disable "Pin to" Folders (FRA)
# Windows 8+
<#

New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\NetCache\{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}" -Name "DisableFRAdminPinByFolder" -PropertyType DWord -Value 1 -Force
# Desktop
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\NetCache\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" -Name "DisableFRAdminPinByFolder" -PropertyType DWord -Value 1 -Force
# StartMenu
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\NetCache\{625B53C3-AB48-4EC1-BA1F-A1EF4146FC19}" -Name "DisableFRAdminPinByFolder" -PropertyType DWord -Value 1 -Force
# Documents
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\NetCache\{FDD39AD0-238F-46AF-ADB4-6C85480369C7}" -Name "DisableFRAdminPinByFolder" -PropertyType DWord -Value 1 -Force
# Pictures
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\NetCache\{33E28130-4E1E-4676-835A-98395C3BC3BB}" -Name "DisableFRAdminPinByFolder" -PropertyType DWord -Value 1 -Force
# Music
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\NetCache\{4BD8D571-6D19-48D3-BE97-422220080E43}" -Name "DisableFRAdminPinByFolder" -PropertyType DWord -Value 1 -Force
# Videos
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\NetCache\{18989B1D-99B5-455B-841C-AB7C74E4DDFC}" -Name "DisableFRAdminPinByFolder" -PropertyType DWord -Value 1 -Force
# Favorites
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\NetCache\{1777F761-68AD-4D8A-87BD-30B759FA33DD}" -Name "DisableFRAdminPinByFolder" -PropertyType DWord -Value 1 -Force
# Contacts
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\NetCache\{56784854-C6CB-462b-8169-88E350ACB882}" -Name "DisableFRAdminPinByFolder" -PropertyType DWord -Value 1 -Force
# Downloads
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\NetCache\{374DE290-123F-4565-9164-39C4925E467B}" -Name "DisableFRAdminPinByFolder" -PropertyType DWord -Value 1 -Force
# Links
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\NetCache\{BFB9D5E0-C6A9-404C-B2B2-AE6DB6AF4968}" -Name "DisableFRAdminPinByFolder" -PropertyType DWord -Value 1 -Force
# Searches
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\NetCache\{7D1D3A04-DEBB-4115-95CF-2F29DA2920DA}" -Name "DisableFRAdminPinByFolder" -PropertyType DWord -Value 1 -Force
# Saved Games
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\NetCache\{4C5C32FF-BB9D-43B0-B5B4-2D72E54EAAA4}" -Name "DisableFRAdminPinByFolder" -PropertyType DWord -Value 1 -Force

#>
# Localize XP Relative Paths
# Vista+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System\Fdeploy" -Name "LocalizeXPRelativePaths" -PropertyType DWord -Value 1 -Force
# Redirection Enable Cache Rename
# Windows 8+
#New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\System\Fdeploy" -Name "FolderRedirectionEnableCacheRename" -PropertyType DWord -Value 1 -Force
# Redirection Enable Cache Rename
# Windows 8+
#New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\System\Fdeploy" -Name "PrimaryComputerEnabledFR" -PropertyType DWord -Value 1 -Force
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System\Fdeploy" -Name "PrimaryComputerEnabledFR" -PropertyType DWord -Value 1 -Force



##########################################################
######  				    QOS              		######
##########################################################
# Qos Service Type Best Effort
# XP+
# Needs {426031c0-0b47-4852-b0ca-ac3d37bfcb39}
# Max value = 63
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Psched\DiffservByteMappingConforming" -Name "ServiceTypeBestEffort" -PropertyType DWord -Value 50 -Force
# Qos Service Type Controlled Load
# XP+
# Needs {426031c0-0b47-4852-b0ca-ac3d37bfcb39}
# Max value = 63
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Psched\DiffservByteMappingConforming" -Name "ServiceTypeControlledLoad" -PropertyType DWord -Value 50 -Force
# Qos Service Type Guaranteed
# XP+
# Needs {426031c0-0b47-4852-b0ca-ac3d37bfcb39}
# Max value = 63
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Psched\DiffservByteMappingConforming" -Name "ServiceTypeGuaranteed" -PropertyType DWord -Value 50 -Force
# Service Type Network Control
# XP+
# Needs {426031c0-0b47-4852-b0ca-ac3d37bfcb39}
# Max value = 63
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Psched\DiffservByteMappingConforming" -Name "ServiceTypeNetworkControl" -PropertyType DWord -Value 50 -Force
# Service Type Qualitative
# XP+
# Needs {426031c0-0b47-4852-b0ca-ac3d37bfcb39}
# Max value = 63
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Psched\DiffservByteMappingConforming" -Name "ServiceTypeQualitative" -PropertyType DWord -Value 50 -Force
# Service Type Best Effort NC
# XP+
# Needs {426031c0-0b47-4852-b0ca-ac3d37bfcb39}
# Max value = 63
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Psched\DiffservByteMappingConforming" -Name "ServiceTypeBestEffort" -PropertyType DWord -Value 50 -Force
# Service Type Best Effort NC
# XP+
# Needs {426031c0-0b47-4852-b0ca-ac3d37bfcb39}
# Max value = 63
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Psched\DiffservByteMappingConforming" -Name "ServiceTypeControlledLoad" -PropertyType DWord -Value 50 -Force
# Service Type Guaranteed
# XP+
# Needs {426031c0-0b47-4852-b0ca-ac3d37bfcb39}
# Max value = 63
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Psched\DiffservByteMappingConforming" -Name "ServiceTypeGuaranteed" -PropertyType DWord -Value 25 -Force
# Service TypeNetwork Control over NC
# XP+
# Needs {426031c0-0b47-4852-b0ca-ac3d37bfcb39}
# Max value = 63
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Psched\DiffservByteMappingConforming" -Name "ServiceTypeNetworkControl" -PropertyType DWord -Value 25 -Force
# Qos Service Type Qualitative over NC
# XP+
# Needs {426031c0-0b47-4852-b0ca-ac3d37bfcb39}
# Max value = 63
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Psched\DiffservByteMappingConforming" -Name "ServiceTypeQualitative" -PropertyType DWord -Value 25 -Force
# Max Outstanding Sends
# XP+
# Needs {426031c0-0b47-4852-b0ca-ac3d37bfcb39}
# Max value = 4000000000
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Psched" -Name "MaxOutstandingSends" -PropertyType DWord -Value 4000000000 -Force
# Non Best Effort Limit
# XP+
# Needs {426031c0-0b47-4852-b0ca-ac3d37bfcb39}
# Max value = 100
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Psched" -Name "NonBestEffortLimit" -PropertyType DWord -Value 100 -Force
# TimerResolution
# XP+
# Needs {426031c0-0b47-4852-b0ca-ac3d37bfcb39}
# Max value = 4000000000
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Psched" -Name "TimerResolution" -PropertyType DWord -Value 4000000000 -Force
# Service Type Best Effort PV
# XP+
# Needs {426031c0-0b47-4852-b0ca-ac3d37bfcb39}
# Max value = 7
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Psched" -Name "ServiceTypeBestEffort" -PropertyType DWord -Value 7 -Force
# Service Type Controlled Load over PV
# XP+
# Needs {426031c0-0b47-4852-b0ca-ac3d37bfcb39}
# Max value = 7
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Psched" -Name "ServiceTypeControlledLoad" -PropertyType DWord -Value 7 -Force
# Service Type Guaranteed PV
# XP+
# Needs {426031c0-0b47-4852-b0ca-ac3d37bfcb39}
# Max value = 7
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Psched\UserPriorityMapping" -Name "ServiceTypeGuaranteed" -PropertyType DWord -Value 7 -Force
# Service Type Network Control PV
# XP+
# Needs {426031c0-0b47-4852-b0ca-ac3d37bfcb39}
# Max value = 7
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Psched\UserPriorityMapping" -Name "ServiceTypeNetworkControl" -PropertyType DWord -Value 7 -Force
# Service Type Non Conforming
# XP+
# Needs {426031c0-0b47-4852-b0ca-ac3d37bfcb39}
# Max value = 7
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Psched\UserPriorityMapping" -Name "ServiceTypeNonConforming" -PropertyType DWord -Value 7 -Force
# Service Type Qualitative PV
# XP+
# Needs {426031c0-0b47-4852-b0ca-ac3d37bfcb39}
# Max value = 7
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Psched\UserPriorityMapping" -Name "ServiceTypeQualitative" -PropertyType DWord -Value 7 -Force


##########################################################
######  		            P2P       		        ######
##########################################################
# Turn off Microsoft Peer-to-Peer Networking Services
# XP SP2+
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Peernet" -Name "Disabled" -PropertyType DWord -Value 1 -Force
# Disable Multicast Bootstrap
# XP SP2+
#New-ItemProperty -Path "HKLM:\Software\policies\Microsoft\Peernet\Pnrp\IPv6-Global" -Name "DisableMulticastBootstrap" -PropertyType DWord -Value 1 -Force
# PNRP
# XP SP2+
#New-ItemProperty -Path "HKLM:\Software\policies\Microsoft\Peernet\Pnrp\IPv6-Global" -Name "Disabled" -PropertyType DWord -Value 1 -Force
# PNRP -Search only
# XP SP2+
#New-ItemProperty -Path "HKLM:\Software\policies\Microsoft\Peernet\Pnrp\IPv6-Global" -Name "SearchOnly" -PropertyType DWord -Value 1 -Force
# PNRP - Seed Server
# XP SP2+
# FIXME: New-ItemProperty -Path "HKLM:\Software\policies\Microsoft\Peernet\Pnrp\IPv6-Global" -Name "SeedServer" -PropertyType DWord -Value 1 -Force
#New-ItemProperty -Path "HKLM:\Software\policies\Microsoft\Peernet\Pnrp\IPv6-Global" -Name "DontIncludeMicrosoftSeedServer" -PropertyType DWord -Value 1 -Force
# PNRP - Disable Multicast Bootstrap
# XP SP2+
#New-ItemProperty -Path "HKLM:\Software\policies\Microsoft\Peernet\Pnrp\IPv6-LinkLocal" -Name "DisableMulticastBootstrap" -PropertyType DWord -Value 1 -Force
# PNRP - Disabled
# XP SP2+
#New-ItemProperty -Path "HKLM:\Software\policies\Microsoft\Peernet\Pnrp\IPv6-LinkLocal" -Name "Disabled" -PropertyType DWord -Value 1 -Force
# PNRP - Search only
# XP SP2+
#New-ItemProperty -Path "HKLM:\Software\policies\Microsoft\Peernet\Pnrp\IPv6-LinkLocal" -Name "SearchOnly" -PropertyType DWord -Value 1 -Force
# PNRP - Seed Server
# XP SP2+
# FIXME: New-ItemProperty -Path "HKLM:\Software\policies\Microsoft\Peernet\Pnrp\IPv6-LinkLocal" -Name "SeedServer" -PropertyType DWord -Value 1 -Force
# PNRP - Disable Multicast Bootstrap
# XP SP2+
#New-ItemProperty -Path "HKLM:\Software\policies\Microsoft\Peernet\Pnrp\IPv6-SiteLocal" -Name "DisableMulticastBootstrap" -PropertyType DWord -Value 1 -Force
# PNRP - Disabled
# XP SP2+
#New-ItemProperty -Path "HKLM:\Software\policies\Microsoft\Peernet\Pnrp\IPv6-SiteLocal" -Name "Disabled" -PropertyType DWord -Value 1 -Force
# PNRP - Search Only
# XP SP2+
#New-ItemProperty -Path "HKLM:\Software\policies\Microsoft\Peernet\Pnrp\IPv6-SiteLocal" -Name "SearchOnly" -PropertyType DWord -Value 1 -Force
# PNRP - Seed Server
# XP SP2+
#New-ItemProperty -Path "HKLM:\Software\policies\Microsoft\Peernet\Pnrp\IPv6-SiteLocal" -Name "SeedServer" -PropertyType DWord -Value 1 -Force
# PNRP - Disable Password Policy Enforcement
# XP Vista+
#New-ItemProperty -Path "HKLM:\Software\policies\Microsoft\Peernet" -Name "IgnoreDomainPasswordPolicyForNewGroups" -PropertyType DWord -Value 0 -Force



##########################################################
######  		    Peer To Peer Caching       		######
##########################################################
# Enable Windows Branch Cache
# Windows 7+ (BITS 4.0+)
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PeerDist\Service" -Name "Enable" -PropertyType DWord -Value 0 -Force
# Set Cache Percent
# Windows 7+ (BITS 4.0+)
# Min = 1%
# Max = 100%
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PeerDist\Service" -Name "SizePercent" -PropertyType DWord -Value 1 -Force
# Enable Windows BranchCache - Hosted
# Windows 7+ (BITS 4.0+)
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PeerDist\HostedCache\Connection" -Name "Location" -PropertyType DWord -Value 1 -Force
# Enable Windows BranchCache - Distributed
# Windows 7+ (BITS 4.0+)
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PeerDist\CooperativeCaching" -Name "Enable" -PropertyType DWord -Value 0 -Force
# Enable Windows BranchCache - SMB
# Windows 7+ (BITS 4.0+)
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\NetCache" -Name "PeerCachingLatencyThreshold" -PropertyType DWord -Value 100000000 -Force
# Enable Windows BranchCache - Hosted Cache Discovery
# Windows 8+
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PeerDist\HostedCache\Discovery" -Name "SCPDiscoveryEnabled" -PropertyType DWord -Value 0 -Force
# Enable Windows BranchCache - Hosted Cache Discovery
# Windows 8+
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PeerDist\Service\Versioning" -Name "PreferredContentInformationVersion" -PropertyType DWord -Value 2 -Force





##########################################################
######  				    KDC           	    	######
##########################################################
# Policies KDC
# Windows Vista+
#New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters" -Name "EmitLILI" -PropertyType DWord -Value 1 -Force
# Forest Search
# Windows Vista+
#New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters" -Name "UseForestSearch" -PropertyType DWord -Value 0 -Force
# Forest Search List
# Windows 8+
#New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters" -Name "ForestSearchList" -PropertyType DWord -Value 0 -Force
# Cbac and Armor
# Windows 8+
#New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters" -Name "EnableCbacAndArmor" -PropertyType DWord -Value 0 -Force
# Cbac and Armor Level
# Windows 8+
# 0 = NoCbacAndArmor
# 1 = MixModeCbacAndArmor
# 2 = FullModeCbacAndArmor
# 3 = FullModeCbacAndRequireArmor
#New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters" -Name "CbacAndArmorLevel" -PropertyType DWord -Value 0 -Force
# Ticket Size Threshold
# Windows 8+
# Min = c (it's not a typo)
# Max = 2147483647
#New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters" -Name "EnableTicketSizeThreshold" -PropertyType DWord -Value 2147483647 -Force
# Request Compound ID
# Windows 10+
#New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters" -Name "RequestCompoundId" -PropertyType DWord -Value 1 -Force
# PKINIT Freshness
# Windows 10+
# 0 = NoPKINITFreshness
# 1 = SupportPKINITFreshness
# 2 = RequirePKINITFreshness
#New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters" -Name "PKINITFreshness" -PropertyType DWord -Value 2 -Force



##########################################################
######  				MSI Installer          		######
##########################################################
# Allow Lockdown Browse
# Win 2k+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name "AllowLockdownBrowse -PropertyType DWord -Value 1 -Force
# Allow Lockdown Media
# Win 2k+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name "AllowLockdownMedia" -PropertyType DWord -Value 1 -Force
# Allow Lockdown Patch
# Win 2k+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name "AllowLockdownPatch" -PropertyType DWord -Value 1 -Force
# Always Install Elevated
# Win 2k+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -PropertyType DWord -Value 0 -Force
# Disable Automatic Application Shutdown
# Win 2k+
# 0 = ApplicationShutdown On
# 1 = ApplicationShutdown Off
# 2 = Automatic Application Shutdown Off
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name "DisableAutomaticApplicationShutdown" -PropertyType DWord -Value 0 -Force
# Disable Browse
# Win 2k+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name "DisableBrowse" -PropertyType DWord -Value 0 -Force
# Disable Flyweight Patching
# Win 2k+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name "DisableFlyweightPatching" -PropertyType DWord -Value 0 -Force
# Disable Logging From Package
# Win 2k+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name "DisableLoggingFromPackage" -PropertyType DWord -Value 0 -Force
# Disable Media
# Win 2k+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name "DisableMedia" -PropertyType DWord -Value 0 -Force
# Disable MSI
# Win 2k+
# 0 = Never
# 1 = Non Managed
# 2 = Disabled Always
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name "DisableMSI" -PropertyType DWord -Value 0 -Force
# Disable Patch
# Win 2k+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name "DisablePatch" -PropertyType DWord -Value 0 -Force
# Disable Rollback
# Win 2k+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name "DisableRollback" -PropertyType DWord -Value 0 -Force
#New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Installer" -Name "DisableRollback" -PropertyType DWord -Value 0 -Force
# Enable User Control
# Win 2k+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name "EnableUserControl" -PropertyType DWord -Value 1 -Force
# MSI - Disable LUA Patching
# Win 2k+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name "DisableLUAPatching" -PropertyType DWord -Value 1 -Force
# MSI - Disable Patch Uninstall
# Win 2k+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name "DisablePatchUninstall" -PropertyType DWord -Value 1 -Force
# MSI - Disable SR Check Points
# Win 2k+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name "LimitSystemRestoreCheckpointing" -PropertyType DWord -Value 1 -Force
# MSI - Disable User Installs
# Win 2k+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name "DisableUserInstalls" -PropertyType DWord -Value 1 -Force
# MSI - Enforce Upgrade Component Rules
# Win 2k+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name "EnforceUpgradeComponentRules" -PropertyType DWord -Value 1 -Force
# MSI - MaxPatchCacheSize
# Win 2k+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name "MaxPatchCacheSize" -PropertyType DWord -Value 100 -Force
# MSI Logging
# Win 2k+
# FIXME: New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name "Logging" -PropertyType DWord -Value 100 -Force
# Safe for Scripting
# Win 2k+
# FIXME: New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name "SafeForScripting" -PropertyType DWord -Value 100 -Force
# Search Order
# Win 2k+
# FIXME: New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name "SearchOrder" -PropertyType DWord -Value 100 -Force
# Disable Shared Component
# Win 2k+
# New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name "DisableSharedComponent" -PropertyType DWord -Value 1 -Force
# Msi - Disable EmbeddedUI
# Win 2k+
# New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name "MsiDisableEmbeddedUI" -PropertyType DWord -Value 1 -Force










##########################################################
######  				    iSCSI           		######
##########################################################
# Configure iSNS Servers
# Vista+
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\iSCSI" -Name "ConfigureiSNSServers" -PropertyType DWord -Value 0 -Force
# Configure Target Portals
# Vista+
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\iSCSI" -Name "ConfigureTargetPortals" -PropertyType DWord -Value 0 -Force
# Configure Targets
# Vista+
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\iSCSI" -Name "ConfigureTargets" -PropertyType DWord -Value 0 -Force
# Configure Targets
# Vista+
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\iSCSI" -Name "NewStaticTargets" -PropertyType DWord -Value 0 -Force
# Change IQN Name
# Vista+
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\iSCSI" -Name "ChangeIQNNam" -PropertyType DWord -Value 0 -Force
# Restrict Additional Logins
# Vista+
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\iSCSI" -Name "RestrictAdditionalLogins" -PropertyType DWord -Value 1 -Force
# Change CHAP Secret
# Vista+
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\iSCSI" -Name "ChangeCHAPSecret" -PropertyType DWord -Value 1 -Force
# Require IPSec
# Vista+
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\iSCSI" -Name "RequireIPSec" -PropertyType DWord -Value 1 -Force
# Require Require Mutual CHAP
# Vista+
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\iSCSI" -Name "RequireMutualCHAP" -PropertyType DWord -Value 1 -Force
# Require Require One way CHAP
# Vista+
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\iSCSI" -Name "RequireOneWayCHAP" -PropertyType DWord -Value 0 -Force



##########################################################
######  				Cloud Content   			######
######                  Spotlight etc               ######
##########################################################
# Turn off Spotlight (not needed since 1603+)
# Windows 10
# (NOSERVER)
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "ConfigureWindowsSpotlight" -PropertyType DWord -Value 2 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableThirdPartySuggestions" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightOnActionCenter" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightWindowsWelcomeExperience" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "IncludeEnterpriseSpotlight" -PropertyType DWord -Value 0 -Force
# Turn off Windows Consumer Features
# (NOSERVER)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -PropertyType DWord -Value 1 -Force
# Turn off Windows Cloud based Tips
# (NOSERVER)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -PropertyType DWord -Value 1 -Force
# Disable Windows Spotlight on settings
# Windows 10 RS4+ (NOSERVER)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightOnSettings" -PropertyType DWord -Value 1 -Force
# Live Tiles
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoCloudApplicationNotification" -PropertyType DWord -Value 1 -Force


##########################################################
######  				Device Guard				######
###### You need the following extension             ######
###### F312195E-3D9D-447A-A3F5-08DFFA24735E!        ######
##########################################################
# Turn on Defender Credential Guard with UEFI lockdown
# Since Windows 1607+ you don't need to enable it, it will be automatically enabled if on Ent+ + hardware extension (see "you need" above)
# New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\LSA" -Name "LsaCfgFlags" -PropertyType DWord -Value 1 -Force
# New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Device Guard" -Name "EnableVirtualizationBasedSecurity" -PropertyType DWord -Value 1 -Force
# System Guard
# 0 = default
# 1 = enabled
# 2 = disabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\DeviceGuard" -Name "ConfigureSystemGuardLaunch" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -PropertyType DWord -Value 1 -Force
# Checkbox MAT
Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\DeviceGuard" -Name "HVCIMATRequired" -PropertyType DWord -Value 0 -Force
# Turn on Core Isolation Memory Integrity
# 1 = Enabled with Uefi Lock
# 2 = Enabled without Lock
# 3 = Not configured
Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\DeviceGuard" -Name "HypervisorEnforcedCodeIntegrity" -PropertyType DWord -Value 2 -Force
# Turn on Credential Isolation Drop
# Depending on your choice 0-3 (see entry above)
Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\DeviceGuard" -Name "LsaCfgFlags" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\DeviceGuard" -Name "RequirePlatformSecurityFeatures" -PropertyType DWord -Value 3 -Force

#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "DeployConfigCIPolicy" -PropertyType DWord -Value 1 -Force


##########################################################
######  			File Revocation   				######
##########################################################
# FIXME: .. EIDs
# Windows 6.3+
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\FileRevocation" -Name "DelegatedTuples" -PropertyType DWord -Value 0 -Force





##########################################################
######  				RemoteRPC   				######
##########################################################
# Turn off RemoteRPC
Set-ItemProperty -Path "HKLM:\SOFTWARE\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\DeviceInstall\Settings" -Name "AllowRemoteRPC" -PropertyType DWord -Value 0 -Force

##########################################################
######  			    AppX Runtime   		        ######
##########################################################
# Appx Runtime Block File Elevation
# Windows 8+
# New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Associations" -Name "BlockFileElevation" -PropertyType DWord -Value 1 -Force
# Appx Runtime Block Protocol Elevation
# New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Associations" -Name "BlockProtocolElevation" -PropertyType DWord -Value 1 -Force
# Appx Runtime Application Content Uri Rules
# Windows 10+
#New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Associations" -Name "EnableDynamicContentUriRules" -PropertyType DWord -Value 0 -Force
# Appx Runtime Block Hosted App Access WinRT
# Windows 10+
#New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Associations" -Name "BlockHostedAppAccessWinRT" -PropertyType DWord -Value 1 -Force

##########################################################
######  			  AppX Package Manager 	        ######
##########################################################
# Appx Deployment Allow All TrustedApps
# Windows 8+
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Appx" -Name "AllowAllTrustedApps" -PropertyType DWord -Value 1 -Force
# Deployment In Special Profiles
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Appx" -Name "AllowDeploymentInSpecialProfiles" -PropertyType DWord -Value 1 -Force
# Allow Developmen tWithout Dev License
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Appx" -Name "AllowDevelopmentWithoutDevLicense" -PropertyType DWord -Value 0 -Force
# Disable Deployment To Non System Volumes
# Windows 10 RS2+
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Appx" -Name "RestrictAppToSystemVolume" -PropertyType DWord -Value 1 -Force
# Restrict App Data To SystemVolume
# Windows 10 RS2+
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Appx" -Name "RestrictAppDataToSystemVolume" -PropertyType DWord -Value 1 -Force
# AllowS hared Local AppData
# Windows 10
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Appx" -Name "AllowSharedLocalAppData" -PropertyType DWord -Value 0 -Force


##########################################################
######      Login Domain Credential Providers       ######
##########################################################
# FIXME: ... string

# Default Logon Domain
# Vista+
# Max length = 4096
# New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DefaultLogonDomain" -PropertyType DWord -Value 1 -Force
# Excluded Credential Providers
# Vista+
# Max length = 4096
# New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ExcludedCredentialProviders" -PropertyType DWord -Value 1 -Force
# Allow Domain PIN Logon
# Windows 8+
# New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "AllowDomainPINLogon" -PropertyType DWord -Value 0 -Force
# Block Domain Picture Password
# Windows 8+
# New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "BlockDomainPicturePassword" -PropertyType DWord -Value 1 -Force
# Allow Domain Delay Lock
# Windows 8+
# New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "AllowDomainDelayLock" -PropertyType DWord -Value 1 -Force
# Default Credential Provider
# Windows 10+
# Max Length = 48
# New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DefaultCredentialProvider" -PropertyType DWord -Value 1 -Force


##########################################################
######  			    Disk NV Cache   		    ######
##########################################################
# Boot Resume Policy
# Vista+
# New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\NvCache" -Name "OptimizeBootAndResume" -PropertyType DWord -Value 1 -Force
# Cache Power Mode Policy
# Vista+
# New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\NvCache" -Name "EnablePowerModeState" -PropertyType DWord -Value 1 -Force
# Turn off NV Cache
# Vista+
# New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\NvCache" -Name "EnableNvCache" -PropertyType DWord -Value 0 -Force
# Solid State Policy
# Vista+
# New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\NvCache" -Name "EnableSolidStateMode" -PropertyType DWord -Value 0 -Force


##########################################################
######  		    Fault Tolerant Heap  		    ######
##########################################################
# Fault Tolerant Heap
# Windows 7+
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{dc42ff48-e40d-4a60-8675-e71f7e64aa9a}" -Name "ScenarioExecutionEnabled" -PropertyType DWord -Value 1 -Force
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{dc42ff48-e40d-4a60-8675-e71f7e64aa9a}" -Name "EnabledScenarioExecutionLevel" -PropertyType DWord -Value 2 -Force
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{dc42ff48-e40d-4a60-8675-e71f7e64aa9a}" -Name "ScenarioExecutionEnabled" -PropertyType DWord -Value 1 -Force





##########################################################
######  			File Recovery & WDI			    ######
##########################################################
# Default Execution Policy
# Vista+
# New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{8519d925-541e-4a2b-8b1e-8059d16082f2}" -Name "ScenarioExecutionEnabled" -PropertyType DWord -Value 1 -Force
# Default Execution Policy Level
# 1 = TS only
# 2 = Level Resolution
# 3 = 2 + Silent
# New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{8519d925-541e-4a2b-8b1e-8059d16082f2}" -Name "EnabledScenarioExecutionLevel" -PropertyType DWord -Value 1 -Force
# MSI File recovery - Default Execution Policy Level
# Vista+
# New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{54077489-683b-4762-86c8-02cf87a33423}" -Name "ScenarioExecutionEnabled" -PropertyType DWord -Value 1 -Force
# Default Execution Policy Level
# 1 = TS only
# 2 = Level Resolution
# 3 = 2 + Silent
# New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{54077489-683b-4762-86c8-02cf87a33423}" -Name "EnabledScenarioExecutionLevel" -PropertyType DWord -Value 1 -Force

### WDI
# Dps Scenario Data Size Limit Policy
# Vista+
# New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI" -Name "DataRetentionBySizeEnabled" -PropertyType DWord -Value 1 -Force
# FIXME: New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI" -Name "DirSizeLimit" -PropertyType DWord -Value 1 -Force
# Dps Scenario Execution Policy
# Vista+
# New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI" -Name "ScenarioExecutionEnabled" -PropertyType DWord -Value 1 -Force
# Dps Scenario Execution Policy Level
# Vista+
# New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI" -Name "EnabledScenarioExecutionLevel" -PropertyType DWord -Value 1 -Force


##########################################################
######  			User Accounts					######
##########################################################
# Turn on 'Users can't add or log on with Microsoft accounts'
# 0000000 = This policy is disabled
# 0000001 = Users can’t add Microsoft accounts
# 0000003 = Users can’t add or log on with Microsoft accounts (CIS)
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "NoConnectedUser" -PropertyType DWord -Value 3 -Force
# Allow Microsoft accounts to be optional <-> 'Disabled'
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "MSAOptional" -PropertyType DWord -Value 1 -Force
##########################################################
######                  Apps                        ######
##########################################################
# Speech privacy
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "HasAccepted" -PropertyType DWord -Value 0 -Force


# Turn off "Connect Now" Wizard (not in LTSB/LTSC and 1603+) (NOSERVER)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "DisableFlashConfigRegistrar" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "DisableInBand802DOT11Registrar" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "DisableUPnPRegistrar" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "DisableWPDRegistrar" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "EnableRegistrars" -PropertyType DWord -Value 0 -Force
# Turn off downloads of Map data (not in LTSB/LTSC) (NOSERVER)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps" -Name "AllowUntriggeredNetworkTrafficOnSettingsPage" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps" -Name "AutoDownloadAndUpdateMapData" -PropertyType DWord -Value 0 -Force
# Turn off app access to personal data (force deny)
# You should always use "force deny" instead of "disabled"!
# 0 = User in Control
# 1 = ForceAllow
# 2 = ForceDeny
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessAccountInfo" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCalendar" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCallHistory" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCamera" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessContacts" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessEmail" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessGazeInput" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessLocation" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMessaging" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMicrophone" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMotion" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessNotifications" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessPhone" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessRadios" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessTasks" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessTrustedDevices" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoiceAboveLock" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsGetDiagnosticInfo" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsSyncWithDevices" -PropertyType DWord -Value 2 -Force
# Turn off Maps auto updates
Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -PropertyType DWord -Value 0
# Turn off Activity History Feed
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -PropertyType DWord -Value 0
# Turn off publishing of user activities
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -PropertyType DWord -Value 0
# Turn off Mail App
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows Mail" -Name "ManualLaunchAllowed" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Mail" -Name "ManualLaunchAllowed" -PropertyType DWord -Value 0
# Turn off "Automatic installation apps"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -PropertyType DWord -Value 0
# Turn off Shared Experiences: "I can share and receive from"
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" -Name "CdpSessionUserAuthzPolicy" -PropertyType DWord -Value 0 -Force
# Turn off "My devices only" for Nearby sharing: "I can share and receive from"
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" -Name "NearShareChannelUserAuthzPolicy" -PropertyType DWord -Value 0 -Force
# Turn off "Let apps share and sync with wireless devices" (FIXME:)
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" -Name "Value" -PropertyType hex -Value Deny -Force
# Turn off automatic installing suggested apps
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -PropertyType DWord -Value 0 -Force
# Dark theme color for default app mode
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -PropertyType DWord -Value 0
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -PropertyType DWord -Value 0
# Turn off Inventory
# Windows 10 <= 1603
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompa" -Name "DisableInventory" -PropertyType DWord -Value 1 -Force
# Do not allow apps to use advertising ID
# EDU/Pro/Home
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Id" -PropertyType String -Value "null" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -PropertyType DWord -Value 1
# Turn off Linguistic Data Collection
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Name "AllowLinguisticDataCollection" -PropertyType DWord -Value 0
# Prevent users from uninstalling language features
#Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Name "AllowLanguageFeaturesUninstall" -PropertyType DWord -Value 0
# Turn off Cortana (not present in LTSB/LTSC)
Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force
<#
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI" -Name "DisableWcnUi" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "CortanaCapabilities" -PropertyType ExpandString -Value ""
#>
# Re-register Cortana
# Use it in case you want to use Cortana but it got "destroyed" by some cleaning tools.
FIXME:
#add-appxpackage –register –disabledevelopmentmode $env:windir\systemapps\ShellExperienceHost_cw5n1h2txyewy\appxmanifest.xml
#add-appxpackage –register –disabledevelopmentmode $env:windir\systemapps\Microsoft.Windows.Cortana_cw5n1h2txyewy\appxmanifest.xml
# Turn off "Let Cortana respond to "Hey Cortana"
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences" -Name "VoiceActivationOn" -PropertyType DWord -Value 0 -Force
# Turn off "Use Cortana even when my device is locked"
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences" -Name "VoiceActivationEnableAboveLockscreen" -PropertyType DWord -Value 0 -Force
# Turn off "Let Cortana listen for my commands when I press the Windows logo key + C"
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "VoiceShortcut" -PropertyType DWord -Value 0 -Force
# Remove all apps except Windows Store incl. Xbox (Enterprise (N) LTSC 2019)
# The Windows Store however does not run in the background since we enforce to disable all background apps.
# (FIXME:) Add XBOX 360 driver workaround (1909 fixed? - needs more tests)
Get-AppxPackage -AllUsers | Where-Object { $_.name –notlike "*store*" } | Remove-AppxPackage
##########################################################
######                  Start Menu                  ######
######            I prefer StartisBack++ (paid)     ######
##########################################################
# Import default Layout
# FIXME:
#import-startlayout –layoutpath c:\windows\setup\scripts\DefaultStartLayout.xml -mountpath c:\
# Repair (re-register start menu)
#(Get-appxpackage -all *shellexperience* -packagetype bundle |% {add-appxpackage -register -disabledevelopmentmode ($_.installlocation + “\appxmetadata\appxbundlemanifest.xml”)})
# Clear Recent Prog For New User
# Windows 7 - 10
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ClearRecentProgForNewUserInStartMenu" -PropertyType DWord -Value 1 -Force
# No "Games" in Start Menu
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoStartMenuMyGame" -PropertyType DWord -Value 1 -Force
# No Search on Computer link
# Vista only
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoSearchComputerLinkInStartMenu" -PropertyType DWord -Value 1 -Force
# No "Search everywhere" link
# Windows 7 up to Threshold
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoSearchEverywhereLinkInStartMenu" -PropertyType DWord -Value 1 -Force
# Add "Search Internet" Link
# Vista only
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "AddSearchInternetLinkInStartMenu" -PropertyType DWord -Value 0 -Force
# No Search Files
# Vista only
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoSearchFilesInStartMenu" -PropertyType DWord -Value 1 -Force
# No Search Internet
# Vista only / Server 2008 only
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoSearchInternetInStartMenu" -PropertyType DWord -Value 1 -Force
# No Search Programs
# Vista up to 7
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoSearchProgramsInStartMenu" -PropertyType DWord -Value 1 -Force
# No Search Comm
# Vista up to 7
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoSearchCommInStartMenu" -PropertyType DWord -Value 1 -Force
# No User Folder
# Vista up to 7
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoUserFolderInStartMenu" -PropertyType DWord -Value 1 -Force
# Show "Run"
# Vista up to 7
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ForceRunOnStartMenu" -PropertyType DWord -Value 1 -Force
# Turn on Quick Launch
# Vista up to 7
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "QuickLaunchEnabled" -PropertyType DWord -Value 1 -Force
# Clear Recent Docs On Exit
# Win2k+
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ClearRecentDocsOnExit" -PropertyType DWord -Value 1 -Force
# Lock Start Layout
# Windows 10+
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "LockedStartLayout" -PropertyType DWord -Value 1 -Force
# FIXME: reg_sz Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "StartLayoutFile" -PropertyType DWord -Value "C:" -Force
# No programs list dropdown
# Windows 10+
# 0 = None
# 1 = Remove setting
# 2 = Collaps settings
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoStartMenuMorePrograms" -PropertyType DWord -Value 0 -Force
# No Net And Dialup Connect
# Win2k up to Vista
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoNetworkConnections" -PropertyType DWord -Value 1 -Force
# No Pinned Programs
# XP - 7
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoStartMenuPinnedList" -PropertyType DWord -Value 1 -Force
# No Recent Docs History
# XP - 7
#Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -PropertyType DWord -Value 1 -Force
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -PropertyType DWord -Value 1 -Force
# No Recent Docs Menu
# XP - 7
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsMenu" -PropertyType DWord -Value 1 -Force
# No Resolve Track
# XP - 7
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoResolveTrack" -PropertyType DWord -Value 1 -Force
# No Run
# Windows 2k+ - 10+
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRun" -PropertyType DWord -Value 1 -Force
# No Set Folders
# Windows 2k+ - 10+
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoSetFolders" -PropertyType DWord -Value 1 -Force
# No Set Taskbar
# Windows 2k+
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoSetTaskbar" -PropertyType DWord -Value 1 -Force
# No SM Configure Programs
# Windows XP SP1 / Win2k SP3
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoSMConfigurePrograms" -PropertyType DWord -Value 1 -Force
# No SM My Documents
# Win2k - 7
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoSMMyDocs" -PropertyType DWord -Value 1 -Force
# No SM My Music
# XP - 7
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoStartMenuMyMusic" -PropertyType DWord -Value 1 -Force
# No SM My Pictures
# XP - 7
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoSMMyPictures" -PropertyType DWord -Value 1 -Force
# No Start Menu Sub Folders
# Win2k - 10
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoStartMenuSubFolders" -PropertyType DWord -Value 1 -Force
# No Start Page
# Win2k - 10
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoSimpleStartMenu" -PropertyType DWord -Value 1 -Force
# No TaskBar Clock
# Win2k - 10
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideClock" -PropertyType DWord -Value 1 -Force
# No Task Grouping
# Win2k - 10
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoTaskGrouping" -PropertyType DWord -Value 1 -Force
# No Toolbars on Taskbar
# XP+
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoToolbarsOnTaskbar" -PropertyType DWord -Value 1 -Force
# No Tray Context Menu
# Win2k+
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoTrayContextMenu" -PropertyType DWord -Value 1 -Force
# No Tray Items Display
# Win2k+
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoTrayItemsDisplay" -PropertyType DWord -Value 1 -Force
# No User Name
# XP and Server only
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoUserNameOnStartMenu" -PropertyType DWord -Value 1 -Force
# No "Windows Update"
# Win2k - 8.1 only
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoWindowsUpdate" -PropertyType DWord -Value 1 -Force
# No Start Menu "Eject PC"
# XP - 7
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoStartMenuEjectPC" -PropertyType DWord -Value 1 -Force
# Start Menu "Log Off"
# Win2k+
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "StartMenuLogOff" -PropertyType DWord -Value 1 -Force
# No Start Menu "Homegroup"
# Windows 7 only
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoStartMenuHomegroup" -PropertyType DWord -Value 1 -Force
# No Start Menu "Download"
# Windows 7 only
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoStartMenuDownloads" -PropertyType DWord -Value 1 -Force
# No Start Menu "Recorded TV"
# Windows 7 only
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoStartMenuDownloads" -PropertyType DWord -Value 1 -Force
# No Start Menu Videos
# Windows 7 only
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoStartMenuVideos" -PropertyType DWord -Value 1 -Force
# No Uninstall From Start
# Windows 8+
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoUninstallFromStart" -PropertyType DWord -Value 1 -Force
# Power Button Action
# Windows 7 only
# 1 = Logoff
# 2 = Shutdown
# 512 = Lock
# 4 = Restart
# 256 = Switch User
# 64 = Hibernate
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "PowerButtonAction" -PropertyType DWord -Value 2 -Force
# Show "Run As Different User"
# Windows 8+
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ShowRunAsDifferentUserInStart" -PropertyType DWord -Value 1 -Force
# Go To Desktop On SignIn
# Windows 10+
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "GoToDesktopOnSignIn" -PropertyType DWord -Value 1 -Force
# Show Apps View On Start
# Windows 10+
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ShowAppsViewOnStart" -PropertyType DWord -Value 1 -Force
# Disable Global Search On Apps View
# Windows 10+
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "DisableGlobalSearchOnAppsView" -PropertyType DWord -Value 1 -Force
# Desktop Apps First In Apps View
# Windows 10+
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "DesktopAppsFirstInAppsView" -PropertyType DWord -Value 1 -Force
# Show Start On Display with Foreground on WinKey
# Windows 10+
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ShowStartOnDisplayWithForegroundOnWinKey" -PropertyType DWord -Value 1 -Force
# Force Start Size
# Windows 10+
# NOARM
# 1 = Collapsed
# 2 = Expanded
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ForceStartSize" -PropertyType DWord -Value 1 -Force
# Hide People Bar
# Windows 10 RS2+
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HidePeopleBar" -PropertyType DWord -Value 1 -Force
# Hide Recently Added Apps
# Windows 10 RS4+
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideRecentlyAddedApps" -PropertyType DWord -Value 1 -Force
# Disable Context Menus
# Windows 10 RS4+
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "DisableContextMenusInStart" -PropertyType DWord -Value 1 -Force

# Repair Start Menu (re-register the app package)
#add-appxpackage –register –disabledevelopmentmode
#$env:windir\systemapps\ShellExperienceHost_cw5n1h2txyewy\appxmanifest.xml
#     add-appxpackage –register –disabledevelopmentmode $env:windir\systemapps\Microsoft.Windows.Cortana_cw5n1h2txyewy\appxmanifest.xml
# Workaround - Startmenu button isn't responding
# Windows 10+
# Default should be 0 (always) but some "optimizing tools" often changing it.
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "EnableXamlStartMenu" -PropertyType DWord -Value 0 -Force
# Workaround - No apps in Start menu visible
#Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\TileDataModel\Migration\TileStore" -Name "TileStore" -ErrorAction SilentlyContinue
#get-appxpackage -packageType bundle |% {add-appxpackage -register -disabledevelopmentmode ($_.installlocation + "\appxmetadata\appxbundlemanifest.xml")}
#$bundlefamilies = (get-appxpackage -packagetype Bundle).packagefamilyname
#get-appxpackage -packagetype main |? {-not ($bundlefamilies -contains $_.packagefamilyname)} |% {add-appxpackage -register -disabledevelopmentmode ($_.installlocation + "\appxmanifest.xml")}
# Workaround - Search via Startmenu tasklist isn't working
# Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Searc" -Name "EnableSearchBox " -PropertyType DWord -Value 1 -Force
# Workaround for Start Menu not showing up (re-registrer the entire app package)
#Get-AppXPackage -AllUsers |Where-Object {$_.InstallLocation -like “*SystemApps*”} | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register “$($_.InstallLocation)\AppXManifest.xml”}
# Turn off Sleep & keyboard button in Start Menu
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowSleepOption" -PropertyType DWord -Value 0
#powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0
#powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0
# Turn off "Help and Support"
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_ShowHelp" -PropertyType DWord -Value 0 -Force
# Turn off 'Games'
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_ShowMyGame" -PropertyType DWord -Value 0 -Force
# Turn off automatically hiding scroll bars
New-ItemProperty -Path "HKCU:\Control Panel\Accessibility" -Name "DynamicScrollbars" -PropertyType DWord -Value 0 -Force
# Add a Command Prompt shortcut from Start menu (Administrator)
[byte[]]$bytes = Get-Content -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\System Tools\Command Prompt.lnk" -Encoding Byte -Raw
$bytes[0x15] = $bytes[0x15] -bor 0x20
Set-Content -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\System Tools\Command Prompt.lnk" -Value $bytes -Encoding Byte -Force
# Turn off recently added apps on Start Menu
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -PropertyType DWord -Value 1
# Turn off 'Most used' apps list from the Start Menu
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoStartMenuMFUprogramsList" -PropertyType DWord -Value 1
# Turn off app suggestions on Start menu e.g. Windows Ink Workspace
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -PropertyType DWord -Value 0 -Force
# Hide "Recent folders" in Quick access
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -PropertyType DWord -Value 0 -Force
# Unpin all Start Menu tiles
$key = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\*start.tilegrid`$windows.data.curatedtilecollection.tilecollection\Current"
$data = $key.Data[0..25] + ([byte[]](202,50,0,226,44,1,1,0,0))
Set-ItemProperty -Path $key.PSPath -Name "Data" -PropertyType Binary -Value $data
Stop-Process -Name "ShellExperienceHost" -Force -ErrorAction SilentlyContinue
#New-ItemProperty -Path $tilecollection.PSPath -Name "Data" -PropertyType Binary -Value $unpin -Force
# Turn off Task View button
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -PropertyType DWord -Value 0
# Enforce use of small Taskbar icons
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -PropertyType DWord -Value 1
# Turn on taskbar buttons - Show label & never combine
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -PropertyType DWord -Value 2
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MMTaskbarGlomLevel" -PropertyType DWord -Value 2





##########################################################
######                Windows Search                ######
##########################################################
# Prevent launch of SearchUI
# FIXME: # c:\windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe
# Hide Cortana search box and search icon on taskbar
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -PropertyType DWord -Value 0





##########################################################
######              Biometrics                      ######
##########################################################
# Turn off Biometrics (master button)
# Windows 7+
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics" -Name "Enabled" -PropertyType DWord -Value 0 -Force
# Turn off Biometrics creditals provider (Domain)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics" -Name "Domain Accounts" -PropertyType DWord -Value 0 -Force
# Define the default Biometrics FUS Timeout
# Min 5 (in seconds)
# Max 60
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics" -Name "SwitchTimeoutInSeconds" -PropertyType DWord -Value 30 -Force
# Turn on Enhanced anti-spoofing for Facial Detection (if in use)
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" -Name "EnhancedAntiSpoofing" -PropertyType DWord -Value 1 -Force



##########################################################
######      Microsoft Edge (old non Chomium based)  ######
###### LTSB\C versions do not include Microsoft Edge #####
##########################################################
# PDF files that have both landscape and portrait pages, print each in its own orientation
# 1909+
# FIXME: Set-ItemProperty -Path "HKLM:\Windows Components\Microsoft Edge" -Name "MSCompatibilityMode" -PropertyType DWord -Value 0


# Turn off "Compatibility List"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\BrowserEmulation" -Name "MSCompatibilityMode" -PropertyType DWord -Value 0
# Set a "Blank" Startpage (FIXME:)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Internet Settings" -Name "ProvisionedHomePages" -PropertyType DWord -Value "<about:blank>"
# Turn off auto password completation (FIXME:)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "FormSuggest Passwords" -PropertyType DWord -Value "no"
# Turn off first run Welcome page
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "PreventFirstRunPage" -PropertyType DWord -Value 1 -Force
# Turn off Auto Form Suggestion (FIXME:)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "Use FormSuggest" -PropertyType DWord -Value "no" -Force
# Turn off drop-down suggestions
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\ServiceUI" -Name "ShowOneBox" -PropertyType DWord -Value 0 -Force
# New Tabs shall be empty
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\ServiceUI" -Name "AllowWebContentOnNewTabPage" -PropertyType DWord -Value 0 -Force
# Turn off Books Library Updates
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\ServiceUI" -Name "AllowConfigurationUpdateForBooksLibrary" -PropertyType DWord -Value 0 -Force
# Turn off Bookmark telemetry
Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\MicrosoftEdge\BooksLibrary" -Name "EnableExtendedBooksTelemetry" -PropertyType DWord -Value 0 -Force
# Uninstall Microsoft Edge
# Not possible anymore since 1709+, it will be replaced with Chromium Edge anyway (in 20H1?)
# Uninstalling MS Edge results in "Notification Center" to freak out.
# Backup Edge
# mv C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe_BAK
# mv C:\Windows\SystemApps\Microsoft.MicrosoftEdgeDevToolsClient_8wekyb3d8bbwe C:\Windows\SystemApps\Microsoft.MicrosoftEdgeDevToolsClient_8wekyb3d8bbwe_BAK
# Remove package
# Get-WindowsPackage -Online | Where PackageName -like *InternetExplorer* | Remove-WindowsPackage -Online -NoRestart
# Ensure MicrosoftEdge.exe stays dead.
# reg add "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MicrosoftEdge.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
# Turn off data collection in Microsoft Edge
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "PreventLiveTileDataCollection" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\EdgeUI" -Name "DisableMFUTracking" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\EdgeUI" -Name "DisableRecentApps" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\EdgeUI" -Name "TurnOffBackstack" -PropertyType DWord -Value 1
# Turn off Do Not Track (DNT) in Microsoft Edge
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "DoNotTrack" -PropertyType DWord -Value 2
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "DoNotTrack" -PropertyType DWord -Value 2
# Turn off third-party cookies in Microsoft Edge
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "Cookies" -PropertyType DWord -Value 1
# Turn usage stats in sample submissions
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Edge Dev" -Name "UsageStatsInSample" -PropertyType DWord -Value 0
# Turn on override prevention "SmartScreen for Windows Store apps"
# New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "PreventOverride" -PropertyType DWord -Value 1 -Force
# Turn on (set to Warning) "SmartScreen for Windows Store apps"
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -PropertyType DWord -Value 0 -Force
#  Turn on (set to Warning) "SmartScreen for Microsoft Edge" (FIXME:)
#New-ItemProperty -Path "HKCU:\SOFTWARE\Classes\Local Settings\SOFTWARE\Microsoft\Windows\CurrentVersion\AppContainer\Storage\Microsoft.Microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -PropertyType DWord -Value "1" -Force
# Disable Adobe Flash
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -Name "FlashPlayerEnabled" -PropertyType DWord -Value 0 -Force
# Prevent using Localhost IP address for WebRTC
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "LocalHostIP" -PropertyType DWord -Value 1 -Force
# Remove Microsoft Edge shortcut from the Desktop
$value = Get-ItemPropertyValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name Desktop
Remove-Item -Path "$value\Microsoft Edge.lnk" -Force -ErrorAction SilentlyContinue
# Turn off creation of an MS Edge shortcut on the desktop for each user profile
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "DisableEdgeDesktopShortcutCreation" -PropertyType DWord -Value 1 -Force
# Prevent Microsoft Edge to start and load the Start and New Tab page at Windows startup and after each time Microsoft Edge is closed
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Name "AllowTabPreloading" -PropertyType DWord -Value 0
# Do not allow prelaunch
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "AllowPrelaunch" -PropertyType DWord -Value 0



##########################################################
###### 	        Mobile PC Presentation              ######
##########################################################
# Turn off mobile pc presentation
# Vista+
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\PresentationSettings" -Name "NoPresentationSettings" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\PresentationSettings" -Name "NoPresentationSettings" -PropertyType DWord -Value 1




##########################################################
######              Logon/Shutdown Scripts          ######
##########################################################
# Max script wait policy
# Win2k+
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "MaxGPOScriptWait" -PropertyType DWord -Value 8000
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "MaxGPOScriptWait" -PropertyType DWord -Value 8000
# Do not hide Loggoff scripts
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "HideLogoffScripts" -PropertyType DWord -Value 0
# Sync script before shutdown
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "RunLogonScriptSync" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "RunLogonScriptSync" -PropertyType DWord -Value 1
# Unhide logon scripts
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "HideLogonScripts" -PropertyType DWord -Value 0
# PowerShell Policy
# Windows 7+
# Run PS computer scripts first
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "RunComputerPSScriptsFirst" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "RunUserPSScriptsFirst" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "RunUserPSScriptsFirst" -PropertyType DWord -Value 1
# Show shutdown script (always)
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "HideShutdownScripts" -PropertyType DWord -Value 0
# Run startup PS script in sync
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "RunStartupScriptSync" -PropertyType DWord -Value 1
# Run startup PS script in sync visible (always)
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "HideStartupScripts" -PropertyType DWord -Value 0
# Disallow all NetBIOS based scripts (logon)
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "Allow-LogonScript-NetbiosDisabled" -PropertyType DWord -Value 0










##########################################################
######          Microsoft Edge (Chomium)            ######
##########################################################
# Unclear when/how MS Edge gets integrated 20H2?!
# Does it fully repplace IE & MS Edge (legacy one),
# since there is alreay a side-by-side option I assume MS keeps Edge?!
# Enable side-by-side experience
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate" -Name "Allowsxs" -PropertyType DWord -Value 1 -Force



##########################################################
######              Hardening UNC Paths             ######
##########################################################
# Hardening UNC Paths Breaks GPO Access - Microsoft Group Policy Remote Code Execution Vulnerability (MS15-011)
# https://social.technet.Microsoft.com/Forums/en-US/6a20e3f6-728a-4aa9-831a-6133f446ea08/gpos-do-not-apply-on-windows-10-enterprise-x64
# Vista+
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -Name "\\*\netlogon" -Value "RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -Name "\\*\sysvol" -Value "RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1"




##########################################################
######          Storage Sense (1703+)               ######
# (FIXME:)
##########################################################
# Turn off Storage Sense
# Windows 10 RS6+
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageSense" -Name "AllowStorageSenseGlobal" -PropertyType DWord -Value 0
# Clean Tashbin every 14 days
# 0 - 365
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageSense" -Name "ConfigStorageSenseRecycleBinCleanupThreshold" -PropertyType DWord -Value 14
# Enable Temp cleanup
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageSense" -Name "AllowStorageSenseTemporaryFilesCleanup" -PropertyType DWord -Value 1
# Global cleaning
# 1 = Daily
# 7 = Weekly
# 30 = Monthly
# 0 = DuringLowFreeDiskSpace
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageSense" -Name "ConfigStorageSenseGlobalCadence" -PropertyType DWord -Value 7
# Cleanup Downloads
# 0 - 365 (in days)
# Will be removed in 20H1+
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageSense" -Name "ConfigStorageSenseDownloadsCleanupThreshold" -PropertyType DWord -Value 0
# Cloud
# 0 - 365
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageSense" -Name "ConfigStorageSenseCloudContentDehydrationThreshold" -PropertyType DWord -Value 0
# Turn off scheduled defragmentation task
Disable-ScheduledTask -TaskName "Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null
# Turn on Storage Sense to automatically free up space
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name 01 -PropertyType DWord -Value 1 -Force
# Run Storage Sense every month | Otherwise use CCleaner incl. Winapp2.ini which is the alternative to Storage Sense.
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name 2048 -PropertyType DWord -Value 30 -Force

##########################################################
######               Thumbnails                     ######
######          Malware can hide in Thumbnails      ######
##########################################################
# Turn off Thumbnails
# Vista+
#New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "DisableThumbnails" -PropertyType DWord -Value 1 -Force
# Turn off Thumbnails on network folders
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "DisableThumbnailsOnNetworkFolders" -PropertyType DWord -Value 1 -Force
# Vista SP1+
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "DisableThumbsDBOnNetworkFolders" -PropertyType DWord -Value 1 -Force



##########################################################
######              SmartScreen                     ######
##########################################################
# Disable app based SMartScreen checks and controls
# Windows 10 RS5+
# Following status are supported:
# Anywhere
# AppRecommendations
# PreferStore
# StoreOnly
# FIXME: 1 or 0
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\SmartScreen" -Name "ConfigureAppInstallControlEnabled" -PropertyType DWord -Value 1 -Force
# Hide notification about disabled Smartscreen for Microsoft Edge
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows Security Health\State" -Name "AppAndBrowser_EdgeSmartScreenOff" -PropertyType DWord -Value 0 -Force
# Turn off SmartScreen for apps and files
# Windows 8+
# Block = Block execution/opening (Secure)
# Warn = Warn before execution/opening (Default)
# Off = Turn off
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -PropertyType String -Value "Off" -Force
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "ShellSmartScreenLevel" -PropertyType DWord -Value 0 (FIXME:) -Force
# reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v "ShellSmartScreenLevel" /t REG_SZ /d "Warn" /f  ^^^^^^^^^^
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -PropertyType DWord -Value 0 -Force
# Turn off Windows Defender SmartScreen (phising filter) for (old) Microsoft Edge
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Classes\Local Settings\SOFTWARE\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$edge\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Classes\Local Settings\SOFTWARE\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$edge\MicrosoftEdge\PhishingFilter" -Name "PreventOverride" -PropertyType DWord -Value 0 -Force
# Turn on 'Prevent bypassing Windows Defender SmartScreen prompts for sites'
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "PreventOverride" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "PreventOverrideAppRepUnknown" -PropertyType DWord -Value 1 -Force
##########################################################
###### 			    Windows Defender (WD)           ######
######      Overview: Get-Command -Module Defender  ######
#                                                        #
######      Full doc: Get-Help cmdlet name –Full    ######
######      Get Threats: Get-MpThreatDetection      ######
###### Test samples: https://www.eicar.org/?page_id=3950 #
# Test website: http://www.wicar.org/test-malware.html   #
##########################################################
# Turn off enhanced Notifications
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" -Name "DisableEnhancedNotifications" -PropertyType DWord -Value 1 -Force
# Enable Windows Defender Tamper protection
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -PropertyType DWord -Value 5 -Force
# Disable Windows Defender (master toggle) (you need to reboot)
#New-ItemProperty -Path “HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender” -Name "DisableAntiSpyware" -Value 1 -PropertyType DWORD -Force
# List all path exclusions
#Get-MpPreference | fl excl*
# Banking Protection
# https://www.Microsoft.com/security/blog/2019/10/08/in-hot-pursuit-of-elusive-threats-ai-driven-behavior-based-blocking-stops-attacks-in-their-tracks/
# https://www.mrg-effitas.com/wp-content/uploads/2019/08/2019Q2-Online-Banking.pdf
#

# Check for Signature Updates every 6 hours
Set-MpPreference -SignatureUpdateInterval 6 | Out-Null
# Daily signature checks (default)
#Set-MpPreference -SignatureScheduleDay Everyday
# Signature Updates 120 Minutes after midnight
#Set-MpPreference -SignatureScheduleTime 120
# Start a full scan sundays at 2AM and exclude processhacker (example) (FIXME:)
# Set-MpPreference -UILockdown:$True -ExclusionProcess processhacker ‑ScanAvgCPULoadFactor 20 ‑RemediationScheduleDay Sunday ‑RemediationScheduleTime 120
# Add WD scan exclusions (example)
#Add-MpPreference -ExclusionPath C:\Scripts, C:\CK\AVtest
#Get-MpPreference | Select-Object ‑Property ExclusionPath
# Turn off MRT (Report Infections) Telemetry
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\MRT" -Name "DontReportInfectionInformation" -Value 1 -Force
# Turn on protection against Potentially Unwanted Applications
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" -Name "MpEnablePus" -PropertyType DWord -Value 1 -Force
# Turn on removable driver scanning
Set-MpPreference -DisableRemovableDriveScanning $false | Out-Null
# Turn off eMail scanning
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisableEmailScanning" -PropertyType DWord -Value 0 -Force
# Turn on Attack Surface Reduction Rules
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -Name "ExploitGuard_ASR_Rules" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -Name "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -Name "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -Name "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -Name "5beb7efe-fd9a-4556-801d-275e5ffc04cc" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -Name "3b576869-a4ec-4529-8536-b80a7769e899" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -Name "d4f940ab-401b-4efc-aadc-ad5f3c50688a" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -Name "d3e037e1-3eb8-44c8-a917-57927947596d" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -Name "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -Name "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -Name "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" -PropertyType DWord -Value 1 -Force
# Turn off Spynet reporting
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "LocalSettingOverrideSpynetReporting" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -PropertyType DWord -Value 0 -Force
# Uninstall Windows Defender (install_wim_tweak method Build <=1703) (FIXME:)
# reg add "HKCU\SOFTWARE\Classes\Local Settings\SOFTWARE\Microsoft\Windows\CurrentVersion\AppContainer\Storage\Microsoft.Microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f
# reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f
# reg add "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SecHealthUI.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
# reg add "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "Off" /f
# reg add "HKLM:\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d 1 /f
# reg add "HKLM:\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 1 /f
# reg add "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
# reg add "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v DontReportInfectionInformation /t REG_DWORD /d 1 /f
# reg add "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpyNetReporting /t REG_DWORD /d 0 /f
# reg add "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 2 /f
# reg delete "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /f
# reg delete "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f
# reg delete "HKLM:\SYSTEM\CurrentControlSet\Services\Sense" /f
# install_wim_tweak /o /c Windows-Defender /r
#reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d 0 /f
#reg delete "HKLM:\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /f
# Turn off Windows Defender
#If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender")) {
#    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Force | Out-Null
#}
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -PropertyType DWord -Value 1
#If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
#    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -ErrorAction SilentlyContinue
#} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 15063) {
#    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -ErrorAction SilentlyContinue
#}
#}
# Turn on blocking of downloaded files
#Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -PropertyType DWord -Value 1
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -ErrorAction SilentlyContinue
# Turn on Windows Defender Account Protection Warnings
Remove-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows Security Health\State" -Name "AccountProtection_MicrosoftAccount_Disconnected" -ErrorAction SilentlyContinue
# Turn off Account Protection Notifications
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows Security Health\State" -Name "AccountProtection_MicrosoftAccount_Disconnected" -PropertyType DWord -Value 1
# Turn on Windows Defender AppGuard (see "Windows Features section")
# Enable-WindowsOptionalFeature -online -FeatureName "Windows-Defender-ApplicationGuard" -NoRestart -WarningAction SilentlyContinue | Out-Null
# Turn on Defender Exploit Guard
Set-MpPreference -EnableControlledFolderAccess $true | Out-Null
# Turn off submission of Windows Defender Malware Samples
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\SubmitSamplesConsent" -Name "value" -PropertyType DWord -Value 2 -Force
# New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -PropertyType DWord -Value 2 -Force
# Turn off Windows Defender Trayicon
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" -Name "HideSystray" -PropertyType DWord -Value 1
# Turn off Cloud Protection
Set-MpPreference -CloudBlockLevel 0 | Out-Null
# Turn off Windows Defender Cloud & Sample submission
# https://docs.Microsoft.com/en-us/powershell/module/defender/set-mppreference?view=win10-ps#parameters
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -PropertyType DWord -Value 0
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -PropertyType DWord -Value 2
Set-MpPreference -MAPSReporting 0 | Out-Null
# Set the default signature update order
#Set-MpPreference -SignatureFallbackOrder "{MicrosoftUpdateServer|MMPC}" | Out-Null
# Set the default Signature update path (UNC path) for manually updating definitions
# https://www.Microsoft.com/security/portal/definitions/adl.aspx
#Set-MpPreference -SignatureDefinitionUpdateFileSharesSources \DESKTOP-B20E3PO\Updates
# Fix crippled WD after a "broken signature update"
#"%PROGRAMFILES%\Windows Defender\MPCMDRUN.exe" -RemoveDefinitions -All
#"%PROGRAMFILES%\Windows Defender\MPCMDRUN.exe" –SignatureUpdate
# Don't scan if CPU is X % busy
Set-MpPreference -ScanAvgCPULoadFactor 55 | Out-Null
# Turn off IDLE scan
Set-MpPreference -ScanOnlyIfIdleEnabled:$false
# Manual scan (example)
#Start-MpScan -ScanType CustomScan -ScanPath ”C:\Program Files”
# Enable signature update check before starting a scan
Set-MpPreference -CheckForSignaturesBeforeRunningScan $true | Out-Null
# Turn on "Windows Defender Exploit Guard Network Protection"
Set-MpPreference -EnableNetworkProtection Enabled
# Turn on Windows Defender Sandbox
setx /M MP_FORCE_USE_SANDBOX=1
# Enforce Sandbox (better method?)
# [Environment]::SetEnvironmentVariable("MP_FORCE_USE_SANDBOX",1,"Machine")
# Turn on "Windows Defender PUA Protection"
Set-MpPreference -PUAProtection 1 | Out-Null
# Turn off WD "Firewall & Network protection"
# I use my Router & AdGuard Home as shield
#Set-NetFirewallProfile -Enabled false
# Turn on Windows Defender Exploit Protection Settings
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" -Name "DisallowExploitProtectionOverride" -ErrorAction SilentlyContinue
# Allow malicious app/website connections (now part off "Windows Defender Exploit Guard Network Protection")
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Name "EnableNetworkProtection" -PropertyType DWord -Value 0
# Turn on Windows Defender real-time protection
Set-MpPreference -DisableRealtimeMonitoring $false | Out-Null
# Turn off Generic malware reports
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" -Name "DisableGenericRePorts" -PropertyType DWord -Value 0 -Force
# Turn on "Block at first seen"
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "DisableBlockAtFirstSeen" -PropertyType DWord -Value 0 -Force
# Fake Computer ID (FIXME:) - is that even possible?! I never tried it!
Set-MpPreference -ComputerID 49AE549F-1C94-4B4E-B09G-A65C71DC2806 | Out-Null
# Set Computer name (default empty) - I have no clue what this option does (FIXME:)
#Set-MpPreference PSComputerName ???? | Out-Null
# Set unknown default action to "Warn" (but don't clean)
Set-MpPreference -UnknownThreatDefaultAction 0 | Out-Null
# Set exclusion path (example)
#Set-MpPreference -ExclusionPath "{C:\KMSAuto\KMSAuto x64.exe, C:\KMSAuto\KMSAuto++.exe, C:\KMSAuto\KMSAuto_Files...}" | Out-Null
# Turn off Windows Defender UI Lockdown
Set-MpPreference -UILockdown $false | Out-Null
# Turn on archive scanning
# By default, Windows Defender doesn't check the archive files (RAR, ZIP, CAB), which can potentially contain malicious files.
Set-MpPreference -DisableArchiveScanning 0
# Turn off auto exclusions (I was not able to extract the default list, sr)
Set-MpPreference -DisableAutoExclusions $false | Out-Null
# Turn off "Block at first seen"
Set-MpPreference -DisableBlockAtFirstSeen $false | Out-Null
# Turn off resuming on full scan interruptions
Set-MpPreference -DisableCatchupFullScan $true | Out-Null
# Turn off quick scan resumption
Set-MpPreference -DisableCatchupQuickScan $true | Out-Null
# Turn off eMail scanning (do not enable ever eMail scanning it will notify the sender that it got opened and triggers other stuff)
Set-MpPreference -DisableEmailScanning $true | Out-Null
# Turn off IPS (FIXME:) is the value a string or not?
#Set-MpPreference -DisableIntrusionPreventionSystem ? | Out-Null
# Turn on AV protection
Set-MpPreference -DisableIOAVProtection $false | Out-Null
# Turn on Privacy Mode
Set-MpPreference -DisablePrivacyMode $false | Out-Null
# Turn off Windows Defender Backups (it will still create one for 24 hours)
Set-MpPreference -DisableRestorePoint $true | Out-Null
# Turn off mapped network drive scans
Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan $true | Out-Null
# Turn on Network drive scans
Set-MpPreference -DisableScanningNetworkFiles $true | Out-Null
# Turn on Script scanning (In case Windows Host Script is enabled)
Set-MpPreference -DisableScriptScanning $false | Out-Null
# Turn on controlled folder access (Ransomware Protection)
Set-MpPreference -EnableControlledFolderAccess 0 | Out-Null
# Turn on file hash checks
Set-MpPreference -EnableControlledFolderAccess $false | Out-Null
# Turn off low cpu priority (the OS already does the job)
Set-MpPreference -EnableLowCpuPriority $false | Out-Null
# Add Exclusion for file extensions (exampe)
#Set-MpPreference -ExclusionExtension "{C:\KMSAuto\KMSAuto x64.exe, C:\KMSAuto\KMSAuto++.exe, C:\KMSAuto\KMSAuto_Files...}" | Out-Null
# Add specific process for exclusion (do not add any processes with internet permission into the list in case cloud scan was disabled!)
Set-MpPreference -ExclusionProcess "processhacker.exe", "VeraCrypt.exe", "Everything.exe", "Taskmgr.exe" | Out-Null
# To remove an exception for a particular directory (example)
# Remove-MpPreference -ExclusionPath C:\install
# Turn on Cloud Protection (FIXME:)
Set-MpPreference -SubmitSamplesConsent SendAllSamples
# Signature Update Interval (auto)
Set-MpPreference SignatureUpdateInterval 0 | Out-Null
# Signature catch Interval (default)
Set-MpPreference -SignatureUpdateCatchupInterval 1 | Out-Null
# Randomize task scheduler times
Set-MpPreference -SignatureUpdateCatchupInterval $true | Out-Null
# Purge the quarantine after 90 days
Set-MpPreference -QuarantinePurgeItemsAfterDelay 90 | Out-Null
# Set the default scan scheduler time (default)
#Set-MpPreference -QuarantinePurgeItemsAfterDelay 02:00:00 | Out-Null
# Set the default quick scan scheduler time (default)
#Set-MpPreference -ScanScheduleQuickScanTime 00:00:00 | Out-Null
# Set the default threat action in case malware was found
Set-MpPreference -ModerateThreatDefaultAction 0 | Out-Null
# Set the default action for high security threats
Set-MpPreference -HighThreatDefaultAction 0 | Out-Null
# Windows Defender Credential Guard (starts Lsalso.exe)
# https://docs.Microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage
# bcdedit /set {0cb3b571-2f2e-4343-a879-d86a476d7215} loadoptions DISABLE-LSA-ISO,DISABLE-VBS
# bcdedit /set vsmlaunchtype off
# Set-VMSecurity -VMName <VMName> -VirtualizationBasedSecurityOptOut $true


##########################################################
######                      HomeGroup               ######
##########################################################
# Turn off HomeGroup (default and can't re-enabled)
# 1607 - obsolete
#Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\HomeGroup" -Name "DisableHomeGroup" -PropertyType DWord -Value 1
#Set-ItemProperty -Path "HKCU:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\HomeGroup" -Name "DisableHomeGroup" -PropertyType DWord -Value 1


##########################################################
######                      Taskbar                 ######
##########################################################
# Turn on all tray icons
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutoTrayNotify" -PropertyType DWord -Value 1
# Turn off People icon
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -PropertyType DWord -Value 0
# Always show all icons in the notification area
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -PropertyType DWord -Value 0 -Force
# Show seconds on taskbar clock
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSecondsInSystemClock" -PropertyType DWord -Value 1 -Force
# Hide People button on the taskbar
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "AutoCheckSelect" -PropertyType DWord -Value 0
# Turn off "Windows Ink Workspace" button
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PenWorkspace" -Name "PenWorkspaceButtonDesiredVisibility" -PropertyType DWord -Value 0 -Force
# Turn on acrylic taskbar transparency
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "UseOLEDTaskbarTransparency" -PropertyType DWord -Value 1 -Force
##########################################################
######                    SmartCard                 ######
##########################################################
# Do not allow invalid and expired certificates
# Vista+
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider" -Name "AllowTimeInvalidCertificates" -PropertyType DWord -Value 0
# Allow Certificates With No EKU
# Vista+
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider" -Name "AllowCertificatesWithNoEKU" -PropertyType DWord -Value 0
# Allow Integrated Unblock
# Vista+
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider" -Name "AllowIntegratedUnblock" -PropertyType DWord -Value 1
# Filter Duplicate Certs
# Vista+
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider" -Name "FilterDuplicateCerts" -PropertyType DWord -Value 1 -Force
# Force Reading All Certificates
# Vista+
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider" -Name "ForceReadingAllCertificates" -PropertyType DWord -Value 1 -Force
# Allow Signature Only Keys
# Vista+
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider" -Name "AllowSignatureOnlyKeys" -PropertyType DWord -Value 0 -Force
# Cert Prop Enabled String
# Vista+
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CertProp" -Name "CertPropEnabled" -PropertyType DWord -Value 1
# Cert Prop Root Cleanup String
# Vista+
# 0 = All options 0 - 2 are just called "cleanup option X"
# 1 = ^^
# 2 = ^^
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CertProp" -Name "RootCertificateCleanupOption" -PropertyType DWord -Value 1
# Integrated Unblock Prompt String
# Vista+
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider" -Name "IntegratedUnblockPromptString" -PropertyType DWord -Value 1
# Reverse Subject
# Vista+
# FIXME: breakage Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider" -Name "ReverseSubject" -PropertyType DWord -Value 1
# Disallow Plaintext Pin
# Vista SP1+
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider" -Name "DisallowPlaintextPin" -PropertyType DWord -Value 1 -Force
# X509 Hints Needed
# Vista+
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider" -Name "X509HintsNeeded" -PropertyType DWord -Value 0 -Force
# SCPnP Enabled
# Windows 7+
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScPnP" -Name "EnableScPnP" -PropertyType DWord -Value 1 -Force
# SCPnP Notification
# Windows 7+
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScPnP" -Name "ScPnPNotification" -PropertyType DWord -Value 0 -Force
# Enumerate ECC Certs
# Windows 7+
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider" -Name "EnumerateECCCerts" -PropertyType DWord -Value 1 -Force



##########################################################
######                    Cred SSP                  ######
##########################################################
# Do not allow default Credentials
# Windows Vista+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation" -Name "AllowDefaultCredentials" -PropertyType DWord -Value 0 -Force
# Do not allow default Credentials (name based)
# Windows Vista+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowDefaultCredentials" -Name "ConcatenateDefaults_AllowDefault" -PropertyType DWord -Value 0 -Force
# Allow Def Credential sWhen NTLM Only
# Windows Vista+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation" -Name "AllowDefCredentialsWhenNTLMOnly" -PropertyType DWord -Value 1 -Force
# Allow Def Credential sWhen NTLM Only (name based)
# Windows Vista+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowDefCredentialsWhenNTLMOnly" -Name "ConcatenateDefaults_AllowDefNTLMOnly" -PropertyType DWord -Value 1 -Force
# Allow Fresh Credentials
# Windows Vista+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation" -Name "AllowFreshCredentials" -PropertyType DWord -Value 1 -Force
# Allow Fresh Credentials (name)
# Windows Vista+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentials" -Name "ConcatenateDefaults_AllowFresh" -PropertyType DWord -Value 1 -Force
# Allow Fresh Credentials When NTLM Only
# Windows Vista+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation" -Name "AllowFreshCredentialsWhenNTLMOnly" -PropertyType DWord -Value 1 -Force
# Allow Fresh Credentials When NTLM Only (name)
# Windows Vista+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnl" -Name "ConcatenateDefaults_AllowFreshNTLMOnly" -PropertyType DWord -Value 1 -Force
# Allow Fresh Credentials When NTLM Only (name)
# Windows Vista+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly" -Name "ConcatenateDefaults_AllowFreshNTLMOnly" -PropertyType DWord -Value 1 -Force
# Allow Saved Credentials
# Windows Vista+
#FIXME:
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation" -Name "entials)" key="Software\Policies\Microsoft\Windows\CredentialsDelegation" valueName="AllowSavedCredentials" -PropertyType DWord -Value 1 -Force
# Allow Saved Credentials (name)
# Windows Vista+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowSavedCredentials" -Name "ConcatenateDefaults_AllowSaved" -PropertyType DWord -Value 1 -Force
# Allow Saved Credentials - NTLM Only
# Windows Vista+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation" -Name "AllowSavedCredentialsWhenNTLMOnly" -PropertyType DWord -Value 1 -Force
# Allow Saved Credentials - NTLM Only (name)
# Windows Vista+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowSavedCredentialsWhenNTLMOnly" -Name "ConcatenateDefaults_AllowSavedNTLMOnly" -PropertyType DWord -Value 1 -Force
# Deny Default Credentials
# Windows Vista+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation" -Name "DenyDefaultCredentials" -PropertyType DWord -Value 1 -Force
# Deny Default Credentials (name)
# Windows Vista+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\DenyDefaultCredentials" -Name "ConcatenateDefaults_DenyDefault" -PropertyType DWord -Value 1 -Force
# Deny Fresh Credentials
# Windows Vista+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation" -Name "DenyFreshCredentials" -PropertyType DWord -Value 0 -Force
# Deny Fresh Credentials (name)
# Windows Vista+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\DenyFreshCredentials" -Name "ConcatenateDefaults_DenyFresh" -PropertyType DWord -Value 0 -Force
# Deny Saved Credentials
# Windows Vista+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation" -Name "DenySavedCredentials" -PropertyType DWord -Value 0 -Force
# Deny Saved Credentials (name)
# Windows Vista+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\DenySavedCredentials" -Name "ConcatenateDefaults_DenySaved" -PropertyType DWord -Value 0 -Force
# Restricted Remote Administration
# Windows 10+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation" -Name "RestrictedRemoteAdministration" -PropertyType DWord -Value 0 -Force
# Restricted Remote Administration Drop
# Windows 10+
# 3 = Prefer Remote CredentialGuard
# 2 = Require Remote CredentialGuard
# 1 = Require Restricted Admin
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation" -Name "RestrictedRemoteAdministrationType" -PropertyType DWord -Value 1 -Force
# Allow Protected Creds
# Windows 10 RS2+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation" -Name "AllowProtectedCreds" -PropertyType DWord -Value 1 -Force
# Allow Encryption Oracle
# Vista+
# 0 = Force
# 1 = Secure
# 2 = Allow
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" -Name "AllowEncryptionOracle" -PropertyType DWord -Value 1 -Force



##########################################################
######                  Svchost.exe                 ######
##########################################################
# Enable svchost.exe migration
# Windows 10 1809+
# Disable due to SmartCard etc breakage! (default off)
#Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SCMConfig" -Name "EnableSvchostMitigationPolicy" -PropertyType DWord -Value 1




##########################################################
######                  Handwriting                 ######
##########################################################
# Turn off Turn off handwriting recognition error reporting
Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -PropertyType DWord -Value 1 -Force
# Set default Panel Dock State
# Windows 10 RS3+
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Handwriting" -Name "PanelDefaultModeDocked" -PropertyType DWord -Value 0
# Turn off Pen training
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PenTraining" -Name "DisablePenTraining" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\PenTraining" -Name "DisablePenTraining" -PropertyType DWord -Value 1 -Force
# Turn off handwriting personalization data sharing
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -PropertyType DWord -Value 1 -Force




##########################################################
######                   Hotspot                    ######
##########################################################
# Enforce Hotspot Auth
# Windows 8+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\HotspotAuthentication" -Name "Enabled" -PropertyType DWord -Value 1



##########################################################
######                      BSOD                    ######
##########################################################
# Turn off Startup and Recovery - Debug Information
# Defaults 1,1,5,1,1,1
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "AutoReboot" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "LogEvent" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "MinidumpsCount" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "Overwrite" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "CrashDumpEnabled" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "AlwaysKeepMemoryDump" -PropertyType DWord -Value 0 -Force
##########################################################
######                      Sync                    ######
##########################################################
# Turn off app based sync
# Windows 10 RS3+
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging" -Name "AllowMessageSync" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging" -Name "CloudServiceSyncEnabled" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableApplicationSettingSync" -PropertyType DWord -Value 2 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableApplicationSettingSyncUserOverride" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableAppSyncSettingSync" -PropertyType DWord -Value 2 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableAppSyncSettingSyncUserOverride" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableCredentialsSettingSync" -PropertyType DWord -Value 2 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableCredentialsSettingSyncUserOverride" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableDesktopThemeSettingSync" -PropertyType DWord -Value 2 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableDesktopThemeSettingSyncUserOverride" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisablePersonalizationSettingSync" -PropertyType DWord -Value 2 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisablePersonalizationSettingSyncUserOverride" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableStartLayoutSettingSync" -PropertyType DWord -Value 2 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableStartLayoutSettingSyncUserOverride" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableWebBrowserSettingSync" -PropertyType DWord -Value 2 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableWebBrowserSettingSyncUserOverride" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableWindowsSettingSync" -PropertyType DWord -Value 2 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableWindowsSettingSyncUserOverride" -PropertyType DWord -Value 1 -Force
# Turn off Cloud Clipboard Feature
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowCrossDeviceClipboard" -PropertyType DWord -Value 0 -Force
# Turn off Settings are been synced when logged-in
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableSettingSync" -PropertyType DWord -Value 2 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableSettingSyncUserOverride" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "EnableBackupForWin8Apps" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableSyncOnPaidNetwork" -PropertyType DWord -Value 1 -Force
# Turn off "Sync your settings: Ease of Access
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" -Name "Enabled" -PropertyType DWord -Value 0 -Force
# Turn off Clipboard Cloud Sync Feature
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Clipboard" -Name "EnableCloudClipboard" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Clipboard" -Name "CloudClipboardAutomaticUpload" -PropertyType DWord -Value 0 -Force
# Turn off "Sync your settings: Passwords"
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" -Name "Enabled" -PropertyType DWord -Value 0 -Force
# Turn off "Sync your settings: Language preferences"
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" -Name "Enabled" -PropertyType DWord -Value 0 -Force
# Turn off "Sync your settings: Theme"
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" -Name "Enabled" -PropertyType DWord -Value 0 -Force
# Turn off Sync your settings: Other Windows settings
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" -Name "Enabled" -PropertyType DWord -Value 0 -Force
###############################################
######              Privacy              ######
###############################################
# Turn off Sound recording
# This does not break apps like Audacity etc.
# Vista+
Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\SOFTWARE\Policies\Microsoft\SoundRecorder" -Name "Soundrec" -PropertyType DWord -Value 0 -Force


# Turn off Win Calc
# Vista+
# Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Windows" -Name "TurnOffWinCal" -PropertyType DWord -Value 1 -Force
# Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Windows" -Name "TurnOffWinCal" -PropertyType DWord -Value 1 -Force
# Turn off File History
# Windows 8+
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\FileHistory" -Name "Disabled" -PropertyType DWord -Value 1 -Force
# Turn off App Privacy Experience (OOBE)
# Windows 10 RS5+
Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE" -Name "DisablePrivacyExperience" -PropertyType DWord -Value 1 -Force
# Disable "Let apps use my camera"
Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}" -Name "Value" -PropertyType String -Value "Deny" | Out-Null
# Disable "Let websites provide locally relevant content by accessing my language list"
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Internet Explorer\International" -Name "AcceptLanguage" -Force
Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Value 1 | Out-Null
# Disable "Let apps use my microphone"
# I personally need a Mic, let it enabled and work with the internal whitelist or GPO
#Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}\" -Name "Value" -PropertyType String -Value "Deny" | Out-Null
# Disable "Let apps access my name, picture and other account info"
Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}\" -Name "Value" -PropertyType String -Value "Deny" | Out-Null
# Disable "let apps access my calendar" (use FOSS apps like Thunderbird or Webmail/calendar instead)
Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}\" -Name "Value" -PropertyType String -Value "Deny" | Out-Null
# Disable "Let apps read or send sms and text messages"
Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}\" -Name "Value" -PropertyType String -Value "Deny" | Out-Null
# Disable "Let apps control Radios"
Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}\" -Name "Value" -PropertyType String -Value "Deny" | Out-Null
# Disable "Sync with devices" (we do not use Sync nor MS Accounts so this option is useless)
Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled\" -Name "Value" -PropertyType String -Value "Deny" | Out-Null
# Manage single or multiple sessions per user (RDP) - Prevent multiple sessions at once
#New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fSingleSessionPerUser" -PropertyType DWord -Value 1 -Force
# Strict DLL search order
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "CWDIllegalInDllSearch" -PropertyType DWord -Value 1 -Force
# Turn off Windows DRM (WMDRM)
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM" -Name "DisableOnline" -PropertyType DWord -Value 1 -Force
# Prevent users from sharing files within their profile
# Vista+
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoInplaceSharing" -PropertyType DWord -Value 1 -Force
# Turn off "Notify antivirus programs when opening attachments"
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "ScanWithAntiVirus" -PropertyType DWord -Value 1 -Force
# Turn off taskbar live thumbnail previews
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisablePreviewWindow" -PropertyType DWord -Value 0 -Force
# Turn off taskbar live thumbnail Aero peek
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -PropertyType DWord -Value 0 -Force
# Turn off Mobile Device Management (MDM) enrollment (does not exists on LTSB(C) and servers)
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM" -Name "DisableRegistration" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM" -Name "AutoEnrollMDM" -PropertyType DWord -Value 0 -Force
# Turn off projecting (Connect) to the device, and ensure it requires pin for pairing
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "AllowProjectionToPC" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "RequirePinForPairing" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WirelessDisplay" -Name "EnforcePinBasedPairing" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\PresentationSettings" -Name "NoPresentationSettings" -PropertyType DWord -Value 1 -Force
# Turn off Steps Recorder
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableUAR" -PropertyType DWord -Value 1 -Force
# Turn off speech recognition udpates
Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Speech" -Name "AllowSpeechModelUpdate" -PropertyType DWord -Value 0
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Speech" -Name "AllowSpeechModelUpdate" -PropertyType DWord -Value 0 -Force
# Turn off "Search Companion" from downloading files from Microsoft
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion" -Name "DisableContentFileUpdates" -PropertyType DWord -Value 1 -Force
# Turn off Error Reporting
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "DontSendAdditionalData" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "LoggingDisabled" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" -Name "DoReport" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" -Name "DWNoExternalURL" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" -Name "ForceQueueMode" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" -Name "DWNoFileCollection" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" -Name "DWNoSecondLevelCollection" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\HelpSvc" -Name "Headlines" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\HelpSvc" -Name "MicrosoftKBSearch" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" -Name "Disabled" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" -Name "DisableSendGenericDriverNotFoundToWER" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" -Name "DisableSendRequestAdditionalSoftwareToWER" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "DontSendAdditionalData" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "LoggingDisabled" -PropertyType DWord -Value 1 -Force
# Turn off Microsoft Account user authentication
# Windows 10 RS2+
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftAccount" -Name "DisableUserAuth" -PropertyType DWord -Value 1 -Force
# Turn off Network Connectivity Status Indicator active test (possible data leakage)
# Info:
# msftconnecttest.com + ipv6.msftconnecttest.com
# dns.msftncsi.com looking + 131.107.255.255
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" -Name "NoActiveProbe" -PropertyType DWord -Value 1
# Turn on cleaning of recent used files
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ClearRecentDocsOnExit" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -PropertyType DWord -Value 1 -Force
# Delete Diagtrack and Cortana leftovers
# FIXME:
reg add  "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"  /v "{60E6D465-398E-4850-BE86-7EF7620A2377}" /t REG_SZ /d  "v2.24|Action=Block|Active=TRUE|Dir=Out|App=C:\windows\system32\svchost.exe|Svc=DiagTrack|Name=Windows  Telemetry|" /f
reg add  "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"  /v "{2765E0F4-2918-4A46-B9C9-43CDD8FCBA2B}" /t REG_SZ /d  "v2.24|Action=Block|Active=TRUE|Dir=Out|App=C:\windows\systemapps\Microsoft.windows.cortana_cw5n1h2txyewy\searchui.exe|Name=Search  and Cortana  application|AppPkgId=S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742|"  /f
##########################################################
######              VM Hardening                    ######
##########################################################
# CVE-2017-5715 Migration
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" -Name "MinVmVersionForCpuBasedMitigations" -Value 1.0
# Cached Logon Credential
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows Nt\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -Value 0


##########################################################
######              Internet Explorer               ######
##########################################################
# Keep all intranet sites in Internet Explorer
# 1909+
# FIXME: Set-ItemProperty -Path "HKCU:\Windows Components\Internet Explorer" -Name "MSCompatibilityMode" -PropertyType DWord -Value 0
# Keep all intranet sites in Internet Explorer
# https://go.microsoft.com/fwlink/?linkid=2094210
# 1909+
# FIXME: Set-ItemProperty -Path "HKLM:\Machine\Windows Components\Internet Explorer" -Name "SendIntranetToInternetExplorer" -PropertyType DWord -Value 1 -Force
# Turn off "Master" check (Domain)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Browser\Parameters" -Name "MaintainServerList" -PropertyType ExpandString -Value "no"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Browser\Parameters" -Name "IsDomainMaster" -PropertyType ExpandString -Value "no"
# Pretend Telemetry was already running
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "FirstRunTelemetryComplete" -PropertyType DWord -Value 1 -Force
# Uninstall Internet Explorer
# WARNING: Don't remove other IE related packages otherwise you will lose the internet settings in your control panel!
#Microsoft-Windows-InternetExplorer-Optional-Package
Disable-WindowsOptionalFeature -Online -FeatureName "Internet-Explorer-Optional-$env:PROCESSOR_ARCHITECTURE" -NoRestart -WarningAction SilentlyContinue | Out-Null
# Turn off Password Reveal Button in Internet Explorer (not needed since 1603+)
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CredUI" -Name "DisablePasswordReveal" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "DisablePasswordReveal" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI" -Name "DisablePasswordReveal" -PropertyType DWord -Value 1 -Force
# Turn off "Help" in Microsoft Edge
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EdgeUI" -Name "DisableHelpSticker" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\EdgeUI" -Name "DisableHelpSticker" -PropertyType DWord -Value 1
# Turn off Search Suggestions in Microsoft Edge
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\SearchScopes" -Name "ShowSearchSuggestionsGlobal" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\SearchScopes" -Name "ShowSearchSuggestionsGlobal" -PropertyType DWord -Value 0
# Turn on HTTP/2 in Internet Explorer
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "EnableHTTP2" -PropertyType DWord -Value 1
# Turn off SSLv3 & suppress certificate errors in Internet Explorer
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "CallLegacyWCMPolicies" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "EnableSSL3Fallback" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "PreventIgnoreCertErrors" -PropertyType DWord -Value 1
# Turn on automatic browsing history cleaning in Internet Explorer
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Privacy" -Name "ClearBrowsingHistoryOnExit" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\Privacy" -Name "ClearBrowsingHistoryOnExit" -PropertyType DWord -Value 1
# Turn off Do Not Track (DNT) in Internet Explorer
# DnT is a website based optional feature, a.k.a. pointless because not much websites using it... opt-out via uBo/ADGHome instead!
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "DoNotTrack" -PropertyType DWord -Value 0
# Turn off automatic crash Detection in Internet Explorer
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Restrictions" -Name "NoCrashDetection" -PropertyType DWord -Value 1
# Turn off Internet Explorer prefetching
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\PrefetchPrerender" -Name "Enabled" -PropertyType DWord -Value 0
# Enforce DEP in Internet Explorer
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "DEPOff" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "Isolation64Bit" -PropertyType DWord -Value 1
# Turn off Background synchronization for feeds and Web Slices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" -Name "BackgroundSyncStatus" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" -Name "BackgroundSyncStatus" -PropertyType DWord -Value 0
# Turn off Site List Editing
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\BrowserEmulation" -Name "DisableSiteListEditing" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\BrowserEmulation" -Name "DisableSiteListEditing" -PropertyType DWord -Value 1
# Turn off FlipAhead suggestion
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\FlipAhead" -Name "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\FlipAhead" -Name "Enabled" -PropertyType DWord -Value 0
# Turn off Geolocation in IE
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Geolocation" -Name "PolicyDisableGeolocation" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\Geolocation" -Name "PolicyDisableGeolocation" -PropertyType DWord -Value 1
# Turn off Location provider
# Windows 8+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableWindowsLocationProvider" -PropertyType DWord -Value 1
# Turn off Internet Explorer suggestions
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Name "AllowServicePoweredQSA" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\DomainSuggestion" -Name "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\SearchScopes" -Name "TopResult" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Suggested Sites" -Name "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "AutoSearch" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\WindowsSearch" -Name "EnabledScopes" -PropertyType DWord -Value 0
# Turn off "Sync your settings: Internet Explorer settings"
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" -Name "Enabled" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" -Name "Enabled" -PropertyType DWord -Value 0 -Force
# Turn off Internet Explorer continues browsing
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\ContinuousBrowsing" -Name "Enabled" -PropertyType DWord -Value 0
# Turn off Internet Explorer SQM (now known as CEIP)
# https://getadmx.com/?Category=Windows_10_2016&Policy=Microsoft.Policies.InternetExplorer::SQM_DisableCEIP
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\SQM" -Name "DisableCustomerImprovementProgram" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\SQM" -Name "DisableCustomerImprovementProgram" -PropertyType DWord -Value 0
# Turn off Internet Explorer "In-Private" logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Safety\PrivacIE" -Name "DisableLogging" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\Safety\PrivacIE" -Name "DisableLogging" -PropertyType DWord -Value 1
# Turn on Internet Explorer phising filter
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter" -Name "EnabledV9" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter" -Name "EnabledV9" -PropertyType DWord -Value 1
# Turn off Internet Explorer "First run" wizard
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -PropertyType DWord -Value 1
# Turn off Internet Explorer Adobe Flash
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Name "DisableFlashInIE" -PropertyType DWord -Value 1
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -Name "FlashPlayerEnabled" -PropertyType DWord -Value 0
# Set Default StartPage (FIXME:)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "Start Page" -PropertyType DWord -Value "about:blank" -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "Start Page" -PropertyType DWord -Value "about:blank" -Force
# Enforce new blank tabs
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\TabbedBrowsing" -Name "NewTabPageShow" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\TabbedBrowsing" -Name "NewTabPageShow" -PropertyType DWord -Value 0 -Force
# ActiveX control blocking
Remove-ItemProperty -Path "HCU:\Software\Microsoft\Internet Explorer\VersionManager" -Name "DownloadVersionList" -PropertyType DWord -Value 0 -Force
# License Manager
# Removed since some builds (1609?)
#Remove-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LicenseManager" -Name "Start" -PropertyType DWord -Value 3 -Force
###############################################
###### MS Store & Apps (master toggle)   ######
###############################################
# Disable Push To Install
# Disabling the service will block the ability to instally any apps (Store/manual)
# Windows 10+
# Sandbox depends on it?! (FIXME:)
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\PushToInstall" -Name "DisablePushToInstall" -PropertyType DWord -Value 1 -Force



# Turn off Windows Store
# Windows8+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsStore" -Name "RemoveWindowsStore" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\WindowsStore" -Name "RemoveWindowsStore" -PropertyType DWord -Value 1 -Force
# Turn off OS upgrade offers
# Windows 8+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsStore" -Name "DisableOSUpgrade" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\WindowsStore" -Name "DisableOSUpgrade" -PropertyType DWord -Value 1 -Force
# Only use a private MS Store
# Windows 10+
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsStore" -Name "RequirePrivateStoreOnly" -PropertyType DWord -Value 1 -Force
# Disable MS Store Apps
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "DisableStoreApps" -PropertyType DWord -Value 1 -Force
# Turn off all running backgrounds apps
# Basically a master toggle for GPO based settings
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivac" -Name "LetAppsRunInBackground" -PropertyType DWord -Value 2 -Force
# Turn off auto App updates
# Windows 8+ (windows 8 use a value of 2 or 3 while 10 uses 2 or 4)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -PropertyType DWord -Value 2 -Force
# Disable app URI handlers
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableAppUriHandlers" -PropertyType DWord -Value 0 -Force


###############################################
######              Speed Misc           ######
###############################################






###############################################
######          APP(x) security          ######
###############################################
# Do not allow apps to run on none OS drives
Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Appx" -Name "RestrictAppDataToSystemVolume" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Appx" -Name "RestrictAppToSystemVolume" -PropertyType DWord -Value 1 -Force
# Prevent apps over cellular data
# Windows 10 RS2+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WwanSvc\CellularDataAccess" -Name "LetAppsAccessCellularData" -PropertyType DWord -Value 0 -Force
# FIXME:, whitelist via "LetAppsAccessCellularData_UserInControlOfTheseApps_List"
# Disallow apps to shutdown the system
# Vista+
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "AllowBlockingAppsAtShutdown" -PropertyType DWord -Value 0 -Force

###############################################
###### 			     COM                 ######
###############################################
# Harden the COM Infrastructure
# Default 20 (32)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Winmgmt" -Name "Type" -PropertyType DWord -Value 10 -Force
# GPO
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\gpsvc" -Name "Type" -PropertyType DWord -Value 10 -Force
# Turn on COM search for CLSID
# This irrelevant in Windows 10 Build 1603+
# Win2k+
# New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\App Management" -Name "COMClassStore" -PropertyType DWord -Value 0 -Force

###############################################
###### 			    DCOM                 ######
###############################################
# Allow DCOM security check local list exceptions
# Windows XP SP2+
<#
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DCOM\AppCompat" -Name "AllowLocalActivationSecurityCheckExemptionList" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DCOM\AppCompat" -Name "ListBox_Support_ActivationSecurityCheckExemptionList" -PropertyType DWord -Value 0 -Force
#>

###############################################
###### 	        Digital Locker           ######
###############################################
# Turn off Digital Locker
# Vista+
<#
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Digital Locker" -Name "DoNotRunDigitalLocker" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Digital Locker" -Name "DoNotRunDigitalLocker" -PropertyType DWord -Value 1 -Force
#>


###############################################
###### 			 System Restore          ######
###### Windows 10 SR is based on the Win 7 ####
###### solution which is very limited!   ######
######
## Use "Macrium Reflect" or "relic" instead ###
###############################################
# Turn off System Restore (master button)
# Windows 7+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\SystemRestore" -Name "DisableSR" -PropertyType DWord -Value 1 -Force
# Turn off the SR config and lock it down
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\SystemRestore" -Name "DisableConfig" -PropertyType DWord -Value 1 -Force


###############################################
###### 			     SMB                 ######
###############################################
# Turn off SMB v1
# Since Windows 1707 SMB is disabled/removed
#Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
#New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -PropertyType DWord -Value 0 -Force
# Turn off SMB v3.1.1+
# Windows 10 default SMB version
#Set-SmbServerConfiguration -EnableSMB3Protocol $false -Force
# Turn on encrypted File Server VSSP provider
# Windows 8+
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\fssProv" -Name "EncryptProtocol" -PropertyType DWord -Value 1 -Force
# Turn off shared folders
# XP+
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\SharedFolders" -Name "PublishSharedFolders" -PropertyType DWord -Value 0 -Force


###############################################
###### 			  Remote Shell           ######
###############################################
# Turn off Remote Shell Access
# Vista+
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" -Name "AllowRemoteShellAccess" -PropertyType DWord -Value 0 -Force

<#

# IDLE Timeout
# Min = 0
# Max = 2147483647
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" -Name "IdleTimeout" -PropertyType DWord -Value 0 -Force
# Max connected users
# Min = 1
# Max = 100
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" -Name "MaxConcurrentUsers" -PropertyType DWord -Value 1 -Force
# Max Shell memory (in MB)
# Min = 0
# Max = 2147483647
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" -Name "MaxMemoryPerShellMB" -PropertyType DWord -Value 1 -Force
# Max processes per Shell
# Min = 0
# Max = 2147483647
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" -Name "MaxProcessesPerShell" -PropertyType DWord -Value 0 -Force
# Default Shell timeout
# Min = 0
# Max = 2147483647
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" -Name "ShellTimeOut" -PropertyType DWord -Value 0 -Force

#>

###############################################
###### 			    IME Policy           ######
###############################################
# Turn On Misconversion Logging For Misconversion Report
# Windows 8+
New-ItemProperty -Path "HKCU:\software\policies\Microsoft\ime\shared" -Name "misconvlogging" -PropertyType DWord -Value 1 -Force
# Turn Off Saving Auto Tuning Data To File
# Windows 8+
New-ItemProperty -Path "HKCU:\software\policies\Microsoft\ime\shared" -Name "SaveAutoTuneDataToFile" -PropertyType DWord -Value 1 -Force
# Turn Off Saving Auto Tuning Data To File
# Windows 8+
New-ItemProperty -Path "HKCU:\software\policies\Microsoft\ime\shared" -Name "UseHistorybasedPredictiveInput" -PropertyType DWord -Value 0 -Force
# Turn Off Open Extended Dictionary
# Windows 8+
New-ItemProperty -Path "HKCU:\software\policies\Microsoft\ime\shared" -Name "OpenExtendedDict" -PropertyType DWord -Value 0 -Force
# Turn Off Internet Search Integration
# Windows 8+
New-ItemProperty -Path "HKCU:\software\policies\Microsoft\ime\shared" -Name "SearchPlugin" -PropertyType DWord -Value 0 -Force
# Turn Off Custom Dictionary
# Windows 8+
New-ItemProperty -Path "HKCU:\software\policies\Microsoft\ime\shared" -Name "UserDict" -PropertyType DWord -Value 0 -Force
# Restrict Character Code Range Of Conversion
# Windows 8+
# FIXME: New-ItemProperty -Path "HKCU:\software\policies\Microsoft\ime\shared" -Name "CodeAreaForConversion" -PropertyType DWord -Value 0 -Force
# Do Not Include Non Publishing Standard Glyph In The Candidate List
# Windows 8+
# New-ItemProperty -Path "HKCU:\software\policies\Microsoft\ime\shared" -Name "ShowOnlyPublishingStandardGlyph" -PropertyType DWord -Value 0 -Force
# Turn On Cloud Candidate
# Windows 10+ (NOARM)
New-ItemProperty -Path "HKCU:\software\policies\Microsoft\ime\shared" -Name "Enable Cloud Candidate" -PropertyType DWord -Value 0 -Force
# Turn off Cloud Candidate CHS
# Windows 10+
New-ItemProperty -Path "HKCU:\software\policies\Microsoft\ime\shared" -Name "Enable Cloud Candidate" -PropertyType DWord -Value 0 -Force
# Turn On Live Stickers
# Windows 10 RS4+
New-ItemProperty -Path "HKCU:\software\policies\Microsoft\ime\shared" -Name "EnableLiveSticker" -PropertyType DWord -Value 0 -Force
# Turn off Lexicon Update
# Windows 10+ (NOARM)
New-ItemProperty -Path "HKCU:\software\policies\Microsoft\ime\shared" -Name "Enable Lexicon Update" -PropertyType DWord -Value 0 -Force

###############################################
###### 			Remote Desktop           ######
###############################################
# Turn off Remote Desktop (master button)
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "AllowSignedFiles" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "DisablePasswordSaving" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Conferencing" -Name "NoRDS" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "AllowSignedFiles" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "AllowUnsignedFiles" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "CreateEncryptedOnlyTickets" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "DisablePasswordSaving" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowUnsolicited" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDenyTSConnections" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fEnableUsbBlockDeviceBySetupClass" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fEnableUsbNoAckIsochWriteToDevice" -PropertyType Dword -Value 80 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fEnableUsbSelectDeviceByInterface" -PropertyType Dword -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\RemoteAdminSettings" -Name "Enabled" -PropertyType Dword -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\RemoteDesktop" -Name "Enabled" -PropertyType Dword -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\UPnPFramework" -Name "Enabled" -PropertyType Dword -Value 0 -Force
# Enforce Strong Remote Desktop Encryption (if RD is enabled)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel" -PropertyType DWord -Value 3 -Force





###############################################
###### 				Security             ######
##      https://msrc-blog.Microsoft.com/     ##
###############################################
# Disable Intel Transactional Synchronization Extensions (TSX)
# Closes Zombieload v2 on Intel Haswell, Broadwell and Skylake CPU's
# https://software.intel.com/security-software-guidance/software-guidance/intel-transactional-synchronization-extensions-intel-tsx-asynchronous-abort
# https://portal.msrc.microsoft.com/en-us/security-guidance/releasenotedetail/164aa83e-499c-e911-a994-000d3a33c573
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" -Name "DisableTsx" -PropertyType DWord -Value 1 -Force
# Default SSL Cipher Order
# (FIXME:)
# Windows Vista+
# SSLConfiguration
#Set-ItemProperty -Path "HKLM:\HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Name "Functions" -PropertyType String -Value TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA
#
#[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002]
#"EccCurves"=hex(7):4e,00,69,00,73,00,74,00,50,00,33,00,38,00,34,00,00,00,4e,00,\
#  69,00,73,00,74,00,50,00,32,00,35,00,36,00,00,00,00,00
#
# Default SSL Curve Order
#
# SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002



# Disallow 16-Bit apps
# Windows NET+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AppCompat" -Name "VDMDisallowed" -PropertyType DWord -Value 1 -Force
# Turn off 16-Bit Prop Page
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AppCompat" -Name "DisablePropPage" -PropertyType DWord -Value 1 -Force
# Do not display last login info
# Vista+
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisplayLastLogonInfo" -PropertyType DWord -Value 0 -Force
# Do not display logon hours warning
# Vista+
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLogonHoursWarnings" -PropertyType DWord -Value 1 -Force
# Software SAS (default) policy
# Vista+
# (FIXME:)
# 0 = None
# 1 = SYSTEM
# 2 = UIAccess
# 3 = Both
# Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "SoftwareSASGeneration" -PropertyType DWord -Value 1 -Force
# Report Cached Logon Policy
# Vista+
# FIXME:
# Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ReportControllerMissing" -PropertyType DWord -Value 1 -Force
# Automatic restart Sign-On
# RS6+ (NOSERVER)
# FIXME:
# Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableAutomaticRestartSignOn" -PropertyType DWord -Value 1 -Force
# Automatic restart sign
# RS6+ (NOSERVER)
# FIXME: ... string value (both)
# Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConfigAutomaticRestartSignOn_EnableIfSecure" -PropertyType DWord -Value 1 -Force
# Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConfigAutomaticRestartSignOn_EnableAlways" -PropertyType DWord -Value 1 -Force
# Disable Named Pipe Shutdown
# Vista+
# FIXME: .. possible breakage
# Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableShutdownNamedPipe" -PropertyType DWord -Value 1 -Force
# Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownSessionTimeout" -PropertyType DWord -Value 1 -Force

# Approve ActiveX Installer
# relict from pre Vista
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AxInstaller\ApprovedActiveXInstallSites" -Name "ApprovedList" -PropertyType DWord -Value 1 -Force
# FIXME:, list sites via ApprovedActiveXInstallSiteslist + AxISURLZonePolicies

# Allowed Null Session
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "RestrictAnonymous" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "everyoneincludesanonymous" -Value 0
# Remove MasterKeyLegacyCompliance
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography\Protect\Providers\df9d8cd0-1501-11d1-8c7a-00c04fc297eb" -Name "MasterKeyLegacyCompliance" -PropertyType DWord -Value 0 -Force
# Enforce SEHOP (OS takes care of it)
#New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -PropertyType DWord -Value 0 -Force
# Enforce DEP (OS takes care of it)
# bcdedit /set nx AlwaysON
# Allow and enable (if possible) IPSec NAT.
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PolicyAgent" -Name "AssumeUDPEncapsulationContextOnSendRule" -PropertyType DWord -Value 2 -Force
# DO NOT enforce ASLR!
# https://msrc-blog.Microsoft.com/2010/12/08/on-the-effectiveness-of-dep-and-aslr/
# https://mspoweruser.com/windows-aslr-flaw-heres-can-fix/
# There are several drawbacks, and the software developer should decide if using DEP & ASLR makes sense e.g. Everything does not use ASLR because it's a search replacement for e.g. Cortana.
#New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "MitigationOptions" -PropertyType Binary -Value ([byte[]](00,01,01,00,00,00,00,00,00,00,00,00,00,00,00,00))
# Require security devide "Password for Work"
# NOT needed unless you explicitly use it
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -Name "RequireSecurityDevice" -PropertyType DWord -Value 1 -Force
# Turn off CDM
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCdm" -PropertyType DWord -Value 1 -Force
# Disable HTTP Printing - this will not break printing out HTTP websites!
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "DisableHTTPPrinting" -PropertyType DWord -Value 1 -Force
# Do not allow Windows Search to Index encrypted storages
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowIndexingEncryptedStoresOrItems" -PropertyType DWord -Value 0 -Force
# Turn off Printer Web PnP Downloads
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "DisableWebPnPDownload" -PropertyType DWord -Value 1 -Force
# Allow all drivers to be loaded
# Windows 8+
# 1 = GoodPlusUnknown
# 3 = GoodPlusUnknownPlusKnownBadCritical
# 7 = DriverLoadPolicy-All
# 8 = GoodOnly
# WARNING: Bootloop if changed!
#New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" -Name "DriverLoadPolicy" -PropertyType DWord -Value 7 -Force
# Connections
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "fMinimizeConnections" -PropertyType DWord -Value 1 -Force
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "fBlockNonDomain" -PropertyType DWord -Value 1 -Force
#New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Name "NoGPOListChanges" -PropertyType DWord -Value 0 -Force
# Prevent Socket Hijacking Missing
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters" -Name "ForceActiveDesktopOn" -Value 1
# Prevent empty sessions
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "allownullsessionfallback" -PropertyType DWord -Value 0 -Force
# Turn off LM Hash
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLmHash" -PropertyType DWord -Value 1 -Force
# Turn off blank passwords
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -PropertyType DWord -Value 1 -Force
# Turn on LDAP Client Integrity Check
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ldap" -Name "LDAPClientIntegrity" -PropertyType DWord -Value 1 -Force
# NTLMMinServerSec
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinServerSec" -PropertyType DWord -Value 536870912 -Force
# Enforce default protection mode
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "ProtectionMode" -PropertyType DWord -Value 1 -Force
# Turn off shared connection GUI
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_ShowSharedAccessUI" -PropertyType DWord -Value 0 -Force


# Restrict Remote SAM (FIXME:)
#[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa]
#"RestrictRemoteSAM"="O:BAG:BAD:(A;;RC;;;BA)"


# Turn on Credentials Delegation
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" -Name "AllowProtectedCreds" -PropertyType DWord -Value 1 -Force
# CredSSP Patch Causing RDP Authentication Error due to Encryption Oracle Remediation
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP" -Name "AllowEncryptionOracle" -PropertyType DWord -Value 2 -Force
# Delete Pagefile.sys at Shutdown
Set-ItemProperty -Path "HKLM:\SYSTEM\Current\ControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutDown" -PropertyType DWord -Value 1 -Force
<# Server
# https://support.Microsoft.com/en-us/help/3000483/ms15-011-vulnerability-in-group-policy-could-allow-remote-code-execution
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -Name "RequireMutualAuthentication" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -Name "RequireIntegrity" -PropertyType DWord -Value 1

# https://support.Microsoft.com/en-us/help/3116180/ms15-124-cumulative-security-update-for-internet-explorer-december-8-2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\InternetExplorer\Main\FeatureControl" -Name "FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\InternetExplorer\Main\FeatureControl" -Name "FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING" -PropertyType DWord -Value 1
# https://support.Microsoft.com/en-us/help/3140245/update-to-enable-tls-1-1-and-tls-1-2-as-default-secure-protocols-in-wi

# Server only - Clear plain-text passwords from WDigest memory
# https://docs.Microsoft.com/en-us/security-updates/SecurityAdvisories/2016/2871997
# https://support.Microsoft.com/kb/2871997
# Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value "0"
# Remove-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -PropertyType DWord -Value 0 -Force

# Server only - Block unsafe ticket-granting (FIXME:)
# https://portal.msrc.Microsoft.com/en-us/security-guidance/advisory/ADV190006
# https://support.Microsoft.com/en-us/help/4490425/updates-to-tgt-delegation-across-incoming-trusts-in-windows-server
# netdom.exe trust fabrikam.com /domain:contoso.com /EnableTGTDelegation:No | Out-Null

#>
# Turn off Adobe Reader DC Protected Mode (I use SumatraPDF instead)
#New-ItemProperty -Path "HKCU:\SOFTWARE\Adobe\Acrobat Reader\DC\Privileged" -Name "bProtectedMode" -PropertyType DWord -Value 1
#New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "bProtectedMode" -PropertyType DWord -Value 1
# Turn off Adobe JavaScript
# https://www.adobe.com/devnet-docs/acrobatetk/tools/AppSec/sandboxprotections.html
# http://www.adobe.com/support/security/advisories/apsa09-07.html
#New-ItemProperty -Path "HKCU:\Software\Adobe\Acrobat Reader\9.0\JSPrefs" -Name "bEnableJS" -PropertyType DWord -Value 0
#New-ItemProperty -Path "HKCU:\Software\Adobe\Acrobat Reader\9.0\JSPrefs" -Name "bEnableConsoleOpen" -PropertyType DWord -Value 0
#New-ItemProperty -Path "HKCU:\Software\Adobe\Acrobat Reader\9.0\JSPrefs" -Name "benableMenuItems" -PropertyType DWord -Value 0



# Turn off WPD (not needed in 1909+ wpad js engine runs isolated)
# https://twitter.com/epakskape/status/1007316208087994368
# https://docs.Microsoft.com/en-us/azure/active-directory/devices/hybrid-azuread-join-manual-steps + KB3165191 (MS16-077)
# AdGuard Home
#0.0.0.0 wpad wpad.my.home
#:: wpad wpad.my.home
# Win WPAD HOSTS
#0.0.0.0 wpad
#0.0.0.0 wpad.my.home
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\WinHttpAutoProxySvc" -Name "Start" -PropertyType DWord -Value 4 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -PropertyType DWord -Value 0 -Force
# Turn off Sidebar Gadgets (obsolete but still in gpedit)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar" -Name "TurnOffSidebar" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar" -Name "TurnOffUnsignedGadgets" -PropertyType DWord -Value 1
# Turn off "Active Desktop"
# pre Vista+
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ForceActiveDesktopOn" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoActiveDesktop" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" -Name "ShowSuperHidden" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoActiveDesktopChanges" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" -Name "NoAddingComponents" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" -Name "NoComponents" -PropertyType DWord -Value 1 -Force
# Turn on certificate checks for apps (does not exists on LTSB(C))
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers" -Name "authenticodeenabled" -PropertyType DWord -Value 1 -Force
# Turn off network options from Lock Screen
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -PropertyType DWord -Value 1
# Turn off shutdown options from Lock Screen
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -PropertyType DWord -Value 0
# Turn on Data Execution Prevention (DEP)
bcdedit /set `{current`} nx OptOut | Out-Null
#bcdedit /set `{current`} nx OptIn | Out-Null
# Turn off Windows Script Host
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -PropertyType DWord -Value 0
# Turn on Windows Firewall
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -ErrorAction SilentlyContinue
# Turn off automatic installation of new network devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -PropertyType DWord -Value 0
# Enable network profile -> public (disables file sharing, device discovery, and more...)
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Name "Category" -ErrorAction SilentlyContinue
# Set unknown networks profiles to public
Set-NetConnectionProfile -NetworkCategory Public
# Turn off Wi-Fi Hotspot reports
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "value" -PropertyType DWord -Value 0 -Force
# Disallow Autoplay for non-volume devices
# Windows 7+
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoAutoplayfornonVolume" -PropertyType DWord -Value 1 -Force
# Turn off Clipboard History Feature
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Clipboard" -Name "EnableClipboardHistory" -PropertyType DWord -Value 0 -Force
# Turn off Clipboard cloud features
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Clipboard" -Name "IsClipboardSignalProducingFeatureAvailable" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Clipboard" -Name "IsCloudAndHistoryFeatureAvailable" -PropertyType DWord -Value 0


# Allowed to format and eject removable media <-> 'Administrators and Interactive Users'
# <deleted> = (Default)
# 0000000 = Administrators only
# 0000001 = Administrators and power users
# 0000002 = Administrators and interactive users (CIS)
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AllocateDASD2" -PropertyType DWord -Value 2 -Force
# Turn off verbose start
#New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system" -Name verbosestatus -PropertyType DWord -Value 1 -Force
# Disable search via web from within apps
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchToUseLocation" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchPrivacy" -PropertyType DWord -Value 3 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchSafeSearch" -PropertyType DWord -Value 3 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWeb" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWebOverMeteredConnections" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DeviceHistoryEnabled" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "HasAboveLockTips" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "PreventRemoteQueries" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "IsMicrophoneAvailable" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "IsWindowsHelloActive" -PropertyType DWord -Value 0
# Turn off "Hide Drives With No Media"
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideDrivesWithNoMedia" -PropertyType DWord -Value 0 -Force
# Turn off UPnP Discovery
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\DirectPlayNATHelp\DPNHUPnP" -Name "UPnPMode" -PropertyType DWord -Value 2 -Force
# Miracast / PlayTo  (end of life product)
#New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\MiracastReceiver" -Name "NetworkQualificationEnabled" -PropertyType DWord -Value 0 -Force
#New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\MiracastReceiver" -Name "ConsentToast" -PropertyType DWord -Value 2 -Force
#New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\MiracastReceiver" -Name "Primary Authorization Method" -PropertyType DWord -Value 3 -Force
#New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\MiracastReceiver" -Name "Secondary Authorization Method" -PropertyType DWord -Value 0 -Force
#New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\MiracastReceiver" -Name "Tertiary Authorization Method" -PropertyType DWord -Value 0 -Force
#New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\MiracastReceiver" -Name "EnabledOnACOnly"-PropertyType DWord -Value 0 -Force
#New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PlayToReceiver" -Name "AutoEnabled" -PropertyType DWord -Value 0 -Force
# Turn off Hotspot 2.0 Networking
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WlanSvc\AnqpCache" -Name "OsuRegistrationStatus" -PropertyType DWord -Value 0 -Force
# Turn off LMHOSTS lookup
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "EnableLMHOSTS" -PropertyType DWord -Value 0 -Force
# KB160177 - https://support.Microsoft.com/kb/160177
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NodeType" -PropertyType DWord -Value 2 -Force
# Turn off Domain Name Devolution
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "UseDomainNameDevolution" -PropertyType DWord -Value 0 -Force
# Turn off Fast Restart (also known as "Hiberboot") (Hibernate/Sleep instead of shutting down) to prevent disk encryption errors with third party tools (fixed in 1909+?)
# Vista+
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -PropertyType DWord -Value 0
# Turn off Clipboard History capability
# https://support.microsoft.com/en-in/help/4464215/windows-10-get-help-with-clipboard
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowClipboardHistory" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowCroosDeviceClipboard" -PropertyType DWord -Value 0 -Force
# Turn on untrusted Font blocking (WD controlled)
# <deleted> = (Default)
# 00,10,a5,d4,e8,00,00,00 (1000000000000) = Block untrusted fonts and log events (CIS)
# 00,20,4a,a9,d1,01,00,00 (2000000000000) = Do not block untrusted fonts
# 00,30,ef,7d,ba,02,00,00 (3000000000000) = Log events without blocking untrusted fonts
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\MitigationOptions" -Name "MitigationOptions_FontBocking" -PropertyType hex -Value 00,10,a5,d4,e8,00,00,00 -Force
# Turn on Structured Exception Handling Overwrite Protection (SEHOP - default on)
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -PropertyType DWord -Value 0 -Force
# Turn on Safe DLL search mode (SafeDllSearchMode)
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "SafeDllSearchMode" -PropertyType DWord -Value 1 -Force
# Turn off Font Providers
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableFontProviders" -PropertyType DWord -Value 0 -Force
# Turn off IPv6 (Ensure TCPIP6 Parameter 'DisabledComponents <-> '0xff (255))
# I use IPv6 with my router filters Teredo/6to4/ISATAP traffic, however ISATAP and 6to4 got disabled by default since Creators Update
# https://techcommunity.microsoft.com/t5/Networking-Blog/Core-Network-Stack-Features-in-the-Creators-Update-for-Windows/ba-p/339676
# 0000000 = Enable all IPv6 components
# 0000xff = Disable all IPv6 components (CIS)
# 0000002 = Disable 6to4
# 0000004 = Disable ISATAP
# 0000008 = Disable Teredo
# 000000a = Disable Teredo and 6to4
# 0000001 = Disable all tunnel interfaces
# 0000010 = Disable all LAN and PPP interfaces
# 0000011 = Disable all LAN, PPP and tunnel interfaces
# 0000020 = Prefer IPv4 over IPv6
#New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" -Name "DisabledComponents" -PropertyType DWord -Value 000000a -Force
# Turn off the "Order Prints" picture task
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoOnlinePrintsWizard" -PropertyType DWord -Value 1 -Force
# Turn off "Publish to Web" task for files and folders
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoPublishingWizard" -PropertyType DWord -Value 1 -Force
# Turn off User Activities
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -PropertyType DWord -Value 0 -Force
# Turn off "Offer Remote Assistance"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -PropertyType DWord -Value 0
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "CreateEncryptedOnlyTickets" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "AllowFullControl" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "AllowToGetHelp" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "EnableChatControl" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "MaxTicketExpiry" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "MaxTicketExpiryUnits" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnection" -PropertyType DWord -Value 1 -Force
# Prevent Remote Desktop Services
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -PropertyType DWord -Value 1
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "DenyTSConnections" -PropertyType DWord -Value 1 -Force
# Turn off COM port redirection
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "DisableCcm" -PropertyType DWord -Value 1 -Force
# Turn off drive redirection
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "DisableCdm" -PropertyType DWord -Value 1 -Force
# Turn off LPT port redirection
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "DisableLPT" -PropertyType DWord -Value 1 -Force
# Turn off Plug and Play device redirection
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "DisablePNPRedir" -PropertyType DWord -Value 1 -Force
# Turn off Cloud Search
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -PropertyType DWord -Value 0 -Force
# Turn off Online Help
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableInHelp" -PropertyType DWord -Value 1 -Force
# Disable Remote Registry
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry" -Name "Start" -PropertyType DWord -Value 4 -Force
# Disable LLMNR (Port: 5355)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -PropertyType DWord -Value 0
# Turn on Retpoline to migrate Spectre v2 (FIXME: Check if needed)
#New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverride" -PropertyType DWord -Value 1024 -Force
#New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverrideMask" -PropertyType DWord -Value 1024 -Force
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -Name "cadca5fe-87d3-4b96-b7fb-a231484277cc" -PropertyType DWord -Value 0
# Spectre variant v4 (FIXME: Check if needed)
#Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverride" -Value "00000008"
#Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverrideMask" -Value "00000003"
# Turn off access to mapped drives from app running with elevated permissions with Admin Approval Mode enabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -PropertyType DWord -Value 0
# Turn off Domain Picture Passwords
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "BlockDomainPicturePassword" -PropertyType DWord -Value 1 -Force

##########################################################
###### 					LanMan Server               ######
##########################################################
# Turn off Administrative Shares
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -PropertyType DWord -Value 0
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareServer" -PropertyType DWord -Value 0 -Force
# Hash Publication
# Windows 7+
# 0 = Follow Share
# 1 = Disable on All Shares
# 2 = Enable on All Shares
#Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer" -Name "HashPublicationForPeerCaching" -PropertyType DWord -Value 0
# POL Hash Support version
# Windows 8+
# 1 = Support v1
# 2 = Support v2
# 3 = Support v1 and V2
#Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer" -Name "HashSupportVersion" -PropertyType DWord -Value 2
# Cipher Suite Order
# FIXME: Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer" -Name "CipherSuiteOrder" -PropertyType DWord -Value 2
# Honor Cipher Suite Order
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer" -Name "HonorCipherSuiteOrder" -PropertyType DWord -Value 1 -Force


##########################################################
###### 					Task Manager                ######
##########################################################
# Turn off MS Task Manager
# Win2k+
# I use Process Hacker
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableTaskMgr" -PropertyType DWord -Value 1 -Force
#New-ItemProperty -Path "HKLM:\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableTaskMgr" -PropertyType DWord -Value 1 -Force


##########################################################
###### 					Ctrl+Alt+DEL                ######
##########################################################
# Turn off Loggoff
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoLogoff" -PropertyType DWord -Value 1 -Force
# Turn off "Lock Computer"
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableLockWorkstation" -PropertyType DWord -Value 1 -Force
# Turn off "Disable Password"
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableChangePassword" -PropertyType DWord -Value 1 -Force


##########################################################
###### 					Desktop                     ######
##########################################################
# Turn off "Get even more out of Windows" notification
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -PropertyType DWord -Value 0 -Force
# Turn off "Disable Password"
# pre Vista
# FIXME: SZ value
# sz_ATC_AdminAddItem       New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop\AdminComponent" -Name "Add" -PropertyType DWord -Value 1 -Force
# sz_ATC_AdminDeleteItem    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop\AdminComponent" -Name "Delete" -PropertyType DWord -Value 1 -Force
# Turn off "Add"
# pre Vista
# New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" -Name "NoAddingComponents" -PropertyType DWord -Value 1 -Force
# Turn off "Close"
# pre Vista
# New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" -Name "NoClosingComponents" -PropertyType DWord -Value 1 -Force
# Turn off "DEL"
# pre Vista
# New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" -Name "NoDeletingComponents" -PropertyType DWord -Value 1 -Force
# Turn off "Components"
# pre Vista
# New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" -Name "NoComponents" -PropertyType DWord -Value 1 -Force
# Turn off "No HTML Paper"
# pre Vista
# New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" -Name "NoHTMLWallPaper" -PropertyType DWord -Value 1 -Force
# Turn off "No HTML Paper"
# Win2k+
# New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" -Name "NoHTMLWallPaper" -PropertyType DWord -Value 1 -Force
# Turn off "Wallpaper"
# Win2k+
# 1 = Tile
# 2 = Stretch
# 3 = Keep Aspect Ratio
# 4 = Crop to fit
# 5 = Span
# New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "Wallpaper" -PropertyType DWord -Value 1 -Force
# AD Filter
# Win2k+
# New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Directory UI" -Name "EnableFilter" -PropertyType DWord -Value 1 -Force
# Query Limit
# Win2k+
# Max = 4000000000
# New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Directory UI" -Name "QueryLimit" -PropertyType DWord -Value 1 -Force
# Disallow "Desktop"
# Win2k+
# New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDesktop" -PropertyType DWord -Value 1 -Force
# Turn off Desktop Cleanup Wizard
# XP and Server Only
# New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDesktopCleanupWizard" -PropertyType DWord -Value 1 -Force
# Turn off Internet Icon
# Win2k+
# New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\NonEnum" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -PropertyType DWord -Value 1 -Force
# Turn off "My Documents" Icon
# Win2k+
# New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\NonEnum" -Name "{450D8FBA-AD25-11D0-98A8-0800361B1103}" -PropertyType DWord -Value 1 -Force
# Turn off "Netood" Icon
# Win2k+
# New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoNetHood" -PropertyType DWord -Value 1 -Force
# Turn off "Properties"
# Win2k SP3+
# New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoPropertiesMyComputer" -PropertyType DWord -Value 1 -Force
# Turn off "Recent Docs NetHood"
# Win2k SP3+
# New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsNetHood" -PropertyType DWord -Value 1 -Force
# Turn off "RecycleBin" Icon
# XP+
# New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\NonEnum" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -PropertyType DWord -Value 1 -Force
# Turn off "RecycleBin" Properties
# XP+
# New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoPropertiesRecycleBin" -PropertyType DWord -Value 1 -Force
# Turn off "SaveSettings"
# Win2k+
# New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoSaveSettings" -PropertyType DWord -Value 1 -Force
# Turn off "DragDropClose"
# Win2k+
# New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoCloseDragDropBands" -PropertyType DWord -Value 1 -Force
# Turn off "Moving Bands"
# Win2k+
# New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoMovingBands" -PropertyType DWord -Value 1 -Force
# Turn off Window Minimizing shortcuts
# Windows 7+
# New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoWindowMinimizingShortcuts" -PropertyType DWord -Value 1 -Force




##########################################################
###### 				   NetMeeting v3.0+             ######
##########################################################
# Turn off App Sharing
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Conferencing" -Name "NoAppSharing" -PropertyType DWord -Value 1 -Force
# Prevent Granting Control
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Conferencing" -Name "NoAllowControl" -PropertyType DWord -Value 1 -Force
# Prevent Sharing
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Conferencing" -Name "NoSharing" -PropertyType DWord -Value 1 -Force
# Prevent Sharing via CMD Prompt
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Conferencing" -Name "NoSharingDosWindows" -PropertyType DWord -Value 1 -Force
# Prevent Desktop Sharing
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Conferencing" -Name "NoSharingDesktop" -PropertyType DWord -Value 1 -Force
# Prevent Explorer Sharing
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Conferencing" -Name "NoSharingExplorer" -PropertyType DWord -Value 1 -Force
# Turn off True Color Sharing
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Conferencing" -Name "NoTrueColorSharing" -PropertyType DWord -Value 1 -Force
# Turn off Audio Sharing
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Conferencing" -Name "NoAudio" -PropertyType DWord -Value 1 -Force
# Turn off Audio Sharing
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Conferencing" -Name "NoChangeDirectSound" -PropertyType DWord -Value 1 -Force
# Turn off Full-Duplex
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Conferencing" -Name "NoFullDuplex" -PropertyType DWord -Value 1 -Force
# Turn off Video Receiving
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Conferencing" -Name "NoReceivingVideo" -PropertyType DWord -Value 1 -Force
# Turn off Video Sharing
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Conferencing" -Name "NoSendingVideo" -PropertyType DWord -Value 1 -Force
# AV Throughput
# Min = 85000
# Max = 621700
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Conferencing" -Name "MaximumBandwidth" -PropertyType DWord -Value 621700 -Force
# Persist Auto Accept Calls
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Conferencing" -Name "PersistAutoAcceptCalls" -PropertyType DWord -Value 621700 -Force
# Turn off Chats
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Conferencing" -Name "NoChat" -PropertyType DWord -Value 1 -Force
# Disable New Whiteboard
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Conferencing" -Name "NoNewWhiteBoard" -PropertyType DWord -Value 1 -Force
# Disable Old Whiteboard
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Conferencing" -Name "NoOldWhiteBoard" -PropertyType DWord -Value 1 -Force
# Disable Auto-Configuration
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Conferencing" -Name "Use AutoConfig" -PropertyType DWord -Value 0 -Force
# FIXME: New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Conferencing" -Name "Use ConfigFile" -PropertyType DWord -Value 0 -Force
# Prevent adding ILS
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Conferencing" -Name "NoAddingDirectoryServers" -PropertyType DWord -Value 1 -Force
# No Auto Accept Calls
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Conferencing" -Name "NoAutoAcceptCalls" -PropertyType DWord -Value 1 -Force
# Prevent Changing Call Mode
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Conferencing" -Name "NoChangingCallMode" -PropertyType DWord -Value 1 -Force
# Prevent Directory Services
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Conferencing" -Name "NoDirectoryServices" -PropertyType DWord -Value 1 -Force
# Turn off Receiving Files
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Conferencing" -Name "NoReceivingFiles" -PropertyType DWord -Value 1 -Force
# Prevent Sending Files
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Conferencing" -Name "NoSendingFiles" -PropertyType DWord -Value 1 -Force
# Prevent Web Directory
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Conferencing" -Name "NoWebDirectory" -PropertyType DWord -Value 1 -Force
# Restrict FT Send Size
# Max = 999999999
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Conferencing" -Name "MaxFileSendSize" -PropertyType DWord -Value 0 -Force
# Intranet Support
# FIXME: New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Conferencing" -Name "IntranetSupportURL" -PropertyType DWord -Value 0 -Force
# Security Options
# 1 = Security Level Required
# 2 = Security Level Disabled
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Conferencing" -Name "CallSecurity" -PropertyType DWord -Value 1 -Force
# Disable Advance Calling Button
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Conferencing" -Name "NoAdvancedCalling" -PropertyType DWord -Value 1 -Force
# Disable Audio Page
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Conferencing" -Name "NoAudioPage" -PropertyType DWord -Value 1 -Force
# No general Help
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Conferencing" -Name "NoGeneralPage" -PropertyType DWord -Value 1 -Force
# Disable Security Page
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Conferencing" -Name "NoSecurityPage" -PropertyType DWord -Value 1 -Force
# Disable Video Page
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Conferencing" -Name "NoVideoPage" -PropertyType DWord -Value 1 -Force





##########################################################
###### 				 Control Panel Display          ######
##########################################################
# Disable Control Panel
# Win2k
#New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "NoDispCPL" -PropertyType DWord -Value 1 -Force
# Hide Settings
# pre Vista
#New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "NoDispSettingsPage" -PropertyType DWord -Value 1 -Force
# Hide Appearance Page
# Win2k+
#New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "NoDispAppearancePage" -PropertyType DWord -Value 1 -Force
# Hide Screensaver UI
# Win2k+
#New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "NoDispScrSavPage" -PropertyType DWord -Value 1 -Force
# Show Screensaver
# Win2k SP1+
#New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaveActive" -PropertyType DWord -Value 1 -Force
# Point to Screenserver
# Win2k SP1+
#New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "SCRNSAVE.EXE" -PropertyType DWord -Value 1 -Force
# Screensaver Secure check
# Win2k SP1+
#New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -PropertyType DWord -Value 1 -Force
# Screen Saver TimeOut
# Win2k SP1+
# Min = 10
# Max = 599940
#New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -PropertyType DWord -Value 95940 -Force
# No Desktop Background UI
# Win2k+
#New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" -Name "NoChangingWallPaper" -PropertyType DWord -Value 1 -Force
# No MousePointers UI
# Windows 7+
#New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Personalization" -Name "NoChangingMousePointers" -PropertyType DWord -Value 1 -Force
# No Desktop Icons UI
# Windows 7+
#New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Personalization" -Name "NoDispBackgroundPage" -PropertyType DWord -Value 1 -Force
# Disable Color Scheme Choice
# Vista - XP
#New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Personalization" -Name "NoColorChoice" -PropertyType DWord -Value 1 -Force
# Disable Theme Change
# XP+
#New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Personalization" -Name "NoThemesTab" -PropertyType DWord -Value 1 -Force
# Define a default Theme
# XP+
# FIXME: New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Personalization" -Name "ThemeFile" -PropertyType DWord -Value 1 -Force
# Disable visual style
# XP+
#New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "NoVisualStyleChoice" -PropertyType DWord -Value 1 -Force
# Set default visual style
# XP+
#New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "SetVisualStyle" -PropertyType DWord -Value 1 -Force
# Set default visual style
# pre Vista
#New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "NoSizeChoice" -PropertyType DWord -Value 1 -Force










##########################################################
###### 				    .NET Framework              ######
##########################################################
# Turn off Telemetry Data in .NET Core
# https://www.michaelcrump.net/part12-aspnetcore/
setx -Ux DOTNET_CLI_TELEMETRY_OPTOUT 1 | Out-Null
setx -Ux DOTNET_SKIP_FIRST_TIME_EXPERIENCE 1 | Out-Null
# Install NET 3.5 offline
# Check the official guide for more information, because MS officially do not provide an "offline" option.
# DISM.exe /Online /Add-Package /PackagePath:”C:%sourcessxsMicrosoft-windows-netfx3-ondemand-package.cab”
# Get-WindowsOptionalFeature -FeatureName NetFx3 -Online
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -PropertyType DWord -Value $ram -Force
# Enforce on .NET 4 runtime for all apps
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework" -Name "OnlyUseLatestCLR" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework" -Name "OnlyUseLatestCLR" -PropertyType DWord -Value 1 -Force
# Change default cryptography for .NET Framework v4+
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -PropertyType DWord -Value 1
# x86 only
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -PropertyType DWord -Value 1
##########################################################
###### 					Login                       ######
##########################################################
# Turn off System Recovery and Factory reset
reagentc /disable 2>&1 | Out-Null
# Turn off automatic recovery mode during boot (workaround for VeraCrypt)
# bcdedit /set `{current`} BootStatusPolicy IgnoreAllFailures | Out-Null
# Turn on F8 boot menu options
#bcdedit /set `{current`} BootMenuPolicy Legacy | Out-Null
# Turn off user first sign-in animation
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFirstLogonAnimation" -PropertyType DWord -Value 0 -Force
# Wait for network at computer startup and logon
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "SyncForegroundPolicy" -PropertyType DWord -Value 1 -Force
##########################################################
###### 				Notification Center             ######
##########################################################
# Turn off "New App Installed" notification
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -PropertyType DWord -Value 1 -Force
# Hide notification about sign in with Microsoft under Windows Security
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows Security Health\State" -Name "AccountProtection_MicrosoftAccount_Disconnected" -PropertyType DWord -Value 1 -Force
##########################################################
###### 						Backup                  ######
######					(Macrium Reflect)           ######
##########################################################
# Enable System Restore
#Enable-ComputerRestore -Drive $env:SystemDrive
#Get-ScheduledTask -TaskName SR | Enable-ScheduledTask
#Get-Service -Name swprv, vss | Set-Service -StartupType Manual
#Get-Service -Name swprv, vss | Start-Service
#Get-CimInstance -ClassName Win32_ShadowCopy | Remove-CimInstance
# Turn on automatic backups of registry to "\System32\config\RegBack" folder
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" -Name "EnablePeriodicBackup" -PropertyType DWord -Value 1 -Force
##########################################################
###### 					Windows Features            ######
# https://docs.Microsoft.com/en-us/powershell/dsc/reference/resources/windows/windowsoptionalfeatureresource
# https://docs.Microsoft.com/en-us/powershell/module/servermanager/uninstall-windowsfeature?view=winserver2012r2-ps
# Get installed features via: "get-windowsoptionalfeature -online"
##########################################################
# Uninstall unwanted optional features
$uninstallfeatures = @(
    "IIS-CommonHttpFeatures"
    "IIS-HttpErrors"
    "IIS-WebServer"                                                         # IIS Server
    "IIS-WebServerRole"
    "Internet-Explorer-Optional-amd64"
    "MultiPoint-Connector-Services"
    "MultiPoint-Connector"
    "MultiPoint-Tools"
    "NET-Framework-Core"                                                    # .NET Core runtimes
    "NetFx3"									                            # .NET Framework 2.0 3.5 runtimes (I use abdh. offline installer because the online installer waste around 400+ MB after extraction)
    #"SMB1Protocol-Client"
    #"SMB1Protocol-Deprecation"
    #"SMB1Protocol-Server"
    #"SMB1Protocol"
    #"SmbDirect"
    "TelnetClient"                                                          # Telnet Client
    "WindowsMediaPlayer"
    #"Client-DeviceLockdown"
    #"Client-EmbeddedBootExp"
    #"Client-EmbeddedLogon"
    #"Client-EmbeddedShellLauncher"
)

foreach ($uninstallfeatures in $uninstallfeatures) {
    Write-Output "Uninstalling $uninstallfeatures"
    Uninstall-WindowsOptionalFeature -Online -FeatureName $uninstallfeatures -NoRestart -WarningAction SilentlyContinue | Out-Null
}


# Disable unwanted optional features
$disablefeatures = @(
    "Client-KeyboardFilter"
    "Client-ProjFS"
    "Client-UnifiedWriteFilter"
    "Containers-DisposableClientVM"
    "Containers"
    "DataCenterBridging"
    "DirectoryServices-ADAM-Client"
    "DirectPlay"
    "FaxServicesClientPackage"
    "HostGuardian"
    "IIS-ApplicationDevelopment"
    "IIS-ApplicationInit"
    "IIS-ASPNET"
    "IIS-BasicAuthentication"
    "IIS-CertProvider"
    "IIS-CGI"
    "IIS-ClientCertificateMappingAuthentication"
    "IIS-CustomLogging"
    "IIS-DefaultDocument"
    "IIS-DigestAuthentication"
    "IIS-DirectoryBrowsing"
    "IIS-FTPExtensibility"
    "IIS-FTPServer"
    "IIS-FTPSvc"
    "IIS-HealthAndDiagnostics"
    "IIS-HostableWebCore"
    "IIS-HttpCompressionDynamic"
    "IIS-HttpCompressionStatic"
    "IIS-HttpLogging"
    "IIS-HttpRedirect"
    "IIS-HttpTracing"
    "IIS-IIS6ManagementCompatibility"
    "IIS-IPSecurity"
    "IIS-ISAPIExtensions"
    "IIS-ISAPIFilter"
    "IIS-LegacyScripts"
    "IIS-LegacySnapIn"
    "IIS-LoggingLibraries"
    "IIS-ManagementConsole"
    "IIS-ManagementService"
    "IIS-Metabase"
    "IIS-NetFxExtensibility"
    "IIS-NetFxExtensibility45"
    "IIS-ODBCLogging"
    "IIS-Performance"
    "IIS-RequestFiltering"
    "IIS-RequestMonitor"
    "IIS-Security"
    "IIS-ServerSideIncludes"
    "IIS-StaticContent"
    "IIS-URLAuthorization"
    "IIS-WebDAV"
    "IIS-WebServerManagementTools"
    "IIS-WebSockets"
    "IIS-WindowsAuthentication"
    "IIS-WMICompatibility"
    "LegacyComponents"
    "MediaPlayback"
    "MSMQ-ADIntegration"
    "MSMQ-Container"
    "MSMQ-DCOMProxy"
    "MSMQ-HTTP"
    "MSMQ-Multicast"
    "MSMQ-Server"
    "MSMQ-Triggers"
    "MSRDC-Infrastructure"
    "NetFx4Extended-ASPNET45"
    "NFS-Administration"
    "Printing-Foundation-Features"
    "Printing-Foundation-InternetPrinting-Client"
    "Printing-Foundation-LPDPrintService"
    "Printing-Foundation-LPRPortMonitor"
    "Printing-PrintToPDFServices-Features"									# PDF printing features (normally not needed, use third-party software)
    "ServicesForNFS-ClientOnly"
    "SimpleTCP"
    "TFTP"
    "TIFFIFilter"
    "WAS-ConfigurationAPI"
    "WAS-NetFxEnvironment"
    "WAS-ProcessModel"
    "WAS-WindowsActivationService"
    "WCF-HTTP-Activation"
    "WCF-HTTP-Activation45"
    "WCF-MSMQ-Activation45"
    "WCF-NonHTTP-Activation"
    "WCF-Pipe-Activation45"
    "WCF-Services45"
    "WCF-TCP-Activation45"
    #"Windows-Defender-ApplicationGuard"
    #"Windows-Defender-Default-Definitions"									# Do NOT uninstall!
    #"Windows-Identity-Foundation"
    "WorkFolders-Client"
    #"Microsoft-Hyper-V-All"
    #"Microsoft-Hyper-V-Hypervisor"
    #"Microsoft-Hyper-V-Management-Clients"
    #"Microsoft-Hyper-V-Management-PowerShell"
    #"Microsoft-Hyper-V-Services"
    #"Microsoft-Hyper-V-Tools-All"
    #"Microsoft-Hyper-V"
)


foreach ($disablefeatures in $disablefeatures) {
    Write-Output "Disabling $disablefeatures"
    Disable-WindowsOptionalFeature -Online -FeatureName $disablefeatures -NoRestart -WarningAction SilentlyContinue | Out-Null
}


# Install optional features
$installfeatures = @(
    "Hyper-V"                                                               # Hyper-V, needed for several security mechanism
    "HypervisorPlatform"
    "Microsoft-Hyper-V-All"                                                 # Sandbox, WD etc.
    "Microsoft-Windows-Client-EmbeddedExp-Package"
    "Microsoft-Windows-NetFx3-OC-Package"                                   # Can't be removed without breaking additional stuff
    "Microsoft-Windows-NetFx3-WCF-OC-Package"
    "Microsoft-Windows-NetFx4-US-OC-Package"                                # Can't be removed without breaking additional stuff
    "Microsoft-Windows-NetFx4-WCF-US-OC-Package"
    "Microsoft-Windows-Subsystem-Linux"									    # Linux Subsystem
    "MicrosoftWindowsPowerShellV2"                                          # PowerShell 2.0 (will be replaced with Core)
    "MicrosoftWindowsPowerShellV2Root"
    #"NetFx3"                                                               # We do not want to enable .NET Framework this way, because it checks online for updates/components.
    "NetFx4-AdvSrvs"
    #"PowerShell-V2"
    "SearchEngine-Client-Package"
    "VirtualMachinePlatform"
    "WCF-TCP-PortSharing45"
)


foreach ($installfeatures in $installfeatures) {
    Write-Output "Installing $installfeatures"
    Install-WindowsFeature -Name $installfeatures -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null
}

# Turn off Touchpad Sensitivity
# 0 = Most sensitive
# 1 = High sensitivity
# 2 = Medium sensitivity (default)
# 3 = Low sensitivity
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PrecisionTouchPad" -Name "AAPThreshold " -PropertyType DWord -Value 99 -Force
# Turn on Windows Photo Viewer association
New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
New-Item -Path $("HKCR:\$type\shell\open") -Force | Out-Null
New-Item -Path $("HKCR:\$type\shell\open\command") | Out-Null
Set-ItemProperty -Path $("HKCR:\$type\shell\open") -Name "MuiVerb" -PropertyType ExpandString -Value "@%ProgramFiles%\Windows Photo Viewer\photoviewer.dll,-3043"
Set-ItemProperty -Path $("HKCR:\$type\shell\open\command") -Name "(Default)" -PropertyType ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
# Needed for Linux "Subsystem" (Windows >= 1803)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowDevelopmentWithoutDevLicense" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -PropertyType DWord -Value 1
# Turn on Aero Shake
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisallowShaking" -ErrorAction SilentlyContinue
# Turn off Maintenance (will break Defrag, Storage Sense & Backup etc.)
#New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Name MaintenanceDisabled -PropertyType DWord -Value 1 -Force
# Turn off Wifi Sense
# NoServer key (the first one)
New-ItemProperty -Path "HKLM:\Software\Microsoft\wcmsvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager" -Name "WiFiSenseCredShared" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager" -Name "WiFiSenseOpen" -PropertyType DWord -Value 0 -Force
#New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name value -PropertyType DWord -Value 0 -Force
# Turn off Windows Compatibility Manager
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name DisablePCA -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name DisablePCA -PropertyType DWord -Value 1 -Force
# Use the "PrtScn" button to open screen snipping
#New-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name PrintScreenKeyForSnippingEnabled -PropertyType DWord -Value 1 -Force
# Remove default printers "Microsoft XPS Document Writer" & "Microsoft Print to PDF
Remove-Printer -Name "Fax", "Microsoft XPS Document Writer", "Microsoft Print to PDF" -ErrorAction SilentlyContinue
# Turn off Game Information downloads
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameUX" -Name "DownloadGameInfo" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameUX" -Name "GameUpdateOptions" -PropertyType DWord -Value 0 -Force
# Turn off Windows Game Recording & Broadcasting (it does not matter if you enable/disable it, it's my own preference MS fixed performancd regressions)
# Windows 10+ (NOSERVER)
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowgameDVR" -PropertyType DWord -Value 0 -Force
# Turn off GameDVR
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name AppCaptureEnabled -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -PropertyType DWord -Value 0 -Force
# Turn off Game Bar
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\GameBar" -Name "AllowAutoGameMode" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\GameBar" -Name "UseNexusForGameBarEnabled" -PropertyType DWord -Value 0 -Force
# Turn off Game Bar tips
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\GameBar" -Name "ShowStartupPanel" -PropertyType DWord -Value 0 -Force
##########################################################
###### 					MS One Drive                ######
##########################################################
# Uninstall One Drive
Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Force
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\OneDrive -Name DisablePersonalSync" -Force
<#
Stop-Process -Name OneDrive -Force -ErrorAction SilentlyContinue
Start-Process -FilePath "$env:SystemRoot\SysWOW64\OneDriveSetup.exe" -ArgumentList "/uninstall" -Wait
Stop-Process -Name explorer
IF (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"))
{
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Force
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -PropertyType DWord -Value 1
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSync" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableMeteredNetworkFileSync" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableLibrariesDefaultSaveToOneDrive" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\OneDrive -Name DisablePersonalSync" -PropertyType DWord -Value 1 -Force
Remove-ItemProperty -Path "HKCU:\Environment" -Name "OneDrive" -Force -ErrorAction SilentlyContinue
IF ((Get-ChildItem -Path "$env:USERPROFILE\OneDrive" -ErrorAction SilentlyContinue | Measure-Object).Count -eq 0)
{
	Remove-Item -Path "$env:USERPROFILE\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
}
else
{
	Write-Error "$env:USERPROFILE\OneDrive folder is not empty"
}
Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:ProgramData\Microsoft OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
#>
Unregister-ScheduledTask -TaskName *OneDrive* -Confirm:$false
# Turn off user pre sign-in traffic
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\OneDrive" -Name "PreventNetworkTrafficPreUserSignIn" -PropertyType DWord -Value 1

##########################################################
###### 						Sound                   ######
##########################################################
# Turn off default sound scheme
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoChangingSoundScheme" -PropertyType DWord -Value 1
# Turn off Windows Startup sound
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" -Name "DisableStartupSound" -PropertyType DWord -Value 1
# Disable default sounds and set it to "No Sounds"
# FIXME:
$SoundScheme = ".None"
	Get-ChildItem -Path "HKCU:\AppEvents\Schemes\Apps\*\*" | ForEach-Object {
		If (!(Test-Path "$($_.PsPath)\$($SoundScheme)")) {
			New-Item -Path "$($_.PsPath)\$($SoundScheme)" | Out-Null
		}
		If (!(Test-Path "$($_.PsPath)\.Current")) {
			New-Item -Path "$($_.PsPath)\.Current" | Out-Null
		}
		$Data = (Get-ItemProperty -Path "$($_.PsPath)\$($SoundScheme)" -Name "(Default)" -ErrorAction SilentlyContinue)."(Default)"
		Set-ItemProperty -Path "$($_.PsPath)\$($SoundScheme)" -Name "(Default)" -PropertyType String -Value $Data
		Set-ItemProperty -Path "$($_.PsPath)\.Current" -Name "(Default)" -PropertyType String -Value $Data
	}
Set-ItemProperty -Path "HKCU:\AppEvents\Schemes" -Name "(Default)" -PropertyType String -Value $SoundScheme

##########################################################
###### 					Windows Updates             ######
##########################################################
# Never use Windows Update as update source
<#
# Windows 8+
# You basically can load your own local server to deliver updates
FIXME: REG_SZ  Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing" -Name "LocalSourcePath" -PropertyType DWord -Value 2 - Force
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing" -Name "UseWindowsUpdate" -PropertyType DWord -Value 2 - Force
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing" -Name "RepairContentServerSource" -PropertyType DWord -Value 2 - Force
#>
# Silence MRT Tool (you still can whenever you want manually dl and execute it)
Set-ItemProperty -Path "HKLM:\Software\Microsoft\MRT" -Name "DontReportInfectionInformation" -PropertyType DWord -Value 1 - Force
Set-ItemProperty -Path "HKLM:\Software\Microsoft\MRT" -Name "DontOfferThroughWUAU" -PropertyType DWord -Value 1 - Force
# Supress any Windows Update restarts
Set-ItemProperty -Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings" -Name "UxOption" -PropertyType DWord -Value 1
# Reveal latest Windows Update time (LastSuccessTime)
# HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\ResultsInstall
# Turn off all Windows Updates (forever)
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "SetDisableUXWUAccess" -PropertyType DWord -Value 1 -Force
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -PropertyType DWord -Value 1 -Force
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" -Name "DisableWindowsUpdateAccess" -PropertyType DWord -Value 1 -Force
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" -Name "DisableWindowsUpdateAccessMode" -PropertyType DWord -Value 0 -Force
# Turn off new Windows Update UI (I use WuMgr or WUMT)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX" -Name "IsConvergedUpdateStackEnabled" -PropertyType DWord -Value 0 -Force
# Turn off Windows Update deferrals (FIXME:)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdates" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdates" -PropertyType DWord -Value 0 -Force
# Turn off driver updates (obsolete in 20H1+)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -PropertyType DWord -Value 0 -Force
# Turn off Malicious SOFTWARE Removal Tool offering over WUS
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -PropertyType DWord -Value 0
# Disable Preview Builds
# Windows 10 RS2+
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "EnableConfigFlighting" -PropertyType DWord -Value 0
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "EnableExperimentation" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "EnablePreviewBuilds" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\SOFTWARE\Microsoft\WindowsSelfHost\Applicability" -Name "EnablePreviewBuilds" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\SOFTWARE\Microsoft\WindowsSelfHost\Applicability" -Name "ThresholdFlightsDisabled" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\SOFTWARE\Microsoft\WindowsSelfHost\Applicability" -Name "Ring" -PropertyType string -Value "Disabled" -Force
# Turn on automatic updates for other Microsoft products e.g. MS Office
# https://docs.Microsoft.com/en-us/windows/win32/wua_sdk/opt-in-to-Microsoft-update
# https://social.technet.Microsoft.com/Forums/en-US/479fae70-62ea-4f00-b1a9-fdbba0ba1bc8/how-to-enable-windows-updates-for-other-ms-products-for-all-users?forum=win10itprosetup
#$ServiceManager = New-Object -ComObject "Microsoft.Update.ServiceManager"
#$ServiceManager.ClientApplicationID = "My App"
#$NewService = $ServiceManager.AddService2("7971f918-a847-4430-9279-4a52d1efe18d",7,"")
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\7971F918-A847-4430-9279-4A52D1EFE18D" -Name "RegisteredWithAU" -PropertyType Dword -Value 1 -Force
# Turn off Windows Update restart notification
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name RestartNotificationsAllowed2 -PropertyType DWord -Value 0 -Force
# Turn off and delete reserved storage after the next update installation
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" -Name "BaseHardReserveSize" -Value 0 -Type QWord -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" -Name "BaseSoftReserveSize" -Value 0 -Type QWord -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" -Name "HardReserveAdjustment" -Value 0 -Type QWord -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" -Name "MinDiskSize" -Value 0 -Type QWord -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" -Name "ShippedWithReserves" -Value 0 -Type DWord -ErrorAction SilentlyContinue
# Disable P2P Updates (1703+)
# dword:00000000 = off
# dword:00000001 = on
# dword:00000002 = LAN only
# dword:00000003 = Lan and Internet
# dword:00000099 = Simple
# dword:00000100 = Bypass
# Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DownloadMode" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -PropertyType DWord -Value 100 -Force
# Max upload bandwith for delivery optimization
# Min = 0
# Max = 4000000
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DOMaxUploadBandwidth" -PropertyType DWord -Value 0 -Force
# Max cache for delivery optimization
# Windows 10+
# Min = 1
# Max = 100
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DOMaxCacheSize" -PropertyType DWord -Value 1 -Force
# Min = 0
# Max = 4294967295
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DOAbsoluteMaxCacheSize" -PropertyType DWord -Value 1 -Force
# Max cache age delivery optimization
# Windows 10+
# Min = 0
# Max = 4294967295
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DOMaxCacheAge" -PropertyType DWord -Value 0 -Force
# Max monthly upload data cap
# Windows 10+
# Min = 0
# Max = 4294967295
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DOMonthlyUploadDataCap" -PropertyType DWord -Value 0 -Force
# Background Qos
# Windows 10+
# Min = 1
# Max = 4294967295
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DOMinBackgroundQos" -PropertyType DWord -Value 1 -Force
# Background Qos
# Windows 10+
# Min = 0
# Max = 4294967295
# FIXME: New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DOModifyCacheDrive" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "MaxDownloadBandwidth" -PropertyType DWord -Value 0 -Force
# Turn off automatic Windows Update restarts
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -PropertyType DWord -Value 0
##########################################################
###### 					Language                    ######
##########################################################
# Set default Code page to UTF-8
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Nls\CodePage" -Name "ACP" -PropertyType String -Value 65001
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Nls\CodePage" -Name "OEMCP" -PropertyType String -Value 65001
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Nls\CodePage" -Name "MACCP" -PropertyType String -Value 65001
# DO NOT USE THIS: https://superuser.com/questions/269818/change-default-code-page-of-windows-console-to-utf-8
#REG ADD HKCU\Console\%SystemRoot^%_system32_cmd.exe /v CodePage /t REG_DWORD /d 65001
#New-Item -ErrorAction Ignore HKCU:\Console\%SystemRoot%_system32_cmd.exe
#Set-ItemProperty HKCU:\Console\%SystemRoot%_system32_cmd.exe CodePage 65001
### NONO ^^
# Set the default input method to the English language
# FIXME: - detect language first
Set-WinDefaultInputMethodOverride "0409:00000409"
# Turn on secondary "en-US" keyboard
# FIXME:
$langs = Get-WinUserLanguageList
$langs.Add("en-US")
Set-WinUserLanguageList $langs -Force
##########################################################
######          Turn off critical tools             ######
######           Shell restrict command             ######
##########################################################
# Turn off regedit
# Win2k+
# 2 = UI and silent
# 1 = UI only
#Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableRegistryTools" -PropertyType String -Value 2
# Turn off CMD
#Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCMD" -PropertyType String -Value 1
# Restrict RUN
# FIXME:  (string)
#Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "RestrictRun" -PropertyType String -Value 1
#Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" -Name "RestrictRun" -PropertyType String -Value 1
# Restrict app list (custom)
#Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\RestrictRun" -Name "DisallowApps" -PropertyType String -Value 1




##########################################################
######      Performance & Cleaning + Compression    ######
##########################################################
# Changing OS Timer Resolution
# The timer is limited by CPU not GPU.
# Windows 10 changes timer resolution every x seconds automatically, this requires to run a script or tool in the background
# however whenever a game/application requests a higher resolution e.g. Discord then this would make the whole utility/script useless.
# This is a myth because
# Disable memory compression
Disable-MMAgent -mc | Out-Null
# Enable-MMAgent -mc
# Turn on all "Visual effects" (This is done in GPU (not for all objects), disabling it does overall change nothing)
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -PropertyType String -Value 1
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -PropertyType String -Value 400
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -PropertyType Binary -Value ([byte[]](158,30,7,128,18,0,0,0))
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -PropertyType String -Value 1
Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -PropertyType DWord -Value 3
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -PropertyType DWord -Value 1
# Turn off NTFS Last Access Time stamps (Fsutil.exe)
# https://docs.Microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-behavior
# https://ss64.com/nt/fsutil.html
fsutil behavior set DisableLastAccess 1 | Out-Null
#fsutil behavior set disable8dot3 1 | Out-Null
# Turn off Modern UI swap file (get around 256 MB extra space)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "SwapfileControl" -PropertyType Dword -Value 0
# Remove PerfLogs
Remove-Item $env:SystemDrive\PerfLogs -Recurse -Force -ErrorAction SilentlyContinue
# Remove LOCALAPPDATA\Temp
Remove-Item $env:LOCALAPPDATA\Temp -Recurse -Force -ErrorAction SilentlyContinue
# Remove SYSTEMROOT\Temp
Restart-Service -Name Spooler -Force
Remove-Item -Path "$env:SystemRoot\Temp" -Recurse -Force -ErrorAction SilentlyContinue
##########################################################
######                      Display                 ######
##########################################################
# Turn off Touch Screen Support
New-ItemProperty -Path "HKCU:\Software\Microsoft\Wisp\Touch" -Name "TouchGate" -PropertyType DWord -Value 0 -Force
# Disable Windows Startup Delay (FIXME:) (needs investigation)
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\Current\Version\Explorer\Serialize" -Name "StartupDelayInMSec" -PropertyType Dword -Value 0 -Force
# Turn off default display- and sleep-mode timeouts via powercfg
#powercfg /X monitor-timeout-ac 0 | Out-Null
#powercfg /X monitor-timeout-dc 0 | Out-Null
#powercfg /X standby-timeout-ac 0 | Out-Null
#powercfg /X standby-timeout-dc 0 | Out-Null
# Enforce per-app System DPI awareness
New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "EnablePerProcessSystemDPI" -PropertyType DWord -Value 1 -Force
##########################################################
######                  Action Center               ######
##########################################################
# Turn off Action Center Notifications
#New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Wndows\Explorer" -Name "DisableNotificationCenter" -PropertyType Dword -Value 1 -Force
# Turn off Action Center Sidebar
# New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" -Name "UseActionCenterExperience " -PropertyType DWord -Value 0 -Force
# Turn on Action Center Push Notifications
#Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -ErrorAction SilentlyContinue
#Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -ErrorAction SilentlyContinue
# Turn off Battery Fly-out UI
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" -Name "UseWin32BatteryFlyout " -PropertyType DWord -Value 1 -Force
# Turn off Network Fly-out UI
# 0 = Default fly-out
# 1 = Opens Network Settings window
# 2 = Windows 8/8.1 style sidebar
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Control Panel\Settings\Network" -Name "ReplaceVan" -PropertyType DWord -Value 2 -Force
# Turn off New Volume Control
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\MTCUVC" -Name "EnableMtcUvc" -PropertyType DWord -Value 0 -Force
#
#
#
##########################################################
######                      Time                    ######
##########################################################
# Default W32 Time Policy
# XP+
<#

Tick Tock:  Im not a "clock expert" if someone has some good default settings for server/users just do a PR.
            I'm open for suggestions I typically only change the default server and that's pretty much it.

Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\W32Time\Config" -Name "FrequencyCorrectRate" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\W32Time\Config" -Name "HoldPeriod" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\W32Time\Config" -Name "LargePhaseOffset" -PropertyType DWord -Value 4294967295
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\W32Time\Config" -Name "MaxAllowedPhaseOffset" -PropertyType DWord -Value 4294967295
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\W32Time\Config" -Name "MaxNegPhaseCorrection" -PropertyType DWord -Value 4294967295
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\W32Time\Config" -Name "MaxPosPhaseCorrection" -PropertyType DWord -Value 4294967295
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\W32Time\Config" -Name "PhaseCorrectRate" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\W32Time\Config" -Name "PollAdjustFactor" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\W32Time\Config" -Name "SpikeWatchPeriod" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\W32Time\Config" -Name "UpdateInterval" -PropertyType DWord -Value 4294967295
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\W32Time\Config" -Name "AnnounceFlags" -PropertyType DWord -Value 16
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\W32Time\Config" -Name "EventLogFlags" -PropertyType DWord -Value 3
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\W32Time\Config" -Name "LocalClockDispersion" -PropertyType DWord -Value 16
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\W32Time\Config" -Name "MaxPollInterval" -PropertyType DWord -Value 16
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\W32Time\Config" -Name "MinPollInterval" -PropertyType DWord -Value 15
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\W32Time\Config" -Name "ClockHoldoverPeriod" -PropertyType DWord -Value 1024
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\W32Time\Config" -Name "RequireSecureTimeSyncRequests" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\W32Time\Config" -Name "UtilizeSslTimeData" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\W32Time\Config" -Name "ClockAdjustmentAuditLimit" -PropertyType DWord -Value 128
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\W32Time\Config" -Name "ChainEntryTimeout" -PropertyType DWord -Value 8
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\W32Time\Config" -Name "ChainMaxEntries" -PropertyType DWord -Value 1024
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\W32Time\Config" -Name "ChainMaxHostEntries" -PropertyType DWord -Value 4
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\W32Time\Config" -Name "ChainDisable" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\W32Time\Config" -Name "ChainLoggingRate" -PropertyType DWord -Value 10080

# Default W32 NTP Client
# (FIXME:) -> strings
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\W32time\Parameters" -Name "NoSync" -PropertyType DWord -Value 10080
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\W32time\Parameters" -Name "NTP" -PropertyType DWord -Value 10080
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\W32time\Parameters" -Name "NT5DS" -PropertyType DWord -Value 10080
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\W32time\Parameters" -Name "AllSync" -PropertyType DWord -Value 10080
# FIXME: end
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\W32time\Parameters" -Name "CrossSiteSyncFlags" -PropertyType DWord -Value 2
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\W32time\Parameters" -Name "ResolvePeerBackoffMinutes" -PropertyType DWord -Value 2
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\W32time\Parameters" -Name "ResolvePeerBackoffMaxTimes" -PropertyType DWord -Value 2
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\W32time\Parameters" -Name "SpecialPollInterval" -PropertyType DWord -Value 131072

# Enable NTP Client Server
# Windows XP+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\W32Time\TimeProviders\NtpServer" -Name "Enabled" -PropertyType DWord -Value 1

#>


# Enable NTP Client
# Windows XP+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\W32time\TimeProviders\NtpClient" -Name "Enabled" -PropertyType DWord -Value 1
# Turn off NTP Client (DO NOT disable NTP, better use a secure server instead)
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient" -Name "Enabled" -PropertyType DWord -Value 0 -Force
# Turn on BIOS time (UTC)
# Workaround for some Linux distros
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -PropertyType DWord -Value 1
# Change NTP server to pool.ntp.org
w32tm /config /syncfromflags:manual /manualpeerlist:"0.pool.ntp.org 1.pool.ntp.org 2.pool.ntp.org 3.pool.ntp.org"


##########################################################
######              Device Credential               ######
##########################################################
# Allow secondary authentication device
# Windows 10+
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SecondaryAuthenticationFactor" -Name "AllowSecondaryAuthenticationDevice" -PropertyType DWord -Value 1 -Force


##########################################################
######          Distributed Link Tracking           ######
##########################################################
# Turn on Link Tracking
# Vista+
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DLT_AllowDomainMode" -PropertyType DWord -Value 1 -Force

##########################################################
######                  Device Compat               ######
##########################################################
# Turn off Device Compat
# Windows 8+
#Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Policies\Microsoft\Compatibility" -Name "DisableDeviceFlags" -PropertyType DWord -Value 1 -Force
# Turn off Device Shims
# Windows 8+
#Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Policies\Microsoft\Compatibility" -Name "DisableDriverShims" -PropertyType DWord -Value 1 -Force


##########################################################
######          DNS (Cloudflare example)            ######
######        Better use DNS via Router/PI!)        ######
##########################################################
# Set custom Windows DNS (example: Cloudflare)
# FIXME: put all known dns provider in an array
Get-NetAdapter -Physical | Set-DnsClientServerAddress -ServerAddresses 1.1.1.1,1.0.0.1,2606:4700:4700::1111,2606:4700:4700::1001
# Disable WinHTTP Web Proxy Auto-Discovery Service (inefficent since 1909+)
#Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -PropertyType DWord -Value 1 -Force
#Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "UseDomainNameDeveloution" -PropertyType DWord -Value 0 -Force
# Adapter Domain Name
# XP only
# FIXME: Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "AdapterDomainName" -PropertyType DWord -Value 1 -Force
# DNS Client
# XP only
# FIXME: Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "NameServer" -PropertyType DWord -Value 1 -Force
# Primary Dns Suffix
# Win2k+
# FIXME: Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "NV PrimaryDnsSuffix" -PropertyType DWord -Value 1 -Force
# Register Adapter Name
# XP+
# FIXME: Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "RegisterAdapterName" -PropertyType DWord -Value 1 -Force
# Register Reverse Lookup
# XP+
# 2 = Only If A Succeeds
# 1 = Register
# 0 = Do Not Register
# FIXME: Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "RegisterReverseLookup" -PropertyType DWord -Value 1 -Force
# Registration Enabled
# XP+
# FIXME: Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "RegistrationEnabled" -PropertyType DWord -Value 1 -Force
# Registration Overwrites In Conflic
# XP only
# FIXME: Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "RegistrationOverwritesInConflict" -PropertyType DWord -Value 0 -Force
# Registration Refresh Interval
# XP
# Min = 1800
# Max = 4294967200
# FIXME: Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "RegistrationRefreshInterval" -PropertyType DWord -Value 0 -Force
# Registration Ttl
# XP
# Max = 4294967200
# FIXME: Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "RegistrationTtl" -PropertyType DWord -Value 4294967200 -Force
# Search List
# XP+
# FIXME: Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "SearchList" -PropertyType DWord -Value 4294967200 -Force
# Search List
# XP+
# 256 = Only secure
# 16 = Only unsecure
# 0 = Followed by Secure
# FIXME: Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "UpdateSecurityLevel" -PropertyType DWord -Value 256 -Force
# Update TopLevel Domain Zones
# XP+
# 256 = Only secure
# 16 = Only unsecure
# 0 = Followed by Secure
# FIXME: Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "UpdateTopLevelDomainZones" -PropertyType DWord -Value 1 -Force
# Use Domain Name Devolution
# XP+
# FIXME: Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "UseDomainNameDevolution" -PropertyType DWord -Value 1 -Force
# Domain Name Devolution Level
# Win2k+
# Min = 2
# Max = 4294967200
# FIXME: Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableDevolutionLevelControl" -PropertyType DWord -Value 2 -Force
# Turn off Multicast
# Vista+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -PropertyType DWord -Value 0 -Force
# Append To MultiLabel Name
# Vista+
# FIXME: Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "AppendToMultiLabelName" -PropertyType DWord -Value 0 -Force
# Turn off Smart Multi Homed Name Resolution
# Windows 8+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "DisableSmartNameResolution" -PropertyType DWord -Value 1 -Force
# Smart Protocol Reorder
# Windows 8+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "DisableSmartProtocolReordering" -PropertyType DWord -Value 1 -Force
# Allow FQDN NetBios Queries
# Windows 8+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "QueryNetBTFQDN" -PropertyType DWord -Value 0 -Force
# Prefer Local Responses Over Lower Order Dns
# Windows 8+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "PreferLocalOverLowerBindingDNS" -PropertyType DWord -Value 1 -Force
# IDN Encoding
# Windows 8+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "DisableIdnEncoding" -PropertyType DWord -Value 0 -Force
# IDN Mapping
# Windows 8+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableIdnMapping" -PropertyType DWord -Value 0 -Force


##########################################################
######              Task Scheduler                   #####
##########################################################
# Allow Task Scheduler to be browsed
# pre Vista
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Task Scheduler5.0" -Name "Allow Browse" -PropertyType DWord -Value 1 -Force
#Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Task Scheduler5.0" -Name "Allow Browse" -PropertyType DWord -Value 1 -Force
# Disabled Advanced
# pre Vista
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Task Scheduler5.0" -Name "Disable Advanced" -PropertyType DWord -Value 1 -Force
#Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Task Scheduler5.0" -Name "Disable Advanced" -PropertyType DWord -Value 1 -Force
# Disable Drag And Drop
# pre Vista
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Task Scheduler5.0" -Name "DragAndDrop" -PropertyType DWord -Value 0 -Force
#Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Task Scheduler5.0" -Name "DragAndDrop" -PropertyType DWord -Value 0 -Force
# Prevent Task Scheduler execution
# pre Vista
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Task Scheduler5.0" -Name "Execution" -PropertyType DWord -Value 1 -Force
#Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Task Scheduler5.0" -Name "Execution" -PropertyType DWord -Value 1 -Force
# Hide Property Pages
# pre Vista
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Task Scheduler5.0" -Name "Property Pages" -PropertyType DWord -Value 0 -Force
#Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Task Scheduler5.0" -Name "Property Pages" -PropertyType DWord -Value 0 -Force
# Forbit task creation
# pre Vista
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Task Scheduler5.0" -Name "TaskScheduler" -PropertyType DWord -Value 0 -Force
#Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Task Scheduler5.0" -Name "TaskScheduler" -PropertyType DWord -Value 0 -Force
# Prevent to create new tasks
# pre Vista
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Task Scheduler5.0" -Name "Task Creation" -PropertyType DWord -Value 1 -Force
#Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Task Scheduler5.0" -Name "Task Creation" -PropertyType DWord -Value 1 -Force
# Prevent deletion of new tasks
# pre Vista
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Task Scheduler5.0" -Name "Task Deletion" -PropertyType DWord -Value 1 -Force
#Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Task Scheduler5.0" -Name "Task Deletion" -PropertyType DWord -Value 1 -Force

# Turn off Task Scheduler migrates several security problems but is problematic and causes additional problems. (FIXME:)
#Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\Schedule" -Name "Start" -PropertyType DWord -Value 4 -Force
# Create a task via Task Scheduler to clear the "\SoftwareDistribution\Download" folder automatically every 4 weeks (Monday).
$action = New-ScheduledTaskAction -Execute powershell.exe -Argument @"
	`$getservice = Get-Service -Name wuauserv
	`$getservice.WaitForStatus("Stopped", "01:00:00")
	Get-ChildItem -Path `$env:SystemRoot\SoftwareDistribution\Download -Recurse -Force | Remove-Item -Recurse -Force
"@
$trigger = New-JobTrigger -Weekly -WeeksInterval 4 -DaysOfWeek Monday -At 11am
# Win8+ compatibility is needed - it's not a bug!
$settings = New-ScheduledTaskSettingsSet -Compatibility Win8 -StartWhenAvailable
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest
$params = @{
	"TaskName"	=	"SoftwareDistributionCleanup"
	"Action"	=	$action
	"Trigger"	=	$trigger
	"Settings"	=	$settings
	"Principal"	=	$principal
}
Register-ScheduledTask @params -Force
# Create a task via Task Scheduler to clear the $env:TEMP folder automatically, every 60 days.
$action = New-ScheduledTaskAction -Execute powershell.exe -Argument @"
	Get-ChildItem -Path `$env:TEMP -Force -Recurse | Remove-Item -Force -Recurse
"@
$trigger = New-ScheduledTaskTrigger -Daily -DaysInterval 60 -At 10am
$settings = New-ScheduledTaskSettingsSet -Compatibility Win8 -StartWhenAvailable
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest
$params = @{
	"TaskName"	=	"TempCleanup"
	"Action"	=	$action
	"Trigger"	=	$trigger
	"Settings"	=	$settings
	"Principal"	=	$principal
}
Register-ScheduledTask @params -Force

# (FIXME:)
#Get-ScheduledTask | Where-Object {$_.TaskName -match "{Telemetry, Application Experience"} | Unregister-ScheduledTask -Confirm:$false
# Unregister every task
# Tasks are been stored here: `C:\Windows\System32\Tasks` if you want to delete everything use `C:\Windows\System32\tasks\ {*}"`
Get-ScheduledTask | Where-Object {$_.TaskName -match "{*"} | Unregister-ScheduledTask -Confirm:$false


## Disable all controversial scheduler tasks, it's enough to disable them, you don't have do actually "remove" them (because they might getting re-created with KB or feature Update X)
# Some are not integrated or by default disabled in LTSC e.g. BthSQM, just ignore the warnings!
# https://docs.Microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask?view=win10-ps
# License Validation
#Disable-ScheduledTask -TaskName "\Microsoft\Windows\Application Experience\CreateObjectTask"
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Subscription\EnableLicenseAcquisition" | Out-Null
# Disable MAPS Update task (master toggle for MAPS)
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Maps\MapsUpdateTask" | Out-Null
# Disable MAPS Toast Notifications for new Updates
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Maps\MapsToastTask" | Out-Null
# Turn off XBL Game task
Disable-ScheduledTask -TaskName "\Microsoft\XblGameSave\XblGameSaveTask" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\XblGameSave\XblGameSaveTaskLogon" | Out-Null
# Disable SmartScreen (WD -> APP) task
#Disable-ScheduledTask -TaskName "\Microsoft\Windows\AppID\SmartScreenSpecific" | Out-Null
# Disable Biometrics Facelogin Cleanup task
Disable-ScheduledTask -TaskName "\Microsoft\Windows\HelloFace\FODCleanupTask" | Out-Null
# Disable System restore maintainance and runner task
#Disable-ScheduledTask -TaskName "\Microsoft\Windows\SystemRestore\SR" | Out-Null
# Turn off all Microsoft Experience Tasks (incl. master toggle)
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Application Experience\AitAgent" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Application Experience\StartupAppTask" | Out-Null
# Turn off Microsoft "activation" startup checks (does not work on VOL. SKUs)
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Subscription\LicenseAcquisition" | Out-Null
# Turn off Autochk scans
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Autochk\Proxy" | Out-Null
# Turn off Cloud Experience task
Disable-ScheduledTask -TaskName "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask" | Out-Null
# Turn off Windows Diagnostic collector task
#Disable-ScheduledTask -TaskName "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
# Turn off Windows Disk Diagnostics
#Disable-ScheduledTask -TaskName "\Microsoft\Windows\DiskFootprint\Diagnostics" | Out-Null
# Turn on File History maintainance task
Disable-ScheduledTask -TaskName "\Microsoft\Windows\FileHistory\File History (maintenance mode)" | Out-Null
# Turn off gathering network info (which transmits device infos)
Disable-ScheduledTask -TaskName "\Microsoft\Windows\NetTrace\GatherNetworkInfo" | Out-Null
# Turn off Sqm maintainance task
Disable-ScheduledTask -TaskName "\Microsoft\Windows\PI\Sqm-Tasks" | Out-Null
# Turn off automatic app update task for MS Store apps
Disable-ScheduledTask -TaskName "\Microsoft\Windows\WindowsUpdate\Automatic App Update" | Out-Null
# Turn off CLIP maintainance and cleanup task
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Clip\License Validation" | Out-Null
# Turn off all Family Shield Tasks
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Shell\FamilySafetyRefreshTask" | Out-Null
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Shell\FamilySafetyMonitor\" | Disable-ScheduledTask
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Shell\FamilySafetyRefresh\" | Disable-ScheduledTask
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Shell\FamilySafetyUpload\" | Disable-ScheduledTask
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Shell\FamilySafetyMonitorToastTask" | Out-Null
# Turn off Remote Assistance task
Get-ScheduledTask -TaskPath "\Microsoft\Windows\RemoteAssistance" | Disable-ScheduledTask
# Turn off Power Efficency diagniostic logging
#Disable-ScheduledTask -TaskName "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" | Out-Null
# Turn off Speech update and cleanup task
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Speech\SpeechModelDownloadTask" | Out-Null
# Windows Update related tasks
Disable-ScheduledTask -TaskName "\Microsoft\Windows\UpdateOrchestrator\Maintenance Install" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\UpdateOrchestrator\Reboot" | Out-Null
# Turn off User profile uploading task
Disable-ScheduledTask -TaskName "\Microsoft\Windows\User Profile Service\HiveUploadTask" | Out-Null
# Turn off Startisback++ update & maintainance check
Disable-ScheduledTask -TaskName "\StartIsBack health check" | Out-Null
# Turn off consolidator & UsbCeip (master toggle)
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\" | Disable-ScheduledTask
# Turn off SIUF strings & SIUF settings
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Feedback\Siuf" | Disable-ScheduledTask
# Turn off Location task, maintainance & cleanup
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Location" | Disable-ScheduledTask
# Turn off Windows Error Reporting Quere & Maintainance
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null
# Turn off Workplace maintainance task
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Workplace Join" | Disable-ScheduledTask
##########################################################
###### 			Cipher Suites (Schannel SSP)         #####
##########################################################
# Turn off TLS weak Ciphers - may be reset with servicing updates!
# Default target set
# [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL]
# [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers]
# [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\CipherSuites]
# [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes]
# [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms]
# [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols]
# certutil.exe –displayEccCurve
# https://bettercrypto.org
# https://www.ssllabs.com/ssltest/
# https://www.nartac.com/Products/IISCrypto/
# https://docs.Microsoft.com/en-us/windows-server/security/tls/manage-tls#configuring-tls-cipher-suite-order
# https://www.acunetix.com/blog/articles/tls-ssl-cipher-hardening/
# For Windows to CP:
# ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256
# Disable-TlsCipherSuite -Name "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P256"
# Disable-TlsCipherSuite -Name "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P384"
# Disable-TlsCipherSuite -Name "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256"
# Disable-TlsCipherSuite -Name "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P384"
# Disable-TlsCipherSuite -Name "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P256"
# Disable-TlsCipherSuite -Name "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P384"
# Disable-TlsCipherSuite -Name "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
# Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_128_CBC_SHA"
# Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_128_CBC_SHA256"
# Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_256_CBC_SHA"
# Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_256_CBC_SHA256"
#
# Only for older OS Builds!
# Path does not exist on an cipher updated system!
# SCHANNEL is empty unless you request it e.g. VMWare or in case you use a Windows Server
# Set but do not enforce!
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128" -Name "Enabled" -PropertyType DWord -Value ffffffff
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256" -Name "Enabled" -PropertyType DWord -Value ffffffff
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56" -Name "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL" -Name "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128" -Name "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128" -Name "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128" -Name "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128" -Name "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128" -Name "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128" -Name "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128" -Name "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168" -Name "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168/168" -Name "Enabled" -PropertyType DWord -Value 0
# Key Exchanges
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" -Name "Enabled" -PropertyType DWord -Value ffffffff
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\ECDH" -Name "Enabled" -PropertyType DWord -Value ffffffff
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS" -Name "Enabled" -PropertyType DWord -Value ffffffff
# Hashes
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5" -Name "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA" -Name "Enabled" -PropertyType DWord -Value ffffffff
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA256" -Name "Enabled" -PropertyType DWord -Value ffffffff
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA384" -Name "Enabled" -PropertyType DWord -Value ffffffff
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA512" -Name "Enabled" -PropertyType DWord -Value ffffffff
# Protocols
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client" -Name "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client" -Name "DisabledByDefault" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server" -Name "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server" -Name "DisabledByDefault" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client" -Name "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client" -Name "DisabledByDefault" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server" -Name "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server" -Name "DisabledByDefault" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Name "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Name "DisabledByDefault" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name "DisabledByDefault" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Name "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Name "DisabledByDefault" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name "DisabledByDefault" -PropertyType DWord -Value 1
#Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name "Enabled" -PropertyType DWord -Value ffffffff
#Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name "DisabledByDefault" -PropertyType DWord -Value 0
#Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "Enabled" -PropertyType DWord -Value ffffffff
#Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "DisabledByDefault" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name "Enabled" -PropertyType DWord -Value ffffffff
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name "DisabledByDefault" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "Enabled" -PropertyType DWord -Value ffffffff
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "DisabledByDefault" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "Enabled" -PropertyType DWord -Value ffffffff
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "DisabledByDefault" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -PropertyType DWord -Value ffffffff
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "DisabledByDefault" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" -Name "Enabled" -PropertyType DWord -Value ffffffff
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" -Name "DisabledByDefault" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Name "Enabled" -PropertyType DWord -Value ffffffff
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Name "DisabledByDefault" -PropertyType DWord -Value 0



##########################################################
###### 					Java Hardening               #####
###### (FIXME:) check if installed or not
##########################################################
# Remove the default configuration first
#remove-item $env:WinDir\Sun\Java\Deployment\deployment.config -Force
#remove-item $env:WinDir\Sun\Java\Deployment\deployment.properties -Force
# Enforce some standard, eg. default security level set to high etc
#$propertiesfile = "deployment.webjava.enabled=true "
#$propertiesfile += "`ndeployment.webjava.enabled.locked `ndeployment.security.level.locked "
#$propertiesfile += "`ndeployment.security.level=VERY_HIGH"
#New-Item -Path $env:WinDir\Sun\Java\Deployment -ItemType Directory -Force | Out-Null



##########################################################
###### 					    USB                      #####
##########################################################
# Deny all access for all Removable Storage
# Vista+
# FIXME: Set it per-device
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\RemovableStorageDevices" -Name "Deny_All" -PropertyType DWord -Value 1 -Force
#Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\RemovableStorageDevices" -Name "Deny_All" -PropertyType DWord -Value 1 -Force

Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56308-b6bf-11d0-94f2-00a0c91efb8b}" -Name "Deny_Execute" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56308-b6bf-11d0-94f2-00a0c91efb8b}" -Name "Deny_Read" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56308-b6bf-11d0-94f2-00a0c91efb8b}" -Name "Deny_Write" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56308-b6bf-11d0-94f2-00a0c91efb8b}" -Name "Deny_Execute" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56308-b6bf-11d0-94f2-00a0c91efb8b}" -Name "Deny_Read" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56308-b6bf-11d0-94f2-00a0c91efb8b}" -Name "Deny_Write" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56311-b6bf-11d0-94f2-00a0c91efb8b}" -Name "Deny_Execute" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56311-b6bf-11d0-94f2-00a0c91efb8b}" -Name "Deny_Read" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56311-b6bf-11d0-94f2-00a0c91efb8b}" -Name "Deny_Write" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56311-b6bf-11d0-94f2-00a0c91efb8b}" -Name "Deny_Execute" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56311-b6bf-11d0-94f2-00a0c91efb8b}" -Name "Deny_Read" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56311-b6bf-11d0-94f2-00a0c91efb8b}" -Name "Deny_Write" -PropertyType DWord -Value 1 -Force


##########################################################
###### 					Network Stack                #####
##########################################################
<#
# Disable IPv6
Set-service Tcpip6 -StartupType disabled
Set-service wanarpv6 -StartupType disabled
Set-service iphlpsvc -StartupType disabled
#>
# Prefer IPv4 over IPv6
# https://support.microsoft.com/en-in/help/929852/guidance-for-configuring-ipv6-in-windows-for-advanced-users
#Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\tcpip6\Parameters" -Name "DisabledComponents" | Select-Object -exp DisabledComponents Set-Itemproperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\tcpip6\Parameters" -Name "DisabledComponents" -value 32
# Turn off ISATAP
# Turn off ^^ (FIXME:, not a dword, reg_sz)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition" -Name "ISATAP_State" -PropertyType DWord -Value "Disabled" -Force

# Turn off Teredo (FIXME:, not a dword, reg_sz)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition" -Name "Teredo_State" -PropertyType DWord -Value "Disabled" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition" -Name "Force_Tunneling" -PropertyType DWord -Value "Disabled" -Force


# Turn off 6to4
# Turn off ^^ (FIXME:, not a dword, reg_sz)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition" -Name "6to4_State" -PropertyType DWord -Value "Disabled" -Force

# Turn off IPHTTPS
# 0 = Default State
# 2 = Enabled
# 3 = Disabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition" -Name "IPHTTPS_ClientState" -PropertyType DWord -Value 3 -Force


# IP Auto-Conf limit state
#Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableIPAutoConfigurationLimits" -PropertyType DWord -Value 1 -Force
# Turn off WSD
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableWsd" -PropertyType DWord -Value 0 -Force
# Fragment Smack Denial of Service Vulnerability (ADV180022)
Set-NetIPv4Protocol -ReassemblyLimit 0
Set-NetIPv6Protocol -ReassemblyLimit 0
# Disable TCP/IP Auto-Tuning
# See here, http://technet.Microsoft.com/en-us/magazine/2007.01.cableguy.aspx
netsh.exe interface tcp set global autotuninglevel= disabled
# IPv6
# Turn off IP source routing protection level
# 0000000 = No additional protection, source routed packets are allowed
# 0000001 = Medium, source routed packets ignored when IP forwarding is enabled
# 0000002 = Highest protection, source routing is completely disabled (CIS)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisableIpSourceRouting" -PropertyType DWord -Value 2 -Force
# IPv4
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableICMPRedirect" -PropertyType DWord -Value 0 -Force

# Enforce NetBIOS is disabled
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NoNameReleaseOnDemand" -PropertyType DWord -Value 1 -Force
# GLobal TCP stack hardening (FIXME:)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableDeadGWDetect" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableICMPRedirect" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "IPEnableRouter" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "KeepAliveTime" -PropertyType REG_DWORD -Value 0x000493E0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "SynAttackProtect" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpMaxHalfOpen" -PropertyType DWord -Value 64 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpMaxHalfOpenRetried" -PropertyType DWord -Value 50 -Force


# Turn off all "useless" network adapter protocols
# http://techgenix.com/using-powershell-disable-network-adapter-bindings/
# https://community.idera.com/database-tools/powershell/ask_the_experts/f/powershell_for_windows-12/13716/disable-unnecessary-network-features-as-internet-protocol-version-6
# https://docs.Microsoft.com/en-us/sql/database-engine/configure-windows/enable-or-disable-a-server-network-protocol?view=sql-server-2017
# https://www.tenforums.com/tutorials/90033-enable-disable-ipv6-windows.html
function DisableUnneededProtocols {
	$Components = @(
					'Client for Microsoft Networks'
					'File and Printer Sharing for Microsoft Networks'
					#'Internet Protocol Version 6 (TCP/IPv6)'
					'Link-Layer Topology Discovery Mapper I/O Driver'
					'Link-Layer Topology Discovery Responder'
					'Microsoft LLDP Protocol Driver'
					'Microsoft Network Adapter Multiplexor Protocol'
					#'QoS Packet Scheduler'
					)

	foreach ($Component in $Components){
		Enable-NetAdapterBinding -Name "*" -DisplayName $Component -ErrorAction SilentlyContinue | Out-Null
	}

}
#####
### Debunking: https://www.speedguide.net/articles/gaming-tweaks-5812
#####
# Turn off LargeSystemCache
# This is an XP tweak, the value is always 0 unless the driver gives an intent to Windows (10) to change it, there is no benefit changing it.
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "LargeSystemCache" -PropertyType DWord -Value 0
#
# Nagle's Algorithm
# This tweak is useless since Windows 8.1+, because the Algorithm was replaced by a more efficent one. The default values are usually fine,
# I'm not aware of any professional gamer which still uses such a tweak or an outdated OS.
#
# Network Throttling Index & System Responsiveness
# SystemResponsiveness & NetworkThrottlingIndex <-> done by the OS itself and does not change anything
# https://msdn.Microsoft.com/en-us/library/ms684247.aspx
# I enabled so that you can do a backup, apply the tweak, and see nothing happens.
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -PropertyType DWord -Value 4294967295
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -PropertyType DWord -Value 20
# Multimedia Class Scheduler Service (MMCSS) tweaks
# https://msdn.Microsoft.com/en-us/library/windows/desktop/ms684247.aspx
# default: 0, recommended: 0. Both 0x00 and 0xFFFFFFFF
# Affinity is OS controlled and never CPU, same like e.g. Core Parking and C-states.
# Application should exclusively ask MMCSS for its help otherwise nothing will be changed because the OS never knows if the app is MMCSS "optimized" or not.
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Affinity" -PropertyType DWord -Value 0
# (FIXME:) Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Background Only" -PropertyType REG_SZ "False"
# (FIXME:) Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Scheduling Category" -PropertyType REG_SZ "High"
# (FIXME:) Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "SFIO Priority" -PropertyType REG_SZ "High"
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "GPU Priority" -PropertyType DWord -Value 8
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -PropertyType DWord -Value 2
# Turn off ECN Capability
# As per RFC3168 http://tools.ietf.org/html/rfc3168
Set-NetTCPSetting -SettingName InternetCustom -EcnCapability Disabled | Out-Null
# Turn off Receive Segment Coalescing State (RSC)
Disable-NetAdapterRsc -Name * | Out-Null
# Turn off Large Send Offload (LSO)
Disable-NetAdapterLso -Name * | Out-Null
# Turn off Receive-Side Scaling State (RSS)
netsh int tcp set global rss=disabled | Out-Null
# Turn off "TCP Fast Open" due to privacy concerns
# RFC 7413
# Once enabled data can be sent before the connection complete!
# https://arxiv.org/pdf/1905.03518
# https://blogs.windows.com/msedgedev/2016/06/15/building-a-faster-and-more-secure-web-with-tcp-fast-open-tls-false-start-and-tls-1-3/
netsh int tcp set global fastopen=disabled | Out-Null
# Turn off ECN function
# Most (if not all routers) supporting large data traffic with "Explicit Congestion Notification" (ECN)
netsh int tcp set global ecncapability=enabled | Out-Null
# Turn off RFC 1323 )known as time stamps)
# Why? Because each data package gets 2,5 kb bigger and we want to avoid
# all "useless traffic".
netsh int tcp set global timestamps=disabled | Out-Null
# VMWAre Workaround
# https://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=2129176
#Disable-NetAdapterRsc -Name Ethernetx | Out-Null
#netsh int tcp set global RSC=disabled | Out-Null
# better workaround within VMWAre
#esxcli system settings advanced set -o /Net/Vmxnet3SwLRO -i 0
#esxcli system settings advanced set -o /Net/Vmxnet3HwLRO -i 0
##########################################################
###### 				PowerShell hardening             #####
##########################################################
# Set default language mode
# https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_language_modes?view=powershell-6
# protection against GandCrab Ransomware & Co.
# Peristent
[Environment]::SetEnvironmentVariable('__PSLockdownPolicy', '4', 'Machine')
# Current session only
#$ExecutionContext.SessionState.LanguageMode = "ConstrainedLanguage"
# Set the default PowerShell Execution Policy
# Windows 7+
# FIXME: -> string
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell" -Name "EnableScripts" -PropertyType DWord -Value 1
# AllScriptsSigned
# RemoteSignedScripts
# AllScripts
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell" -Name "ExecutionPolicy" -PropertyType DWord -Value 1
# Turn off module logging (we only want to log blocked scripts)
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -PropertyType DWord -Value 0
# Turn on script block logging
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -PropertyType DWord -Value 1
# Turn on Transcripting
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -PropertyType DWord -Value 1
# Turn on Script Block Invocation Logging
# FIXME: Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\UpdatableHelp" -Name "EnableUpdateHelpDefaultSourcePath" -PropertyType DWord -Value 1


# Block PS via firewall
# (FIXME:) This is my bs which I need to fix or I chill and relax an wait for PS7 and let it go...
#for /R %f in (powershell*.exe) do (
#netsh advfirewall firewall add rule name=“PS-Allow-LAN (%f)" dir=out remoteip=localsubnet action=allow program=“%f" enable=yes
#netsh advfirewall firewall add rule name=“PS-Deny-All (%f)" dir=out action=block program=“%f" enable=yes
#)
#netsh advfirewall firewall add rule name=“PS-Allow-LAN" dir=out \ remoteip=localsubnet action=allow program="c:\windows\system32\WindowsPowerShell\v2.0\powershell.exe" \ enable=yes
#netsh advfirewall firewall add rule name=“PS-Deny-All" dir=out \ action=block program="c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe" \ enable=yes
#Set-NetFirewallProfile -Profiel Domain,Public,Private -Enabled true
# Turn off PowerShell Core telemetry (FIXME:)
# https://news.ycombinator.com/item?id=18629942
# https://docs.Microsoft.com/en-us/powershell/scripting/whats-new/what-s-new-in-powershell-core-61?view=powershell-6#telemetry-can-only-be-disabled-with-an-environment-variable
##########################################################
###### 		Firewall (ignore the warnings)           #####
# Public profile should be used (privacy reasons)
# Following the CIS standards
##########################################################
# Block Cortana
#Powershell Set-NetFirewallRule -DisplayName search -Action Block
# Workaround for Port 135 listening status
# https://www.grc.com/freeware/dcom.htm
netsh advfirewall firewall add rule name="Prevent TCP Port 135 listening" protocol=TCP dir=in localport=135 action=block enable=yes
# Turn off Remote Desktop
Disable-NetFirewallRule -DisplayGroup "Remote Desktop"
# Enforce that Firewall is running and enabled
Set-NetFirewallProfile -Profile * -Enabled True
<# Enforce Domain Profile defaults & CIS rec.
# Turn on Windows Firewall: Domain - Firewall state <-> 'On (recommended)'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "EnableFirewall" -PropertyType DWord -Value 1 -Force
# Enforce 'Windows Firewall: Domain: Inbound connections <-> 'Block (default)'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "DefaultInboundAction" -PropertyType DWord -Value 1 -Force
# Enforce 'Windows Firewall: Domain: Outbound connections <-> 'Allow (default)'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "DefaultOutboundAction" -PropertyType DWord -Value 1 -Force
# 'Windows Firewall: Domain: Settings: Display a notification <-> 'No'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "DisableNotifications" -PropertyType DWord -Value 0 -Force
# Set 'Windows Firewall: Domain: Logging: Name <-> '%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -Name "LogFilePath" -PropertyType String -Value "%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log" -Force
# Set 'Windows Firewall: Domain: Logging: Size limit (KB) <-> '16,384 KB or greater'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -Name "LogFileSize" -PropertyType DWord -Value 400 -Force
# Set 'Windows Firewall: Domain: Logging: Log dropped packets <-> 'Yes'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -Name "LogDroppedPackets" -PropertyType DWord -Value 1 -Force
# Set 'Windows Firewall: Domain: Logging: Log successful connections <-> 'Yes'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -Name "LogSuccessfulConnections" -PropertyType DWord -Value 1 -Force
#>

<# Enforce Private Profile defaults & CIS rec.
# Turn on Windows Firewall: Private - Firewall state <-> 'On (recommended)'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "EnableFirewall" -PropertyType DWord -Value 1 -Force
# Enforce 'Windows Firewall: Private: Inbound connections <-> 'Block (default)'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "DefaultInboundAction" -PropertyType DWord -Value 1 -Force
# Enforce 'Windows Firewall: Private: Outbound connections <-> 'Allow (default)'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "DefaultOutboundAction" -PropertyType DWord -Value 1 -Force
# 'Windows Firewall: Private: Settings: Display a notification <-> 'No'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "DisableNotifications" -PropertyType DWord -Value 0 -Force
# Set 'Windows Firewall: Private: Logging: Name <-> '%SYSTEMROOT%\System32\logfiles\firewall\Privatefw.log'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -Name "LogFilePath" -PropertyType String -Value "%SYSTEMROOT%\System32\logfiles\firewall\Privatefw.log" -Force
# Set 'Windows Firewall: Private: Logging: Size limit (KB) <-> '16,384 KB or greater'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -Name "LogFileSize" -PropertyType DWord -Value 400 -Force
# Set 'Windows Firewall: Private: Logging: Log dropped packets <-> 'Yes'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -Name "LogDroppedPackets" -PropertyType DWord -Value 1 -Force
# Set 'Windows Firewall: Private: Logging: Log successful connections <-> 'Yes'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -Name "LogSuccessfulConnections" -PropertyType DWord -Value 1 -Force
#>

<# Enforce Public Profile defaults & CIS rec.
# Turn on Windows Firewall: Public - Firewall state <-> 'On (recommended)'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "EnableFirewall" -PropertyType DWord -Value 1 -Force
# Enforce 'Windows Firewall: Public: Inbound connections <-> 'Block (default)'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "DefaultInboundAction" -PropertyType DWord -Value 1 -Force
# Enforce 'Windows Firewall: Public: Outbound connections <-> 'Allow (default)'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "DefaultOutboundAction" -PropertyType DWord -Value 1 -Force
# 'Windows Firewall: Public: Settings: Display a notification <-> 'No'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "DisableNotifications" -PropertyType DWord -Value 0 -Force
# Set 'Windows Firewall: Public: Logging: Name <-> '%SYSTEMROOT%\System32\logfiles\firewall\Publicfw.log'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Name "LogFilePath" -PropertyType String -Value "%SYSTEMROOT%\System32\logfiles\firewall\Publicfw.log" -Force
# Set 'Windows Firewall: Public: Logging: Size limit (KB) <-> '16,384 KB or greater'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Name "LogFileSize" -PropertyType DWord -Value 400 -Force
# Set 'Windows Firewall: Public: Logging: Log dropped packets <-> 'Yes'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Name "LogDroppedPackets" -PropertyType DWord -Value 1 -Force
# Set 'Windows Firewall: Public: Logging: Log successful connections <-> 'Yes'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Name "LogSuccessfulConnections" -PropertyType DWord -Value 1 -Force
#>
# 'Prohibit installation and configuration of Network Bridge on your DNS domain network <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_AllowNetBridge_NLA" -PropertyType DWord -Value 0 -Force
# 'Prohibit use of Internet Connection Sharing on your DNS domain network <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_ShowSharedAccessUI" -PropertyType DWord -Value 0 -Force
# 'Require domain users to elevate when setting a network's location <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_StdDomainUserSetLocatio" -PropertyType DWord -Value 1 -Force
#
# Null route Source IP for e.g. Pi-Hole or AdGuard Home
#route -p add 131.253.18.253 MASK 255.255.255.255 0.0.0.0
#
## Add anti-telemetry domains to HOSTS file incl. the ones for LTSB/LTSC 2019!
#
#
# Typically usage is Add-HostEntry but you can work with an array if you want to.
# To remove old hosts entry use "Remove-HostEntry *"
# Todo: Sort, redundant check + check if rules exists
# Todo: Maybe null route instead of blocking (HOSTS bypass by Windows own DNS system?)
# Todo: ASN block Skype, apps etc. Cloudfront?
# Todo: dnsapi.dll hardcoded domains!
$hosts_file = "$env:systemroot\System32\drivers\etc\HOSTS"
$domains = @(
    "a-0001.a-msedge.net"
    "a-0002.a-msedge.net"
    "a-0003.a-msedge.net"
    "a-0004.a-msedge.net"
    "a-0005.a-msedge.net"
    "a-0006.a-msedge.net"
    "a-0007.a-msedge.net"
    "a-0008.a-msedge.net"
    "a-0009.a-msedge.net"
    "a-msedge.net"
    "a.ads1.msn.com"
    "a.ads2.msads.net"
    "a.ads2.msn.com"
    "a.rad.msn.com"
    "a23-218-212-69.deploy.static.akamaitechnologies.com"
    "client.wns.windows.com"
    "dns.msftncsi.com"
    "a248.e.akamai.net"
    "a1621.g.akamai.net"
    "a1856.g2.akamai.net"
    "a1961.g.akamai.net"
    "ac3.msn.com"
    "ad.doubleclick.net"
    "adnexus.net"
    "adnxs.com"
    "ads.msn.com"
    "ads1.msads.net"
    "ads1.msn.com"
    "aidps.atdmt.com"
    "aka-cdn-ns.adtech.de"
    "apps.skype.com"
    "az361816.vo.msecnd.net"
    "az512334.vo.msecnd.net"
    "b.ads1.msn.com"
    "b.ads2.msads.net"
    "b.rad.msn.com"
    "bs.serving-sys.com"
    "c.atdmt.com"
    "c.msn.com"
    "cdn.atdmt.com"
    "cds26.ams9.msecn.net"
    "choice.microsoft.com"
    "choice.microsoft.com.nsatc.net"
    "compatexchange.cloudapp.net"
    "corp.sts.microsoft.com"
    "corpext.msitadfs.glbdns2.microsoft.com"
    "cs1.wpc.v0cdn.net"
    "db3aqu.atdmt.com"
    "df.telemetry.microsoft.com"
    "diagnostics.support.microsoft.com"
    "e2835.dspb.akamaiedge.net"
    "e7341.g.akamaiedge.net"
    "e7502.ce.akamaiedge.net"
    "e8218.ce.akamaiedge.net"
    "ec.atdmt.com"
    "fe2.update.microsoft.com.akadns.net"
    "feedback.microsoft-hohm.com"
    "feedback.search.microsoft.com"
    "feedback.windows.com"
    "flex.msn.com"
    "g.msn.com"
    "h1.msn.com"
    "i1.services.social.microsoft.com"
    "i1.services.social.microsoft.com.nsatc.net"
    "lb1.www.ms.akadns.net"
    "live.rads.msn.com"
    "m.adnxs.com"
    "m.hotmail.com"
    "msedge.net"
    "msftncsi.com"
    "msnbot-65-55-108-23.search.msn.com"
    "msntest.serving-sys.com"
    "oca.telemetry.microsoft.com"
    "oca.telemetry.microsoft.com.nsatc.net"
    "pre.footprintpredict.com"
    "preview.msn.com"
    "pricelist.skype.com"
    "rad.live.com"
    "rad.msn.com"
    "redir.metaservices.microsoft.com"
    "reports.wes.df.telemetry.microsoft.com"
    "s.gateway.messenger.live.com"
    "schemas.microsoft.akadns.net"
    "secure.adnxs.com"
    "secure.flashtalking.com"
    "services.wes.df.telemetry.microsoft.com"
    "settings-sandbox.data.microsoft.com"
    "settings-win.data.microsoft.com"
    "sls.update.microsoft.com.akadns.net"
    "sO.2mdn.net"
    "sqm.df.telemetry.microsoft.com"
    "sqm.telemetry.microsoft.com"
    "sqm.telemetry.microsoft.com.nsatc.net"
    "static.2mdn.net"
    "statsfe1.ws.microsoft.com"
    "statsfe2.update.microsoft.com.akadns.net"
    "statsfe2.ws.microsoft.com"
    "survey.watson.microsoft.com"
    "telecommand.telemetry.microsoft.com"
    "telecommand.telemetry.microsoft.com.nsatc.net"
    "telemetry.appex.bing.net"
    "telemetry.appex.bing.net:443"
    "telemetry.microsoft.com"
    "telemetry.urs.microsoft.com"
    "ui.skype.com"
    "view.atdmt.com"
    "v10.events.data.microsoft.com"
    "v20.events.data.microsoft.com"
    "v30.events.data.microsoft.com"
    "vortex-bn2.metron.live.com.nsatc.net"
    "vortex-cy2.metron.live.com.nsatc.net"
    "vortex-sandbox.data.microsoft.com"
    "vortex-win.data.microsoft.com"
    "vortex.data.microsoft.com"
    "watson.live.com"
    "watson.microsoft.com"
    "v10.vortex-win.data.microsoft.com"
    "storecatalogrevocation.storequality.microsoft.com"
    "modern.watson.data.microsoft.com.akadns.net"
    "cy2.vortex.data.microsoft.com.akadns.net"
    "watson.ppe.telemetry.microsoft.com"
    "watson.telemetry.microsoft.com"
    "watson.telemetry.microsoft.com.nsatc.net"
    "wes.df.telemetry.microsoft.com"
    "www.msftconnecttest.com"
    "www.msftncsi.com"
    #"www.bing.com"
)
# Set proper file encoding and add 0.0.0.0
# Do not use 127.x because DNS resolution is handled internal
# and 127 checks each domain if it exists... that's a no-no!
Write-Output "" | Out-File -Encoding ASCII -Append $hosts_file
foreach ($domain in $domains) {
    if (-Not (Select-String -Path $hosts_file -Pattern $domain)) {
        Write-Output "0.0.0.0 $domain" | Out-File -Encoding ASCII -Append $hosts_file
    }
}

# IP's are added into our Windows Firewall
# Level 0 Telemetry
$ips = @(
    # Too many IPs will cause svchost.exe to freak out
    # we are excluding AMS, Cloudfont & other CDN's.
    # IP's captured via Win 10 private Firewall AFTER setting Telemetry level to 0.
    "13.64.186.225"
    "13.66.56.243"
    "13.68.31.193"
    "13.68.82.8"
    "13.68.87.47"
    "13.68.87.175"
    "13.68.88.129"
    "13.68.93.109"
    "13.73.26.107"
    "13.74.179.117"
    "13.76.218.117"
    "13.76.219.191"
    "13.76.219.210"
    "13.77.112.132"
    "13.77.115.36"
    "13.78.130.220"
    "13.78.168.230"
    "13.78.177.144"
    "13.78.179.199"
    "13.78.180.50"
    "13.78.180.90"
    "13.78.184.44"
    "13.78.184.186"
    "13.78.186.254"
    "13.78.187.58"
    "13.78.230.134"
    "13.78.232.226"
    "13.78.233.133"
    "13.78.235.126"
    "13.78.235.247"
    "13.79.239.69"
    "13.79.239.82"
    "13.80.12.54"
    "13.81.5.53"
    "13.83.148.218"
    "13.83.148.235"
    "13.83.149.5"
    "13.83.149.67"
    "13.85.88.16"
    "13.86.124.174"
    "13.86.124.184"
    "13.86.124.191"
    "13.88.28.53"
    "13.88.145.128"
    "13.92.194.212"
    "13.92.211.120"
    "13.107.3.128"
    "13.107.3.254"
    "13.107.4.50"
    "13.107.4.52"
    "13.107.4.254"
    "13.107.5.80"
    "13.107.5.88"
    "13.107.6.156"
    "13.107.6.158"
    "13.107.6.254"
    "13.107.13.88"
    "13.107.18.11"
    "13.107.18.254"
    "13.107.21.200"
    "13.107.21.229"
    "13.107.42.11"
    "13.107.42.12"
    "13.107.42.13"
    "13.107.42.14"
    "13.107.42.254"
    "13.107.43.12"
    "13.107.46.88"
    "13.107.47.88"
    "13.107.49.254"
    "13.107.128.254"
    "13.107.136.254"
    "13.107.246.10"
    "13.107.246.254"
    "13.107.255.72"
    "13.107.255.73"
    "13.107.255.74"
    "13.107.255.76"
    "20.36.218.63"
    "20.36.218.70"
    "20.36.222.39"
    "20.36.252.130"
    "20.41.41.23"
    "20.42.24.29"
    "20.42.24.50"
    "20.44.77.24"
    "20.44.77.45"
    "20.44.77.49"
    "20.44.86.43"
    "20.45.4.77"
    "20.45.4.178"
    "20.185.109.208"
    "20.189.74.153"
    "23.96.52.53"
    "23.96.208.208"
    "23.97.61.137"
    "23.97.178.173"
    "23.97.209.97"
    "23.99.49.121"
    "23.99.109.44"
    "23.99.109.64"
    "23.99.116.116"
    "23.99.121.207"
    "23.100.122.175"
    "23.101.156.198"
    "23.101.158.111"
    "23.102.4.253"
    "23.102.21.4"
    "23.103.182.126"
    "23.103.189.125"
    "23.103.189.126"
    "23.103.189.157"
    "23.103.189.158"
    "40.67.248.104"
    "40.67.251.132"
    "40.67.251.134"
    "40.67.252.206"
    "40.67.253.249"
    "40.67.254.36"
    "40.67.254.97"
    "40.67.255.199"
    "40.68.222.212"
    "40.69.153.67"
    "40.69.176.16"
    "40.69.216.73"
    "40.69.216.129"
    "40.69.216.251"
    "40.69.218.62"
    "40.69.219.197"
    "40.69.220.46"
    "40.69.221.239"
    "40.69.222.109"
    "40.69.223.39"
    "40.69.223.198"
    "40.70.0.108"
    "40.70.184.83"
    "40.70.220.248"
    "40.70.221.249"
    "40.74.70.63"
    "40.77.224.8"
    "40.77.224.11"
    "40.77.224.145"
    "40.77.224.254"
    "40.77.225.248"
    "40.77.226.13"
    "40.77.226.181"
    "40.77.226.246"
    "40.77.226.247"
    "40.77.226.248"
    "40.77.226.249"
    "40.77.226.250"
    "40.77.228.47"
    "40.77.228.87"
    "40.77.228.92"
    "40.77.229.8"
    "40.77.229.9"
    "40.77.229.12"
    "40.77.229.13"
    "40.77.229.16"
    "40.77.229.21"
    "40.77.229.22"
    "40.77.229.24"
    "40.77.229.26"
    "40.77.229.27"
    "40.77.229.29"
    "40.77.229.30"
    "40.77.229.32"
    "40.77.229.35"
    "40.77.229.38"
    "40.77.229.44"
    "40.77.229.45"
    "40.77.229.50"
    "40.77.229.53"
    "40.77.229.62"
    "40.77.229.65"
    "40.77.229.67"
    "40.77.229.69"
    "40.77.229.70"
    "40.77.229.71"
    "40.77.229.74"
    "40.77.229.76"
    "40.77.229.80"
    "40.77.229.81"
    "40.77.229.82"
    "40.77.229.88"
    "40.77.229.118"
    "40.77.229.123"
    "40.77.229.128"
    "40.77.229.133"
    "40.77.229.141"
    "40.77.229.199"
    "40.77.230.45"
    "40.77.232.101"
    "40.79.48.16"
    "40.79.65.78"
    "40.79.65.123"
    "40.79.65.235"
    "40.79.65.237"
    "40.79.66.194"
    "40.79.66.209"
    "40.79.67.176"
    "40.79.70.158"
    "40.79.85.125"
    "40.80.145.78"
    "40.83.74.46"
    "40.83.127.51"
    "40.83.150.233"
    "40.85.78.63"
    "40.89.135.48"
    "40.90.136.1"
    "40.90.136.19"
    "40.90.136.20"
    "40.90.136.163"
    "40.90.136.166"
    "40.90.136.180"
    "40.90.137.120"
    "40.90.137.122"
    "40.90.137.124"
    "40.90.137.125"
    "40.90.137.126"
    "40.90.137.127"
    "40.90.190.179"
    "40.90.218.0"
    "40.90.221.9"
    "40.91.73.219"
    "40.91.75.5"
    "40.91.76.238"
    "40.91.78.9"
    "40.91.91.94"
    "40.91.120.196"
    "40.91.122.44"
    "40.97.161.50"
    "40.101.4.2"
    "40.101.12.130"
    "40.101.18.242"
    "40.101.19.146"
    "40.101.46.178"
    "40.101.80.178"
    "40.101.83.18"
    "40.101.124.34"
    "40.101.124.194"
    "40.101.137.2"
    "40.101.137.18"
    "40.101.137.66"
    "40.102.34.194"
    "40.112.72.44"
    "40.112.75.175"
    "40.112.90.122"
    "40.112.91.29"
    "40.113.0.16"
    "40.113.97.222"
    "40.114.54.223"
    "40.114.140.1"
    "40.114.224.200"
    "40.114.241.141"
    "40.115.3.210"
    "40.115.33.128"
    "40.115.119.185"
    "40.117.96.136"
    "40.117.190.72"
    "40.118.61.1"
    "40.118.103.7"
    "40.118.106.130"
    "40.119.211.203"
    "40.121.213.159"
    "40.122.160.14"
    "40.126.1.166"
    "40.126.9.5"
    "40.127.128.174"
    "40.127.142.76"
    "40.127.195.156"
    "51.105.208.173"
    "51.136.15.177"
    "51.136.37.147"
    "51.137.137.111"
    "51.140.40.236"
    "51.140.65.84"
    "51.140.98.69"
    "51.140.127.197"
    "51.140.157.153"
    "51.141.13.164"
    "51.141.26.229"
    "51.141.32.51"
    "51.141.166.104"
    "51.143.111.7"
    "51.143.111.81"
    "51.144.108.120"
    "51.145.123.29"
    "52.97.135.114"
    "52.97.146.34"
    "52.97.151.50"
    "52.97.151.82"
    "52.97.152.114"
    "52.97.155.114"
    "52.97.171.194"
    "52.98.66.98"
    "52.109.8.19"
    "52.109.8.20"
    "52.109.8.21"
    "52.109.12.18"
    "52.109.12.19"
    "52.109.12.20"
    "52.109.12.21"
    "52.109.12.22"
    "52.109.12.23"
    "52.109.12.24"
    "52.109.76.30"
    "52.109.76.31"
    "52.109.76.32"
    "52.109.76.33"
    "52.109.76.34"
    "52.109.76.35"
    "52.109.76.36"
    "52.109.76.40"
    "52.109.88.6"
    "52.109.88.34"
    "52.109.88.35"
    "52.109.88.36"
    "52.109.88.37"
    "52.109.88.38"
    "52.109.88.39"
    "52.109.88.40"
    "52.109.88.44"
    "52.109.120.17"
    "52.109.120.18"
    "52.109.120.19"
    "52.109.120.20"
    "52.109.120.21"
    "52.109.120.22"
    "52.109.120.23"
    "52.109.124.18"
    "52.109.124.19"
    "52.109.124.20"
    "52.109.124.21"
    "52.109.124.22"
    "52.109.124.23"
    "52.109.124.24"
    "52.113.194.131"
    "52.114.6.46"
    "52.114.6.47"
    "52.114.7.36"
    "52.114.7.37"
    "52.114.7.38"
    "52.114.7.39"
    "52.114.32.5"
    "52.114.32.6"
    "52.114.32.7"
    "52.114.32.8"
    "52.114.32.24"
    "52.114.32.25"
    "52.114.36.1"
    "52.114.36.2"
    "52.114.36.3"
    "52.114.36.4"
    "52.114.74.43"
    "52.114.74.44"
    "52.114.74.45"
    "52.114.75.78"
    "52.114.75.79"
    "52.114.75.149"
    "52.114.75.150"
    "52.114.76.34"
    "52.114.76.35"
    "52.114.76.37"
    "52.114.77.33"
    "52.114.77.34"
    "52.114.77.137"
    "52.114.77.164"
    "52.114.88.19"
    "52.114.88.20"
    "52.114.88.21"
    "52.114.88.22"
    "52.114.88.28"
    "52.114.88.29"
    "52.114.128.7"
    "52.114.128.8"
    "52.114.128.9"
    "52.114.128.10"
    "52.114.128.43"
    "52.114.128.44"
    "52.114.128.58"
    "52.114.132.14"
    "52.114.132.20"
    "52.114.132.21"
    "52.114.132.22"
    "52.114.132.23"
    "52.114.132.73"
    "52.114.132.74"
    "52.114.158.50"
    "52.114.158.51"
    "52.114.158.52"
    "52.114.158.53"
    "52.114.158.91"
    "52.114.158.92"
    "52.114.158.102"
    "52.136.230.174"
    "52.138.148.87"
    "52.138.148.89"
    "52.138.148.159"
    "52.138.204.217"
    "52.138.216.83"
    "52.142.84.61"
    "52.142.114.2"
    "52.156.204.185"
    "52.157.234.37"
    "52.158.24.209"
    "52.158.24.229"
    "52.158.25.39"
    "52.158.208.111"
    "52.158.238.42"
    "52.161.15.246"
    "52.163.118.68"
    "52.164.191.55"
    "52.164.227.208"
    "52.164.240.33"
    "52.164.240.59"
    "52.164.241.205"
    "52.164.251.44"
    "52.166.110.64"
    "52.166.110.215"
    "52.166.120.77"
    "52.167.88.112"
    "52.167.222.82"
    "52.167.222.147"
    "52.167.223.135"
    "52.168.24.174"
    "52.169.71.150"
    "52.169.82.131"
    "52.169.83.3"
    "52.169.87.42"
    "52.169.123.48"
    "52.169.189.83"
    "52.170.83.19"
    "52.170.194.77"
    "52.171.136.200"
    "52.173.152.64"
    "52.174.22.246"
    "52.175.23.79"
    "52.175.30.196"
    "52.176.224.96"
    "52.178.38.151"
    "52.178.147.240"
    "52.178.151.212"
    "52.178.161.41"
    "52.178.163.85"
    "52.178.178.16"
    "52.178.192.146"
    "52.178.193.116"
    "52.178.223.23"
    "52.179.13.204"
    "52.183.47.176"
    "52.183.104.36"
    "52.183.114.173"
    "52.183.118.171"
    "52.184.82.129"
    "52.184.152.136"
    "52.184.155.206"
    "52.184.168.116"
    "52.187.60.107"
    "52.188.72.233"
    "52.188.77.27"
    "52.225.136.36"
    "52.226.130.114"
    "52.229.39.152"
    "52.229.170.171"
    "52.229.170.224"
    "52.229.171.86"
    "52.229.171.202"
    "52.229.172.155"
    "52.229.174.29"
    "52.229.174.172"
    "52.229.174.233"
    "52.229.175.79"
    "52.230.10.183"
    "52.230.85.180"
    "52.230.216.17"
    "52.230.216.157"
    "52.230.220.159"
    "52.230.223.92"
    "52.230.223.167"
    "52.230.240.94"
    "52.232.16.77"
    "52.232.19.76"
    "52.232.69.150"
    "52.232.225.93"
    "52.233.199.249"
    "52.236.42.239"
    "52.236.43.202"
    "52.239.137.4"
    "52.239.150.170"
    "52.239.151.138"
    "52.239.151.170"
    "52.239.156.74"
    "52.239.156.138"
    "52.239.157.138"
    "52.239.157.202"
    "52.239.177.36"
    "52.239.177.68"
    "52.239.177.100"
    "52.239.177.228"
    "52.239.184.10"
    "52.239.184.42"
    "52.239.207.100"
    "52.248.96.36"
    "52.249.24.101"
    "64.4.16.212"
    "64.4.16.214"
    "64.4.16.216"
    "64.4.16.218"
    "64.4.27.50"
    "64.4.54.18"
    "64.4.54.22"
    "64.4.54.253"
    "65.52.100.91"
    "65.52.100.92"
    "65.52.100.93"
    "65.52.100.94"
    "65.52.108.29"
    "65.52.108.33"
    "65.52.108.59"
    "65.52.108.90"
    "65.52.108.92"
    "65.52.108.153"
    "65.52.108.154"
    "65.52.108.185"
    "65.52.161.64"
    "65.52.226.14"
    "65.54.187.128"
    "65.54.187.130"
    "65.54.187.131"
    "65.54.187.132"
    "65.54.187.134"
    "65.54.198.196"
    "65.55.29.238"
    "65.55.44.51"
    "65.55.44.54"
    "65.55.44.108"
    "65.55.44.109"
    "65.55.83.120"
    "65.55.108.23"
    "65.55.113.11"
    "65.55.113.12"
    "65.55.113.13"
    "65.55.130.50"
    "65.55.163.76"
    "65.55.163.78"
    "65.55.163.80"
    "65.55.176.90"
    "65.55.242.254"
    "65.55.252.43"
    "65.55.252.63"
    "65.55.252.70"
    "65.55.252.71"
    "65.55.252.72"
    "65.55.252.93"
    "65.55.252.190"
    "65.55.252.202"
    "66.119.144.157"
    "66.119.144.158"
    "66.119.144.189"
    "66.119.144.190"
    "66.119.147.131"
    "104.40.210.32"
    "104.40.211.35"
    "104.41.207.73"
    "104.41.219.140"
    "104.42.41.237"
    "104.43.137.66"
    "104.43.139.21"
    "104.43.140.223"
    "104.43.203.255"
    "104.43.228.53"
    "104.43.228.202"
    "104.43.237.169"
    "104.44.80.172"
    "104.44.88.24"
    "104.44.88.28"
    "104.44.88.103"
    "104.45.11.195"
    "104.45.18.177"
    "104.45.177.233"
    "104.45.214.112"
    "104.46.1.211"
    "104.46.38.64"
    "104.46.91.34"
    "104.208.248.16"
    "104.209.172.133"
    "104.210.4.77"
    "104.210.40.87"
    "104.210.212.243"
    "104.211.96.15"
    "104.214.35.244"
    "104.214.77.221"
    "104.214.150.122"
    "104.214.220.181"
    "104.215.146.200"
    "111.221.29.11"
    "111.221.29.40"
    "111.221.29.134"
    "111.221.29.253"
    "111.221.29.254"
    "131.253.6.87"
    "131.253.6.103"
    "131.253.14.227"
    "131.253.14.229"
    "131.253.14.230"
    "131.253.14.231"
    "131.253.33.50"
    "131.253.33.200"
    "131.253.33.203"
    "131.253.33.254"
    "131.253.34.230"
    "131.253.34.234"
    "134.170.30.202"
    "134.170.30.203"
    "134.170.30.204"
    "134.170.30.221"
    "134.170.51.187"
    "134.170.51.188"
    "134.170.51.190"
    "134.170.51.246"
    "134.170.51.247"
    "134.170.51.248"
    "134.170.52.151"
    "134.170.53.29"
    "134.170.53.30"
    "134.170.115.55"
    "134.170.115.56"
    "134.170.115.60"
    "134.170.115.62"
    "134.170.165.248"
    "134.170.165.249"
    "134.170.165.251"
    "134.170.165.253"
    "134.170.178.97"
    "134.170.185.70"
    "134.170.188.248"
    "134.170.235.16"
    "137.116.44.10"
    "137.116.234.82"
    "137.117.142.136"
    "137.117.144.39"
    "137.117.235.16"
    "137.117.243.30"
    "137.135.62.92"
    "137.135.251.63"
    "138.91.122.49"
    "157.55.109.7"
    "157.55.109.224"
    "157.55.109.226"
    "157.55.109.228"
    "157.55.109.230"
    "157.55.109.232"
    "157.55.129.21"
    "157.55.133.204"
    "157.55.134.136"
    "157.55.134.138"
    "157.55.134.140"
    "157.55.134.142"
    "157.55.135.128"
    "157.55.135.130"
    "157.55.135.132"
    "157.55.135.134"
    "157.55.240.89"
    "157.55.240.126"
    "157.55.240.220"
    "157.56.57.5"
    "157.56.74.250"
    "157.56.77.138"
    "157.56.77.139"
    "157.56.77.140"
    "157.56.77.141"
    "157.56.77.148"
    "157.56.77.149"
    "157.56.91.77"
    "157.56.96.54"
    "157.56.96.58"
    "157.56.96.123"
    "157.56.96.157"
    "157.56.106.184"
    "157.56.106.185"
    "157.56.106.189"
    "157.56.113.217"
    "157.56.121.89"
    "157.56.124.87"
    "157.56.149.250"
    "157.56.194.72"
    "157.56.194.73"
    "157.56.194.74"
    "168.61.24.141"
    "168.61.146.25"
    "168.61.149.17"
    "168.61.172.71"
    "168.62.187.13"
    "168.63.18.79"
    "168.63.100.61"
    "168.63.102.42"
    "168.63.108.233"
    "191.234.72.183"
    "191.234.72.186"
    "191.234.72.188"
    "191.234.72.190"
    "191.236.155.80"
    "191.237.208.126"
    "191.237.218.239"
    "191.239.50.18"
    "191.239.50.77"
    "191.239.52.100"
    "191.239.54.52"
    "191.239.213.197"
    "204.152.141.244"
    "207.46.7.252"
    "207.46.26.12"
    "207.46.26.14"
    "207.46.26.16"
    "207.46.26.18"
    "207.46.101.29"
    "207.46.114.58"
    "207.46.114.61"
    "207.46.153.155"
    "207.46.194.14"
    "207.46.194.25"
    "207.46.194.33"
    "207.46.194.40"
    "207.46.223.94"
    "207.68.166.254"
)
# Check firewall rules and remove it, if already set
Remove-NetFirewallRule -DisplayName "Anti-Telemetry IPs" -ErrorAction SilentlyContinue
# Write new rules and give it a name
New-NetFirewallRule -DisplayName "Anti-Telemetry IPs" -Direction Outbound ` -Action Block -RemoteAddress ([string[]]$ips)
# Block Cortana via Firewall Rule (FIXME:)
New-NetFirewallRule -DisplayName "Anti Cortana Web Access" -Direction Outbound -Program "%windir%\systemapps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe" -Action Block
# Add local IPSec rules if IPSec is enabled.
netsh.exe advfirewall consec add rule name=Testing-IPSec-NETSH endpoint1=any port1=any endpoint2=localsubnet port2=3389,135,139,445,21,20,23 protocol=tcp profile=any action=requireinrequestout interfacetype=any auth1=computerpsk auth1psk=$ThePreSharedKey enable=yes
##########################################################
######              Bitlocker (VeraCrypt)           ######
# If you use VeraCrypt the entries are not written in reg
##########################################################
# Removes the startup delay from MBAM
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\MBAM" -Name "NoStartupDelay" -PropertyType DWord -Value 1 -Force

# (FIXME:)
# Computer\HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Policies\Microsoft\FVE
# upper layer + hidden toggles ^^


# Import HOSTS file
# FIXME:
#[Net.ServicePointManager]::SecurityProtocol = "tls13, tls12"
#Invoke-WebRequest "https://CHEF-KOCH.github.io/compressed/blacklist-test.txt" -OutFile "C:\Windows\System32\drivers\etc\hosts"
#ipconfig /flushdns


# No NOT use this !
# FIXME: - Check status and correct
#Set-ItemProperty -Path "HKLM:\SOFTWARE\SOFTWARE\Policies\Microsoft\FVE\MDOPBitLockerManagement" -Name "ClientWakeupFrequency" -PropertyType DWord -Value 1 -Force
#Set-ItemProperty -Path "HKLM:\SOFTWARE\SOFTWARE\Policies\Microsoft\FVE\MDOPBitLockerManagement" -Name "StatusReportingFrequency" -PropertyType DWord -Value 1 -Force
# Turn on machine account lockout threshold'
# FIXME: Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "MaxDevicePasswordFailedAttempts" -PropertyType DWord -Value 000000a -Force
# Prevent installation of devices that match any of these device IDs"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceIDs" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Prevent installation of devices that match any of these device IDs: Prevent installation of devices that match any of these device IDs <-> 'PCI\CC_0C0A' (FIXME:)
# Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "1" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Prevent installation of devices that match any of these device IDs: Also apply to matching devices that are already installed. <-> 'True' (FIXME:)
# Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceIDsRetroactive" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Prevent installation of devices using drivers that match these device setup classes <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceClasses" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Prevent installation of devices using drivers that match these device setup classes: Prevent installation of devices using drivers for these device setup (FIXME:)
# {d48179be-ec20-11d1-b6b8-00c04fa372a7} - IEEE 1394 devices that support the SBP2 Protocol Class
# {7ebefbc0-3200-11d2-b4c2-00a0C9697d07} - IEEE 1394 devices that support the IEC-61883 Protocol Class
# {c06ff265-ae09-48f0-812c-16753d7cba83} - IEEE 1394 devices that support the AVC Protocol Class
# {6bdd1fc1-810f-11d0-bec7-08002be2092f} - IEEE 1394 Host Bus Controller Class
# Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceClasses" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
# "1"="{d48179be-ec20-11d1-b6b8-00c04fa372a7}"
# "1"="{7ebefbc0-3200-11d2-b4c2-00a0C9697d07}"
# "1"="{c06ff265-ae09-48f0-812c-16753d7cba83}"
# "1"="{6bdd1fc1-810f-11d0-bec7-08002be2092f}"
# Prevent installation of devices using drivers that match these device setup classes: Also apply to matching devices that are already installed. <-> 'True' (FIXME:)
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceClassesRetroactive" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab" -Name "DCSettingIndex" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
# (FIXME:) in case of no TPM chip, is there a Windows 10 without tpm which got the certification? I don't think so.
#
# Allow standby states (S1-S3) when sleeping (plugged-in)
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab" -Name "ACSettingIndex" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Allow access to BitLocker-protected fixed data drives from earlier versions of Windows <-> 'Disabled
Remove-Item -Path "HKLM:\Software\Policies\Microsoft\FVE" -Name "DVDiscoveryVolumeType" -PropertyType String -Value "" -Force
# Choose how BitLocker-protected fixed drives can be recovered <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVRecovery" -PropertyType DWord -Value 1 -Force
# Allow data recovery agent
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVManageDRA" -PropertyType DWord -Value 1 -Force
# Allow 48-Bit Recovery Password
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVRecoveryPassword" -PropertyType DWord -Value 2 -Force
# Recovery Key <-> 'Enabled: Allow 256-bit recovery key'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVRecoveryKey" -PropertyType DWord -Value 2 -Force
# Disable additional recovery options from the BitLocker setup wizard <-> 'Enabled: True'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVHideRecoveryPage" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Save BitLocker recovery information to AD DS for fixed data drives <-> 'Enabled: False'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVActiveDirectoryBackup" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Configure storage of BitLocker recovery information to AD DS <-> 'Enabled: Backup recovery passwords and key packages'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVActiveDirectoryInfoToStore" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Do not enable BitLocker until recovery information is stored to AD DS for fixed data drives <-> 'Enabled: False'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVRequireActiveDirectoryBackup" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Use of hardware-based encryption for fixed data drives <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVHardwareEncryption" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Use of hardware-based encryption for fixed data drives: Use BitLocker software-based encryption when hardware encryption is not available <-> 'Enabled: True'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVAllowSoftwareEncryptionFailover" -PropertyType DWord -Value 1 -Force
# Configure use of hardware-based encryption for fixed data drives: Restrict encryption algorithms and cipher suites allowed for hardware-based encryption <-> 'Enabled: False'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVRestrictHardwareEncryptionAlgorithms" -PropertyType DWord -Value 0 -Force
# Restrict crypto algorithms or cipher suites to the following: <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVAllowedHardwareEncryptionAlgorithms" -PropertyType hex -Value 32,00,2e,00,31,00,36,00,2e,00,38,00,34,00,30,00,2e,00,31,00,2e,00,31,00,30,00,31,00,2e,00,33,00,2e,00,34,00,2e,00,31,00,2e,00,32,00,3b,00,32,00,2e,00,31,00,36,00,2e,00,38,00,34,00,30,00,2e,00,31,00,2e,00,31,00,30,00,31,00,2e,00,33,00,2e,00,34,00,2e,00,31,00,2e,00,34,00,32,00,00,00,00,00 -Force -PropertyType hex -Value 00,00 -Force
# Configure use of passwords for fixed data drives <-> 'Disabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVPassphrase" -PropertyType DWord -Value 0 -Force
# Configure use of smart cards on fixed data drives <-> 'Enabled' (no effect if no smart card was detected)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVAllowUserCert" -PropertyType DWord -Value 1 -Force
# Require use of smart cards on fixed data drives <-> 'Enabled: True'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVEnforceUserCert" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Allow enhanced PINs for startup <-> 'Enabled' (FIXME:)
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseEnhancedPin" -PropertyType DWord -Value 1 -Force
# Allow Secure Boot for integrity validation <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSAllowSecureBootForIntegrity" -PropertyType DWord -Value 1 -Force
# Choose how BitLocker-protected operating system drives can be recovered <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSRecovery" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Allow data recovery agent <-> 'Enabled: False'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSManageDRA" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Require 48-digit recovery password
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSRecoveryPassword" -PropertyType DWord -Value 2 -Force -ErrorAction SilentlyContinue
# Recovery Key <-> 'Enabled: Do not allow 256-bit recovery key'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSRecoveryKey" -PropertyType DWord -Value 2 -Force -ErrorAction SilentlyContinue
# Hide the recovery page from non adminstrators
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSHideRecoveryPage" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Save BitLocker recovery information to AD DS for operating system drives <-> 'Enabled: True'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSActiveDirectoryBackup" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Configure storage of BitLocker recovery information to AD DS <-> 'Enabled: Store recovery passwords and key packages'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSActiveDirectoryInfoToStore" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Do not enable BitLocker until recovery information is stored to AD DS for operating system drives <-> 'Enabled: True'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSRequireActiveDirectoryBackup" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Configure minimum PIN length for startup <-> 'Enabled: 7 or more characters'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "MinimumPIN" -PropertyType DWord -Value 20 -Force -ErrorAction SilentlyContinue
# Turn on ardware-based encryption for operating systemm drives
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSHardwareEncryption" -PropertyType DWord -Value 1 -Force
# Use BitLocker software-based encryption when hardware encryption is not available <-> 'Enabled: True'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSAllowSoftwareEncryptionFailover" -PropertyType DWord -Value 1 -Force
# Restrict encryption algorithms and cipher suites allowed for hardware-based encryption <-> 'Enabled: False'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSRestrictHardwareEncryptionAlgorithms" -PropertyType DWord -Value 0 -Force
# Restrict crypto algorithms or cipher suites to the following: <-> 'Enabled`
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSAllowedHardwareEncryptionAlgorithms" -PropertyType hex -Value 32,00,2e,00,31,00,36,00,2e,00,38,00,34,00,30,00,2e,00,31,00,2e,00,31,00,30,00,31,00,2e,00,33,00,2e,00,34,00,2e,00,31,00,2e,00,32,00,3b,00,32,00,2e,00,31,00,36,00,2e,00,38,00,34,00,30,00,2e,00,31,00,2e,00,31,00,30,00,31,00,2e,00,33,00,2e,00,34,00,2e,00,31,00,2e,00,34,00,32,00,00,00,00,00 -Force
# Passwords for operating system drives <-> 'Disabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSPassphrase" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Require additional authentication at startup <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseAdvancedStartup" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Allow BitLocker without a compatible TPM <-> 'Enabled: False'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "EnableBDEWithNoTPM" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Configure TPM startup <-> 'Enabled: 'Do not allow TPM'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseTPM" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Configure TPM startup PIN <-> 'Enabled: Require startup PIN with TPM'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseTPMPIN" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Configure TPM startup key: <-> 'Enabled: Do not allow startup key with TPM'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseTPMKey" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Configure TPM startup key and PIN <-> 'Enabled: Do not allow startup key and PIN with TPM'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseTPMKeyPIN" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Allow access to BitLocker-protected removable data drives from earlier versions of Windows <-> 'Disabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVDiscoveryVolumeType" -PropertyType String -Value "" -Force
# BitLocker-protected removable drives can be recovered <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVRecovery" -PropertyType DWord -Value 1 -Force
# BitLocker-protected removable drives can be recovered: Allow data recovery agent <-> 'Enabled: True'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVManageDRA" -PropertyType DWord -Value 1 -Force
# BitLocker-protected removable drives can be recovered: Recovery Password <-> 'Enabled: Do not allow 48-digit recovery password'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVRecoveryPassword" -PropertyType DWord -Value 2 -Force -ErrorAction SilentlyContinue
# BitLocker-protected removable drives can be recovered: Recovery Key <-> 'Enabled: Do not allow 256-bit recovery key'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVRecoveryKey" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Omit recovery options from the BitLocker setup wizard <-> 'Enabled: True'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVHideRecoveryPage" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Save BitLocker recovery information to AD DS for removable data drives <-> 'Enabled: False'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVActiveDirectoryBackup" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Configure storage of BitLocker recovery information to AD DS: <-> 'Enabled: Backup recovery passwords and key packages'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVActiveDirectoryInfoToStore" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Do not enable BitLocker until recovery information is stored to AD DS for removable data drives <-> 'Enabled: False'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVRequireActiveDirectoryBackup" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Configure use of hardware-based encryption for removable data drives <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVHardwareEncryption" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
# BitLocker software-based encryption when hardware encryption is not available <-> 'Enabled: True'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVAllowSoftwareEncryptionFailover" -PropertyType DWord -Value 1 -Force
# Restrict encryption algorithms and cipher suites allowed for hardware-based encryption <-> 'Enabled: False'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVRestrictHardwareEncryptionAlgorithms" -PropertyType DWord -Value 0 -Force
# Restrict crypto algorithms or cipher suites
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVAllowedHardwareEncryptionAlgorithms" -PropertyType hex -Value 32,00,2e,00,31,00,36,00,2e,00,38,00,34,00,30,00,2e,00,31,00,2e,00,31,00,30,00,31,00,2e,00,33,00,2e,00,34,00,2e,00,31,00,2e,00,32,00,3b,00,32,00,2e,00,31,00,36,00,2e,00,38,00,34,00,30,00,2e,00,31,00,2e,00,31,00,30,00,31,00,2e,00,33,00,2e,00,34,00,2e,00,31,00,2e,00,34,00,32,00,00,00,00,00 -Force
# Passwords for removable data drives <-> 'Disabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVPassphrase" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Smart cards on removable data drives <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVAllowUserCert" -PropertyType DWord -Value 1 -Force
# Require use of smart cards on removable data drives <-> 'Enabled: True'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVEnforceUserCert" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Deny write access to removable drives not protected by BitLocker <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVDenyWriteAccess" -PropertyType DWord -Value 1 -Force
# Do not allow write access to devices configured in another organization <-> 'Enabled: False'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVDenyCrossOrg" -PropertyType DWord -Value 1 -Force
# Drive encryption method and cipher strength (AES)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "EncryptionMethodWithXtsOs" -PropertyType DWord -Value 7 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "EncryptionMethodWithXtsRdv" -PropertyType DWord -Value 4 -Force
##########################################################
######              MS Office & LibreOffice         ######
# FIXME: Check if Office is present or not
##########################################################
# Disable Office Cursor Animation ("Feedback Animation")
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\15.0\Common\Graphics" -Name "DisableAnimations" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Common\Graphics" -Name "DisableAnimations" -PropertyType DWord -Value 1 -Force
# Turn off OSM telemetry
# Logging
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Office\16.0\OSM" -Name "Enablelogging" -PropertyType DWord -Value 0 -Force
# Upload
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Office\16.0\OSM" -Name "EnableUpload" -PropertyType DWord -Value 0 -Force
# File Obfuscation
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Office\16.0\OSM" -Name "EnableFileObfuscation" -PropertyType DWord -Value 1 -Force
# Common Telemetry
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Office\Common\ClientTelemetry" -Name "DisableTelemetry" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Office\Common\ClientTelemetry" -Name "qmenable" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Office\Common\ClientTelemetry" -Name "sendcustomerdata" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Office\Common\ClientTelemetry" -Name "sendtelemetry" -PropertyType DWord -Value 3 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Office\Common\ClientTelemetry" -Name "updatereliabilitydata" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\Office\16.0\User Settings\CustomSettings\Create\Software\Microsoft\Office\Common\ClientTelemetry" -Name "SendTelemetry" -PropertyType DWord -Value 3 -Force
Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\Office\16.0\User Settings\CustomSettings\Create\Software\Microsoft\Office\Common\ClientTelemetry" -Name "DisableTelemetry" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\Office\16.0\User Settings\CustomSettings\Create\Software\Microsoft\Office\16.0\Common\Privacy" -Name "disconnectedstate" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\Office\16.0\User Settings\CustomSettings\Create\Software\Microsoft\Office\16.0\Common\Privacy" -Name "usercontentdisabled" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\Office\16.0\User Settings\CustomSettings\Create\Software\Microsoft\Office\16.0\Common\Privacy" -Name "downloadcontentdisabled" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\Office\16.0\User Settings\CustomSettings\Create\Software\Microsoft\Office\16.0\Common\Privacy" -Name "controllerconnectedservicesenabled" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\Office\16.0\User Settings\CustomSettings\Create\Software\Microsoft\Office\Common\ClientTelemetry\Common\General" -Name "disableboottoofficestart" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\Office\16.0\User Settings\CustomSettings\Create\Software\Microsoft\Office\Common\ClientTelemetry\Common\General" -Name "optindisable" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\Office\16.0\User Settings\CustomSettings\Create\Software\Microsoft\Office\Common\ClientTelemetry\Common\General" -Name "shownfirstrunoptin" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\Office\16.0\User Settings\CustomSettings\Create\Software\Microsoft\Office\Common\ClientTelemetry\Common\General" -Name "ShownFileFmtPrompt" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\Office\16.0\Lync" -Name "disableautomaticsendtracing" -PropertyType DWord -Value 1 -Force
# RTM <-> VLCS
Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\Office\16.0\User Settings\CustomSettings\Create\Software\Microsoft\Office\Common\ClientTelemetry\Firstrun" -Name "BootedRTM" -PropertyType DWord -Value 1 -Force
# Do not validate files (triggers AV/metadata)
Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\Office\16.0\Common\Security\FileValidation" -Name "disablereporting" -PropertyType DWord -Value 1 -Force
# Watson (debug + performance + telemetry)
Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\Office\16.0\Common\PTWatson" -Name "PTWOptIn" -PropertyType DWord -Value 0 -Force
# Outlook logging
Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\Office\16.0\Outlook\Options\Mail" -Name "EnableLogging" -PropertyType DWord -Value 0 -Force
# World logging
Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\Office\16.0\Word\Options" -Name "EnableLogging" -PropertyType DWord -Value 0 -Force
# Common Feedback
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Office\16.0\Common\feedback" -Name "enabled" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Office\16.0\Common\feedback" -Name "includescreenshot" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Office\16.0\Common\ptwatson" -Name "ptwoptin" -PropertyType DWord -Value 0 -Force
# Office Application based telemetry
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Office\16.0\OSM\preventedapplications" -Name "accesssolution" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Office\16.0\OSM\preventedapplications" -Name "olksolution" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Office\16.0\OSM\preventedapplications" -Name "onenotesolution" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Office\16.0\OSM\preventedapplications" -Name "pptsolution" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Office\16.0\OSM\preventedapplications" -Name "projectsolution" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Office\16.0\OSM\preventedapplications" -Name "publishersolution" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Office\16.0\OSM\preventedapplications" -Name "visiosolution" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Office\16.0\OSM\preventedapplications" -Name "wdsolution" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Office\16.0\OSM\preventedapplications" -Name "xlsolution" -PropertyType DWord -Value 1 -Force
# TYPE (add-ins etc) telemetry
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Office\16.0\OSM\preventedsolutiontypes" -Name "agave" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Office\16.0\OSM\preventedsolutiontypes" -Name "appaddins" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Office\16.0\OSM\preventedsolutiontypes" -Name "comaddins" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Office\16.0\OSM\preventedsolutiontypes" -Name "documentfiles" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Office\16.0\OSM\preventedsolutiontypes" -Name "templatefiles" -PropertyType DWord -Value 1 -Force
# Online features
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Office\16.0\Common\General" -Name "skydrivesigninoption" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Office\16.0\Common\General" -Name "shownfirstrunoptin" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Office\16.0\Firstrun" -Name "disablemovie" -PropertyType DWord -Value 1 -Force
# Turn off MS Office Telemetry Agent
Disable-ScheduledTask -TaskName "\Microsoft\Office\OfficeTelemetry\AgentFallBack2016" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Office\OfficeTelemetry\AgentFallBack2019" | Out-Null
# Stop automatic MS Office Updates
Disable-ScheduledTask -TaskName "\Microsoft\Office\OfficeTelemetry\Office Automatic Updates 2.0" | Out-Null
# MS Office Telemetry master toggle
Disable-ScheduledTask -TaskName "\Microsoft\Office\OfficeTelemetry\OfficeTelemetryAgentLogOn2016" | Out-Null
#Get-ScheduledTask -TaskPath "\Microsoft\Office\Office 15 Subscription Heartbeat\" | Disable-ScheduledTask
#Get-ScheduledTask -TaskPath "\Microsoft\Office\Office 16 Subscription Heartbeat\" | Disable-ScheduledTask
#Get-ScheduledTask -TaskPath "\Microsoft\Office\Office 17 Subscription Heartbeat\" | Disable-ScheduledTask
# MS Office Telemetry scheduled task fallback
Disable-ScheduledTask -TaskName "\Microsoft\Office\OfficeTelemetry\AgentFallBack" | Out-Null
# MS Office Login telemetry agent watcher
Disable-ScheduledTask -TaskName "\Microsoft\Office\OfficeTelemetry\AgentLogOn" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Office\OfficeInventory\AgentLogOn" | Out-Null
<#
# Turn on Microsoft Office Updates
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate" -Name "enableautomaticupdates" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate" -Name "hideenabledisableupdates" -PropertyType DWord -Value 1 -Force
# Block Macros by default in Office
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\access\security" -Name "blockcontentexecutionfrominternet" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\access\security" -Name "excelbypassencryptedmacroscan" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\access\security" -Name "vbawarnings" -PropertyType DWord -Value 4 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" -Name "excelbypassencryptedmacroscan" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\ms project\securit" -Name "vbawarnings" -PropertyType DWord -Value 4 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\ms project\security" -Name "level" -PropertyType DWord -Value 4 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" -Name "level" -PropertyType DWord -Value 4 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security" -Name "vbawarnings" -PropertyType DWord -Value 4 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\publisher\security" -Name "vbawarnings" -PropertyType DWord -Value 4 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\visio\security" -Name "blockcontentexecutionfrominternet" -PropertyType DWord -Value 4 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\visio\security" -Name "vbawarnings" -PropertyType DWord -Value 4 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\word\security" -Name "vbawarnings" -PropertyType DWord -Value 4 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\word\security" -Name "wordbypassencryptedmacroscan" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\common\security" -Name "automationsecurity" -PropertyType DWord -Value 0 -Force
# Turn off Office Fax services
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\services\fax" -Name "nofax" -PropertyType DWord -Value 1 -Force
# Turn off all Office Internet connections (Updates are still possible)
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\internet" -Name "useonlinecontent" -PropertyType DWord -Value 0 -Force
# Turn off One Drive login in Office
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\general" -Name "skydrivesigninoption" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\signin" -Name "signinoptions" -PropertyType DWord -Value 3 -Force
# Turn off Office Feedback
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\15.0\common\feedback" -Name "enabled" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\15.0\common\feedback" -Name "includescreenshot" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback" -Name "enabled" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback" -Name "includescreenshot" -PropertyType DWord -Value 0 -Force
# Turn off Data Collection
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\general" -Name "notrack" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\general" -Name "optindisable" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\general" -Name "shownfirstrunoptin" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\general" -Name "ptwoptin" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\general" -Name "bootedrtm" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\general" -Name "disablemovie" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\general" -Name "EnableFileObfuscation" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\general" -Name "Enablelogging" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm" -Name "EnableUpload" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -Name "accesssolution" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -Name "olksolution" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -Name "onenotesolution" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -Name "pptsolution" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -Name "projectsolution" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -Name "publishersolution" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -Name "visiosolution" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -Name "wdsolution" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -Name "xlsolution" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -Name "agave" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -Name "appaddins" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -Name "comaddins" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -Name "documentfiles" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -Name "templatefiles" -PropertyType DWord -Value 1 -Force
# Turn off loading of external content in Office
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\outlook\options\mail" -Name "blockextcontent" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\outlook\options\mail" -Name "junkmailenablelinks" -PropertyType DWord -Value 0 -Force
# Turn off Online repair in Office
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate" -Name "onlinerepair" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate" -Name "fallbacktocdn" -PropertyType DWord -Value 0 -Force
# Turn off Telemetry agent
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Common" -Name "qmenable" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Common" -Name "sendcustomerdata" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Common" -Name "updatereliabilitydata" -PropertyType DWord -Value 0 -Force

FIXME:
#>

# (Dynamic Data Exchange) DDE Migration
# Not needed in LibreOffice
# https://wiki.documentfoundation.org/Feature_Comparison:_LibreOffice_-_Microsoft_Office#Spreadsheet_applications:_LibreOffice_Calc_vs._Microsoft_Excel
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Word\Options" -Name "DontUpdateLinks" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\15.0\Word\Options" -Name "DontUpdateLinks" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\14.0\Word\Options" -Name "DontUpdateLinks" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Word\Options\WordMail" -Name "DontUpdateLinks" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\15.0\Word\Options\WordMail" -Name "DontUpdateLinks" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\14.0\Word\Options\WordMail" -Name "DontUpdateLinks" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\OneNote\Options" -Name "DisableEmbeddedFiles" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\15.0\OneNote\Options" -Name "DisableEmbeddedFiles" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\14.0\OneNote\Options" -Name "DisableEmbeddedFiles" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Excel\Options" -Name "DontUpdateLinks" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Excel\Options" -Name "DDEAllowed" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Excel\Options" -Name "DDECleaned" -PropertyType DWord -Value 279 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\15.0\Excel\Options" -Name "DontUpdateLinks" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\15.0\Excel\Options" -Name "DDEAllowed" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\15.0\Excel\Options" -Name "DDECleaned" -PropertyType DWord -Value 117 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\14.0\Excel\Options" -Name "DontUpdateLinks" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\14.0\Excel\Options" -Name "DDEAllowed" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\14.0\Excel\Options" -Name "DDECleaned" -PropertyType DWord -Value 117 -Force


# Turn off Macros in Microsoft Office
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\word\security" -Name "blockcontentexecutionfrominternet" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" -Name "blockcontentexecutionfrominternet" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security" -Name "blockcontentexecutionfrominternet" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\15.0\word\security" -Name "blockcontentexecutionfrominternet" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\15.0\excel\security" -Name "blockcontentexecutionfrominternet" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\15.0\powerpoint\security" -Name "blockcontentexecutionfrominternet" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\14.0\msproject\security" -Name "VBAWarnings" -PropertyType DWord -Value 2 -Force

# Turn off Office Packer Objects (OLE) (FIXME:)
# https://blog.trendmicro.com/trendlabs-security-intelligence/new-cve-2014-4114-attacks-seen-one-week-after-fix/
# https://docs.Microsoft.com/en-us/office365/troubleshoot/activation/control-block-ole-com
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\Microsoft\Office\16.0\Common\COM Compatibility" -Name "ActivationFilterOverride" -PropertyType DWord -Value 1 -Force


##########################################################
###### 				Local Account                   ######
##########################################################
# Default Local Account Token Filter Policy
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -PropertyType DWord -Value 1 -Force




##########################################################
###### 				User Account Control (UAC)      ######
# (FIXME:) cred. guard
##########################################################
# Turn on Admin Approval Mode
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken" -Value 1 -Force
# Enable LUA
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Force
# Set UAC to high
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -PropertyType DWord -Value 5
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -PropertyType DWord -Value 1
# Make UAC Great Again (MUGA)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -PropertyType DWord -Value 3
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DenyDeviceIDs" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableAutomaticRestartSignOn" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DSCAutomationHostEnabled" -PropertyType DWord -Value 1
# https://blogs.technet.Microsoft.com/system_center_configuration_manager_operating_system_deployment_support_blog/2017/02/23/no-mouse-cursor-during-configmgr-osd-task-sequence/
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableCursorSuppression" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFullTrustStartupTasks" -PropertyType DWord -Value 2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableInstallerDetection" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableSecureUIAPaths" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableUIADesktopToggle" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableUwpStartupTasks" -PropertyType DWord -Value 2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableVirtualization" -PropertyType DWord -Value 2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "SupportFullTrustStartupTasks" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "SupportUwpStartupTasks" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "undockwithoutlogon" -PropertyType DWord -Value 1
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ValidateAdminCodeSignatures" -PropertyType DWord -Value 1
##################################################################################################
###### 				                    Credential Guard                                    ######
######                                                                                      ######
# Because I know to 100% that people will complain about the "second"                       ######
# GUI which is been created in front of UAC. Let me explain it: This is basically a         ######
# protection mechanism which helps to avoid UAC bypasses.                                   ######
# There is (from what I know) no working exploit which bypasses Cred + UAC (I checked github). ###
##################################################################################################
# Turn on CredGuard for Admins
# Vista+
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI" -Name "EnumerateAdministrators" -PropertyType DWord -Value 1
# Turn on secure credential prompting
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI" -Name "EnableSecureCredentialPrompting" -PropertyType DWord -Value 1
# Turn off Password reveal option
# Windows 8+ or IE10 only
#Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI" -Name "DisablePasswordReveal" -PropertyType DWord -Value 1
# Turn off Password Reset Questions
# Windows 10 RS6+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "NoLocalPasswordResetQuestions" -PropertyType DWord -Value 1






#################################################################################################################
###### 					Services                                                                           ######
###### 			Overview services (not all!)                                                                ######
# http://www.blackviper.com/service-configurations/black-vipers-windows-10-service-configurations/         ######
# Todo: Find a way to detect and disable all _xxx services automatically.                                  ######
# Todo: Sysrep needs dmwappushserivce.                                                                     ######
#################################################################################################################
# Disable all the services that doesn't need the OS to boot
# FIXME:
#Get-Service -Exclude DeviceInstall,Netman,NetSetupSvc,VaultSvc,vds,Appinfo,StateRepository,SysMain,seclogon,EventLog,KeyIso,trustedinstaller,Eaphost,dot3svc,BFE,BrokerInfrastructure,CoreMessagingRegistrar,DcomLaunch,Dhcp,LSM,PlugPlay,AudioEndpointBuilder,Audiosrv,ProfSvc,RpcEptMapper,RpcSs,sppsvc,CryptSvc,DeviceInstall,EventSystem,msiserver,nsi,Power,Spooler,swprv,UserManager | Set-Service -StartupType Disabled

# Turn off Autologger and clear the content
#Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger" -Name "AutoLogger-Diagtrack-Listener" -PropertyType Dword -Value 0
New-Item "%ProgramData%\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl" -ItemType File -Force
Set-Content C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl -Value "" -Force
# Turn off Geolocation
Remove-Item -Path "HKCU:\SYSTEM\CurrentControlSet\Services\lfsvc\TriggerInfo\3*" -Recurse -Force
# Turn off all unwanted services
$services = @(
	"AJRouter"									# AllJoyn Router Service | Privacy
	"ALG"										# Application Layer Gateway Service | Privacy
	"AxInstSV"									# ActiveX Installer (AxInstSV)
	"AxInstSVGroup"								# AxInstSVGroup
	"BcastDVRUserService_*"						# GameDVR and Broadcast User Service (FIXME:)
	#"BDESVC"									# Bitlocker
	"BTAGService"								# Bluetooth Audio Gateway Service | Security
	"bthserv"									# Bluetooth Support Service | Security
	"CaptureService_*"							# Once Core capture service
	"CaptureService_*"							# OneCore Capture Service aka telemetry (also exists on LTSC)
	"cbdhsvc_*"									# Clipboard scenarios
	"CDPSvc"									# Connected Devices Platform Service
	"CDPUserSvc_*"								# Connected Devices Platform User Service | Telemetry
	"Connected Devices Platform scenarios"		# Connected Devices Platform scenarios
	"ConsentUxUserSvc_*"						# ConsentUX
	"CscService"								# Offline Files
	"defragsvc"									# Optimize Drives (defrag) (use other tools in case you defrag)
    "DevicePickerUserSvc_*"						# Device Picker
    "diagnosticshub.standardcollector.service"  # DisagnosticHub Service
	"DevicesFlowUserSvc_*"						# Device Flow
	"diagsvc"									# Diagnostic Execution Service
	"dmwappushsvc"								# WAP Push Service
	"DoSvc"										# Delivery Optimization
	"DsSvc"										# Data Sharing Service
	"DusmSvc"									# Data Usage
	"fhsvc"										# File History Service | Privacy
	"irmon"										# Infrared monitor service
	"LanmanServer"								# Server
	"LanmanWorkstation"							# Workstation | Security
	"lfsvc"										# Geolocation Service | Privacy
	"lmhosts"									# TCP/IP NetBIOS Helper (security)
	"LxpSvc"									# Language Experience Service
	"MapsBroker"								# Downloaded Maps Manager
	"MessagingService_*"						# MessagingService (Home/Pro users) | Privacy
	"MsKeyboardFilter"							# Microsoft Keyboard Filter (causes a lag better use other drivers)
	"NaturalAuthentication"						# Natural Authentication
	"NcaSvc"									# Network Connectivity Assistant (Telemetry)
	"NcbService"								# Network Connection Broker
	"NcdAutoSetup"								# Network Connected Devices Auto-Setup
	"Netlogon"									# Netlogon (domain controller environment only) | Security
	"NfsClnt"									# Client for NFS
	"OneSyncSvc_*"								# OneSync
	"PcaSvc"									# Program Compatibility Assistant Service
	"PeerDistSvc"								# Branch Cache (P2P / LAN Windows Updates)
	"PimIndexMaintenanceSvc_*"					# Contact Data
	"RetailDemo"								# Retail Demo | Privacy
	"SEMgrSvc"									# Payments and NFC/SE Manager
	"ShellHWDetection"							# Shell Hardware Detection
	"shpamsvc"									# Shared PC Account Manager
	"SmsRouter"									# Microsoft Windows SMS Router Service | Security
	"SSDPSRV"									# SSDP Discovery (Security)
	"stisvc"									# Windows Image Acquisition (WIA) | Performance
	"swprv"										# Microsoft Software Shadow Copy Provider (Backup) | Security
	"SysMain"									# Superfetch
	"TermService"								# Remote Desktop Services
	"TokenBroker"								# Web Account Manager
	"TrkWks"									# Distributed Link Tracking Client
	"UevAgentService"							# User Experience Virtualization Service
	"UI0Detect"									# Interactive Services Detection
	"UmRdpService"								# Remote Desktop Services UserMode Port Redirector
	"wbengine"									# Block Level Backup Engine Service (I use Macrium Reflect)
	"WdiServiceHost"							# Diagnostic Service Host
	"WdiSystemHost"								# Diagnostic System Host
	"wercplsupport"								# Problem Reports and Solutions Control Panel Support
	"WerSvc"									# Windows Error Reporting Service (Telemetry)
	"WinHttpAutoProxySvc"						# WinHTTP Web Proxy Auto-Discovery Service
	"wisvc"										# Windows Insider Service
	"WpcMonSvc"									# Parental Controls
	"XblAuthManager"							# Xbox Live Auth Manager
	"XblGameSave"								# Xbox Live Game Save  | Performance
	"xbox*"										# All other Xbox Services
	"XboxNetApiSvc"								# Xbox Live Networking Service
	"XboxNetApiSvc"								# Xbox Live Networking Service | Privacy
    "diagnosticshub.standardcollector.service" 	# Microsoft (R) Diagnostics Hub Standard Collector Service
    "DiagTrack"								    # Connected User Experiences and Telemetry (Diagnostics)  | Telemetry
    "dmwappushservice"							# WAP Push Message Routing Service (see known issues) | Telemetry
    "HomeGroupListener"							# HomeGroup Listener  | Telemetry (removed since 1903+)
    "HomeGroupProvider"							# HomeGroup Provider    | Telemetry
    "lfsvc"									    # Geolocation Service   | Telemetry
    "MapsBroker"								# Downloaded Maps Manager   | Privacy
    "ndu"									    # Windows Network Data Usage Monitor    | Privacy (data leakage?)
    "NetTcpPortSharing"							# Net.Tcp Port Sharing Service
    "RemoteAccess"								# Routing and Remote Access
    "RemoteRegistry"							# Remote Registry | Security
    #"SharedAccess"								# Internet Connection Sharing (ICS)
    "TrkWks"									# Distributed Link Tracking Client
    "WbioSrvc"									# Windows Biometric Service (required for Fingerprint reader / facial detection)
    "WMPNetworkSvc"								# Windows Media Player Network Sharing Service
    "wscsvc"									# Windows Security Center Service
    "wlidsvc"									# Disable ability to use Microsoft Accounts (Microsoft Account Sign-In Assistant)
    #"BFE"										# Base Filtering Engine - Disable only if you don't use Windows Firewall e.g. for Comodo
	#"Dnscache "								# DNS Client (only if you use other DNS systems like Unbound/DNSCrypt) | Security & Telemetry
	#"EventSystem"								# COM+ Event System (security but problematic)
	#"iphlpsvc"									# IP Helper (IPv6 translation)
	#"IpxlatCfgSvc"								# IP Translation Configuration Service
	#"Winmgmt"									# Windows Management Instrumentation | Security -> problematic
    #"AppMgmt"									# Application Management (needed for GPO software)
    #"wcncsvc"									# Cortana
    #"WlanSvc"									# WLAN AutoConfig | Security
    "WSearch"									# Windows Search used by e.g. Cortana & file index
)


foreach ($services in $services) {
    Write-Output "Disabling $services"
    Get-Service -Name $services | Set-Service -StartupType Disabled
}

##########################################################
###### 		Hyper-V (Sandbox/VT/VM/WD/etc.          ######
###### Don#t do it, it breaks security features!    ######
##########################################################
<#
# Disable all Hyper-V related tasks
Get-Service -DisplayName HvHost | Set-Service -StartupType Disabled
# Hyper-V Data Exchange Service
Get-Service -DisplayName vmickvpexchange | Set-Service -StartupType Disabled
#Hyper-V Guest Service Interface
Get-Service -DisplayName vmicguestinterface | Set-Service -StartupType Disabled
# Hyper-V Guest Shutdown Service
Get-Service -DisplayName vmicshutdown | Set-Service -StartupType Disabled
# Hyper-V Heartbeat Service
Get-Service -DisplayName vmicheartbeat | Set-Service -StartupType Disabled
# Hyper-V Host Compute Service
Get-Service -DisplayName vmcompute | Set-Service -StartupType Disabled
# Hyper-V PowerShell Direct Service
Get-Service -DisplayName vmicvmsession | Set-Service -StartupType Disabled
# Hyper-V Remote Desktop Virtualization Service
Get-Service -DisplayName vmicrdv | Set-Service -StartupType Disabled
# Hyper-V Time Synchronization Service
Get-Service -DisplayName vmictimesync | Set-Service -StartupType Disabled
# Hyper-V Virtual Machine Management
Get-Service -DisplayName vmms | Set-Service -StartupType Disabled
# Hyper-V Volume Shadow Copy Requestor
Get-Service -DisplayName vmicvss | Set-Service -StartupType Disabled
#>


##########################################################
###### 	Auto import all reg. files in same folder   ######
###### (FIXME:)                                      ######
##########################################################
# Get current dir
$oInvocation = (Get-Variable MyInvocation).Value
$sCurrentDirectory = Split-Path $oInvocation.MyCommand.Path

# Grab all .reg files and pipe it into a reg import command
Get-ChildItem $sCurrentDirectory -Filter "install.exe" -Recurse |
ForEach-Object {
 Start-Process -FilePath "C:\windows\system32\cmd.exe" -WindowStyle Minimized `
 -ArgumentList @('/C REG IMPORT "' + $_.FullName + '"') -Wait
}

##########################################################
###### 			Run this script as weekly task      ######
###### Ensure you put the script under `C:\Scripts\`######
# Todo: Copy script directtly to Windows folder and mark it as read-only?!
##########################################################
$Trigger= New-ScheduledTaskTrigger -At 11:30am –Weekly
$User= "NT AUTHORITY\SYSTEM"
# We don't need any W8 workaround here since we are on PS v6
$Action= New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "C:\Scripts\CK.ps1"
Register-ScheduledTask -TaskName "CKsWin10Hardening" -Trigger $Trigger -User $User -Action $Action -RunLevel Highest –Force


###############################################
######          Windows Backup           ######
###############################################
# Only allow system backups
# Windows Server 2008+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Backup\Server" -Name "OnlySystemBackup" -PropertyType DWord -Value 1 -Force
# Allow local attached storage as backup target
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Backup\Server" -Name "NoBackupToDisk" -PropertyType DWord -Value 0 -Force
# Disallow network as backup target
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Backup\Server" -Name "NoBackupToNetwork" -PropertyType DWord -Value 1 -Force
# Disallow optical media as backup
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Backup\Server" -Name "NoBackupToOptical" -PropertyType DWord -Value 1 -Force
# Disallow "RunOnce" Backups
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Backup\Server" -Name "NoRunNowBackup" -PropertyType DWord -Value 0 -Force

###############################################
######              OpenSSH              ######
###############################################
# FIXME:
# Offline?!
#Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
# Install the OpenSSH Server
#Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
# Uninstall the OpenSSH Client
#Remove-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
# Uninstall the OpenSSH Server
#Remove-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0




###############################################
######       Add or remove programs      ######
# FIXME: registry entries are useless since Windows 8
# use PS instead?!
###############################################
# Choose default the category
# Vista+
# FIXME: (string) Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Uninstall" -Name "DefaultCategory" -PropertyType DWord -Value 0 -Force
# Disallow to add programs from floppy or CD
# Pre Vista
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Uninstall" -Name "NoAddFromCDorFloppy" -PropertyType DWord -Value 1 -Force
# Disallow to add programs from Internet
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Uninstall" -Name "NoAddFromInternet" -PropertyType DWord -Value 1 -Force
# Disallow to add programs from Network
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Uninstall" -Name "NoAddFromNetwork" -PropertyType DWord -Value 1 -Force
# Hide "Add" Button
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Uninstall" -Name "NoAddPage" -PropertyType DWord -Value 1 -Force
# Hide "Add Remove Button"
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Uninstall" -Name "NoAddRemovePrograms" -PropertyType DWord -Value 1 -Force
# Hide "Choose programs" page
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Uninstall" -Name "NoChooseProgramsPage" -PropertyType DWord -Value 1 -Force
# Hide "Remove" page
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Uninstall" -Name "NoRemovePage" -PropertyType DWord -Value 1 -Force
# Hide "Service" page
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Uninstall" -Name "NoServices" -PropertyType DWord -Value 1 -Force
# Hide "Support Info" page
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Uninstall" -Name "NoSupportInfo" -PropertyType DWord -Value 1 -Force
# Hide "Windows setup" page
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Uninstall" -Name "NoWindowsSetupPage" -PropertyType DWord -Value 1 -Force

# Do not allow "Programs" in CPL
# Vista+
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Programs" -Name "NoProgramsCPL" -PropertyType DWord -Value 1 -Force
# Do not allow "Programs And Features" in CPL
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Programs" -Name "NoProgramsAndFeatures" -PropertyType DWord -Value 1 -Force
# Hide "Installed Updates" in CPL
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Programs" -Name "NoInstalledUpdates" -PropertyType DWord -Value 1 -Force
# Hide "Default programs" in CPL
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Programs" -Name "NoDefaultPrograms" -PropertyType DWord -Value 1 -Force
# Hide "Windows Marketplace" in CPL
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Programs" -Name "NoWindowsMarketplace" -PropertyType DWord -Value 1 -Force
# Hide "Get Programs" in CPL
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Programs" -Name "NoGetPrograms" -PropertyType DWord -Value 1 -Force




###############################################
######      Portable Operating System    ######
######             Windows 2-Go          ######
###############################################
# Turn off Windows 2-Go (master button)
# Windows 8+
# MS checks for "{BA649533-0AAC-4E04-B9BC-4DBAE0325B12}"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\PortableOperatingSystem" -Name "Launcher" -PropertyType DWord -Value 0 -Force
# Turn off W2GO Hibernate
# MS checks for "{C34B2751-1CF4-44F5-9262-C3FC39666591}"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\PortableOperatingSystem" -Name "Hibernate" -PropertyType DWord -Value 0 -Force
# Turn off W2GO Sleep
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\PortableOperatingSystem" -Name "Sleep" -PropertyType DWord -Value 0 -Force


###############################################
###### 		         Display             ######
###############################################
# FIXME: Turn on GDI DPI Scaling
# Windows 10 RS2+
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Display" -Name "EnableGdiDPIScaling" -PropertyType DWord -Value 0 -Force
# FIXME: Turn off GDI DPI Scaling
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Display" -Name "DisableGdiDPIScaling" -PropertyType DWord -Value 0 -Force
# Turn on Per-Process System Dpi Settings
# Windows 10 RS4+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "EnablePerProcessSystemDPI" -PropertyType DWord -Value 1 -Force




###############################################
###### 		        DWM                  ######
###############################################
# Turn off DWM animations
# Vista+
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DWM" -Name "DisallowAnimations" -PropertyType DWord -Value 1 -Force
#Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\DWM" -Name "DisallowAnimations" -PropertyType DWord -Value 1 -Force
# Turn off Flip3D
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DWM" -Name "DisallowFlip3d" -PropertyType DWord -Value 1 -Force
#Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\DWM" -Name "DisallowFlip3d" -PropertyType DWord -Value 1 -Force
# Turn off Accent and Gradient effect
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DWM" -Name "DefaultColorizationColorState" -PropertyType DWord -Value 0 -Force
#Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\DWM" -Name "DefaultColorizationColorState" -PropertyType DWord -Value 0 -Force
# Default DWM Colors
# 0 - 255
# DwmDefaultColorizationColorAlpha
# DwmDefaultColorizationColorRed
# DwmDefaultColorizationColorGreen
# DwmDefaultColorizationColorBlue
# Turn off color changes
# This is only useful if you pre define a color (see above) and lock/prevent someone tp change it.
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DWM" -Name "DisallowColorizationColorChanges" -PropertyType DWord -Value 1 -Force
#Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\DWM" -Name "DisallowColorizationColorChanges" -PropertyType DWord -Value 1 -Force





###############################################
###### 		    Logging/Auditing         ######
###############################################
# Turn on Perftrack (default enabled)
# Vista+
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" -Name "ScenarioExecutionEnabled" -PropertyType DWord -Value 1
# Turn off Scheduled Diagnostics (sdiagschd)
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScheduledDiagnostics" -Name "EnabledExecution" -PropertyType DWord -Value 0 -Force
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScheduledDiagnostics" -Name "EnabledExecutionLevel" -PropertyType DWord -Value 1 -Force
# Turn on Event forwarding
# Vista+
# FIXME: (string + useless option anyway)
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\EventForwarding" -Name "" -PropertyType DWord -Value 1 -Force
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\EventForwarding" -Name "MaxForwardingRate" -PropertyType DWord -Value 1 -Force


# Turn on Perftrack (default enabled)
# Vista+
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" -Name "ScenarioExecutionEnabled" -PropertyType DWord -Value 1
# Radar
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{3af8b24a-c441-4fa4-8c5c-bed591bfa867}" -Name "ScenarioExecutionEnabled" -PropertyType DWord -Value 1 -Force
# 1 = Level Ts only
# 2 = Level Resolution
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{3af8b24a-c441-4fa4-8c5c-bed591bfa867}" -Name "ScenarioExecutionEnabled" -PropertyType DWord -Value 1 -Force





# Turn on protected Event logging
# Windows 10+
# You can use the "EncryptionCertificate" value to specify your own certificate (if you want to)
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging" -Name "EnableProtectedEventLogging" -PropertyType DWord -Value 1 -Force


# Enable WMI reliability analysis
# Windows 7+
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Reliability Analysis\WMI" -Name "WMIEnable" -PropertyType DWord -Value 1
# Enable process auditing
# Windows 10+
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -PropertyType DWord -Value 1 -Force
# Audit the default logging policy via auditpol.exe
# (FIXME:)
# auditpol.exe /get /category:*
# auditpol.exe /get /subcategory:"MPSSVC rule-level Policy Change,Filtering Platform policy change,IPsec Main Mode,IPsec Quick Mode,IPsec Extended Mode,IPsec Driver,Other System Events,Filtering Platform Packet Drop,Filtering Platform Connection"
auditpol.exe /set /subcategory:"MPSSVC rule-level Policy Change,Filtering Platform policy change,IPsec Main Mode,IPsec Quick Mode,IPsec Extended Mode,IPsec Driver,Other System Events,Filtering Platform Packet Drop,Filtering Platform Connection" /success:Enable /failure:Enable
# Disable logging via:
# auditpol.exe /set /subcategory:"MPSSVC rule-level Policy Change,Filtering Platform policy change,IPsec Main Mode,IPsec Quick Mode,IPsec Extended Mode,IPsec Driver,Other System Events,Filtering Platform Packet Drop,Filtering Platform Connection" /success:Disable /failure:Disable
#
# IPSec audit logging
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\PolicyAgent\Oakley" -Name "EnableLogging" -PropertyType DWord -Value 1 -Force
# Remove the default Autologger file (created by DiagTrack) and restrict access, this will not work on ARM versions (FIXME:).
$autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
If (Test-Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl") {
    Remove-Item "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl"
}
icacls $autoLoggerDir /deny SYSTEM:`(OI`)`(CI`)F | Out-Null


# Deny Access to Diagnosis Folder
# FIXME:
#icacls "C:\ProgramData\Microsoft\Diagnosis" /remove:g system /inheritance:r /deny system:(OI)(CI)f


###############################################
###### 	    Windows Media Player (WMP)   ######
######              v11+                 ######
###############################################
# Turn off Frame Interpolation
# WMP 9+
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "DontUseFrameInterpolation" -PropertyType DWord -Value 1 -Force
# Turn off WMP "Setup first use configuration"
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "GroupPrivacyAcceptance" -PropertyType DWord -Value 1 -Force
# Turn off Quick Launch Shortcut creation
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "QuickLaunchShortcut" -PropertyType DWord -Value 0 -Force
# PreventWMP Desktop Shortcut creation
# WMP 9+
# FIXME:
# it's a string
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "DesktopShortcut" -PropertyType DWord -Value 0 -Force
# Turn off ScreenSaver
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "EnableScreenSaver" -PropertyType DWord -Value 0 -Force
# Prevent Codec Downloads
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventCodecDownload" -PropertyType DWord -Value 1 -Force
# Turn off WMP Anchor
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "DoNotShowAnchor" -PropertyType DWord -Value 1 -Force
# Do not hide "Privacy" Tab
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "HidePrivacyTab" -PropertyType DWord -Value 0 -Force
# Do not hide "Security" Tab
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "HideSecurityTab" -PropertyType DWord -Value 0 -Force
# Hide Network Tab
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "HideNetworkTab" -PropertyType DWord -Value 1 -Force
# Enable Skin Lockdown
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "SetAndLockSkin" -PropertyType DWord -Value 1 -Force
# Always use the default Skin
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "DefaultSkin" -PropertyType DWord -Value 1 -Force
# Default WMP Proxy Policy
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsMediaPlayer\Protocols\MMS" -Name "ProxyPolicy" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsMediaPlayer\Protocols\HTTP" -Name "ProxyPolicy" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsMediaPlayer\Protocols\RTSP" -Name "ProxyPolicy" -PropertyType DWord -Value 0 -Force
# FIXME: .. string ... New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsMediaPlayer\Protocols\HTTP" -Name "ProxyType" -PropertyType DWord -Value 0 -Force
# Turn off Auto proxy detection for HTTP
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsMediaPlayer\Protocols\HTTP" -Name "AutodetectProxy" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsMediaPlayer\Protocols\HTTP" -Name "BypassProxyLocal" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsMediaPlayer\Protocols\HTTP" -Name "ExludeFromProxy" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsMediaPlayer\Protocols\HTTP" -Name "UseBrowserProxy" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsMediaPlayer\Protocols\HTTP" -Name "UseProxy" -PropertyType DWord -Value 0 -Force
# Turn off Auto proxy detection for MMS
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsMediaPlayer\Protocols\MMS" -Name "AutodetectProxy" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsMediaPlayer\Protocols\MMS" -Name "BypassProxyLocal" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsMediaPlayer\Protocols\MMS" -Name "ExludeFromProxy" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsMediaPlayer\Protocols\MMS" -Name "UseBrowserProxy" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsMediaPlayer\Protocols\MMS" -Name "UseProxy" -PropertyType DWord -Value 0 -Force
# Turn off Auto proxy detection for RTSP
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsMediaPlayer\Protocols\RTSP" -Name "AutodetectProxy" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsMediaPlayer\Protocols\RTSP" -Name "BypassProxyLocal" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsMediaPlayer\Protocols\RTSP" -Name "ExludeFromProxy" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsMediaPlayer\Protocols\RTSP" -Name "UseBrowserProxy" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsMediaPlayer\Protocols\RTSP" -Name "UseProxy" -PropertyType DWord -Value 0 -Force



###############################################
###### 	    Windows Remote Managment     ######
###############################################
# WinRM + Turn off Remote Shell Access (WinRS)
# Vista+
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowBasic" -PropertyType Dword -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowDigest" -PropertyType Dword -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowUnencryptedTraffic" -PropertyType Dword -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowBasic" -PropertyType Dword -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowDigest" -PropertyType Dword -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowUnencryptedTraffic" -PropertyType Dword -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" -Name "AllowRemoteShellAccess" -PropertyType Dword -Value 0 -Force
# Disallow Kerberos
# Vista+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowKerberos" -PropertyType Dword -Value 0 -Force
# Disallow Negotiate
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowNegotiate" -PropertyType Dword -Value 0 -Force
# Allow Cred SSP
# Vista+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowCredSSP" -PropertyType Dword -Value 0 -Force
# Trusted Hosts
# Vista+
# Max length 1024
# FIXME: Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client" -Name "TrustedHosts" -PropertyType Dword -Value 1 -Force
# Allow Auto Config
# Vista+
# FIXME:
# Max length = 1024
# AllowAutoConfig_IPv4Filter (IPv4Filter) + AllowAutoConfig_IPv6Filter (IPv6Filter)
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowAutoConfig" -PropertyType Dword -Value 0 -Force
# Http Compatibility Listener
# Vista+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service" -Name "HttpCompatibilityListener" -PropertyType Dword -Value 0 -Force
# Https Compatibility Listener
# Vista+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service" -Name "HttpsCompatibilityListener" -PropertyType Dword -Value 1 -Force
# Disable "RunAs"
# Vista+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service" -Name "DisableRunAs" -PropertyType Dword -Value 0 -Force
# Allow Cred SSP
# Vista+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowCredSSP" -PropertyType Dword -Value 0 -Force
# Allow Cred SSP
# Vista+
# FIXME:
# None
# Relaxed
# Strict
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service" -Name "CBTHardeningLevelStatus" -PropertyType Dword -Value 0 -Force








########################################################################
######              Local Group Policy Editor changes             ######
######            Not all changes are in registry hives!          ######
#       (FIXME:)
######                   Policy file Editor                       ######
# https://www.powershellgallery.com/packages/PolicyFileEditor/2.0.2    #
########################################################################
# Disable all Online tips
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "AllowOnlineTips" -PropertyType DWord -Data 0 Start-Sleep 2
# Turn off Tailored Experiences
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -PropertyType DWord -Data 0
Start-Sleep 2
# Enable encrypted NTFS pagefile
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "System\CurrentControlSet\Policies" -Name "NtfsEncryptPagingFile" -PropertyType DWord -Data 1
Start-Sleep 2
# Disable (global) Telemetry (Enterprise/EDU)
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -PropertyType DWord -Data 0
Start-Sleep 2
# Turn off Windows Sidebar
# Windows 7 to Vista only
# Dunno why it's still in GPO, I guess there is a package you can install to re-enable Sidebar (official package .. no clue I only know about homebrew sidebar support)
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar" -Name "TurnOffSidebar" -PropertyType DWord -Data 1
Start-Sleep 2
# Do not allow usage of Camera
# Windows 10
#Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "software\Policies\Microsoft\Camera" -Name "AllowCamera" -PropertyType DWord -Data 0
#Start-Sleep 2
# Do not allow Active Help
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" -Name "NoActiveHelp" -PropertyType DWord -Data 1
Start-Sleep 2
# Turn off Biometrics
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Biometrics" -Name "Enabled" -PropertyType DWord -Data 1
Start-Sleep 2
# Turn off Remote Desktop (FIXME:)
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Conferencing" -Name "NoRDS" -PropertyType DWord -Data 1
Start-Sleep 2
# Turn off Input personalization
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -PropertyType DWord -Data 0
Start-Sleep 2
# Turn off usage of geo location in Internet Explorer
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Internet Explorer\Geolocation" -Name "PolicyDisableGeolocation" -PropertyType DWord -Data 1
Start-Sleep 2
# Turn off Internet Explorer Update check
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Internet Explorer\Infodelivery\Restrictions" -Name "NoUpdateCheck" -PropertyType DWord -Data 1
Start-Sleep 2
# Turn off Internet Explorer Do not Track (DnT) Feature
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "DoNotTrack" -PropertyType DWord -Data 0
Start-Sleep 2
# Turn off Internet Explorer "inPrivate Browsing" (similar to Incognito Mode or Private Browsing Mode)
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Internet Explorer\Privacy" -Name "EnableInPrivateBrowsing" -PropertyType DWord -Data 0
Start-Sleep 2
# Turn off SQM "Customer Improvement Program"
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Internet Explorer\SQM" -Name "DisableCustomerImprovementProgram" -PropertyType DWord -Data 0
Start-Sleep 2
# Turn off CEIP
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Messenger\Client" -Name "CEIP" -PropertyType DWord -Data 2
Start-Sleep 2
# Turn off AutoRun
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Messenger\Client" -Name "PreventAutoRun" -PropertyType DWord -Data 1
Start-Sleep 2
# Set Microsoft Edge default Cookie policy (disallow cookies)
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "Cookies" -PropertyType DWord -Data 2
Start-Sleep 2
# Turn off MS Edge Error Reporting Feature
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" -Name "DoReport" -PropertyType DWord -Data 0
Start-Sleep 2
# Turn off MS Edge Queue Mode for Error Reports
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" -Name "ForceQueueMode" -PropertyType DWord -Data 0
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" -Name "DWFileTreeRoot" -PropertyType String -Data ""
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" -Name "DWNoExternalURL" -PropertyType DWord -Data 1
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" -Name "DWNoFileCollection" -PropertyType DWord -Data 1
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" -Name "DWNoSecondLevelCollection" -PropertyType DWord -Data 1
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" -Name "DWReporteeName" -PropertyType String -Data ""
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\SearchCompanion" -Name "DisableContentFileUpdates" -PropertyType DWord -Data 1
Start-Sleep 2
# Turn off SQM CEIP (global)
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -PropertyType DWord -Data 0
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0080000000F0000F0D0B4EB5D3C24F17D10AE531C7DCEF4A94F4A085AD0D4C88B75082573E36F857A" -Name "Category" -PropertyType DWord -Data 1
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0080000000F0000F0D0B4EB5D3C24F17D10AE531C7DCEF4A94F4A085AD0D4C88B75082573E36F857A" -Name "CategoryReadOnly" -PropertyType DWord -Data 0
Start-Sleep 2
# Turn off Registration
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control" -Name "NoRegistration" -PropertyType DWord -Data 1
Start-Sleep 2
# Turn off KMS GenTicket (This will NOT break KMS nor Software Protection Platform)
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name "NoGenTicket" -PropertyType DWord -Data 1
Start-Sleep 2
# Turn off Entitlement reactivation
# Windows 10+
# FIXME: .. possible breakage
# Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name "NoGenTicket" -PropertyType DWord -Data 1
# Start-Sleep 2
# Prevent IIS installation
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows NT\IIS" -Name "PreventIISInstall" -PropertyType DWord -Data 1
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "PhysicalLocation" -PropertyType String -Data anonymous
Start-Sleep 2
# Turn off Consumer Experience
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -PropertyType DWord -Data 1
Start-Sleep 2
# Turn off Advertising ID
# EDU only!
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -PropertyType DWord -Data 1
Start-Sleep 2
# Turn off Application Impact Telemetry
# Windows 7+
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -PropertyType DWord -Data 0
Start-Sleep 2
# Turn off fallback for impact telemetry
# FIXME:
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "SbEnable" -PropertyType DWord -Data 0
Start-Sleep 2
# Turn off program inventory
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -PropertyType DWord -Data 1
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableUAR" -PropertyType DWord -Data 1
Start-Sleep 2
# Turn off getting device info from Web
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -PropertyType DWord -Data 1
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" -Name "DisableSendGenericDriverNotFoundToWER" -PropertyType DWord -Data 1
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" -Name "DisableSendRequestAdditionalSoftwareToWER" -PropertyType DWord -Data 1
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -PropertyType DWord -Data 1
Start-Sleep 2
# Turn off downloads of additional Game Infos
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\GameUX" -Name "DownloadGameInfo" -PropertyType DWord -Data 0
Start-Sleep 2
# Turn off the "Do you want to update your Game" notification
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\GameUX" -Name "GameUpdateOptions" -PropertyType DWord -Data 0
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\GameUX" -Name "ListRecentlyPlayed" -PropertyType DWord -Data 0
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard" -Name "ExitOnMSICW" -PropertyType DWord -Data 1
Start-Sleep 2
# Turn off Location Provider
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -PropertyType DWord -Data 1
Start-Sleep 2
# Turn off OneDrive Sync
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -PropertyType DWord -Data 1
Start-Sleep 2
# Silence OneDrive (FIXME: - GPO or reg?!)
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "Software\Microsoft\OneDrive" -Name "PreventNetworkTrafficPreUserSignIn" -PropertyType DWord -Data 1
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\PowerShell" -Name "EnableScripts" -PropertyType DWord -Data 1
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\PowerShell" -Name "ExecutionPolicy" -PropertyType String -Data "RemoteSigned"
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "**del.EnableExperimentation" -PropertyType String -Data ""
Start-Sleep 2
# Turn off preview Builds
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -PropertyType DWord -Data 0
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "EnableConfigFlighting" -PropertyType DWord -Data 0
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\System" -Name "AsyncScriptDelay" -PropertyType DWord -Data 1
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableLogonScriptDelay" -PropertyType DWord -Data 1
Start-Sleep 2
# Turn off Leak Diagnostic
# Vista+
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{186f47ef-626c-4670-800a-4a30756babad}" -Name "ScenarioExecutionEnabled" -PropertyType DWord -Data 0
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{2698178D-FDAD-40AE-9D3C-1371703ADC5B}" -Name "**del.EnabledScenarioExecutionLevel" -PropertyType String -Data ""
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{2698178D-FDAD-40AE-9D3C-1371703ADC5B}" -Name "ScenarioExecutionEnabled" -PropertyType DWord -Data 0
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{67144949-5132-4859-8036-a737b43825d8}" -Name "**del.EnabledScenarioExecutionLevel" -PropertyType String -Data ""
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{67144949-5132-4859-8036-a737b43825d8}" -Name "ScenarioExecutionEnabled" -PropertyType DWord -Data 0
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{86432a0b-3c7d-4ddf-a89c-172faa90485d}" -Name "ScenarioExecutionEnabled" -PropertyType DWord -Data 0
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" -Name "ScenarioExecutionEnabled" -PropertyType DWord -Data 0
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{a7a5847a-7511-4e4e-90b1-45ad2a002f51}" -Name "**del.EnabledScenarioExecutionLevel" -PropertyType String -Data ""
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{a7a5847a-7511-4e4e-90b1-45ad2a002f51}" -Name "ScenarioExecutionEnabled" -PropertyType DWord -Data 0
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{C295FBBA-FD47-46ac-8BEE-B1715EC634E5}" -Name "ScenarioExecutionEnabled" -PropertyType DWord -Data 0
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{dc42ff48-e40d-4a60-8675-e71f7e64aa9a}" -Name "EnabledScenarioExecutionLevel" -PropertyType DWord -Data 1
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{dc42ff48-e40d-4a60-8675-e71f7e64aa9a}" -Name "ScenarioExecutionEnabled" -PropertyType DWord -Data 0
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{ecfb03d1-58ee-4cc7-a1b5-9bc6febcb915}" -Name "ScenarioExecutionEnabled" -PropertyType DWord -Data 0
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{ffc42108-4920-4acf-a4fc-8abdcc68ada4}" -Name "**del.EnabledScenarioExecutionLevel" -PropertyType String -Data ""
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{ffc42108-4920-4acf-a4fc-8abdcc68ada4}" -Name "ScenarioExecutionEnabled" -PropertyType DWord -Data 0
Start-Sleep 2
# Turn off Windows Errror Reporting
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -PropertyType DWord -Data 1
Start-Sleep 2
# Do not send additional telemetry data
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "DontSendAdditionalData" -PropertyType DWord -Data 1
Start-Sleep 2
# Disable Cortana
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -PropertyType DWord -Data 0
Start-Sleep 2
# Do not allow the usage of "Location"
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchToUseLocation" -PropertyType DWord -Data 0
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchPrivacy" -PropertyType DWord -Data 3
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchSafeSearch" -PropertyType DWord -Data 3
Start-Sleep 2
# Disabled connected Web search
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWeb" -PropertyType DWord -Data 0
Start-Sleep 2
# Disable connected Web search behind metered connections
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWebOverMeteredConnections" -PropertyType DWord -Data 0
Start-Sleep 2
# Disable the use of Web search
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -PropertyType DWord -Data 1
Start-Sleep 2
# Defer Windows upgrades (feature updates) - You still can manually install them!
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferUpgrade" -PropertyType DWord -Data 1
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DoNotConnectToWindowsUpdateInternetLocations" -PropertyType DWord -Data 1
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "**del.AutomaticMaintenanceEnabled" -PropertyType String -Data ""
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "**del.DetectionFrequency" -PropertyType String -Data ""
Start-Sleep 2
# Prevent Auto reboots
# http://king.geek.nz/2016/10/18/wu-windows-1607/
# 2 = Notify before download
# 3 = Automatically download and notify of installation
# schtasks /change /tn \Microsoft\Windows\UpdateOrchestrator\Reboot /DISABLE
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -PropertyType DWord -Data 2
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "DetectionFrequencyEnabled" -PropertyType DWord -Data 0
Start-Sleep 2
# Enable offering "featured updates"
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "EnableFeaturedSoftware" -PropertyType DWord -Data 1
Start-Sleep 2
# Do not auto-update (disabled)
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -PropertyType DWord -Data 0
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay" -PropertyType DWord -Data 0
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallTime" -PropertyType DWord -Data 3
Start-Sleep 2
# Disable Windows DRM (master button)
# Windows NET+
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\WMDRM" -Name "DisableOnline" -PropertyType DWord -Data 1
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\User\registry.pol -Key "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoInstrumentation" -PropertyType DWord -Data 1
Start-Sleep 2
# Turn off Internet Explorer internal logging
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\User\registry.pol -Key "Software\Policies\Microsoft\Internet Explorer\Safety\PrivacIE" -Name "DisableLogging" -PropertyType DWord -Data 1
Start-Sleep 2
# Turn off Windows tips (global)
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\User\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -PropertyType DWord -Data 1
Start-Sleep 2
# Turn off Windows InkWorkspace
# Windows 10 RS1+
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\User\registry.pol -Key "Software\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowWindowsInkWorkspace" -PropertyType DWord -Data 0
Start-Sleep 2
# Turn off suggested apps in InkWorkspace
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\User\registry.pol -Key "Software\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowSuggestedAppsInWindowsInkWorkspace" -PropertyType DWord -Data 0
Start-Sleep 2
# Turn off GPO Server watchdog
# Windows Server only (2008+)
#Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\User\registry.pol -Key "Software\Policies\Microsoft\Windows\System" -Name "ProcessTSUserLogonAsync" -PropertyType DWord -Data 0
#Start-Sleep 2
# Turn off MFU Tracing
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\User\registry.pol -Key "Software\Policies\Microsoft\Windows\EdgeUI" -Name "DisableMFUTracking" -PropertyType DWord -Data 1
# Ensure new GPO rules are been immediantly applied
gpupdate /force




##########################################################
###### 	File Server Classification Infrastructure   ######
##########################################################
# Enable "manual" UX
# Windows 8+
# This function does not have a 0 function, what the hell?! (FIXME:)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\FCI" -Name "EnableManualUX" -PropertyType DWord -Value 1 -Force
# Central Classification List
# FIXME: Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\FCI" -Name "CentralClassificationList" -PropertyType DWord -Value 1 -Force
# Access denied configuration
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ADR\AccessDenied" -Name "Enabled" -PropertyType DWord -Value 0 -Force
# Error MSG
# Min = 15
# Max = 10240
<#

Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ADR\AccessDenied" -Name "ErrorMessage" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ADR\AccessDenied" -Name "EmailMessageText" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ADR\AccessDenied" -Name "AllowEmailRequestsCheck" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ADR\AccessDenied" -Name "PutDataOwnerOnToCheck" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ADR\AccessDenied" -Name "PutAdminOnToCheck" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ADR\AccessDenied" -Name "IncludeDeviceClaimsCheck" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ADR\AccessDenied" -Name "IncludeUserClaimsCheck" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ADR\AccessDenied" -Name "GenerateLogCheck" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ADR\AccessDenied" -Name "AdditonalEmailToText" -PropertyType DWord -Value 0 -Force

#>
# Enable Shell Access Check
# No 0 function!
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "EnableShellExecuteFileStreamCheck" -PropertyType DWord -Value 1 -Force



##########################################################
###### 	        Network Connectivity Assistant      ######
##########################################################
# Support Email
# Windows 7+
# Max length = 50
# FIXME: Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityAssistant" -Name "SupportEmail" -PropertyType DWord -Value 1 -Force
# Friendly Name
# Windows 7+
# Max length = 50
# FIXME: Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityAssistant" -Name "FriendlyName" -PropertyType DWord -Value 0 -Force
# Show UI
# Windows 7+
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityAssistant" -Name "ShowUI" -PropertyType DWord -Value 0 -Force
# Local Names On
# Windows 7+
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityAssistant" -Name "NamePreferenceAllowed" -PropertyType DWord -Value 0 -Force
# Passive Mode
# Windows 7+
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityAssistant" -Name "PassiveMode" -PropertyType DWord -Value 0 -Force
# Corporate Resources
# Windows 7+
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityAssistant" -Name "Probe" -PropertyType DWord -Value 0 -Force
# Corporate Resources
# Windows 7+
# FIXME: Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityAssistant\DTEs" -Name "DTE" -PropertyType DWord -Value 0 -Force
# Custom Commands
# Windows 7+
# FIXME: Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityAssistant\DTEs" -Name "CustomCommand" -PropertyType DWord -Value 0 -Force




##########################################################
###### 		            MSDT                        ######
##########################################################
# Wdi Scenario ExecutionPolicy
# Windows 7+
# FIXME: Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{C295FBBA-FD47-46ac-8BEE-B1715EC634E5}" -Name "ScenarioExecutionEnabled" -PropertyType DWord -Value 0 -Force
# FIXME: Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{C295FBBA-FD47-46ac-8BEE-B1715EC634E5}" -Name "EnabledScenarioExecutionLevel" -PropertyType DWord -Value 0 -Force
# FIXME: Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{C295FBBA-FD47-46ac-8BEE-B1715EC634E5}" -Name "ScenarioExecutionEnabled" -PropertyType DWord -Value 0 -Force
# Msdt Tool Download Policy
# Windows 7+
# 1 = Remote Only
# 2 = Allow All
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{C295FBBA-FD47-46ac-8BEE-B1715EC634E5}" -Name "DownloadToolsEnabled" -PropertyType DWord -Value 0 -Force
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{C295FBBA-FD47-46ac-8BEE-B1715EC634E5}" -Name "DownloadToolsLevel" -PropertyType DWord -Value 2 -Force
# Msdt Support Provider
# Windows 7+
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" -Name "DisableQueryRemoteServer" -PropertyType DWord -Value 0 -Force
# Troubleshooting Allow Recommendations
# Windows 10 RS6+
# 0 = Do Nothing
# 1 = Apply Core System Mitigations Only
# 2 = Ask First
# 3 = Apply Then Notify
# 4 = Apply Silently
# 5 = Defer To User
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Troubleshooting\AllowRecommendations" -Name "TroubleshootingAllowRecommendations" -PropertyType DWord -Value 5 -Force


##########################################################
###### 		        Attachment Manager              ######
##########################################################
# AM - Call Office AntiVirus
# Windows XP SP2+
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "ScanWithAntiVirus" -PropertyType DWord -Value 1 -Force
# AM - Estimate File Handler Risk
# Windows XP SP2+
# 1 = Disabled
# 2 = Handler Based
# 3 = Most Secure
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "UseTrustedHandlers" -PropertyType DWord -Value 3 -Force
# Do not preserve zone information in file attachments (avoid metadata leakage)
# https://getadmx.com/?Category=Windows_10_2016&Policy=Microsoft.Policies.AttachmentManager::AM_MarkZoneOnSavedAtttachments
# Windows XP SP2+
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -PropertyType DWord -Value 1 -Force
# AM - Remove Zone Info
# Windows XP SP2+
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "HideZoneInfoOnProperties" -PropertyType DWord -Value 1 -Force
# AM - Set File Risk Level
# Windows XP SP2+
# 6150 = HighRisk
# 6151 = ModRisk
# 6152 = LowRisk
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "DefaultFileTypeRisk" -PropertyType DWord -Value 1 -Force
# AM - Set High Risk Inclusion
# Windows XP SP2+
# FIXME: Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "HighRiskFileTypes" -PropertyType DWord -Value 1 -Force
# AM - Set Low Risk Inclusion
# Windows XP SP2+
# FIXME: Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "LowRiskFileTypes" -PropertyType DWord -Value 1 -Force
# AM - Set Mod Risk Inclusion
# Windows XP SP2+
# FIXME: Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "ModRiskFileTypes" -PropertyType DWord -Value 1 -Force



##########################################################
###### 		            Disk Quota                  ######
######    {3610eda5-77ef-11d2-8dc5-00c04fa31a66}    ######
##########################################################
# Turn off DQ
# Win2k+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DiskQuota" -Name "Enable" -PropertyType DWord -Value 0 -Force
# Enforce DQ
# Win2k+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DiskQuota" -Name "Enforce" -PropertyType DWord -Value 0 -Force
# Limit
# Win2k+
# Max = 1000
<#
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DiskQuota" -Name "UnitsKB" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DiskQuota" -Name "UnitsMB" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DiskQuota" -Name "UnitsGB" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DiskQuota" -Name "UnitsTB" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DiskQuota" -Name "UnitsPB" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DiskQuota" -Name "UnitsEB" -PropertyType DWord -Value 1 -Force
#>
# Threshold
# Win2k+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DiskQuota" -Name "Threshold" -PropertyType DWord -Value 1000 -Force
<#
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DiskQuota" -Name "UnitsMB" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DiskQuota" -Name "UnitsGB" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DiskQuota" -Name "UnitsTB" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DiskQuota" -Name "UnitsPB" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DiskQuota" -Name "UnitsEB" -PropertyType DWord -Value 1 -Force
#>
# Log Event Over Limit
# Win2k+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DiskQuota" -Name "LogEventOverLimit" -PropertyType DWord -Value 0 -Force
# Log Event Over Threshold
# Win2k+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DiskQuota" -Name "LogEventOverThreshold" -PropertyType DWord -Value 1 -Force
# Removable Media
# Win2k+
# FIXME: Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DiskQuota" -Name "ApplyToRemovableMedia" -PropertyType DWord -Value 1 -Force



##########################################################
###### 		            Reliability                 ######
##########################################################
# Turn on persistent time stamps
# All Windows
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Reliability" -Name "TimeStampEnabled" -PropertyType DWord -Value 1 -Force
# Timestamp interval
# Windows NET only
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\PCHealth\ErrorReporting" -Name "TimeStampEnabled" -PropertyType DWord -Value 1 -Force
# Turn off shutdown tracker
# Windows NET only
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Reliability" -Name "SnapShot" -PropertyType DWord -Value 0 -Force
# Turn on Shutdown reason
# XP+
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Reliability" -Name "ShutdownReasonOn" -PropertyType DWord -Value 1 -Force
# Turn on shutodnw reason (UI)
# 1 = Always
# 2 = Workstation only
# 3 = Server only
# # FIXME: Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Reliability" -Name "ShutdownReasonUI" -PropertyType DWord -Value 1 -Force


##########################################################
###### 		    Device Installation Restrictions    ######
##########################################################
# Allow installation of devices that match any of these device instance IDs
# FIXME: Set-ItemProperty -Path "HKLM:\System\Device Installation\Device Installation Restrictions" -Name "x000D_" -PropertyType DWord -Value 0 -Force
# Prevent installation of devices that match any of these device instance IDs
# FIXME: Set-ItemProperty -Path "HKLM:\System\Device Installation\Device Installation Restrictions" -Name "x000D_" -PropertyType DWord -Value 0 -Force



##########################################################
###### 		            Disk Diagnostics            ######
##########################################################
# Default Execution Policy
# Windows Vista+
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{29689E29-2CE9-4751-B4FC-8EFF5066E3FD}" -Name "ScenarioExecutionEnabled" -PropertyType DWord -Value 0 -Force
# Default Alert Policy
# always true
# Max length 512 chars
# (FIXME:)
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{29689E29-2CE9-4751-B4FC-8EFF5066E3FD}" -Name "DfdAlertTextOverride" -PropertyType DWord -Value 0 -Force

##########################################################
###### 		           Windows Messenger            ######
##########################################################
# Turn off Windows Messenger (master button)
# XP+
# Turn off MS Messenger (not needed since 1603+)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client" -Name "CEIP" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Messenger\Client" -Name "CEIP" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client" -Name "PreventRun" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Messenger\Client" -Name "PreventRun" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client" -Name "PreventAutoRun" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Messenger\Client" -Name "PreventAutoRun" -PropertyType DWord -Value 1


##########################################################
###### 		            NCSI                        ######
######             Connectivity Check               ######
#  This does not break internet access but the status    #
#  icon is not functional                                #
##########################################################
# FIXME:
# We need a URL/DNS which is reliable (100% uptime) + does not collect stats.

# Specifiy your webURL for online checks
# Windows 7+
# FIXME: Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator\CorporateConnectivity" -Name "WebProbeUrl" -PropertyType DWord -Value 1
# DNS probe host
# FIXME: Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator\CorporateConnectivity" -Name "DnsProbeHost" -PropertyType DWord -Value 1
# DNS probe content
# FIXME: Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator\CorporateConnectivity" -Name "DnsProbeContent" -PropertyType DWord -Value 1
# DNS probe content
# FIXME: Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator\CorporateConnectivity" -Name "DomainLocationDeterminationUrl" -PropertyType DWord -Value 1
# FIXME: Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator\CorporateConnectivity" -Name "DisablePassivePolling" -PropertyType DWord -Value 1
# Global DNS
# Windows 10 RS3+
# Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator\CorporateConnectivity" -Name "UseGlobalDns" -PropertyType DWord -Value 1



##########################################################
######  				  App HVSI		            ######
##########################################################
# Allow App HVSI Config
# Windows 10 (NOSERVER)
# Education only ?!
# FIXME: I need to test EDU
# 0 = Disabled
# 1 = Container to Host
# 2 = Host To Container
# 3 = Both Directions
# New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AllowAppHVSI_ProviderSet" -PropertyType DWord -Value 3 -Force
# Allow AllowVirtualGPU
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AllowVirtualGPU" -PropertyType DWord -Value 1 -Force
# Allowed File Type
# 1 =
# 2 =
# 3 =
# FIXME: Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AppHVSIClipboardFileType" -PropertyType DWord -Value 3 -Force
# Certificate Thumbprints
# Windows 10 (NOSERVER)
# Education only ?!
# Max length = 16383
# FIXME: Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "CertificateThumbprints" -PropertyType DWord -Value 1 -Force
# Printing settings
# Windows 10 (NOSERVER)
# Education only ?!
# Min = 0
# Max = 15
# FIXME: Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AppHVSIPrintingSettings" -PropertyType DWord -Value 1 -Force
# Block Non Enterprise Content
# Windows 10 (NOSERVER)
# Education only ?!
# FIXME: Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "BlockNonEnterpriseContent" -PropertyType DWord -Value 1 -Force
# Allow Camera Microphone Redirection
# Windows 10 (NOSERVER)
# Education only ?!
# FIXME: Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AllowCameraMicrophoneRedirection" -PropertyType DWord -Value 0 -Force
# Allow Persistence
# Windows 10 (NOSERVER)
# Education only ?!
# FIXME: Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AllowPersistence" -PropertyType DWord -Value 0 -Force
# Audit Application Guard Config
# Windows 10 (NOSERVER)
# Education only ?!
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AuditApplicationGuard" -PropertyType DWord -Value 1 -Force
# Save file to host
# Windows 10 (NOSERVER)
# Education only ?!
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "SaveFilesToHost" -PropertyType DWord -Value 1 -Force
# File Trust Criteria
# Windows 10 (NOSERVER)
# Education only ?!
# Min = 0
# Max = 2
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "FileTrustCriteria" -PropertyType DWord -Value 1 -Force
# File Trust Origin - Removable Media
# New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "FileTrustOriginRemovableMedia" -PropertyType DWord -Value 0 -Force
# File Trust Origin - Network Shares
# New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "FileTrustOriginNetworkShare" -PropertyType DWord -Value 0 -Force
# File Trust Origin - MOTW
# New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "FileTrustOriginMarkOfTheWeb" -PropertyType DWord -Value 0 -Force

##########################################################
######  				CleanMGR defaults  	        ######
###### FIXME: 20H1 disabled "Downloads" cleaning by default
######              2 = Clean | 0 = Nope            ######
##########################################################
# Turn off CleanMgr task
#Disable-ScheduledTask -TaskName "\Microsoft\Windows\ApplicationData\DsSvcCleanup" | Out-Null
#
# FIXME: Check "Flags" in 20H1
# Clean temp folders
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Active Setup Temp Folders" -Name "StateFlags0333" -PropertyType DWord -Value 2 -Force
# Clean Branch Cache
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\BranchCache" -Name "StateFlags0333" -PropertyType DWord -Value 2 -Force
# Index
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Content Indexer Cleaner" -Name "StateFlags0333" -PropertyType DWord -Value 2 -Force
# Delivery Optimization Files
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Delivery Optimization Files" -Name "StateFlags0333" -PropertyType DWord -Value 2 -Force
# Diagnostic Data Viewer database files
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Diagnostic Data Viewer database files" -Name "StateFlags0333" -PropertyType DWord -Value 2 -Force
# Old Driver packages
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Device Driver Packages" -Name "StateFlags0333" -PropertyType DWord -Value 2 -Force
# Downloads
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Downloaded Program Files" -Name "StateFlags0333" -PropertyType DWord -Value 0 -Force
# Downloads Folder
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\DownloadsFolder" -Name "StateFlags0333" -PropertyType DWord -Value 0 -Force
# Game News, Update and static files
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\GameNewsFiles" -Name "StateFlags0333" -PropertyType DWord -Value 2 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\GameStatisticsFiles" -Name "StateFlags0333" -PropertyType DWord -Value 2 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\GameUpdateFiles" -Name "StateFlags0333" -PropertyType DWord -Value 2 -Force
# Internet Cache Files
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Internet Cache Files" -Name "StateFlags0333" -PropertyType DWord -Value 2 -Force
# Memory dumps
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Memory Dump Files" -Name "StateFlags0333" -PropertyType DWord -Value 2 -Force
# Offline files
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Offline Pages Files" -Name "StateFlags0333" -PropertyType DWord -Value 2 -Force
# ChkDsk leftover files
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Old ChkDsk Files" -Name "StateFlags0333" -PropertyType DWord -Value 2 -Force
# Windows 10 Previous Installations
# This will be cleaned after 60 - 90 days (once the task was executed)
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Previous Installations" -Name "StateFlags0333" -PropertyType DWord -Value 2 -Force
# Recycle Bin
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Recycle Bin" -Name "StateFlags0333" -PropertyType DWord -Value 2 -Force
# RetailDemo files
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\RetailDemo Offline Content" -Name "StateFlags0333" -PropertyType DWord -Value 2 -Force
# Service Pack Cleanup
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Service Pack Cleanup" -Name "StateFlags0333" -PropertyType DWord -Value 2 -Force
# Setup Log Files
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Setup Log Files" -Name "StateFlags0333" -PropertyType DWord -Value 2 -Force
# System error memory dump files
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\System error memory dump files" -Name "StateFlags0333" -PropertyType DWord -Value 2 -Force
# System error minidump files
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\System error minidump files" -Name "StateFlags0333" -PropertyType DWord -Value 2 -Force
# TEMP files
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Files" -Name "StateFlags0333" -PropertyType DWord -Value 2 -Force
# Temporary Setup Files
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Setup Files" -Name "StateFlags0333" -PropertyType DWord -Value 2 -Force
# Temporary Sync Files
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Sync Files" -Name "StateFlags0333" -PropertyType DWord -Value 2 -Force
# Thumbnail Cache
# FIXME: Check if server or not
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" -Name "StateFlags0333" -PropertyType DWord -Value 2 -Force
# Update cleanup
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Update Cleanup" -Name "StateFlags0333" -PropertyType DWord -Value 2 -Force
# Upgrade Discarded Files
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Upgrade Discarded Files" -Name "StateFlags0333" -PropertyType DWord -Value 2 -Force
# User file versions
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\User file versions" -Name "StateFlags0333" -PropertyType DWord -Value 2 -Force
# Windows Defender log files and old updates
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Defender" -Name "StateFlags0333" -PropertyType DWord -Value 2 -Force
# Windows Error Reporting Archive Files
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Error Reporting Archive Files" -Name "StateFlags0333" -PropertyType DWord -Value 2 -Force
# Windows Error Reporting Queue Files
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Error Reporting Queue Files" -Name "StateFlags0333" -PropertyType DWord -Value 2 -Force
# Windows Error Reporting System Archive Files
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Error Reporting System Archive Files" -Name "StateFlags0333" -PropertyType DWord -Value 2 -Force
# Windows Error Reporting System Queue Files
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Error Reporting System Queue Files" -Name "StateFlags0333" -PropertyType DWord -Value 2 -Force
# Windows Error Reporting Temp Files
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Error Reporting Temp Files" -Name "StateFlags0333" -PropertyType DWord -Value 2 -Force
# Windows ESD installation files
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows ESD installation files" -Name "StateFlags0333" -PropertyType DWord -Value 2 -Force
# Windows Upgrade Log Files
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Upgrade Log Files" -Name "StateFlags0333" -PropertyType DWord -Value 2 -Force


##########################################################
######  				Device Installs   	        ######
##########################################################
# All Signing Equal
# Vista+
# New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Settings" -Name "AllSigningEqual" -PropertyType DWord -Value 1 -Force
# Install Timeout
# Vista+
# Min = 240
# Max = 4294968
# New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Settings" -Name "InstallTimeout" -PropertyType DWord -Value 1294968 -Force
# Disable System Restore
# Vista+
# Min = 240
# Max = 4294968
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Settings" -Name "DisableSystemRestore" -PropertyType DWord -Value 1 -Force
# Disallow RPCInterface
# Vista+
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Settings" -Name "AllowRemoteRPC" -PropertyType DWord -Value 0 -Force
# Allow Admin Install
# Vista+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "AllowAdminInstall" -PropertyType DWord -Value 0 -Force
# Allow Device Classes
# Vista+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "AllowDeviceClasses" -PropertyType DWord -Value 0 -Force
# Deny Classes
# Vista+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceClasses" -PropertyType DWord -Value 0 -Force
# Deny Classes List
# Vista+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses" -Name "DenyDeviceClassesRetroactive" -PropertyType DWord -Value 0 -Force
# IDs Allow List
# Vista+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions\AllowDeviceIDs" -Name "DenyDeviceIDs" -PropertyType DWord -Value 0 -Force
# Deny List
# Vista+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions\AllowDeviceIDs" -Name "DenyDeviceIDsRetroactive" -PropertyType DWord -Value 0 -Force
# Removable Deny
# Vista+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions\AllowDeviceIDs" -Name "DenyRemovableDevices" -PropertyType DWord -Value 0 -Force
# Removable Deny
# Vista+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyUnspecified" -PropertyType DWord -Value 0 -Force
# Reboot Time
# Vista+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "ForceReboot" -PropertyType DWord -Value 0 -Force
# Reboot Time
# Vista+
# Min = 0
# Max = 4294968
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "ForceReboot" -PropertyType DWord -Value 0 -Force
# Simple Text
# Vista+
# Min = 0
# Max length = 63
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DeniedPolicy" -Name "SimpleText" -PropertyType DWord -Value 0 -Force
# Detail Text
# Vista+
# Min = 0
# Max length = 128
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DeniedPolicy" -Name "DetailText" -PropertyType DWord -Value 0 -Force
# Classes - Allow User
# Vista+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DeniedPolicy" -Name "AllowUserDeviceClasses" -PropertyType DWord -Value 1 -Force
# DriverSigning
# Vista+
# 0 = None
# 1 = Warn
# 2 = Block
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows NT\Driver Signing" -Name "BehaviorOnFailedVerify" -PropertyType DWord -Value 2 -Force


##########################################################
######  				Driver Policy	            ######
##########################################################
# Prevent Driver Changes
# FIXME:
#New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceIDs" -PropertyType DWord -Value 1 -Force
#New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceIDsRetroactive" -PropertyType DWord -Value 0 -Force
#New-ItemProperty -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs" -Name "DenyDeviceIDs" -PropertyType REGZ "PCI\VEN_XXXX&DEV_XXXX&SUBSYS_XXXXXXXX&REV_XX" -Force



##########################################################
######  				    TPM   			        ######
##########################################################
<#
# OS Managed Auth
# Windws 8+
# 4 = TpmAuthFull
# 2 = TpmAuthAdminPlusUser
# 0 = TpmAuthNone
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\TPM" -Name "OSManagedAuthLevel" -PropertyType DWord -Value 2 -Force
# Blocked CommandsList
# Windws Vista+
# 4 = TpmAuthFull
# 2 = TpmAuthAdminPlusUser
# 0 = TpmAuthNone
FIXME: Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Tpm\BlockedCommands" -Name "Enabled" -PropertyType DWord -Value 1 -Force
# Ignore Default List
# Windws Vista+
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Tpm\BlockedCommands" -Name "IgnoreDefaultList" -PropertyType DWord -Value 0 -Force
# Ignore Local List
# Windws Vista+
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Tpm\BlockedCommands" -Name "IgnoreLocalList" -PropertyType DWord -Value 0 -Force
# Standard User Authorization Failure Duration
# Windws 8+ (FIXME:)
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Tpm" -Name "StandardUserAuthorizationFailureDuration" -PropertyType DWord -Value 1000 -Force
# Standard User Authorization Failure Individual Threshold
# Windws 8+
# Max = 100
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Tpm" -Name "StandardUserAuthorizationFailureIndividualThreshold" -PropertyType DWord -Value 80 -Force
# Standard User Authorization Failure Total Threshold
# Windws 8+
# Max = 100
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Tpm" -Name "StandardUserAuthorizationFailureTotalThreshold" -PropertyType DWord -Value 80 -Force
# Use Legacy DAP
# Windws 10 RS2+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Tpm" -Name "UseLegacyDictionaryAttackParameters" -PropertyType DWord -Value 0 -Force
# Opt Into DSHA
# Windws 10 RS3+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Tpm" -Name "EnableDeviceHealthAttestationService" -PropertyType DWord -Value 1 -Force
#Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\DeviceHealthAttestationService" -Name "EnableDeviceHealthAttestationService" -PropertyType DWord -Value 1 -Force
# Clear TPM If Not Ready
# Windws 10 RS3+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Tpm" -Name "ClearTPMIfNotReadyGP" -PropertyType DWord -Value 1 -Force

#>


##########################################################
###### 		                WCM                     ######
##########################################################
# Block non domain
# Windws 8+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "fBlockNonDomain" -PropertyType DWord -Value 0
# Block roaming
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "fBlockRoaming" -PropertyType DWord -Value 1
# Minimize Connections
# 1 = Minimize simultaneous connections
# 2 = Always connected to cellular
# 3 = Prevent Wifi on ethernet
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "fMinimizeConnections" -PropertyType DWord -Value 1
# Disable internal power Management
# Windows 8+
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "fDisablePowerManagement" -PropertyType DWord -Value 1
# Enable soft disconnect if no network is in use
# Windows 10 RS3+
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "fSoftDisconnectConnections" -PropertyType DWord -Value 1



##########################################################
###### 		                RPC                     ######
##########################################################
# Enable Auth Ep Resolution
# Windows XP SP2+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc" -Name "EnableAuthEpResolution" -PropertyType DWord -Value 1 -Force
# Enable Extended Error Information
# Windows XP SP2+
# 0 = EE Info off
# 1 = EE Info on with Exc
# 2 = EE Info off with Exc
# 3 = Rpc EE Info On
# FIXME: Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc" -Name "ExtErrorInformation" -PropertyType DWord -Value 1 -Force
# Rpc Ignore Delegation Failure
# Windows NET+
# FIXME: Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc" -Name "IgnoreDelegationFailure" -PropertyType DWord -Value 1 -Force
# Rpc Minimum Http Connection Timeout
# Windows XP SP1+
# Max 90
# Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc" -Name "MinimumConnectionTimeout" -PropertyType DWord -Value 1 -Force
# Restrict Remote Clients
# Windows XP SP2+
# 0 = Restrict Remote Clients - None
# 1 = Restrict Remote Clients - Auth (default)
# 2 = Rpc Restrict Remote Clients - High
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc" -Name "RestrictRemoteClients" -PropertyType DWord -Value 2 -Force


##########################################################
###### 		    Link Layer Topology Discovery       ######
###### FIXME: leak + server check?!
##########################################################
<#

# Enable LLTDIO
# Vista+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\LLTD" -Name "EnableLLTDIO" -PropertyType DWord -Value 1 -Force
# Disallow LLTDIO on Domain
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\LLTD" -Name "AllowLLTDIOOnDomain" -PropertyType DWord -Value 0 -Force
# Allow LLTDIO on Public Net
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\LLTD" -Name "AllowLLTDIOOnPublicNet" -PropertyType DWord -Value 1 -Force
# Disallow LLTDIO on prohibit Private Net
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\LLTD" -Name "ProhibitLLTDIOOnPrivateNet" -PropertyType DWord -Value 0 -Force

#>


##########################################################
###### 		        Maintenance Scheduler           ######
##########################################################
# Turn off Maintenance Scheduler
# Windows 8+
# FIXME: Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Task Scheduler\Maintenance" -Name "Activation Boundary" -PropertyType DWord -Value 1
# Eandomize scheduler tasks
# Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Task Scheduler\Maintenance" -Name "Randomized" -PropertyType DWord -Value 1
# Set random delay
# Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Task Scheduler\Maintenance" -Name "Random Delay" -PropertyType DWord -Value 1



##########################################################
###### 		        Windows Connect Now             ######
######                      SFC                     ######
##########################################################
# Turn off Windows Connect Now GUI
# Vista+
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\UI" -Name "DisableWcnUi" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\WCN\UI" -Name "DisableWcnUi" -PropertyType DWord -Value 1 -Force
# Turn off Registrar Help
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\UI" -Name "DisableUPnPRegistrar" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\UI" -Name "DisableInBand802DOT11Registrar" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\UI" -Name "DisableFlashConfigRegistrar" -PropertyType DWord -Value 1 -Force
# Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\UI" -Name "DisableWPDRegistrar" -PropertyType DWord -Value 1 -Force
# Max = 65535
# Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\UI" -Name "MaxWCNDeviceNumber" -PropertyType DWord -Value 65535 -Force
# Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\UI" -Name "HigherPrecedenceRegistrar" -PropertyType DWord -Value 1 -Force
# Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\UI" -Name "HigherPrecedenceRegistrar" -PropertyType DWord -Value 1 -Force
# FIXME: Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\UI" -Name "HigherPrecedenceRegistrar" -PropertyType DWord -Value 1 -Force


##########################################################
###### 		        Automatic Driver Updates        ######
##########################################################
# Turn off driver offers via WUS
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -PropertyType DWord -Value 1
# Turn off device metadata retrieval from Internet
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -PropertyType DWord -Value 1


##########################################################
###### 		    Windows File Protection (WFP)       ######
######                      SFC                     ######
##########################################################
# Known DllList
# FIXME: it's a string Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Windows File Protection" -Name "KnownDllList" -PropertyType DWord -Value "nlhtml.dll" -Force
# Do not scan at boot
# Windows pre Vista
# Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Windows File Protection" -Name "SfcScan" -PropertyType DWord -Value 0
# WFPQuota
# Windows pre Vista
# Max = 4294967295
# Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Windows File Protection" -Name "SfcQuota" -PropertyType DWord -Value 4294967295
# WFPQuota_Size in decimal ^^
# WFPDll Cache Dir
# Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Windows File Protection" -Name "SFCDllCacheDir" -PropertyType DWord -Value "WFPDllCacheDirBox" (FIXME:)
# Show SFC progress
# Windows pre Vista
# Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Windows File Protection" -Name "SfcShowProgress" -PropertyType DWord -Value 1

##########################################################
###### 		        Default Passport Policy         ######
##########################################################
# Use Passport for Work
# Windows 10 (NOSERVER)
# We do not use any MS account
# FIXME: Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -Name "MSPassportForWorkCategory" -PropertyType DWord -Value 0 -Force
# Turn off Post logon Provisioning
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -Name "DisablePostLogonProvisioning" -PropertyType DWord -Value 1
# Require hardware policy
# Windows 10 RS2+ (NOSERVER)
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -Name "RequireSecurityDevice" -PropertyType DWord -Value 1
# Exclude TPM 1.2 Data devices
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\ExcludeSecurityDevices" -Name "TPM12" -PropertyType DWord -Value 1
# Biometrics as passwords
# NOSERVER
# We do not want any biometrics.
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\Credential Provider" -Name "Domain Accounts" -PropertyType DWord -Value 0
# Disable PIN Recovery
# (NOSERVER)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -Name "EnablePinRecovery" -PropertyType DWord -Value 0
# PIN complexity Policy
# (NOSERVER)
# FIXME: it's a string
# Min = 4
# Max = 127
# I suggest min 6 chars do not mix "Pass" with "PIN" (6 or 8 is considerable "enough")
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity" -Name "MinimumPINLength" -PropertyType DWord -Value 6
# Max PIN lenght
# (NOSERVER)
# Min = 4
# Max = 127
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity" -Name "MaximumPINLength" -PropertyType DWord -Value 127
# Enforce use of uppercase letter
# (NOSERVER)
# Valid values are 1 or 2 (2 is default which is disabled)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity" -Name "UppercaseLetters" -PropertyType DWord -Value 1
# Enforce use of lowercase letter
# (NOSERVER)
# Valid values are 1 or 2 (2 is default which is disabled)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity" -Name "LowercaseLetters" -PropertyType DWord -Value 1
# Enforce use of special characters
# (NOSERVER)
# Valid values are 1 or 2 (2 is default which is disabled)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity" -Name "SpecialCharacters" -PropertyType DWord -Value 1
# Enforce use of Digits
# (NOSERVER)
# Valid values are 1 or 2 (2 is default which is disabled)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity" -Name "Digits" -PropertyType DWord -Value 1
# Turn off PIN history
# (NOSERVER)
# Min = 0
# Mac = 50
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity" -Name "History" -PropertyType DWord -Value 0 -Force
# Password Expiration Policy
# (NOSERVER)
# Min = 0
# Mac = 7
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity" -Name "Expiration" -PropertyType DWord -Value 0 -Force
# Use Certificate for on prem. auth Policy
# (NOSERVER)
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -Name "UseCertificateForOnPremAuth" -PropertyType DWord -Value 1 -Force
# Default Device Unlock Policy
# (NOSERVER)
# FIXME: Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\DeviceUnlock" -Name "GroupA -PropertyType DWord -Value 1 -Force
# FIXME: Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\DeviceUnlock" -Name "GroupB" -PropertyType DWord -Value 1 -Force
# FIXME: Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\DeviceUnlock" -Name "Plugins" -PropertyType DWord -Value 1 -Force
# Dynamic lock policy
# (NOSERVER)
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\DynamicLock" -Name "DynamicLock" -PropertyType DWord -Value 1 -Force
# Turn off Dynamic Lock Plugins
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\DynamicLock" -Name "Plugins" -PropertyType DWord -Value 0 -Force
# Smart card emulation policy
# (NOSERVER)
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -Name "DisableSmartCardNode" -PropertyType DWord -Value 0 -Force
# Allow Smart Card user access
# (NOSERVER)
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -Name "AllowAllUserAccessToSmartCardNode" -PropertyType DWord -Value 1 -Force
# Certificate propagation policy
# (NOSERVER)
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -Name "UseHelloCertificatesAsSmartCardCertificates" -PropertyType DWord -Value 0 -Force


##########################################################
###### 		            LockScreen                  ######
##########################################################
# Turn on Lock Screen
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -PropertyType DWord -Value 0
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -ErrorAction SilentlyContinue
# Turn off Lock Screen Image
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "LockScreenOverlaysDisabled" -PropertyType DWord -Value 1
# Set your own Lock Screen image - Static Lock Screen
# (FIXME:)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "LockScreenImage" -PropertyType DWord -Value "C:\windows\web\screen\lockscreen.jpg"
# Do not allow to change the LockScreen
# Windows 8+
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization" -Name "NoChangingLockScreen" -PropertyType DWord -Value 1 -Force
# No Lock Screen Slideshow
# Windows 10+
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenSlideshow" -PropertyType DWord -Value 1 -Force
# Turn on "Prevent enabling lock screen camera"
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera" -PropertyType DWord -Value 1 -Force
# Personalize Background Colors
# Windows 10+
# FIXME:
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "PersonalColors_Background" -PropertyType DWord -Value 1 -Force
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "PersonalColors_Accent" -PropertyType DWord -Value 1 -Force
# Start Background Spin
# Windows 10+
# Max = 20
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "ForceStartBackground" -PropertyType DWord -Value 10 -Force
# Prevent changing Background
# Windows 8+
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization" -Name "NoChangingStartMenuBackground" -PropertyType DWord -Value 10 -Force
# Specifiy the default LockScreen Image
# Windows 8+
# FIXME: New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization" -Name "LockScreenImage" -PropertyType DWord -Value 10 -Force
# FIXME: New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization" -Name "LockScreenOverlaysDisabled" -PropertyType DWord -Value 10 -Force



##########################################################
###### 		                MMC                     ######
##########################################################
# Restrict MMC Author
# Win 2k+
<#
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\MMC" -Name "RestrictAuthorMode" -PropertyType DWord -Value 1
# Restrict permitted SnapIn
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\MMC" -Name "RestrictToPermittedSnapins" -PropertyType DWord -Value 1
# Restrict MMC extend View
# XP+
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\MMC" -Name "Restrict_Run" -PropertyType DWord -Value 1
#>
# Turn off MMC Active X Control
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\MMC\{C96401CF-0E17-11D3-885B-00C04F72C717}" -Name "Restrict_Run" -PropertyType DWord -Value 1 -Force
# Disallow MMC link to web content
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\MMC\{C96401D1-0E17-11D3-885B-00C04F72C717}" -Name "Restrict_Run" -PropertyType DWord -Value 1 -Force



##########################################################
###### 		         Network Isolation              ######
######    Just another term for "proxy managment"   ######
##########################################################
# Use Domain proxies
# Windows 8+
# FIXME: ... string
# Max length: 16383
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkIsolation" -Name "DomainProxies" -PropertyType DWord -Value 1 -Force
# Intranet Proxies
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkIsolation" -Name "DomainLocalProxies" -PropertyType DWord -Value 1 -Force
# Private Network Subnets
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkIsolation" -Name "DomainSubnets" -PropertyType DWord -Value 1 -Force
# Auth proxies
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkIsolation" -Name "DProxiesAuthoritive" -PropertyType DWord -Value 1 -Force
# Auth proxies Dsub
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkIsolation" -Name "DSubnetsAuthoritive" -PropertyType DWord -Value 1 -Force
# Enterprise resource domains hosted in the cloud
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkIsolation" -Name "CloudResources" -PropertyType DWord -Value 1 -Force
# Neutral Resources
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkIsolation" -Name "NeutralResources" -PropertyType DWord -Value 1 -Force


##########################################################
###### 		        ActiveX Install Service         ######
# FIXME:
# Entries + hide option does not exist unless you use
# IE and opt-in
##########################################################
# Approve Active X installs Sites
# Vista+
<#
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AxInstaller" -Name "ApprovedList" -PropertyType DWord -Value 1 -Force
# Trusted OCX
# 0 = Disabled
# 1 = Trusted Zone Prompt
# 2 = 1+ Silent Install
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AxInstaller\AxISURLZonePolicies" -Name "InstallTrustedOCX" -PropertyType DWord -Value 1 -Force
# UnSigned OCX
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AxInstaller\AxISURLZonePolicies" -Name "InstallUnSignedOCX" -PropertyType DWord -Value 0 -Force
# Ignore unknown CA
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AxInstaller\AxISURLZonePolicies" -Name "IgnoreUnknownCA" -PropertyType DWord -Value 1 -Force
# Ignore Invalid CN
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AxInstaller\AxISURLZonePolicies" -Name "IgnoreInvalidCN" -PropertyType DWord -Value 0 -Force
# Ignore Invalid Cert Date
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AxInstaller\AxISURLZonePolicies" -Name "IgnoreInvalidCertDate" -PropertyType DWord -Value 0 -Force
# Ignore wrong cert warnings
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AxInstaller\AxISURLZonePolicies" -Name "IgnoreWrongCertUsage" -PropertyType DWord -Value 0 -Force
#>


##########################################################
###### 		            MMC Snap-ins                ######
##########################################################
# Personally I don't understand why you want to restrict SnapIn's,
# of course an attacker can change some toggles. BUT this requres phyiscal or remote access & UAC.

<#

# Allow snap-ins to be run which is a critical thing on servers
# Windows Server 2008+
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\MMC\{9FE24B92-C23D-451c-8045-73038D99E620}" -Name "MMC_StarterGPOEditorSnapIn" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\MMC\{C11D2F3B-E2F4-4e5b-824B-84A87AB0F666}" -Name "Restrict_Run" -PropertyType DWord -Value 1
# Turn off Storage Manager for SANS SnapIn
# Win Server 2003 R2+
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\MMC\FX:{317cdc35-c09e-486f-ab09-90dd2e3fdd7d}" -Name "Restrict_Run" -PropertyType DWord -Value 1
# Turn off Storage Manager for SANS Snap-in Extensions
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\MMC\FX:{317cdc37-c09e-486f-ab09-90dd2e3fdd7d}" -Name "Restrict_Run" -PropertyType DWord -Value 1
# Turn off MMC shared and Storage Management SnapIn
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\MMC\FX:{813C1B01-6624-4922-9C6C-03C315646584}" -Name "Restrict_Run" -PropertyType DWord -Value 1
# Turn off MMC shared and Storage Management SnapIn Extensions
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\MMC\FX:{f9f63d92-6225-410b-bb02-26239b8f1f59}" -Name "Restrict_Run" -PropertyType DWord -Value 1
# Turn off MMC DFSS SnapIn
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\MMC\FX:{671ee405-c969-4af9-ad1b-65e96b3b9a10}" -Name "Restrict_Run" -PropertyType DWord -Value 1
# Turn off MMC DFSS SnapIn Extensions
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\MMC\FX:{f78fbadd-c21a-4e0a-b53d-c879a9c8f002}" -Name "Restrict_Run" -PropertyType DWord -Value 1
# Turn off MMC File Server Resource Manager SnapIn
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\MMC\FX:{f8abd46c-1297-4474-9cdf-831ebb245f49}" -Name "Restrict_Run" -PropertyType DWord -Value 1
# Turn off MMC File Server Resource Manager SnapIn Extensions
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\MMC\FX:{f8abd46e-1297-4474-9cdf-831ebb245f49}" -Name "Restrict_Run" -PropertyType DWord -Value 1

#>


##########################################################
###### 		          Server Manager                ######
##########################################################
# Turn on Server Manager auto refresh rate
# Windows Server 2008+
<#

Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Server\ServerManager" -Name "RefreshIntervalEnabled" -PropertyType DWord -Value 1
# Default refresh interval
# Windows Server 2008 or 2008 R2 Only
# Min = 1
# Max = 34560
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Server\ServerManager" -Name "RefreshInterval" -PropertyType "3000" -Value 1

#>
# Turn off "Manage Your Server Page"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\MYS" -Name "DisableShowAtLogon" -PropertyType DWord -Value 1



###############################################################################
#                   OPTIONAL STUFF a.k.a. my own fetish                       #
# Section will be renamed, removed and added as own script                    #
###############################################################################

##########################################################
###### 		        Compress OS & NTFS              ######
#    DO NOT USE IT, it's better to compress Wimlib/ESD   #
# (FIXME:) Compression negatively influcens security?!    #
##########################################################
# Compact.exe /F /CompactOS:always
# $tempfolders = @(“C:\Windows\Temp\*”, “C:\Windows\Prefetch\*”, “C:\Documents and Settings\*\Local Settings\temp\*”, “C:\Users\*\Appdata\Local\Temp\*”)
# NTFS comprssion can cause security problems.
# Remove-Item $tempfolders -force -recurse
# Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "System\CurrentControlSet\Policies" -Name NtfsDisableCompression -PropertyType DWord -Data 0


##########################################################
#    Optional usability tweaks and changed defaults      #
#       Needs to be enabled (uncomment) manually         #
##########################################################
# Enable Windows 10 F8 boot menu options #
# bcdedit /set `{current`} bootmenupolicy Legacy | Out-Null
# Workaround for DPI scaling issue with displays set to 125%
# FIXME: -> Resets after reboot (explorer.exe restart) and shell crash
#New-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\Control Panel\Desktop" -Name "DpiScalingVer" -Value "0x00001018" -PropertyType DWORD -Force
#New-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\Control Panel\Desktop" -Name "Win8DpiScaling" -Value "0x00000001" -PropertyType DWORD -Force
#New-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\Control Panel\Desktop" -Name "LogPixels" -Value "0x00000078" -PropertyType DWORD -Force
# Show Computer shortcut on Desktop
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -PropertyType DWord -Value 0
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -PropertyType DWord -Value 0
# Add Desktop icon on Desktop
#New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}"
# Disable Superfetch
#Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnableSuperfetch" -PropertyType DWord -Value 0 -Force
# Disable Windows Prefetcher
#Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnablePrefetcher" -PropertyType DWord -Value 0 -Force
# Disable CLoud Notification - Does not exists in DSMA SKUs, session 0 will not exist and this key should be restricted to user session
#Set-ItemProperty "HKLM:\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoCloudApplicationNotification" -PropertyType DWord -Value 1 -Force
#Set-ItemProperty "HKCU:\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoCloudApplicationNotification" -PropertyType DWord -Value 1 -Force
# Disable Disk Health Update Model
# Windows 10 RS3+
Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\StorageHealth" -Name "AllowDiskHealthModelUpdates" -PropertyType DWord -Value 0 -Force
#Set-ItemProperty "HKCU:\Software\Policies\Microsoft\Windows\StorageHealth" -Name "AllowDiskHealthModelUpdates" -PropertyType DWord -Value 0 -Force
# Disable app Toast Notifications
#Set-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoToastApplicationNotificationOnLockScreen" -PropertyType DWord -Value 0 -Force
# Turn off Workplace (does not work on ARM)
#Set-ItemProperty "HKCU:\Software\Policies\Microsoft\Windows\WorkplaceJoin" -Name "autoWorkplaceJoin" -PropertyType DWord -Value 0 -Force
# Turn off Work Folders
#Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\WorkFolders" -Name "AutoProvision" -PropertyType DWord -Value 0 -Force
#Set-ItemProperty "HKCU:\Software\Policies\Microsoft\Windows\WorkFolders" -Name "AutoProvision" -PropertyType DWord -Value 0 -Force
# Turn off Mobility Center
# Vista+
#Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\MobilityCenter" -Name "NoMobilityCenter" -PropertyType DWord -Value 1 -Force



##########################################################
#                   Optional removal                     #
#       Needs to be enabled (uncomment) manually         #
##########################################################
# Remove "Computer" shortcut from Desktop
#Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
#Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
# Remove "Desktop" icon from computer
#Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" -Recurse -ErrorAction SilentlyContinue
# Remove "Documents" icon from computer namespace
#Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" -Recurse -ErrorAction SilentlyContinue
#Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" -Recurse -ErrorAction SilentlyContinue
# Remove "Downloads" icon from computer namespace
#Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" -Recurse -ErrorAction SilentlyContinue
#Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}" -Recurse -ErrorAction
# Remove "Music" icon from computer namespace
#Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -Recurse -ErrorAction SilentlyContinue
#Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -Recurse -ErrorAction SilentlyContinue
# Remove "Pictures" icon from computer namespace
#Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -Recurse -ErrorAction SilentlyContinue
#Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -Recurse -ErrorAction SilentlyContinue
# Remove Videos icon from computer namespace
#Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -Recurse -ErrorAction SilentlyContinue
#Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -Recurse -ErrorAction SilentlyContinue


##########################################################
###### 	 Grab OpenVPN/WireGuard file automatically  ######
######		    Example (for the lazy ones)         ######
##########################################################
# Add VPN Interface (PIA example)
# https://docs.microsoft.com/en-us/powershell/module/nettcpip/get-netroute?view=win10-ps
# https://msdn.microsoft.com/en-us/library/hh872448(v=vs.85).aspx
# https://superuser.com/questions/966832/windows-10-dns-resolution-via-vpn-connection-not-working/966833#966833
#Add-VpnConnection -Name PIA -ServerAddress swiss.privateinternetaccess.com
#Set-VpnConnection -Name "PIA" -DnsSuffix swiss.privateinternetaccess.com
#Set-VpnConnection -Name "PIA" -SplitTunneling $True
#New-Item -ItemType Directory -Force -Path "~\OpenVPN\config"
#Invoke-WebRequest "https://insert-your-link-here.ovpn" -OutFile "~\OpenVPN\config\US East, Ashburn.ovpn"


##########################################################
###### 				    Mouse                       ######
##########################################################
# Turn on enhanced mouse pointer precision
#Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -PropertyType String -Value 1
#Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -PropertyType String -Value 6
#Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -PropertyType String -Value 10


##########################################################
###### 				    Control panel               ######
##########################################################
# Disable CPLS
# Win 2k+
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "DisallowCpl" -PropertyType Dword -Value 1
# Force Classic Control Panel
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ForceClassicControlPanel" -PropertyType Dword -Value 1 -Force
# Disallow use of CPL
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoControlPanel" -PropertyType Dword -Value 0 -Force
# Restrict CPLS
# FIXME: Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "RestrictCpl" -PropertyType Dword -Value 0 -Force
# Settings Page Visibility
# Windows RS2+
# FIXME: Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "SettingsPageVisibility" -PropertyType Dword -Value 0 -Force




##########################################################
###### 				    PATH                        ######
##########################################################
# Android Platform Tools
#SETX /M path "%path%;C:\Program Files\platform-tools"



##########################################################
###### 	    Unpin default shortcuts from Taskbar    ######
##########################################################
# FIXME:
$appname = "Microsoft Edge"
((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() | Where-Object{$_.Name -eq $appname}).Verbs() | Where-Object{$_.Name.replace('&','') -match 'Unpin from taskbar'} | ForEach-Object{$_.DoIt(); $exec = $true}
$appname = "Store"
((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() | Where-Object{$_.Name -eq $appname}).Verbs() | Where-Object{$_.Name.replace('&','') -match 'Unpin from taskbar'} | ForEach-Object{$_.DoIt(); $exec = $true}




# Restore original path if modified
if ($origPath.Length -gt 0)
{
    $env:Path = $origPath
}
# Restore original output encoding
$OutputEncoding = $OutputEncodingPrevious

# Restore original directory location
Pop-Location

#####################################################
###### 				    Restart warning             #
# (FIXME:) Restart or crash explorer.exe             #
# (FIXME:) Do not restart if VM/GPO wasn't touched   #
#####################################################
# Re-load Registry
#RUNDLL32.EXE USER32.DLL,UpdatePerUserSystemParameters ,1 ,True
# Restart warning
Write-Host "Yo kid, listen up push a button to restart your system..." -ForegroundColor Black -BackgroundColor White
$key = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
Write-Host "Restarting..."
Restart-Computer
# FIXME: Crash explorer and avoid every restart BS cause restarting is so 1999.


