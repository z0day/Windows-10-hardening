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
        Version  : 0.3 (public version) ALPHA

#>


<#
       .SYNOPSIS
                        - Windows 10 hardening by CHEF-KOCH -

       .DESCRIPTION
        This PowerShell script aims to harden & tweak Windows 10 LTSC (EntS) & Ent.
        All tweaks are explained and there will be no "undo" script or option, a
        backup will automatically stored to C:\.
                                ========== DO NOT README ==========
            -> The tweaks are the ones which I (still) use (under Windows 10 EntS./Ent.)
            -> Script integration into an ISO image is possible, however I do
                not use it because I usually apply the fixes after a fresh installation and
                some tweaks can only be applied after the OS got installed.
            -> This script is a public version, I do not upload my privte one, because I
                often change my mind and tweak/adjust or change several things based on
                my current needs.
            -> I do not support chinese systems, sorry - still love ya folks! However,
                it should work since we enforce UTF-8 w/o BOM with line ending CRLF.
            -> This script has NO OS/PS checks, using it on other SKUs is own your own!
            -> This script IS INSECURE, because it needs higher OS level rights and it
                will change/uninstall a lot - Again, a BACKUP is highly recommened!
            -> This script is not a "unfuck", "debloat", removal- all-in-one-, or setup script.
            -> This script is not optimized nor tested against Server based SKUs.
			-> This script follows MS PowerShell coding standards & practices, see here:
				https://docs.microsoft.com/en-us/powershell/scripting/?view=powershell-6
            -> "Optimized" for PowerShell 6 or PowerShell Core.
            -> The script is avbl. as Chocolatey package (but not yet uploaded).
            -> There are some quirks, some settings are been uninstalled but still been
                set up, this is on purpose because you can easily comment them out in
				caase you like to keep product/function X.
			-> Script provided as-is, without warranty of any kind and used at your own risk.
                                ========== DO NOT README ==========

       .LINK
           https://github.com/CHEF-KOCH/Windows-10-hardening/blob/master/PowerShell/CK.ps1
#>


# We need admin rights, ask for elevated permissions first.
$ErrorActionPreference= 'silentlycontinue'

If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

# Remove all text from the current PowerShell session (in case there is some)
Clear-Host
# Сlear $Error variable in PowerShell
$Error.Clear()
# Enforce UTF-8 without BOM as console output.
$OutputEncoding = [System.Console]::OutputEncoding = [System.Console]::InputEncoding = [System.Text.Encoding]::UTF8
#
# Missing Variables
# IPSec default pre-shared key
$ThePreSharedKey = 'Myown-insecure0815-testpassword-replace-it-with-your-own'
# (fixme) New-Variables <here>
#
#
# Aditional workaround for gaining root in registry
# Todo: Check existent keys.
#


##########################################################
###### 		        BACKUP (Registry)               ######
######  Backup:     HKLM, HKCU and HKCR             ######
###### Also check and delete existent backups       ######
##########################################################
# First remove existing backups
Remove-Item $env:systemroot\hklm.reg | Out-Null
Remove-Item $env:systemroot\hkcu.reg | Out-Null
Remove-Item $env:systemroot\hkcr.reg | Out-Null
# Backup our current Registry Hive
reg export HKLM $env:systemroot\hklm.reg | Out-Null
reg export HKCU $env:systemroot\hkcu.reg | Out-Null
reg export HKCR $env:systemroot\hkcr.reg | Out-Null
##########################################################################################
######      	Telemetry & Feedback, Ads & Fingerprinting Migration				######
# Overview: https://docs.microsoft.com/en-us/windows/privacy/manage-windows-1809-endpoints
# German "audit" 						https://files.catbox.moe/ugqngv.pdf     (I call BS)
# Windows Editions Diff:                https://en.wikipedia.org/wiki/Windows_10_editions
##########################################################################################
# Disable MSDT
Set-ItemProperty-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" -ValueName "DisableQueryRemoteServer" -PropertyType DWord -Value 1 -Force
# Do not allow the real device name in Telemetry
Set-ItemProperty-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -ValueName "AllowDeviceNameInTelemetry" -PropertyType DWord -Value 0 -Force
# No Cross Device Experience
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "EnableCdp" -PropertyType DWord -Value 0 -Force
# Turn off telemetry for Service Provider Foundation
# https://docs.microsoft.com/en-us/powershell/module/spfadmin/set-scspftelemetry?view=systemcenter-ps-2019
#Set-SCSPFTelemetry -Enabled $False -ErrorAction SilentlyContinue
# Sharepoint Telemetry
# https://docs.microsoft.com/en-us/powershell/module/sharepoint-pnp/disable-pnppowershelltelemetry?view=sharepoint-ps
#Disable-PnPPowerShellTelemetry -Force
# Prevent non-administrators from using Safe Mode
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "SafeModeBlockNonAdmins" -PropertyType DWord -Value 1 -Force
# Turn off Turn Help Experience Improvement Program
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" -ValueName "NoImplicitFeedback" -PropertyType DWord -Value 0 -Force
# Turn off App based Customer Experience Improvement Program (CEIP)
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\AppV\CEIP" -ValueName "CEIPEnable" -PropertyType DWord -Value 0 -Force
# Turn off WMP Telemetry (metadata)
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -ValueName "PreventCDDVDMetadataRetrieval" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -ValueName "PreventMusicFileMetadataRetrieval" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -ValueName "PreventRadioPresetsRetrieval" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -ValueName "DisableOnline" -PropertyType DWord -Value 1 -Force
# Turn off Data Collection (not needed >= 1603+)
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -ValueName "AllowTelemetry" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -ValueName "AITEnable" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -ValueName "AllowTelemetry" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -ValueName "LimitEnhancedDiagnosticDataWindowsAnalytics" -PropertyType DWord -Value 1 -Force
# Turn off KMS Client Online AVS Validation (Telemetry)
# This will NOT break KMS activation!
# https://getadmx.com/?Category=Windows_10_2016&Policy=Microsoft.Policies.SoftwareProtectionPlatform::NoAcquireGT
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\SOFTWARE Protection Platform" -ValueName "NoGenTicket" -PropertyType DWord -Value 0
# Turn off "Shared Experiences"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" -ValueName "RomeSdkChannelUserAuthzPolicy" -PropertyType DWord -Value 0
# Turn off automatic connecting to open Wi-Fi networks
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -ValueName "AutoConnectAllowedOEM" -PropertyType DWord -Value 0 -Force
# Turn off Microsoft consumer experiences (current user)
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -ValueName "DisableTailoredExperiencesWithDiagnosticData" -PropertyType DWord -Value 1
# Turn off additional data requests from Microsoft in response to a windows error reporting event
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -ValueName "Disabled" -PropertyType DWord -Value 1
# Turn off "Location information" usage & Sensors
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\PolicyManager\default\System\AllowLocation" -ValueName "value" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -ValueName "DisableLocation" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -ValueName "DisableLocationScripting" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -ValueName "DisableLocation" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -ValueName "DisableLocationScripting" -PropertyType DWord -Value 1 -Force
# Turn off "Show me the Windows welcome experience after updates and occasionally when I sign in to highlight what’s new and suggested"
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -ValueName "SubscribedContent-310093Enabled" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -ValueName "SubscribedContent-338387Enabled" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -ValueName "SubscribedContent-338393Enabled" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -ValueName "SubscribedContent-353698Enabled" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -ValueName "SystemPaneSuggestionsEnabled" -PropertyType DWord -Value 0 -Force
# Turn off "File Explorer ads" (Home/Pro users only!)
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ValueName "ShowSyncProviderNotifications" -PropertyType DWord -Value 0
# Turn off handwriting personalization data sharing
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -ValueName "PreventHandwritingDataSharing" -PropertyType DWord -Value 1 -Force
# Turn off Windows Customer Experience Improvement Program
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -ValueName "CEIPEnable" -PropertyType DWord -Value 0 -Force
# Turn off location tracking for this device
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -ValueName "Value" -PropertyType String -Value "Deny"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -ValueName "SensorPermissionState" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -ValueName "Status" -PropertyType DWord -Value 0
# Turn off "Connected User Experiences and Telemetry" service (DiagTrack)
Get-Service -ValueName DiagTrack | Stop-Service -Force
Get-Service -ValueName DiagTrack | Set-Service -StartupType Disabled
# Migrate some attack scenarios (fixme)
Get-Service -ValueName mrxsmb10 | Stop-Service -Force
Get-Service -ValueName mrxsmb10 | Set-Service -StartupType Disabled
# Turn off the Autologger session at the next computer restart
Update-AutologgerConfig -ValueName AutoLogger-Diagtrack-Listener -Start 0
# Turn off the SQMLogger session at the next computer restart
Update-AutologgerConfig -ValueName SQMLogger -Start 0
# Set the operating system diagnostic data level to "Security" (Ent./Edu. + LTSB/LTSC only)
# 0 = Security: Security data only (CIS L1)
# 1 = Basic: Security + basic system and quality data
# 2 = Enhanced: Basic + enhanced insights and advanced reliability data
# 3 = Full: Enhanced + full diagnostics data
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -ValueName "AllowTelemetry" -PropertyType DWord -Value 0
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -ValueName "AllowTelemetry" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -ValueName "DoNotShowFeedbackNotifications" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -ValueName "MaxTelemetryAllowed" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -ValueName "AllowTelemetry" -PropertyType DWord -Value 0
# Turn off Windows Error Reporting
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -ValueName "Disabled" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -ValueName "DoReport" -PropertyType DWord -Value 0 -Force
# Change Windows Feedback frequency to "Never"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -ValueName "NumberOfSIUFInPeriod" -PropertyType DWord -Value 0
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -ValueName "PeriodInNanoSeconds"
# Turn off tailored experiences with diagnostic data
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -ValueName "TailoredExperiencesWithDiagnosticDataEnabled" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -ValueName "PrivacyConsentPresentationVersion" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -ValueName "PrivacyConsentSettingsVersion" -PropertyType DWord -Value 2 -Force
# Turn off Find my device
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Settings\FindMyDevice" -ValueName "LocationSyncEnabled" -PropertyType DWord -Value 0 -Force
##########################################################
######   				Explorer.exe				######
###### \Software\Microsoft\Windows\CurrentVersion\Explorer
##########################################################
# Disable Auto Suggestion in Explorer (fixme not a dword)
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete" -ValueName "AutoSuggest" -PropertyType DWord -Value "no" -Force
# Turn off Certificate Updates (DO NOT disable it)
#New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot" -ValueName "DisableRootAutoUpdate" -PropertyType DWord -Value 1 -Force
# Turn off Explorer Telemetry
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -ValueName "TelemetrySalt" -PropertyType DWord -Value 3 -Force
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -ValueName "TelemetrySalt" -PropertyType DWord -Value 3 -Force
# Turn off connections to Web Services
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoWebServices" -PropertyType DWord -Value 1 -Force
# Turn off Jump Lists
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ValueName "EnableXamlJumpView" -PropertyType DWord -Value 1 -Force
# Turn off Xaml
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ValueName "EnableXamlStartMenu" -PropertyType DWord -Value 0
# Turn off Experimental Login Screen
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\TestHooks" -ValueName "Threshold" -PropertyType DWord -Value 1 -Force
# Turn off and hide "People Bar" in Explorer (<=1603+)
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -ValueName "HidePeopleBar" -PropertyType DWord -Value 1
# Hide "Remove Hardware and Eject Media" Button until next reboot
# https://superuser.com/questions/12955/how-can-i-remove-the-option-to-eject-sata-drives-from-the-windows-7-tray-icon
Set-ItemProperty -Path "KCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\SysTray called Services" -ValueName "Services " -PropertyType DWord -Value 29
# Turn off Thumbs.db thumbnail cache files only on network folders
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ValueName "DisableThumbsDBOnNetworkFolders" -PropertyType DWord -Value 1
# Turn on thumbnails
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ValueName "IconsOnly" -PropertyType DWord -Value 0
# Turn off thumbnail cache files
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ValueName "DisableThumbnailCache" -PropertyType DWord -Value 1
# Turn off restoring previous folder windows at logon
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ValueName "PersistBrowsers" -ErrorAction SilentlyContinue
# Turn on "Enable navigation pane expanding to current folder"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ValueName "NavPaneExpandToCurrentFolder" -PropertyType DWord -Value 1
# Turn on Classic Control Panel Icons (small)
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -ValueName "StartupPage" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -ValueName "AllItemsIconView" -PropertyType DWord -Value 1
# Turn off 'How do you want to open this file?' prompt
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -ValueName "NoNewAppAlert" -PropertyType DWord -Value 1
# Turn off NumLock (usually the keyboard driver/SOFTWARE controls it)
Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -ValueName "InitialKeyboardIndicators" -PropertyType DWord -Value 2147483648
#New-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -ValueName InitialKeyboardIndicators -PropertyType DWord -Value 2 -Force
#New-ItemProperty -Path "HKCU:\.DEFAULT\Control Panel" -ValueName "InitialKeyboardIndicators" -PropertyType DWord -Value 2 -Force
# Launch folder in a separate process
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ValueName "SeparateProcess" -PropertyType DWord -Value 1
# Show accent color on the title bars and window borders
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\DWM" -ValueName "ColorPrevalence" -PropertyType DWord -Value 1
# Turn off "F1 Help"
New-ItemProperty -Path "HKCU:\SOFTWARE\Classes\Typelib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -ValueName "(default)" -PropertyType String -Value "" -Force
# Turn off Sticky keys prompt (after pressing 5x ALT) (if not working try 506) (fixme)
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -ValueName "Flags" -PropertyType String -Value "510"
# Turn off Sharing Wizard
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ValueName "SharingWizardOn" -PropertyType DWord -Value 0
# Turn off JPEG desktop wallpaper import quality compression
New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -ValueName "JPEGImportQuality" -PropertyType DWord -Value 100 -Force
# Turn on "Ribbon" in File Explorer
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Ribbon" -ValueName "MinimizedStateTabletModeOff" -PropertyType DWord -Value 0 -Force
# Turn on Show Control shortcut on Desktop
New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -ValueName "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -PropertyType DWord -Value 0
# Turn off User Folder shortcut from Desktop
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -ValueName "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -ValueName "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -ErrorAction SilentlyContinue
# Turn off 3D Objects icon from This PC
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue
New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -ValueName "ThisPCPolicy" -PropertyType String -Value "Hide"
# Turn off Documents icon from This PC
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" -Recurse -ErrorAction SilentlyContinue
# Turn on Win32 long paths
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -ValueName "LongPathsEnabled" -PropertyType DWord -Value 1 -Force
# Turn off "The Windows Filtering Platform has blocked a connection" message
auditpol /set /subcategory:"{0CCE9226-69AE-11D9-BED3-505054503030}" /success:disable /failure:disable
# Set File Explorer to open to "This PC" by default
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ValueName "LaunchTo" -PropertyType DWord -Value 1 -Force
# Show Hidden Files, Folders and Drives
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ValueName "Hidden" -PropertyType DWord -Value 1 -Force
# Show Known File Extensions
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\HideFileExt" -ValueName "CheckedValue" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ValueName "HideFileExt" -PropertyType DWord -Value 0 -Force
# Hide Task View button on taskbar
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ValueName "ShowTaskViewButton" -PropertyType DWord -Value 0 -Force
# Show folder merge conflicts
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ValueName "HideMergeConflicts" -PropertyType DWord -Value 0 -Force
# Turn off "Snap Assist"
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ValueName "SnapAssist" -PropertyType DWord -Value 0 -Force
# Turn off check boxes to select items
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ValueName "AutoCheckSelect" -PropertyType DWord -Value 0 -Force
# Turn off app launch tracking to improve Start menu and search results
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ValueName "Start_TrackProgs" -PropertyType DWord -Value 0 -Force
# Turn off "This PC" on Desktop
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -ValueName "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -ValueName "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -ErrorAction SilentlyContinue
# Show "more details" by default in file transfer dialog
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -ValueName "EnthusiastMode" -PropertyType DWord -Value 1 -Force
# Turn off AutoPlay for all media and devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoDriveTypeAutoRun" -PropertyType DWord -Value 255
#Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -ValueName "DisableAutoplay" -PropertyType DWord -Value 1
# Turn off the "- Shortcut" name extension for new shortcuts
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -ValueName "link" -PropertyType Binary -Value ([byte[]](0,0,0,0))
# Turn off shortcut icon arrow
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" -ValueName "29" -PropertyType String -Value "%SystemRoot%\System32\imageres.dll,-1015"
#Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" -ValueName "29" -ErrorAction SilentlyContinue
# Remove the "Previous Versions" (ShadoCopy) tab from properties context menu
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -ValueName "NoPreviousVersionsPage" -PropertyType DWord -Value 1 -Force
# Turn off tip, trick, and suggestions as you use Windows
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -ValueName "SubscribedContent-338389Enabled" -PropertyType DWord -Value 0 -Force
# Delete temporary files that apps aren't using
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -ValueName "04" -PropertyType DWord -Value 1 -Force
# Delete files in recycle bin if they have been there for over 7 days
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -ValueName "256" -PropertyType DWord -Value 7 -Force
# Never delete files in "Downloads" folder
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -ValueName "512" -PropertyType DWord -Value 0 -Force
# Turn off content suggestions in Settings.exe
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -ValueName "SubscribedContent-353694Enabled" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -ValueName "SubscribedContent-353696Enabled" -PropertyType DWord -Value 0 -Force
# Remove 3D Objects folder in "This PC" and in the navigation pane
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -ValueName "ThisPCPolicy" -PropertyType String -Value "Hide" -Force
# Theme color (Dark) for default Windows mode
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -ValueName "ColorPrevalence" -PropertyType DWord -Value 1 -Force
# Dark Theme Color for Default Windows Mode
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -ValueName "SystemUsesLightTheme" -PropertyType DWord -Value 0 -Force
# Turn off thumbnail cache removal (controll via Storage Sense or CCleaner)
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" -ValueName "Autorun" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" -ValueName "Autorun" -PropertyType DWord -Value 0 -Force
# Change environment variable from $env:TEMP to $env:SystemDrive\Temp
# I RamDrive or Sandbox /Temp, that's the reason
# https://adamtheautomator.com/powershell-set-windows-environment-variables/
IF (-not (Test-Path -Path "$env:SystemDrive\Temp"))
{
	New-Item -Path "$env:SystemDrive\Temp" -ItemType Directory -Force
}
[Environment]::SetEnvironmentVariable("TMP", "$env:SystemDrive\Temp", "User")
New-ItemProperty -Path HKCU:\Environment -ValueName "TMP" -PropertyType ExpandString -Value "%SystemDrive%\Temp" -Force
[Environment]::SetEnvironmentVariable("TEMP", "$env:SystemDrive\Temp", "User")
New-ItemProperty -Path HKCU:\Environment -ValueName "TEMP" -PropertyType ExpandString -Value "%SystemDrive%\Temp" -Force
[Environment]::SetEnvironmentVariable("TMP", "$env:SystemDrive\Temp", "Machine")
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -ValueName "TMP" -PropertyType ExpandString -Value "%SystemDrive%\Temp" -Force
[Environment]::SetEnvironmentVariable("TEMP", "$env:SystemDrive\Temp", "Machine")
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -ValueName "TEMP" -PropertyType ExpandString -Value "%SystemDrive%\Temp" -Force
[Environment]::SetEnvironmentVariable("TMP", "$env:SystemDrive\Temp", "Process")
[Environment]::SetEnvironmentVariable("TEMP", "$env:SystemDrive\Temp", "Process")
# Turn off preserve zone information in file attachments
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -ValueName "SaveZoneInformation" -PropertyType DWord -Value 1 -Force
# Turn on recycle bin files delete confirmation
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "ConfirmFileDelete" -PropertyType DWord -Value 1 -Force
##########################################################
###### 				Hibernation & Energy			######
##########################################################
# Turn off Hibernation
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -ValueName "HibernateEnabled" -PropertyType DWord -Value 0
powercfg /HIBERNATE OFF 2>&1 | Out-Null
# Set power management scheme for Desktop's and Laptop's.
IF ((Get-CimInstance -ClassName Win32_ComputerSystem).PCSystemType -eq 1)
{
	# Set the "High performance" powerplan on a Desktop system.
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
###### 					Context Menu 				######
##########################################################
# Add a 'Take Owner' option in your right-click menu (fixme)
reg add "HKEY_CLASSES_ROOT\*\shell\runas" /ve /t REG_SZ /d "Take Ownership" /f
reg add "HKEY_CLASSES_ROOT\*\shell\runas" /v NoWorkingDirectory /t REG_SZ /d "" /f
reg add "HKEY_CLASSES_ROOT\*\shell\runas\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \`"%1\`" && icacls \`"%1\`" /grant administrators:F" /f
reg add "HKEY_CLASSES_ROOT\*\shell\runas\command" /v IsolatedCommand /t REG_SZ /d "cmd.exe /c takeown /f \`"%1\`" && icacls \`"%1\`" /grant administrators:F" /f
New-Item -ErrorAction SilentlyContinue -Force -Path "HKCR:\Directory\shell\runas"
New-Item -ErrorAction SilentlyContinue -Force -Path "HKCR:\Directory\shell\runas\command"
New-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKCR:\Directory\shell\runas" -ValueName '(Default)' -Value "Take Ownership"
New-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKCR:\Directory\shell\runas" -ValueName NoWorkingDirectory -Value ""
New-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKCR:\Directory\shell\runas\command" -ValueName '(Default)' -Value "cmd.exe /c takeown /f `"%1`" /r /d y && icacls `"%1`" /grant administrators:F /t"
New-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKCR:\Directory\shell\runas\command" -ValueName IsolatedCommand -Value "cmd.exe /c takeown /f `"%1`" /r /d y && icacls `"%1`" /grant administrators:F /t"
#
#
# Add "Run as Administrator" context menu for .ps1 files
New-Item -Path "Registry::HKEY_CLASSES_ROOT\Microsoft.PowershellScript.1\Shell\runas\command" -Force -ValueName '' -Value '"C:\windows\system32\windowspowershell\v1.0\powershell.exe" -noexit -file "%1"'
# Add Photo Viewer 'Open with...'
If (!(Test-Path "HKCR:")) {
    New-PSDrive -ValueName HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
}
New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Force | Out-Null
New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\DropTarget" -Force | Out-Null
Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open" -ValueName "MuiVerb" -PropertyType String -Value "@photoviewer.dll,-3043"
Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -ValueName "(Default)" -PropertyType ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open\DropTarget" -ValueName "Clsid" -PropertyType String -Value "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}"
# Remove "Edit with Photos" from context menu
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellEdit" -ValueName "ProgrammaticAccessOnly" -PropertyType String -Value "" -Force
# Remove "Create a new video" from Context Menu
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellCreateVideo" -ValueName "ProgrammaticAccessOnly" -PropertyType String -Value "" -Force
# Remove "Edit" from Context Menu
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\SystemFileAssociations\image\shell\edit" -ValueName "ProgrammaticAccessOnly" -PropertyType String -Value "" -Force
# Remove "Print" from batch and cmd files context menu
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\batfile\shell\print" -ValueName "ProgrammaticAccessOnly" -PropertyType String -Value "" -Force
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\cmdfile\shell\print" -ValueName "ProgrammaticAccessOnly" -PropertyType String -Value "" -Force
# Remove "Compressed (zipped) Folder" from context menu
Remove-Item -Path "HKCU:\HKEY_CLASSES_ROOT\.zip\CompressedFolder\ShellNew" -Force -ErrorAction SilentlyContinue
# Remove "Rich Text Document" from context menu
Remove-Item -Path "HKCU:\HKEY_CLASSES_ROOT\.rtf\ShellNew" -Force -ErrorAction SilentlyContinue
# Remove "Bitmap image" from context menu
Remove-Item -Path "HKCU:\HKEY_CLASSES_ROOT\.bmp\ShellNew" -Force -ErrorAction SilentlyContinue
# Remove "Send to" from folder context menu
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\SendTo" -ValueName "(default)" -PropertyType String -Value "" -Force
# Enforce FIPS standards
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy" -ValueName "Enabled" -PropertyType -PropertyType DWord -Value 1 -Force
# Remove "Include in Library" from context menu
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\Folder\shellex\ContextMenuHandlers\Library Location" -ValueName "(default)" -PropertyType String -Value "-{3dad6c5d-2167-4cae-9914-f99e41c12cfa}" -Force
# Remove "Turn on BitLocker" from context menu because I prefer VeraCrypt (as a private person NOT in an Ent. enviorment!)
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\Drive\shell\encrypt-bde" -ValueName "ProgrammaticAccessOnly" -PropertyType String -Value "" -Force
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\Drive\shell\encrypt-bde-elev" -ValueName "ProgrammaticAccessOnly" -PropertyType String -Value "" -Force
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\Drive\shell\manage-bde" -ValueName "ProgrammaticAccessOnly" -PropertyType String -Value "" -Force
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\Drive\shell\resume-bde" -ValueName "ProgrammaticAccessOnly" -PropertyType String -Value "" -Force
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\Drive\shell\resume-bde-elev" -ValueName "ProgrammaticAccessOnly" -PropertyType String -Value "" -Force
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\Drive\shell\unlock-bde" -ValueName "ProgrammaticAccessOnly" -PropertyType String -Value "" -Force
# Remove "Edit with Paint 3D" from context menu
$exts = @(".bmp", ".gif", ".jpe", ".jpeg", ".jpg", ".png", ".tif", ".tiff")
foreach ($ext in $exts)
{
	New-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\$ext\Shell\3D Edit" -ValueName "ProgrammaticAccessOnly" -PropertyType String -Value "" -Force
}
# Remove "Previous Versions" from file context menu, we disabled ShadowCopy and using Macrium Reflect instead.
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -ValueName "{596AB062-B4D2-4215-9F74-E9109B0A8153}" -PropertyType String -Value "" -Force
# Remove "Cast to Device" from context menu
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -ValueName "{7AD84985-87B4-4a16-BE58-8B72A5B390F7}" -PropertyType String -Value "Play to menu" -Force
# Remove "Share" from context menu
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -ValueName "{E2BF9676-5F8F-435C-97EB-11607A5BEDF7}" -PropertyType String -Value "" -Force
# Make the "Open", "Print", "Edit" context menu items available, when more than 15 selected
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -ValueName "MultipleInvokePromptMinimum" -PropertyType DWord -Value 300 -Force
# Turn off "Look for an app in the Microsoft Store" in "Open with" dialog
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -ValueName "NoUseStoreOpenWith" -PropertyType DWord -Value 1
# Add "Extract" to .MSI file type context menu
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\Msi.Package\shell\Extract\Command" -ValueName "(default)" -PropertyType String -Value "msiexec.exe /a `"%1`" /qb TARGETDIR=`"%1 extracted`"" -Force
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\Msi.Package\shell\Extract" -ValueName "MUIVerb" -PropertyType String -Value "@shell32.dll,-31382" -Force
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\Msi.Package\shell\Extract" -ValueName "Icon" -PropertyType String -Value "shell32.dll,-16817" -Force
# Add "Run as different user" from context menu for .exe file type
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\exefile\shell\runasuser" -ValueName "(default)" -PropertyType String -Value "@shell32.dll,-50944" -Force
Remove-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\exefile\shell\runasuser" -ValueName "Extended" -Force -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\exefile\shell\runasuser" -ValueName "SuppressionPolicyEx" -PropertyType String -Value "{F211AA05-D4DF-4370-A2A0-9F19C09756A7}" -Force
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\exefile\shell\runasuser\command" -ValueName "DelegateExecute" -PropertyType String -Value "{ea72d00e-4960-42fa-ba92-7792a7944c1d}" -Force
# Add "Install" to CAB file type context menu
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\CABFolder\Shell\RunAs\Command" -ValueName "(default)" -PropertyType String -Value "cmd /c DISM /Online /Add-Package /PackagePath:`"%1`" /NoRestart & pause" -Force
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\CABFolder\Shell\RunAs" -ValueName "MUIVerb" -PropertyType String -Value "@shell32.dll,-10210" -Force
New-ItemProperty -Path "HKCU:\HKEY_CLASSES_ROOT\CABFolder\Shell\RunAs" -ValueName "HasLUAShield" -PropertyType String -Value "" -Force
##########################################################
######  				Printer						######
##########################################################
# Do not allow Windows 10 to manage default printer
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -ValueName "LegacyDefaultPrinterMode" -PropertyType DWord -Value 1 -Force



##########################################################
######  			User Accounts					######
##########################################################
# Turn on 'Users can't add or log on with Microsoft accounts'
# 0000000 = This policy is disabled
# 0000001 = Users can’t add Microsoft accounts
# 0000003 = Users can’t add or log on with Microsoft accounts (CIS)
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "NoConnectedUser" -PropertyType DWord -Value 3 -Force
# Allow Microsoft accounts to be optional <-> 'Disabled'
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "MSAOptional" -PropertyType DWord -Value 1 -Force
##########################################################
######                  Apps                        ######
##########################################################
# Turn off Connect Now Wizard (not in LTSB/LTSC and 1603+)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -ValueName "DisableFlashConfigRegistrar" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -ValueName "DisableInBand802DOT11Registrar" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -ValueName "DisableUPnPRegistrar" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -ValueName "DisableWPDRegistrar" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -ValueName "EnableRegistrars" -PropertyType DWord -Value 0 -Force
# Turn off downloads of Map data (not in LTSB/LTSC)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps" -ValueName "AllowUntriggeredNetworkTrafficOnSettingsPage" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps" -ValueName "AutoDownloadAndUpdateMapData" -PropertyType DWord -Value 0 -Force
# Turn off Windows Consumer Features
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -ValueName "DisableWindowsConsumerFeatures" -PropertyType DWord -Value 1 -Force
# Turn off Windows Tips
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -ValueName "DisableSoftLanding" -PropertyType DWord -Value 1 -Force
# Turn off app access to personal data (force deny)
# You should always use "force deny" instead of disabled!
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -ValueName "LetAppsAccessAccountInfo" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -ValueName "LetAppsAccessCalendar" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -ValueName "LetAppsAccessCallHistory" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -ValueName "LetAppsAccessCamera" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -ValueName "LetAppsAccessContacts" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -ValueName "LetAppsAccessEmail" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -ValueName "LetAppsAccessLocation" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -ValueName "LetAppsAccessMessaging" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -ValueName "LetAppsAccessMicrophone" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -ValueName "LetAppsAccessMotion" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -ValueName "LetAppsAccessNotifications" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -ValueName "LetAppsAccessPhone" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -ValueName "LetAppsAccessRadios" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -ValueName "LetAppsAccessTasks" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -ValueName "LetAppsAccessTrustedDevices" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -ValueName "LetAppsGetDiagnosticInfo" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -ValueName "LetAppsSyncWithDevices" -PropertyType DWord -Value 2 -Force
# Turn off Maps auto updates
Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -ValueName "AutoUpdateEnabled" -PropertyType DWord -Value 0
# Turn off Activity History Feed
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "EnableActivityFeed" -PropertyType DWord -Value 0
# Turn off publishing of user Activities
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "PublishUserActivities" -PropertyType DWord -Value 0
# Turn off Mail App
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows Mail" -ValueName "ManualLaunchAllowed" -PropertyType DWord -Value 0


# Turn off "Automatic installation apps"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -ValueName "ContentDeliveryAllowed" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -ValueName "OemPreInstalledAppsEnabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -ValueName "PreInstalledAppsEnabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -ValueName "PreInstalledAppsEverEnabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -ValueName "SilentInstalledAppsEnabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -ValueName "SubscribedContent-310093Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -ValueName "SubscribedContent-338387Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -ValueName "SubscribedContent-338388Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -ValueName "SubscribedContent-338389Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -ValueName "SubscribedContent-353698Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -ValueName "SystemPaneSuggestionsEnabled" -PropertyType DWord -Value 0
# Turn off Shared Experiences: "I can share and receive from"
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" -ValueName "CdpSessionUserAuthzPolicy" -PropertyType DWord -Value 0 -Force
# Turn off "My devices only" for Nearby sharing: "I can share and receive from"
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" -ValueName "NearShareChannelUserAuthzPolicy" -PropertyType DWord -Value 0 -Force
# Turn off "Let apps share and sync with wireless devices" (fixme)
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" -ValueName "Value" -PropertyType hex -Value Deny -Force
# Turn off automatic installing suggested apps
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -ValueName "SilentInstalledAppsEnabled" -PropertyType DWord -Value 0 -Force
# Dark theme color for default app mode
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -ValueName "AppsUseLightTheme" -PropertyType DWord -Value 0
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -ValueName "AppsUseLightTheme" -PropertyType DWord -Value 0
# Turn off Inventory (1603 and below)
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompa" -ValueName "DisableInventory" -PropertyType DWord -Value 1 -Force
# Do not allow apps to use advertising ID
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -ValueName "Enabled" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -ValueName "Id" -PropertyType String -Value "null" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -ValueName "DisabledByGroupPolicy" -PropertyType DWord -Value 1
# Turn off Linguistic Data Collection
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -ValueName "AllowLinguisticDataCollection" -PropertyType DWord -Value 0
# Turn off Cortana (not present in LTSB/LTSC)
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ValueName "AllowCortana" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -ValueName "RestrictImplicitInkCollection" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -ValueName "RestrictImplicitTextCollection" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -ValueName "HarvestContacts" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -ValueName "AcceptedPrivacyPolicy" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI" -ValueName "DisableWcnUi" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ValueName "AllowCortana" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ValueName "CortanaCapabilities" -PropertyType ExpandString -Value ""
# Turn off "Let Cortana respond to "Hey Cortana""
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences" -ValueName "VoiceActivationOn" -PropertyType DWord -Value 0 -Force
# Turn off "Use Cortana even when my device is locked"
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences" -ValueName "VoiceActivationEnableAboveLockscreen" -PropertyType DWord -Value 0 -Force
# Turn off "Let Cortana listen for my commands when I press the Windows logo key + C"
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -ValueName "VoiceShortcut" -PropertyType DWord -Value 0 -Force
#
# Remove all apps except Windows Store incl. Xbox (Enterprise (N) LTSC 2019)
# The Windows Store however does not run in the background since we enforce to disable all background apps.
# (fixme) Add XBOX 360 driver workaround (1909 fixed? - needs more tests)
Get-AppxPackage -AllUsers | where-object {$_.name –notlike "*store*"} | Remove-AppxPackage
##########################################################
######                  Start Menu                  ######
######            I use StartisBack++               ######
##########################################################
# Turn off Sleep & keyboard button in Start Menu
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -ValueName "ShowSleepOption" -PropertyType DWord -Value 0
#powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0
#powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0
# Turn off Help and Support"
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ValueName "Start_ShowHelp" -PropertyType DWord -Value 0 -Force
# Turn off 'Games'
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ValueName "Start_ShowMyGame" -PropertyType DWord -Value 0 -Force
# Turn off automatically hiding scroll bars
New-ItemProperty -Path "HKCU:\Control Panel\Accessibility" -ValueName "DynamicScrollbars" -PropertyType DWord -Value 0 -Force
# Add a Command Prompt shortcut from Start menu (Administrator)
[byte[]]$bytes = Get-Content -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\System Tools\Command Prompt.lnk" -Encoding Byte -Raw
$bytes[0x15] = $bytes[0x15] -bor 0x20
Set-Content -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\System Tools\Command Prompt.lnk" -Value $bytes -Encoding Byte -Force
# Turn off recently added apps on Start Menu
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -ValueName "HideRecentlyAddedApps" -PropertyType DWord -Value 1
# Turn off 'Most used' apps list from the Start Menu
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoStartMenuMFUprogramsList" -PropertyType DWord -Value 1
# Turn off app suggestions on Start menu e.g. Windows Ink Workspace
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -ValueName "SubscribedContent-338388Enabled" -PropertyType DWord -Value 0 -Force
# Hide "Recent folders" in Quick access
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -ValueName "ShowFrequent" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -ValueName "ShowFrequent" -PropertyType DWord -Value 0 -Force
# Hide Cortana search box and search icon on taskbar
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -ValueName "SearchboxTaskbarMode" -PropertyType DWord -Value 0
# Unpin all Start Menu tiles
$key = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\*start.tilegrid`$windows.data.curatedtilecollection.tilecollection\Current"
$data = $key.Data[0..25] + ([byte[]](202,50,0,226,44,1,1,0,0))
Set-ItemProperty -Path $key.PSPath -ValueName "Data" -PropertyType Binary -Value $data
Stop-Process -ValueName "ShellExperienceHost" -Force -ErrorAction SilentlyContinue
#New-ItemProperty -Path $tilecollection.PSPath -ValueName "Data" -PropertyType Binary -Value $unpin -Force
# Turn off Task View button
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ValueName "ShowTaskViewButton" -PropertyType DWord -Value 0
# Enforce use of small Taskbar icons
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ValueName "TaskbarSmallIcons" -PropertyType DWord -Value 1
# Turn on taskbar buttons - Show label & never combine
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ValueName "TaskbarGlomLevel" -PropertyType DWord -Value 2
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ValueName "MMTaskbarGlomLevel" -PropertyType DWord -Value 2
##########################################################
######      Microsoft Edge (old non Chomium based)  ######
###### LTSC\B versions do not include Microsoft Edge #####
##########################################################
# Turn off "Compatibility List"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\BrowserEmulation" -ValueName "MSCompatibilityMode" -PropertyType DWord -Value 0
# Set a "Blank" Startpage (fixme)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Internet Settings" -ValueName "ProvisionedHomePages" -PropertyType DWord -Value "<about:blank>"
# Turn off auto password completation (fixme)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -ValueName "FormSuggest Passwords" -PropertyType DWord -Value "no"
# Turn off first run Welcome page
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -ValueName "PreventFirstRunPage" -PropertyType DWord -Value 1 -Force
# Turn off Auto Form Suggestion (fixme)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -ValueName "Use FormSuggest" -PropertyType DWord -Value "no" -Force
# Turn off drop-down suggestions
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\ServiceUI" -ValueName "ShowOneBox" -PropertyType DWord -Value 0 -Force
# New Tabs shall be empty
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\ServiceUI" -ValueName "AllowWebContentOnNewTabPage" -PropertyType DWord -Value 0 -Force
# Turn off Books Library Updates
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\ServiceUI" -ValueName "AllowConfigurationUpdateForBooksLibrary" -PropertyType DWord -Value 0 -Force



# Uninstall Microsoft Edge
# Not possible anymore since 1709+, it will be replaced with Chromium Edge anyway (in 20H1?)
# Uninstalling MS Edge results in "Notification Center" to freak out.
# Backup Edge
# mv C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe_BAK
# Remove package
# Get-WindowsPackage -Online | Where PackageName -like *InternetExplorer* | Remove-WindowsPackage -Online -NoRestart
# Ensure MicrosoftEdge.exe stays dead.
# reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MicrosoftEdge.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
# Turn off data collection in Microsoft Edge
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -ValueName "PreventLiveTileDataCollection" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\EdgeUI" -ValueName "DisableMFUTracking" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\EdgeUI" -ValueName "DisableRecentApps" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\EdgeUI" -ValueName "TurnOffBackstack" -PropertyType DWord -Value 1
# Turn off Do Not Track (DNT) in Microsoft Edge
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -ValueName "DoNotTrack" -PropertyType DWord -Value 2
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -ValueName "DoNotTrack" -PropertyType DWord -Value 2
# Turn off third-party cookies in Microsoft Edge
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -ValueName "Cookies" -PropertyType DWord -Value 1
# Turn usage stats in sample submissions
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Edge Dev" -ValueName "UsageStatsInSample" -PropertyType DWord -Value 0
# Turn on override prevention "SmartScreen for Windows Store apps"
# New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -ValueName "PreventOverride" -PropertyType DWord -Value 1 -Force
# Turn on (set to Warning) "SmartScreen for Windows Store apps"
#New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -ValueName "EnableWebContentEvaluation" -PropertyType DWord -Value 0 -Force
#  Turn on (set to Warning) "SmartScreen for Microsoft Edge" (fixme)
#New-ItemProperty -Path "HKCU:\SOFTWARE\Classes\Local Settings\SOFTWARE\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" -ValueName "EnabledV9" -PropertyType DWord -Value "1" -Force
# Disable Adobe Flash
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -ValueName "FlashPlayerEnabled" -PropertyType DWord -Value 0 -Force
# Prevent using Localhost IP address for WebRTC
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -ValueName "LocalHostIP" -PropertyType DWord -Value 1 -Force
# Remove Microsoft Edge shortcut from the Desktop
$value = Get-ItemPropertyValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -ValueName Desktop
Remove-Item -Path "$value\Microsoft Edge.lnk" -Force -ErrorAction SilentlyContinue
# Turn off creation of an MS Edge shortcut on the desktop for each user profile
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -ValueName "DisableEdgeDesktopShortcutCreation" -PropertyType DWord -Value 1 -Force
# Prevent Microsoft Edge to start and load the Start and New Tab page at Windows startup and after each time Microsoft Edge is closed
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" -ValueName "AllowTabPreloading" -PropertyType DWord -Value 0
# Prevent Microsoft Edge to pre-launch at Windows startup, when the OS idle, and each time Microsoft Edge is closed
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -ValueName "DisableEdgeDesktopShortcutCreation" -PropertyType DWord -Value 1
##########################################################
######          Storage Sense 1703+                 ######
##########################################################
# Turn off scheduled defragmentation task
Disable-ScheduledTask -TaskName "Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null
# Turn on Storage Sense to automatically free up space
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -ValueName 01 -PropertyType DWord -Value 1 -Force
# Run Storage Sense every month | Otherwise use CCleaner incl. Winapp2.ini which is the alternative to Storage Sense.
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -ValueName 2048 -PropertyType DWord -Value 30 -Force
##########################################################
######              SmartScreen                     ######
##########################################################
# Disable app based SMartScreen checks and controls
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\SmartScreen" -ValueName "ConfigureAppInstallControlEnabled" -PropertyType DWord -Value 0 -Force
# Hide notification about disabled Smartscreen for Microsoft Edge
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows Security Health\State" -ValueName "AppAndBrowser_EdgeSmartScreenOff" -PropertyType DWord -Value 0 -Force
# Turn off SmartScreen for apps and files
# Block = Block execution/opening (Secure)
# Warn = Warn before execution/opening (Default)
# Off = Turn off
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -ValueName "SmartScreenEnabled" -PropertyType String -Value "Off" -Force
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "ShellSmartScreenLevel" -PropertyType DWord -Value 0 (fixme) -Force
# reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v "ShellSmartScreenLevel" /t REG_SZ /d "Warn" /f  ^^^^^^^^^^
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "EnableSmartScreen" -PropertyType DWord -Value 0 -Force
# Turn off Windows Defender SmartScreen (phising filter) for (old) Microsoft Edge
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -ValueName "EnabledV9" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Classes\Local Settings\SOFTWARE\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$edge\MicrosoftEdge\PhishingFilter" -ValueName "EnabledV9" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Classes\Local Settings\SOFTWARE\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$edge\MicrosoftEdge\PhishingFilter" -ValueName "PreventOverride" -PropertyType DWord -Value 0 -Force
# Turn on 'Prevent bypassing Windows Defender SmartScreen prompts for sites'
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -ValueName "PreventOverride" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -ValueName "PreventOverrideAppRepUnknown" -PropertyType DWord -Value 1 -Force
##########################################################
###### 			    Windows Defender (WD)           ######
######      Overview: Get-Command -Module Defender  ######
######      Get Threats: Get-MpThreatDetection      ######
##########################################################
# Start a full scan sundays at 2AM and exclude processhacker (example) (fixme)
# Set-MpPreference -UILockdown:$True -ExclusionProcess processhacker ‑ScanAvgCPULoadFactor 20 ‑RemediationScheduleDay Sunday ‑RemediationScheduleTime 120
# Add WD scan exclusions (example)
#Add-MpPreference -ExclusionPath ('C:\Scripts','C:\CK\AVtest')
#Get-MpPreference | Select-Object ‑Property ExclusionPath
# Turn off MRT (Report Infections) Telemetry
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\MRT" -ValueName "DontReportInfectionInformation" -Value 1 -Force
# Turn on protection against Potentially Unwanted Applications
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" -ValueName "MpEnablePus" -PropertyType DWord -Value 1 -Force
# Turn on removable driver scanning
Set-MpPreference -DisableRemovableDriveScanning $false | Out-Null
# Turn off eMail scanning
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -ValueName "DisableEmailScanning" -PropertyType DWord -Value 0 -Force
# Turn on Attack Surface Reduction Rules
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -ValueName "ExploitGuard_ASR_Rules" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -ValueName "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -ValueName "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -ValueName "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -ValueName "5beb7efe-fd9a-4556-801d-275e5ffc04cc" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -ValueName "3b576869-a4ec-4529-8536-b80a7769e899" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -ValueName "d4f940ab-401b-4efc-aadc-ad5f3c50688a" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -ValueName "d3e037e1-3eb8-44c8-a917-57927947596d" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -ValueName "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -ValueName "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -ValueName "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" -PropertyType DWord -Value 1 -Force
# Turn off Spynet reporting
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -ValueName "LocalSettingOverrideSpynetReporting" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -ValueName "SpynetReporting" -PropertyType DWord -Value 0 -Force
# Uninstall Windows Defender (install_wim_tweak method Build <=1703) (fixme)
# reg add "HKCU\SOFTWARE\Classes\Local Settings\SOFTWARE\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f
# reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f
# reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SecHealthUI.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
# reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "Off" /f
# reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d 1 /f
# reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 1 /f
# reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
# reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v DontReportInfectionInformation /t REG_DWORD /d 1 /f
# reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpyNetReporting /t REG_DWORD /d 0 /f
# reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 2 /f
# reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /f
# reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f
# reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /f
# install_wim_tweak /o /c Windows-Defender /r
#reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d 0 /f
#reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /f
# Turn off Windows Defender
#If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender")) {
#    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Force | Out-Null
#}
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -ValueName "DisableAntiSpyware" -PropertyType DWord -Value 1
#If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
#    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ValueName "WindowsDefender" -ErrorAction SilentlyContinue
#} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 15063) {
#    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ValueName "SecurityHealth" -ErrorAction SilentlyContinue
#}
#}
# Turn on blocking of downloaded files
#Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -ValueName "SaveZoneInformation" -PropertyType DWord -Value 1
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -ValueName "SaveZoneInformation" -ErrorAction SilentlyContinue
# Turn on Windows Defender Account Protection Warnings
Remove-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows Security Health\State" -ValueName "AccountProtection_MicrosoftAccount_Disconnected" -ErrorAction SilentlyContinue
# Turn off Account Protection Notifications
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows Security Health\State" -ValueName "AccountProtection_MicrosoftAccount_Disconnected" -PropertyType DWord -Value 1
# Turn on Windows Defender AppGuard (see "Windows Features section")
# Enable-WindowsOptionalFeature -online -FeatureName "Windows-Defender-ApplicationGuard" -NoRestart -WarningAction SilentlyContinue | Out-Null
# Turn on Core Isolation Memory Integrity
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -ValueName "Enabled" -PropertyType DWord -Value 2
# Turn on Defender Exploit Guard
Set-MpPreference -EnableControlledFolderAccess $true | Out-Null
# Turn off submission of Windows Defender Malware Samples
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\SubmitSamplesConsent" -ValueName "value" -PropertyType DWord -Value 2 -Force
# Turn off Windows Defender Trayicon
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" -ValueName "HideSystray" -PropertyType DWord -Value 1
# Turn off Cloud Protection
Set-MpPreference -CloudBlockLevel 0 | Out-Null
# Turn off Windows Defender Cloud & Sample submission
# https://docs.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=win10-ps#parameters
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -ValueName "SpynetReporting" -PropertyType DWord -Value 0
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -ValueName "SubmitSamplesConsent" -PropertyType DWord -Value 2
Set-MpPreference -MAPSReporting 0 | Out-Null
# Set the default signature update order
#Set-MpPreference -SignatureFallbackOrder "{MicrosoftUpdateServer|MMPC}" | Out-Null
# Set the default Signature update server
#Set-MpPreference -SignatureDefinitionUpdateFileSharesSources "{}" | Out-Null
# Don't scan if CPU is X % busy
Set-MpPreference -ScanAvgCPULoadFactor 55 | Out-Null
# Turn off IDLE scan
Set-MpPreference -ScanOnlyIfIdleEnabled $true | Out-Null
# Enable signature update check before starting a scan
Set-MpPreference -CheckForSignaturesBeforeRunningScan $true | Out-Null
# Turn on "Windows Defender Exploit Guard Network Protection"
Set-MpPreference -EnableNetworkProtection 1 | Out-Null
# Turn on Windows Defender Sandbox
setx /M MP_FORCE_USE_SANDBOX=1
# Turn on "Windows Defender PUA Protection"
Set-MpPreference -PUAProtection 1 | Out-Null
# Turn off WD "Firewall & Network protection"
# I use my Router & AdGuard Home as shield
#Set-NetFirewallProfile -Enabled false
# Turn on Windows Defender Exploit Protection Settings
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" -ValueName "DisallowExploitProtectionOverride" -ErrorAction SilentlyContinue
# Allow malicious app/website connections (now part off "Windows Defender Exploit Guard Network Protection")
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -ValueName "EnableNetworkProtection" -PropertyType DWord -Value 0
# Turn on Windows Defender Behavior Monitoring ()
Set-MpPreference -DisableRealtimeMonitoring $true | Out-Null
# Turn off Generic malware reports
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" -ValueName "DisableGenericRePorts" -PropertyType DWord -Value 0 -Force
# Turn on "Block at first seen"
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -ValueName "DisableBlockAtFirstSeen" -PropertyType DWord -Value 0 -Force
# Fake Computer ID (fixme) - is that even possible?! I never tried it!
Set-MpPreference -ComputerID 49AE549F-1C94-4B4E-B09G-A65C71DC2806 | Out-Null
# Set Computer name (default empty) - I have no clue what this option does (fixme)
#Set-MpPreference PSComputerName ???? | Out-Null
# Set unknown default action to "Warn" (but don't clean)
Set-MpPreference -UnknownThreatDefaultAction 0 | Out-Null
# Set exclusion path (example)
#Set-MpPreference -ExclusionPath "{C:\KMSAuto\KMSAuto x64.exe, C:\KMSAuto\KMSAuto++.exe, C:\KMSAuto\KMSAuto_Files...}" | Out-Null
# Turn off Windows Defender UI Lockdown
Set-MpPreference -UILockdown $false | Out-Null
# Turn on archive scanning
Set-MpPreference -DisableArchiveScanning $false | Out-Null
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
# Turn off IPS (fixme) is the value a string or not?
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
Set-MpPreference -ExclusionProcess "{processhacker.exe, VeraCrypt.exe, Everything.exe, Taskmgr.exe}" | Out-Null
# Turn off automatic sample submission
Set-MpPreference -SubmitSamplesConsent 2 | Out-Null
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
# https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage
# Turn on Defender Credential Guard with UEFI lockdown (since Windows 1607+ you don't need to enable it, it will be automatically enabled)
# New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\LSA" -ValueName "LsaCfgFlags" -PropertyType DWord -Value 1 -Force
# New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Device Guard" -ValueName "EnableVirtualizationBasedSecurity" -PropertyType DWord -Value 1 -Force
# New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Device Guard" -ValueName "RequirePlatformSecurityFeatures" -PropertyType DWord -Value 3 -Force
# bcdedit /set {0cb3b571-2f2e-4343-a879-d86a476d7215} loadoptions DISABLE-LSA-ISO,DISABLE-VBS
# bcdedit /set vsmlaunchtype off
# Set-VMSecurity -VMName <VMName> -VirtualizationBasedSecurityOptOut $true
##########################################################
######                      Taskbar                 ######
##########################################################
# Turn on all tray icons
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoAutoTrayNotify" -PropertyType DWord -Value 1
# Turn off People icon
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -ValueName "PeopleBand" -PropertyType DWord -Value 0
# Always show all icons in the notification area
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -ValueName "EnableAutoTray" -PropertyType DWord -Value 0 -Force
# Show seconds on taskbar clock
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ValueName "ShowSecondsInSystemClock" -PropertyType DWord -Value 1 -Force
# Hide People button on the taskbar
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ValueName "AutoCheckSelect" -PropertyType DWord -Value 0
# Turn off "Windows Ink Workspace" button
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PenWorkspace" -ValueName "PenWorkspaceButtonDesiredVisibility" -PropertyType DWord -Value 0 -Force
# Turn on acrylic taskbar transparency
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ValueName "UseOLEDTaskbarTransparency" -PropertyType DWord -Value 1 -Force
##########################################################
######                      BSOD                    ######
##########################################################
# Turn off Startup and Recovery - Debug Information
# Defaults 1,1,5,1,1,1
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -ValueName "AutoReboot" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -ValueName "LogEvent" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -ValueName "MinidumpsCount" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -ValueName "Overwrite" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -ValueName "CrashDumpEnabled" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -ValueName "AlwaysKeepMemoryDump" -PropertyType DWord -Value 0 -Force
##########################################################
######                      Sync                    ######
##########################################################
# Turn off app based sync
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging" -ValueName "AllowMessageSync" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging" -ValueName "CloudServiceSyncEnabled" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -ValueName "DisableApplicationSettingSync" -PropertyType DWord -Value 2 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -ValueName "DisableApplicationSettingSyncUserOverride" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -ValueName "DisableAppSyncSettingSync" -PropertyType DWord -Value 2 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -ValueName "DisableAppSyncSettingSyncUserOverride" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -ValueName "DisableCredentialsSettingSync" -PropertyType DWord -Value 2 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -ValueName "DisableCredentialsSettingSyncUserOverride" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -ValueName "DisableDesktopThemeSettingSync" -PropertyType DWord -Value 2 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -ValueName "DisableDesktopThemeSettingSyncUserOverride" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -ValueName "DisablePersonalizationSettingSync" -PropertyType DWord -Value 2 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -ValueName "DisablePersonalizationSettingSyncUserOverride" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -ValueName "DisableStartLayoutSettingSync" -PropertyType DWord -Value 2 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -ValueName "DisableStartLayoutSettingSyncUserOverride" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -ValueName "DisableWebBrowserSettingSync" -PropertyType DWord -Value 2 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -ValueName "DisableWebBrowserSettingSyncUserOverride" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -ValueName "DisableWindowsSettingSync" -PropertyType DWord -Value 2 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -ValueName "DisableWindowsSettingSyncUserOverride" -PropertyType DWord -Value 1 -Force
# Turn off Cloud Clipboard Feature
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "AllowCrossDeviceClipboard" -PropertyType DWord -Value 0 -Force
# Turn off Settings are been synced when logged-in
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -ValueName "DisableSettingSync" -PropertyType DWord -Value 2 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -ValueName "DisableSettingSyncUserOverride" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -ValueName "EnableBackupForWin8Apps" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -ValueName "DisableSyncOnPaidNetwork" -PropertyType DWord -Value 1 -Force
# Turn off "Find my device"
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FindMyDevice" -ValueName "AllowFindMyDevice" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\FindMyDevice" -ValueName "AllowFindMyDevice" -PropertyType DWord -Value 0 -Force
# Turn off "Sync your settings: Ease of Access
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" -ValueName "Enabled" -PropertyType DWord -Value 0 -Force
# Turn off Clipboard Cloud Sync Feature
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Clipboard" -ValueName "EnableCloudClipboard" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Clipboard" -ValueName "CloudClipboardAutomaticUpload" -PropertyType DWord -Value 0 -Force
# Turn off "Sync your settings: Passwords"
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" -ValueName "Enabled" -PropertyType DWord -Value 0 -Force
# Turn off "Sync your settings: Language preferences"
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" -ValueName "Enabled" -PropertyType DWord -Value 0 -Force
# Turn off "Sync your settings: Theme"
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" -ValueName "Enabled" -PropertyType DWord -Value 0 -Force
# Turn off Sync your settings: Other Windows settings
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" -ValueName "Enabled" -PropertyType DWord -Value 0 -Force
###############################################
######              Privacy              ######
###############################################
# Disable "Let apps use my camera"
Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}" -ValueName "Value" -PropertyType String -Value "Deny" | Out-Null
# Disable "Let websites provide locally relevant content by accessing my language list"
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Internet Explorer\International" -ValueName "AcceptLanguage" -Force
Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\Control Panel\International\User Profile" -ValueName HttpAcceptLanguageOptOut -Value 1 | Out-Null
# Disable "Let apps use my microphone" (I personally need a Mic, let it enabled and work with the internal whitelist or GPO)
#Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}\" -ValueName "Value" -PropertyType String -Value "Deny" | Out-Null
# Disable "Let apps access my name, picture and other account info"
Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}\" -ValueName "Value" -PropertyType String -Value "Deny" | Out-Null
# Disable "let apps access my calendar" (use FOSS apps like Thunderbird or Webmail/calendar instead)
Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}\" -ValueName "Value" -PropertyType String -Value "Deny" | Out-Null
# Disable "Let apps read or send sms and text messages"
Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}\" -ValueName "Value" -PropertyType String -Value "Deny" | Out-Null
# Disable "Let apps control Radios"
Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}\" -ValueName "Value" -PropertyType String -Value "Deny" | Out-Null
# Disable "Sync with devices" (we do not use Sync nor MS Accounts so this option is useless)
Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled\" -ValueName "Value" -PropertyType String -Value "Deny" | Out-Null






# Manage single or multiple sessions per user (RDP) - Prevent multiple sessions at once
#New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -ValueName "fSingleSessionPerUser" -PropertyType DWord -Value 1 -Force
# Strict DLL search order
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -ValueName "CWDIllegalInDllSearch" -PropertyType DWord -Value 0 -Force
# Turn off WMDRM
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM" -ValueName "DisableOnline" -PropertyType DWord -Value 1 -Force
# Prevent users from sharing files within their profile
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoInplaceSharing" -PropertyType DWord -Value 1 -Force
# Turn off "Notify antivirus programs when opening attachments"
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -ValueName "ScanWithAntiVirus" -PropertyType DWord -Value 1 -Force
# Turn off taskbar live thumbnail previews
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ValueName "DisablePreviewWindow" -PropertyType DWord -Value 0 -Force
# Turn off taskbar live thumbnail Aero peek
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\DWM" -ValueName "EnableAeroPeek" -PropertyType DWord -Value 0 -Force
# Turn off Mobile Device Management (MDM) enrollment (does not exists on LTSB(C))
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM" -ValueName "DisableRegistration" -PropertyType DWord -Value 1 -Force
# Turn off projecting (Connect) to the device, and ensure it requires pin for pairing
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -ValueName "AllowProjectionToPC" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -ValueName "RequirePinForPairing" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WirelessDisplay" -ValueName "EnforcePinBasedPairing" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\PresentationSettings" -ValueName "NoPresentationSettings" -PropertyType DWord -Value 1 -Force
# Turn off Steps Recorder
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -ValueName "DisableUAR" -PropertyType DWord -Value 1 -Force
# Turn off speech recognition udpates
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Speech" -ValueName "AllowSpeechModelUpdate" -PropertyType DWord -Value 0 -Force
# Turn off "Search Companion" from downloading files from Microsoft
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion" -ValueName "DisableContentFileUpdates" -PropertyType DWord -Value 1 -Force
# Turn off Error Reporting
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -ValueName "Disabled" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -ValueName "DontSendAdditionalData" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -ValueName "LoggingDisabled" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" -ValueName "DoReport" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" -ValueName "DWNoExternalURL" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" -ValueName "ForceQueueMode" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" -ValueName "DWNoFileCollection" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" -ValueName "DWNoSecondLevelCollection" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\HelpSvc" -ValueName "Headlines" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\HelpSvc" -ValueName "MicrosoftKBSearch" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" -ValueName "Disabled" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" -ValueName "DisableSendGenericDriverNotFoundToWER" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" -ValueName "DisableSendRequestAdditionalSoftwareToWER" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -ValueName "Disabled" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -ValueName "DontSendAdditionalData" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -ValueName "LoggingDisabled" -PropertyType DWord -Value 1 -Force
# Turn off Microsoft Account user authentication
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftAccount" -ValueName "DisableUserAuth" -PropertyType DWord -Value 1 -Force
# Turn off Network Connectivity Status Indicator active test (possible data leakage)
# Info:
# msftconnecttest.com + ipv6.msftconnecttest.com
# dns.msftncsi.com looking + 131.107.255.255
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" -ValueName "NoActiveProbe" -PropertyType DWord -Value 1
# Turn on cleaning of recent used files
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "ClearRecentDocsOnExit" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoRecentDocsHistory" -PropertyType DWord -Value 1 -Force
# Turn off MS Messenger (not needed since 1603+)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client" -ValueName "CEIP" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Messenger\Client" -ValueName "CEIP" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client" -ValueName "PreventRun" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Messenger\Client" -ValueName "PreventRun" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client" -ValueName "PreventAutoRun" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Messenger\Client" -ValueName "PreventAutoRun" -PropertyType DWord -Value 1
# Turn off Spotlight (not needed since 1603+)
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -ValueName "ConfigureWindowsSpotlight" -PropertyType DWord -Value 2 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -ValueName "DisableTailoredExperiencesWithDiagnosticData" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -ValueName "DisableThirdPartySuggestions" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -ValueName "DisableWindowsSpotlightFeatures" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -ValueName "DisableWindowsSpotlightOnActionCenter" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -ValueName "DisableWindowsSpotlightWindowsWelcomeExperience" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -ValueName "IncludeEnterpriseSpotlight" -PropertyType DWord -Value 0 -Force
# Delete Diagtrack and Cortana leftovers
# (fixme ?)
reg add  "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"  /v "{60E6D465-398E-4850-BE86-7EF7620A2377}" /t REG_SZ /d  "v2.24|Action=Block|Active=TRUE|Dir=Out|App=C:\windows\system32\svchost.exe|Svc=DiagTrack|Name=Windows  Telemetry|" /f
reg add  "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"  /v "{2765E0F4-2918-4A46-B9C9-43CDD8FCBA2B}" /t REG_SZ /d  "v2.24|Action=Block|Active=TRUE|Dir=Out|App=C:\windows\systemapps\microsoft.windows.cortana_cw5n1h2txyewy\searchui.exe|Name=Search  and Cortana  application|AppPkgId=S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742|"  /f
##########################################################
######      Internet Explorer (Ignore the warnings) ######
##########################################################
# Uninstall Internet Explorer
# WARNING: Don't remove other IE related packages otherwise you will lose the internet settings in your control panel!
#Microsoft-Windows-InternetExplorer-Optional-Package
Disable-WindowsOptionalFeature -Online -FeatureName "Internet-Explorer-Optional-$env:PROCESSOR_ARCHITECTURE" -NoRestart -WarningAction SilentlyContinue | Out-Null
# Turn off Password Reveal Button in Internet Explorer (not needed since 1603+)
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CredUI" -ValueName "DisablePasswordReveal" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -ValueName "DisablePasswordReveal" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI" -ValueName "DisablePasswordReveal" -PropertyType DWord -Value 1 -Force
# Turn off "Help" in Microsoft Edge
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EdgeUI" -ValueName "DisableHelpSticker" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\EdgeUI" -ValueName "DisableHelpSticker" -PropertyType DWord -Value 1
# Turn off Search Suggestions in Microsoft Edge
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\SearchScopes" -ValueName "ShowSearchSuggestionsGlobal" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\SearchScopes" -ValueName "ShowSearchSuggestionsGlobal" -PropertyType DWord -Value 0
# Turn on HTTP/2 in Internet Explorer
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -ValueName "EnableHTTP2" -PropertyType DWord -Value 1
# Turn off SSLv3 & suppress certificate errors in Internet Explorer
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -ValueName "CallLegacyWCMPolicies" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -ValueName "EnableSSL3Fallback" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -ValueName "PreventIgnoreCertErrors" -PropertyType DWord -Value 1
# Turn on automatic browsing history cleaning in Internet Explorer
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Privacy" -ValueName "ClearBrowsingHistoryOnExit" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\Privacy" -ValueName "ClearBrowsingHistoryOnExit" -PropertyType DWord -Value 1
# Turn off Do Not Track (DNT) in Internet Explorer
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -ValueName "DoNotTrack" -PropertyType DWord -Value 0
# Turn off automatic crash Detection in Internet Explorer
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Restrictions" -ValueName "NoCrashDetection" -PropertyType DWord -Value 1
# Turn off Internet Explorer prefetching
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\PrefetchPrerender" -ValueName "Enabled" -PropertyType DWord -Value 0
# Enforce DEP in Internet Explorer
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -ValueName "DEPOff" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -ValueName "Isolation64Bit" -PropertyType DWord -Value 1
# Turn off IE Background Sync Status
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" -ValueName "BackgroundSyncStatus" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" -ValueName "BackgroundSyncStatus" -PropertyType DWord -Value 0
# Turn off Site List Editing
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\BrowserEmulation" -ValueName "DisableSiteListEditing" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\BrowserEmulation" -ValueName "DisableSiteListEditing" -PropertyType DWord -Value 1


# Turn off FlipAhead suggestion
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\FlipAhead" -ValueName "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\FlipAhead" -ValueName "Enabled" -PropertyType DWord -Value 0
# Turn off Geolocation in IE
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Geolocation" -ValueName "PolicyDisableGeolocation" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\Geolocation" -ValueName "PolicyDisableGeolocation" -PropertyType DWord -Value 1
# Turn off Internet Explorer suggestions
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -ValueName "AllowServicePoweredQSA" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\DomainSuggestion" -ValueName "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\SearchScopes" -ValueName "TopResult" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Suggested Sites" -ValueName "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -ValueName "AutoSearch" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\WindowsSearch" -ValueName "EnabledScopes" -PropertyType DWord -Value 0
# Turn off "Sync your settings: Internet Explorer settings"
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" -ValueName "Enabled" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" -ValueName "Enabled" -PropertyType DWord -Value 0 -Force
# Turn off Internet Explorer continues browsing
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\ContinuousBrowsing" -ValueName "Enabled" -PropertyType DWord -Value 0
# Turn off Internet Explorer SQM (now known as CEIP)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\SQM" -ValueName "DisableCustomerImprovementProgram" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\SQM" -ValueName "DisableCustomerImprovementProgram" -PropertyType DWord -Value 1
# Turn off Internet Explorer "In-Private" logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Safety\PrivacIE" -ValueName "DisableLogging" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\Safety\PrivacIE" -ValueName "DisableLogging" -PropertyType DWord -Value 1
# Turn on Internet Explorer phising filter
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter" -ValueName "EnabledV9" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter" -ValueName "EnabledV9" -PropertyType DWord -Value 1
# Turn off Internet Explorer "First run" wizard
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -ValueName "DisableFirstRunCustomize" -PropertyType DWord -Value 1
# Turn off Internet Explorer Adobe Flash
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -ValueName "DisableFlashInIE" -PropertyType DWord -Value 1
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -ValueName "FlashPlayerEnabled" -PropertyType DWord -Value 0
# Set Default StartPage (fixme)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -ValueName "Start Page" -PropertyType DWord -Value "about:blank" -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -ValueName "Start Page" -PropertyType DWord -Value "about:blank" -Force
# Enforce new blank tabs
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\TabbedBrowsing" -ValueName "NewTabPageShow" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\TabbedBrowsing" -ValueName "NewTabPageShow" -PropertyType DWord -Value 0 -Force
###############################################
###### MS Store & Apps (master toggle)   ######
###############################################
# Disable MS Store Apps
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -ValueName "DisableStoreApps" -PropertyType DWord -Value 1 -Force
# Turn off all running backgrounds apps
# Basically a master toggle for GPO based settings
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivac" -ValueName "LetAppsRunInBackground" -PropertyType DWord -Value 2 -Force
# Turn off auto app updates
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -ValueName "AutoDownload" -PropertyType DWord -Value 2 -Force
# Disable app URI handlers
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "EnableAppUriHandlers" -PropertyType DWord -Value 0 -Force


###############################################
###### 			Remote Desktop           ######
###############################################
# Enforce Strong Remote Desktop Encryption
Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -ValueName "SecurityLayer" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -ValueName "MinEncryptionLevel" -PropertyType DWord -Value 3 -Force


###############################################
###### 				Security             ######
##      https://msrc-blog.microsoft.com/     ##
###############################################
# Disable NTFS Last-Access Timestamps
Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" -ValueName "NtfsDisableLastAccessUpdate" -PropertyType DWord -Value 1 -Force
# Remove MasterKeyLegacyCompliance
Remove-ItemProperty -Path "HKLM\SOFTWARE\Microsoft\Cryptography\Protect\Providers\df9d8cd0-1501-11d1-8c7a-00c04fc297eb" -ValueName "MasterKeyLegacyCompliance" -PropertyType DWord -Value 0 -Force
# Enforce SEHOP (OS takes care of it)
#New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -ValueName "DisableExceptionChainValidation" -PropertyType DWord -Value 0 -Force
# Enforce DEP (OS takes care of it)
# bcdedit /set nx AlwaysON
# Allow and enable (if possible) IPSec NAT.
New-Item -Path "HKLM\SYSTEM\CurrentControlSet\Services\PolicyAgent" -ValueName "AssumeUDPEncapsulationContextOnSendRule" -PropertyType DWord -Value 2 -Force
# DO NOT enforce ASLR!
# https://msrc-blog.microsoft.com/2010/12/08/on-the-effectiveness-of-dep-and-aslr/
# https://mspoweruser.com/windows-aslr-flaw-heres-can-fix/
# There are several drawbacks, and the software developer should decide if using DEP & ASLR makes sense e.g. Everything does not use ASLR because it's a search replacement for e.g. Cortana.
#New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -ValueName "MitigationOptions" -PropertyType Binary -Value ([byte[]](00,01,01,00,00,00,00,00,00,00,00,00,00,00,00,00))
# Require security devide "Password for Work" (not needed unless you use it)
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -ValueName "RequireSecurityDevice" -PropertyType DWord -Value 1 -Force
# Turn off CDM
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "fDisableCdm" -PropertyType DWord -Value 1 -Force


# Disable HTTP Printing - this will not break printing out HTTP websites!
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -ValueName "DisableHTTPPrinting" -PropertyType DWord -Value 1 -Force

# Do not allow Windows Search to Index encrypted storages
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ValueName "AllowIndexingEncryptedStoresOrItems" -PropertyType DWord -Value 0 -Force
# Turn off Printer Web PnP Downloads
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -ValueName "DisableWebPnPDownload" -PropertyType DWord -Value 1 -Force
# Allow all drivers to be loaded
# WARNING: Bootloop if changed!
#New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" -ValueName "DriverLoadPolicy" -PropertyType DWord -Value 7 -Force

# GPO hardening
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -ValueName "fMinimizeConnections" -PropertyType DWord -Value 1 -Force
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -ValueName "fBlockNonDomain" -PropertyType DWord -Value 1 -Force
#New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -ValueName "NoGPOListChanges" -PropertyType DWord -Value 0 -Force




# Prevent empty sessions
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -ValueName "allownullsessionfallback" -PropertyType DWord -Value 0 -Force
# Turn off LM Hash
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "NoLmHash" -PropertyType DWord -Value 1 -Force
# Turn off blank passwords
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "LimitBlankPasswordUse" -PropertyType DWord -Value 1 -Force

# Turn on LDAP Client Integrity Check
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ldap" -ValueName "LDAPClientIntegrity" -PropertyType DWord -Value 1 -Force
# NTLMMinServerSec
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -ValueName "NTLMMinServerSec" -PropertyType DWord -Value 536870912 -Force
# Enforce default protection mode
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -ValueName "ProtectionMode" -PropertyType DWord -Value 1 -Force


# Turn off shared connection gui
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -ValueName "NC_ShowSharedAccessUI" -PropertyType DWord -Value 0 -Force
# Restrict Remote SAM (fixme)

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa]
"RestrictRemoteSAM"="O:BAG:BAD:(A;;RC;;;BA)"
# Turn on Credentials Delegation
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" -ValueName "AllowProtectedCreds" -PropertyType DWord -Value 1 -Force
# CredSSP Patch Causing RDP Authentication Error due to Encryption Oracle Remediation
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP" -ValueName "AllowEncryptionOracle" -PropertyType DWord -Value 2 -Force
# Delete Pagefile.sys at Shutdown
Set-ItemProperty -Path "HKLM:\SYSTEM\Current\ControlSet\Control\Session Manager\Memory Management" -ValueName "ClearPageFileAtShutDown" -PropertyType DWord -Value 1 -Force
<# Server
# https://support.microsoft.com/en-us/help/3000483/ms15-011-vulnerability-in-group-policy-could-allow-remote-code-execution
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -ValueName "RequireMutualAuthentication" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -ValueName "RequireIntegrity" -PropertyType DWord -Value 1

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths]
"\\\\*\\SYSVOL"="RequiredMutualAuthentication=1, RequireIntegrity=1"
"\\\\*\\NETLOGON"="RequiredMutualAuthentication=1, RequireIntegrity=1" (fixme)

# https://support.microsoft.com/en-us/help/3116180/ms15-124-cumulative-security-update-for-internet-explorer-december-8-2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\InternetExplorer\Main\FeatureControl" -ValueName "FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\InternetExplorer\Main\FeatureControl" -ValueName "FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING" -PropertyType DWord -Value 1
# https://support.microsoft.com/en-us/help/3140245/update-to-enable-tls-1-1-and-tls-1-2-as-default-secure-protocols-in-wi

# Server only - Clear plain-text passwords from WDigest memory
# https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2016/2871997
# https://support.microsoft.com/kb/2871997
#Remove-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest" -ValueName "UseLogonCredential" -PropertyType DWord -Value 0 -Force

# Server only - Block unsafe ticket-granting (fixme)
# https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/ADV190006
# https://support.microsoft.com/en-us/help/4490425/updates-to-tgt-delegation-across-incoming-trusts-in-windows-server
# netdom.exe trust fabrikam.com /domain:contoso.com /EnableTGTDelegation:No | Out-Null

#>
# Turn off Adobe Reader DC Protected Mode (I use SumatraPDF instead)
#New-ItemProperty -Path "HKCU:\SOFTWARE\Adobe\Acrobat Reader\DC\Privileged" -ValueName "bProtectedMode" -PropertyType DWord -Value 1
#New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -ValueName "bProtectedMode" -PropertyType DWord -Value 1
# Turn off Adobe JavaScript
# https://www.adobe.com/devnet-docs/acrobatetk/tools/AppSec/sandboxprotections.html
# http://www.adobe.com/support/security/advisories/apsa09-07.html
#New-ItemProperty -Path "HKCU:\Software\Adobe\Acrobat Reader\9.0\JSPrefs" -ValueName "bEnableJS" -PropertyType DWord -Value 0
#New-ItemProperty -Path "HKCU:\Software\Adobe\Acrobat Reader\9.0\JSPrefs" -ValueName "bEnableConsoleOpen" -PropertyType DWord -Value 0
#New-ItemProperty -Path "HKCU:\Software\Adobe\Acrobat Reader\9.0\JSPrefs" -ValueName "benableMenuItems" -PropertyType DWord -Value 0



# Turn off WPD (not needed in 1909+ wpad js engine runs isolated)
# https://twitter.com/epakskape/status/1007316208087994368
# https://docs.microsoft.com/en-us/azure/active-directory/devices/hybrid-azuread-join-manual-steps + KB3165191 (MS16-077)
# AdGuard Home
#0.0.0.0 wpad wpad.my.home
#:: wpad wpad.my.home
# Win WPAD HOSTS
#0.0.0.0 wpad
#0.0.0.0 wpad.my.home
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\WinHttpAutoProxySvc" -ValueName "Start" -PropertyType DWord -Value 4 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -ValueName "WpadOverride" -PropertyType DWord -Value 0 -Force
# Turn off Homegroup (obsolete HG was removed)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HomeGroup" -ValueName "DisableHomeGroup" -PropertyType DWord -Value 1 -Force
# Turn off Sidebar Gadgets (obsolete but still in gpedit)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar" -ValueName "TurnOffSidebar" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar" -ValueName "TurnOffUnsignedGadgets" -PropertyType DWord -Value 1
# Turn off "Active Desktop"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "ForceActiveDesktopOn" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoActiveDesktop" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoActiveDesktopChanges" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" -ValueName "NoAddingComponents" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" -ValueName "NoComponents" -PropertyType DWord -Value 1 -Force
# Turn on certificate checks for apps (does not exists on LTSB(C))
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers" -ValueName "authenticodeenabled" -PropertyType DWord -Value 1 -Force
# Turn off network options from Lock Screen
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "DontDisplayNetworkSelectionUI" -PropertyType DWord -Value 1
# Turn off shutdown options from Lock Screen
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "ShutdownWithoutLogon" -PropertyType DWord -Value 0
# Turn on Data Execution Prevention (DEP)
bcdedit /set `{current`} nx OptOut | Out-Null
#bcdedit /set `{current`} nx OptIn | Out-Null
# Turn off Windows Script Host
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -ValueName "Enabled" -PropertyType DWord -Value 0
# Turn on Windows Firewall
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -ValueName "EnableFirewall" -ErrorAction SilentlyContinue
# Turn off automatic installation of new network devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -ValueName "AutoSetup" -PropertyType DWord -Value 0
# Enable network profile -> public (disables file sharing, device discovery, and more...)
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -ValueName "Category" -ErrorAction SilentlyContinue
# Set unknown networks profiles to public
Set-NetConnectionProfile -NetworkCategory Public
# Turn off Wi-Fi Hotspot reports
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -ValueName "value" -PropertyType DWord -Value 0 -Force
# Disallow Autoplay for non-volume devices
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -ValueName "NoAutoplayfornonVolume" -PropertyType DWord -Value 1 -Force
# Turn off Clipboard History Feature
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Clipboard" -ValueName "EnableClipboardHistory" -PropertyType DWord -Value 0 -Force
# Allowed to format and eject removable media <-> 'Administrators and Interactive Users'
# <deleted> = (Default)
# 0000000 = Administrators only
# 0000001 = Administrators and power users
# 0000002 = Administrators and interactive users (CIS)
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "AllocateDASD2" -PropertyType DWord -Value 2 -Force
# Turn off verbose start
#New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system" -ValueName verbosestatus -PropertyType DWord -Value 1 -Force
# Turn off unsafe online help functions
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "HelpQualifiedRootDir" -PropertyType hex -Value 00,00 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "HelpQualifiedRootDir" -PropertyType hex -Value 00,00 -Force
# Disable search via web from within apps
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ValueName "AllowSearchToUseLocation" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ValueName "ConnectedSearchPrivacy" -PropertyType DWord -Value 3 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ValueName "ConnectedSearchSafeSearch" -PropertyType DWord -Value 3 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ValueName "ConnectedSearchUseWeb" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ValueName "ConnectedSearchUseWebOverMeteredConnections" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ValueName "DeviceHistoryEnabled" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ValueName "DisableWebSearch" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ValueName "HasAboveLockTips" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ValueName "PreventRemoteQueries" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -ValueName "BingSearchEnabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -ValueName "CortanaConsent" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -ValueName "IsMicrophoneAvailable" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -ValueName "IsWindowsHelloActive" -PropertyType DWord -Value 0
# Turn off "Hide Drives With No Media"
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ValueName "HideDrivesWithNoMedia" -PropertyType DWord -Value 0 -Force
# Turn off UPnP Discovery
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\DirectPlayNATHelp\DPNHUPnP" -ValueName "UPnPMode" -PropertyType DWord -Value 2 -Force
# Miracast / PlayTo  (end of life product)
#New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\MiracastReceiver" -ValueName "NetworkQualificationEnabled" -PropertyType DWord -Value 0 -Force
#New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\MiracastReceiver" -ValueName "ConsentToast" -PropertyType DWord -Value 2 -Force
#New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\MiracastReceiver" -ValueName "Primary Authorization Method" -PropertyType DWord -Value 3 -Force
#New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\MiracastReceiver" -ValueName "Secondary Authorization Method" -PropertyType DWord -Value 0 -Force
#New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\MiracastReceiver" -ValueName "Tertiary Authorization Method" -PropertyType DWord -Value 0 -Force
#New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\MiracastReceiver" -ValueName "EnabledOnACOnly"-PropertyType DWord -Value 0 -Force
#New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PlayToReceiver" -ValueName "AutoEnabled" -PropertyType DWord -Value 0 -Force
# Turn off Hotspot 2.0 Networking
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WlanSvc\AnqpCache" -ValueName "OsuRegistrationStatus" -PropertyType DWord -Value 0 -Force
# Turn off LMHOSTS lookup
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -ValueName "EnableLMHOSTS" -PropertyType DWord -Value 0 -Force
# Turn off Domain Name Devolution
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -ValueName "UseDomainNameDevolution" -PropertyType DWord -Value 0 -Force
# Turn off Fast Restart (Hibernate/Sleep instead of shutting down) to prevent disk encryption errors with third party tools (fixed in 1909+?)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -ValueName "HiberbootEnabled" -PropertyType DWord -Value 0
# Turn off Clipboard History capability
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "AllowClipboardHistory" -PropertyType DWord -Value 0 -Force
# Turn on untrusted Font blocking (WD controlled)
# <deleted> = (Default)
# 00,10,a5,d4,e8,00,00,00 (1000000000000) = Block untrusted fonts and log events (CIS)
# 00,20,4a,a9,d1,01,00,00 (2000000000000) = Do not block untrusted fonts
# 00,30,ef,7d,ba,02,00,00 (3000000000000) = Log events without blocking untrusted fonts
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\MitigationOptions" -ValueName "MitigationOptions_FontBocking" -PropertyType hex -Value 00,10,a5,d4,e8,00,00,00 -Force
# Turn on "Prevent enabling lock screen camera"
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -ValueName "NoLockScreenCamera" -PropertyType DWord -Value 1 -Force
# Turn off all Online Tips
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "AllowOnlineTips" -PropertyType DWord -Value 0 -Force
# Turn off SMB v1 (removed in 1709)
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
#New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "SMB1" -PropertyType DWord -Value 0 -Force
Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force
# Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
# Turn on Structured Exception Handling Overwrite Protection (SEHOP - default on)
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -ValueName "DisableExceptionChainValidation" -PropertyType DWord -Value 0 -Force
# Turn on Safe DLL search mode (SafeDllSearchMode)
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -ValueName "SafeDllSearchMode" -PropertyType DWord -Value 1 -Force
# Turn off Enable Font Providers
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "EnableFontProviders" -PropertyType DWord -Value 0 -Force
# Turn off Microsoft Peer-to-Peer Networking Services
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Peernet" -ValueName "Disabled" -PropertyType DWord -Value 1 -Force
# Turn off IPv6 (Ensure TCPIP6 Parameter 'DisabledComponents <-> '0xff (255))
# - I use IPv6 and my router filters Teredo/6to4/ISATAP traffic. -
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
#New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" -ValueName "DisabledComponents" -PropertyType DWord -Value 000000a -Force
# Turn off Turn off handwriting recognition error reporting
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" -ValueName "PreventHandwritingErrorReports" -PropertyType DWord -Value 1 -Force
# Turn off the "Order Prints" picture task
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoOnlinePrintsWizard" -PropertyType DWord -Value 1 -Force
# Turn off "Publish to Web" task for files and folders
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoPublishingWizard" -PropertyType DWord -Value 1 -Force
# Turn off User Activities
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "UploadUserActivities" -PropertyType DWord -Value 0 -Force
# Turn off "Offer Remote Assistance"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -ValueName "fAllowToGetHelp" -PropertyType DWord -Value 0
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -ValueName "CreateEncryptedOnlyTickets" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -ValueName "AllowFullControl" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -ValueName "AllowToGetHelp" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -ValueName "EnableChatControl" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -ValueName "MaxTicketExpiry" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -ValueName "MaxTicketExpiryUnits" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -ValueName "fDenyTSConnection" -PropertyType DWord -Value 1 -Force
# Turn on Enhanced anti-spoofing for Facial Detection (if in use)
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" -ValueName "EnhancedAntiSpoofing" -PropertyType DWord -Value 1 -Force
# Turn off Facial Biometrics
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics" -ValueName "Enabled" -PropertyType DWord -Value 0 -Force
# Turn on and enforce Data Execution Prevention
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "DisableHHDEP" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -ValueName "NoDataExecutionPrevention" -PropertyType DWord -Value 0 -Force
# Prevent Remote Desktop Services
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -ValueName "UserAuthentication" -PropertyType DWord -Value 1
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "DenyTSConnections" -PropertyType DWord -Value 1 -Force
# Turn off COM port redirection
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "DisableCcm" -PropertyType DWord -Value 1 -Force
# Turn off drive redirection
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "DisableCdm" -PropertyType DWord -Value 1 -Force
# Turn off LPT port redirection
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "DisableLPT" -PropertyType DWord -Value 1 -Force
# Turn off Plug and Play device redirection
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "DisablePNPRedir" -PropertyType DWord -Value 1 -Force
# Turn off Cloud Search
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ValueName "AllowCloudSearch" -PropertyType DWord -Value 0 -Force
# Turn off Online Help
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "DisableInHelp" -PropertyType DWord -Value 1 -Force
# Disable Remote Registry
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry" -ValueName "Start" -PropertyType DWord -Value 4 -Force
# Disable LLMNR (Port: 5355)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -ValueName "EnableMulticast" -PropertyType DWord -Value 0
# Turn on Retpoline to migrate Spectre v2
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -ValueName FeatureSettingsOverride -PropertyType DWord -Value 1024 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -ValueName FeatureSettingsOverrideMask -PropertyType DWord -Value 1024 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -ValueName "cadca5fe-87d3-4b96-b7fb-a231484277cc" -PropertyType DWord -Value 0
# Turn off access to mapped drives from app running with elevated permissions with Admin Approval Mode enabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "EnableLinkedConnections" -PropertyType DWord -Value 0
# Do not let any Website provide locally relevant content by accessing language list
Set-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -ValueName "HttpAcceptLanguageOptOut" -PropertyType DWord -Value 1
# Turn off Administrative Shares
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "AutoShareWks" -PropertyType DWord -Value 0
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "AutoShareServer" -PropertyType DWord -Value 0 -Force
# Turn off Domain Picture Passwords
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "BlockDomainPicturePassword" -PropertyType DWord -Value 1 -Force
##########################################################
###### 					Task Manager                ######
##########################################################
# Turn off MS Task Manager (I use Process Hacker)
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "DisableTaskMgr" -PropertyType DWord -Value 1 -Force
#New-ItemProperty -Path "HKLM:\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "DisableTaskMgr" -PropertyType DWord -Value 1 -Force
##########################################################
###### 				    .NET Framework              ######
##########################################################
# Turn off Telemetry Data in .NET Core
# https://www.michaelcrump.net/part12-aspnetcore/
setx -Ux DOTNET_CLI_TELEMETRY_OPTOUT 1 | Out-Null
setx -Ux DOTNET_SKIP_FIRST_TIME_EXPERIENCE 1 | Out-Null
# Install NET 3.5 offline
# DISM.exe /Online /Add-Package /PackagePath:”C:%sourcessxsmicrosoft-windows-netfx3-ondemand-package.cab”
# Get-WindowsOptionalFeature -FeatureName NetFx3 -Online
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -ValueName SvcHostSplitThresholdInKB -PropertyType DWord -Value $ram -Force
# Enforce on .NET 4 runtime for all apps
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework -ValueName OnlyUseLatestCLR" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework" -ValueName OnlyUseLatestCLR -PropertyType DWord -Value 1 -Force
# Improve cryptography for .NET Framework v4+
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -ValueName "SchUseStrongCrypto" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -ValueName "SchUseStrongCrypto" -PropertyType DWord -Value 1
##########################################################
###### 					Login                       ######
##########################################################
# Turn off System Recovery and Factory reset
reagentc /disable 2>&1 | Out-Null
# Turn off automatic recovery mode during boot
# bcdedit /set `{current`} BootStatusPolicy IgnoreAllFailures | Out-Null
# Turn off insecure guest logons
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -ValueName "AllowInsecureGuestAuth" -PropertyType DWord -Value 0 -Force
# Turn on F8 boot menu options
#bcdedit /set `{current`} BootMenuPolicy Legacy | Out-Null
# Turn off user first sign-in animation
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "EnableFirstLogonAnimation" -PropertyType DWord -Value 0 -Force
# Wait for network at computer startup and logon
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "SyncForegroundPolicy" -PropertyType DWord -Value 1 -Force
##########################################################
###### 				Notification Center             ######
##########################################################
# Turn off "New App Installed" notification
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -ValueName "NoNewAppAlert" -PropertyType DWord -Value 1 -Force
# Hide notification about sign in with Microsoft under Windows Security
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows Security Health\State" -ValueName "AccountProtection_MicrosoftAccount_Disconnected" -PropertyType DWord -Value 1 -Force
##########################################################
###### 						Backup                  ######
######					(Macrium Reflect)           ######
##########################################################
# Enable System Restore
#Enable-ComputerRestore -Drive $env:SystemDrive
#Get-ScheduledTask -TaskName SR | Enable-ScheduledTask
#Get-Service -ValueName swprv, vss | Set-Service -StartupType Manual
#Get-Service -ValueName swprv, vss | Start-Service
#Get-CimInstance -ClassName Win32_ShadowCopy | Remove-CimInstance
# Turn on automatic backups of registry to `\System32\config\RegBack` folder
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" -ValueName "EnablePeriodicBackup" -PropertyType DWord -Value 1 -Force
##########################################################
###### 					Windows Features            ######
# https://docs.microsoft.com/en-us/powershell/dsc/reference/resources/windows/windowsoptionalfeatureresource
# https://docs.microsoft.com/en-us/powershell/module/servermanager/uninstall-windowsfeature?view=winserver2012r2-ps
# Get installed features via: get-windowsoptionalfeature -online
##########################################################
# Uninstall unwanted optional features
$uninstallfeatures = @(
    "IIS-CommonHttpFeatures"
    "IIS-HttpErrors"
    "IIS-WebServer"
    "IIS-WebServerRole"
    "Internet-Explorer-Optional-amd64"
    "MultiPoint-Connector-Services"
    "MultiPoint-Connector"
    "MultiPoint-Tools"
    "NET-Framework-Core"                                                    # .NET Core runtimes
    "NetFx3"									                            # .NET Framework 2.0 3.5 runtimes (I use abdh. offline installer because the online installer waste around 400+ MB after extraction)
    "SMB1Protocol-Client"
    "SMB1Protocol-Deprecation"
    "SMB1Protocol-Server"
    "SMB1Protocol"
    "SmbDirect"
    "TelnetClient"
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
    "Windows-Defender-ApplicationGuard"
    "Windows-Defender-Default-Definitions"									# Do NOT uninstall at best disable it
    "Windows-Identity-Foundation"
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
    "PowerShell-V2"
    "SearchEngine-Client-Package"
    "VirtualMachinePlatform"
    "WCF-TCP-PortSharing45"
)


foreach ($installfeatures in $installfeatures) {
    Write-Output "Installing $installfeatures"
    Install-WindowsFeature -ValueName $installfeatures -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null
}

# Turn off Touchpad Sensitivity
# 0 = Most sensitive
# 1 = High sensitivity
# 2 = Medium sensitivity (default)
# 3 = Low sensitivity
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PrecisionTouchPad" -ValueName "AAPThreshold " -PropertyType DWord -Value 99 -Force
# Turn off Remote Desktop
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "AllowSignedFiles" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "DisablePasswordSaving" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Conferencing" -ValueName "NoRDS" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "AllowSignedFiles" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "AllowUnsignedFiles" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "CreateEncryptedOnlyTickets" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "DisablePasswordSaving" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "fAllowToGetHelp" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "fAllowUnsolicited" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "fDenyTSConnections" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "fEnableUsbBlockDeviceBySetupClass" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "fEnableUsbNoAckIsochWriteToDevice" -PropertyType Dword -Value 80 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "fEnableUsbSelectDeviceByInterface" -PropertyType Dword -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" -ValueName "AllowRemoteShellAccess" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\RemoteAdminSettings" -ValueName "Enabled" -PropertyType Dword -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\RemoteDesktop" -ValueName "Enabled" -PropertyType Dword -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\UPnPFramework" -ValueName "Enabled" -PropertyType Dword -Value 0 -Force
# Turn on Windows Photo Viewer association
New-PSDrive -ValueName HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
New-Item -Path $("HKCR:\$type\shell\open") -Force | Out-Null
New-Item -Path $("HKCR:\$type\shell\open\command") | Out-Null
Set-ItemProperty -Path $("HKCR:\$type\shell\open") -ValueName "MuiVerb" -PropertyType ExpandString -Value "@%ProgramFiles%\Windows Photo Viewer\photoviewer.dll,-3043"
Set-ItemProperty -Path $("HKCR:\$type\shell\open\command") -ValueName "(Default)" -PropertyType ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
# Needed for Linux "Subsystem" (Windows >= 1803)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -ValueName "AllowDevelopmentWithoutDevLicense" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -ValueName "AllowAllTrustedApps" -PropertyType DWord -Value 1
# Turn on Aero Shake
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ValueName "DisallowShaking" -ErrorAction SilentlyContinue
# Turn off Maintenance (will break Defrag, Storage Sense & Backup etc.)
#New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -ValueName MaintenanceDisabled -PropertyType DWord -Value 1 -Force
# Turn off Wifi Sense
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager" -ValueName "WiFiSenseCredShared" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager" -ValueName "WiFiSenseOpen" -PropertyType DWord -Value 0 -Force
#New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -ValueName value -PropertyType DWord -Value 0 -Force
# Turn off Windows Compatibility Manager
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -ValueName DisablePCA -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -ValueName DisablePCA -PropertyType DWord -Value 1 -Force
# Use the "PrtScn" button to open screen snipping
#New-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -ValueName PrintScreenKeyForSnippingEnabled -PropertyType DWord -Value 1 -Force
# Remove default printers "Microsoft XPS Document Writer" & "Microsoft Print to PDF
Remove-Printer -ValueName Fax, "Microsoft XPS Document Writer", "Microsoft Print to PDF" -ErrorAction SilentlyContinue
# Turn off Game Information downloads
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameUX" -ValueName "DownloadGameInfo" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameUX" -ValueName "GameUpdateOptions" -PropertyType DWord -Value 0 -Force
# Turn off Windows Game Recording & Broadcasting (it does not matter if you enable/disable it, it's my own preference MS fixed performancd regressions)
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -ValueName "AllowgameDVR" -PropertyType DWord -Value 0 -Force
# Turn off Game Bar
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -ValueName AppCaptureEnabled -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\System\GameConfigStore -ValueName GameDVR_Enabled" -PropertyType DWord -Value 0 -Force
# Turn off Game Mode
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\GameBar" -ValueName AllowAutoGameMode -PropertyType DWord -Value 0 -Force
# Turn off Game Bar tips
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\GameBar" -ValueName ShowStartupPanel -PropertyType DWord -Value 0 -Force
# Uninstall Default Fax Printer Service
Remove-Printer -ValueName "Fax" -ErrorAction SilentlyContinue
##########################################################
###### 					MS One Drive                ######
##########################################################
Stop-Process -ValueName OneDrive -Force -ErrorAction SilentlyContinue
Start-Process -FilePath "$env:SystemRoot\SysWOW64\OneDriveSetup.exe" -ArgumentList "/uninstall" -Wait
Stop-Process -ValueName explorer
IF (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"))
{
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Force
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -ValueName "DisableFileSyncNGSC" -PropertyType DWord -Value 1
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -ValueName "DisableFileSync" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -ValueName "DisableMeteredNetworkFileSync" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -ValueName "DisableLibrariesDefaultSaveToOneDrive" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\OneDrive -ValueName DisablePersonalSync" -PropertyType DWord -Value 1 -Force
Remove-ItemProperty -Path "HKCU:\Environment" -ValueName "OneDrive" -Force -ErrorAction SilentlyContinue
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
Unregister-ScheduledTask -TaskName *OneDrive* -Confirm:$false
##########################################################
###### 						Sound                   ######
##########################################################
# Turn off default sound scheme
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -ValueName "NoChangingSoundScheme" -PropertyType DWord -Value 1
# Turn off Windows Startup sound
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" -ValueName "DisableStartupSound" -PropertyType DWord -Value 1
# Disable default sounds and set it to "No Sounds" (fixme)
$SoundScheme = ".None"
	Get-ChildItem -Path "HKCU:\AppEvents\Schemes\Apps\*\*" | ForEach-Object {
		If (!(Test-Path "$($_.PsPath)\$($SoundScheme)")) {
			New-Item -Path "$($_.PsPath)\$($SoundScheme)" | Out-Null
		}
		If (!(Test-Path "$($_.PsPath)\.Current")) {
			New-Item -Path "$($_.PsPath)\.Current" | Out-Null
		}
		$Data = (Get-ItemProperty -Path "$($_.PsPath)\$($SoundScheme)" -ValueName "(Default)" -ErrorAction SilentlyContinue)."(Default)"
		Set-ItemProperty -Path "$($_.PsPath)\$($SoundScheme)" -ValueName "(Default)" -PropertyType String -Value $Data
		Set-ItemProperty -Path "$($_.PsPath)\.Current" -ValueName "(Default)" -PropertyType String -Value $Data
	}
Set-ItemProperty -Path "HKCU:\AppEvents\Schemes" -ValueName "(Default)" -PropertyType String -Value $SoundScheme
##########################################################
###### 						Mouse                   ######
##########################################################
# Turn on enhanced mouse pointer precision
#Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -ValueName "MouseSpeed" -PropertyType String -Value 1
#Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -ValueName "MouseThreshold1" -PropertyType String -Value 6
#Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -ValueName "MouseThreshold2" -PropertyType String -Value 10
##########################################################
###### 					Windows Updates             ######
##########################################################
# Silence MRT Tool (you still can whenever you want manually dl and execute it)
Set-ItemProperty -Path "HKLM:\Software\Microsoft\MRT" -ValueName "DontReportInfectionInformation" -PropertyType DWord -Value 1 - Force
# Supress any Windows Update restarts
Set-ItemProperty -Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings" -ValueName "UxOption" -PropertyType DWord -Value 1
# Reveal latest Windows Update time (LastSuccessTime)
# HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\ResultsInstall
# Turn off all Windows Updates (forever)
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "SetDisableUXWUAccess" -PropertyType DWord -Value 1 -Force
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "NoAutoUpdate" -PropertyType DWord -Value 1 -Force
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" -ValueName "DisableWindowsUpdateAccess" -PropertyType DWord -Value 1 -Force
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" -ValueName "DisableWindowsUpdateAccessMode" -PropertyType DWord -Value 0 -Force
# Turn off new Windows Update UI (I use WuMgr or WUMT)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX" -ValueName "IsConvergedUpdateStackEnabled" -PropertyType DWord -Value 0 -Force
# Turn off Windows Update deferrals (fixme)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "DeferFeatureUpdates" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "DeferQualityUpdates" -PropertyType DWord -Value 0 -Force
# Turn off driver offers via WUS
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "ExcludeWUDriversInQualityUpdate" -PropertyType DWord -Value 1
# Turn off driver updates (obsolete in 1909+)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -ValueName "DriverUpdateWizardWuSearchEnabled" -PropertyType DWord -Value 0 -Force
# Turn off Malicious SOFTWARE Removal Tool offering over WUS
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -ValueName "DontPromptForWindowsUpdate" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -ValueName "DontSearchWindowsUpdate" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -ValueName "DriverUpdateWizardWuSearchEnabled" -PropertyType DWord -Value 0
# Turn off device metadata retrieval from Internet
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -ValueName "PreventDeviceMetadataFromNetwork" -PropertyType DWord -Value 1
# Disable Preview Builds
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -ValueName "AllowBuildPreview" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -ValueName "EnableExperimentation" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -ValueName "EnablePreviewBuilds" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\SOFTWARE\Microsoft\WindowsSelfHost\Applicability" -ValueName "EnablePreviewBuilds" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\SOFTWARE\Microsoft\WindowsSelfHost\Applicability" -ValueName "ThresholdFlightsDisabled" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\SOFTWARE\Microsoft\WindowsSelfHost\Applicability" -ValueName "Ring" -PropertyType string -Value "Disabled" -Force
# Turn on automatic updates for other Microsoft products e.g. MS Office
# https://docs.microsoft.com/en-us/windows/win32/wua_sdk/opt-in-to-microsoft-update
# https://social.technet.microsoft.com/Forums/en-US/479fae70-62ea-4f00-b1a9-fdbba0ba1bc8/how-to-enable-windows-updates-for-other-ms-products-for-all-users?forum=win10itprosetup
#$ServiceManager = New-Object -ComObject "Microsoft.Update.ServiceManager"
#$ServiceManager.ClientApplicationID = "My App"
#$NewService = $ServiceManager.AddService2("7971f918-a847-4430-9279-4a52d1efe18d",7,"")
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\7971F918-A847-4430-9279-4A52D1EFE18D" -ValueName "RegisteredWithAU" -PropertyType Dword -Value 1 -Force
# Turn off Windows Update restart notification
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -ValueName RestartNotificationsAllowed2 -PropertyType DWord -Value 0 -Force
# Turn off and delete reserved storage after the next update installation
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" -ValueName "BaseHardReserveSize" -PropertyType QWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" -ValueName "BaseSoftReserveSize" -PropertyType QWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" -ValueName "HardReserveAdjustment" -PropertyType QWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" -ValueName "MinDiskSize" -PropertyType QWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" -ValueName "ShippedWithReserves" -PropertyType DWord -Value 0 -Force
# Disable P2P Updates (1703+)
# dword:00000000 = off
# dword:00000002 = LAN only
# dword:00000003 = Lan and Internet
# Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -ValueName "DODownloadMode" -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -ValueName "DownloadMode" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -ValueName "DODownloadMode" -PropertyType DWord -Value 100 -Force
# Turn off Windows Update automatic restart
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "NoAutoRebootWithLoggedOnUsers" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "AUPowerManagement" -PropertyType DWord -Value 0
##########################################################
###### 					Language                    ######
##########################################################
# Set default Code page to UTF-8
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Nls\CodePage" -ValueName "ACP" -PropertyType String -Value 65001
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Nls\CodePage" -ValueName "OEMCP" -PropertyType String -Value 65001
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Nls\CodePage" -ValueName "MACCP" -PropertyType String -Value 65001
# DO NOT USE THIS: https://superuser.com/questions/269818/change-default-code-page-of-windows-console-to-utf-8
#REG ADD HKCU\Console\%SystemRoot^%_system32_cmd.exe /v CodePage /t REG_DWORD /d 65001
#New-Item -ErrorAction Ignore HKCU:\Console\%SystemRoot%_system32_cmd.exe
#Set-ItemProperty HKCU:\Console\%SystemRoot%_system32_cmd.exe CodePage 65001
### NONO ^^
# Set the default input method to the English language
Set-WinDefaultInputMethodOverride "0409:00000409"
# Turn on secondary "en-US" keyboard (workaround)
$langs = Get-WinUserLanguageList
$langs.Add("en-US")
Set-WinUserLanguageList $langs -Force
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
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -ValueName "DragFullWindows" -PropertyType String -Value 1
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -ValueName "MenuShowDelay" -PropertyType String -Value 400
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -ValueName "UserPreferencesMask" -PropertyType Binary -Value ([byte[]](158,30,7,128,18,0,0,0))
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -ValueName "MinAnimate" -PropertyType String -Value 1
Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -ValueName "KeyboardDelay" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ValueName "ListviewAlphaSelect" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ValueName "ListviewShadow" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ValueName "TaskbarAnimations" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -ValueName "VisualFXSetting" -PropertyType DWord -Value 3
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\DWM" -ValueName "EnableAeroPeek" -PropertyType DWord -Value 1
# Turn off NTFS Last Access Time stamps (Fsutil.exe)
# https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-behavior
# https://ss64.com/nt/fsutil.html
fsutil behavior set DisableLastAccess 1 | Out-Null
#fsutil behavior set disable8dot3 1 | Out-Null
# Turn off Modern UI swap file (get around 256 MB extra space)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -ValueName "SwapfileControl" -PropertyType Dword -Value 0
# Remove PerfLogs
Remove-Item $env:SystemDrive\PerfLogs -Recurse -Force -ErrorAction SilentlyContinue
# Remove LOCALAPPDATA\Temp
Remove-Item $env:LOCALAPPDATA\Temp -Recurse -Force -ErrorAction SilentlyContinue
# Remove SYSTEMROOT\Temp
Restart-Service -ValueName Spooler -Force
Remove-Item -Path "$env:SystemRoot\Temp" -Recurse -Force -ErrorAction SilentlyContinue
##########################################################
######                      Display                 ######
##########################################################
# Turn off Touch Screen Support
New-ItemProperty -Path "HKCU:\Software\Microsoft\Wisp\Touch" -ValueName "TouchGate" -PropertyType DWord -Value 0 -Force
# Disable Windows Startup Delay (fixme) (needs investigation)
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\Current\Version\Explorer\Serialize" -ValueName "StartupDelayInMSec" -PropertyType Dword -Value 0 -Force
# Turn off default display- and sleep-mode timeouts via powercfg
powercfg /X monitor-timeout-ac 0 | Out-Null
powercfg /X monitor-timeout-dc 0 | Out-Null
powercfg /X standby-timeout-ac 0 | Out-Null
powercfg /X standby-timeout-dc 0 | Out-Null
# Enable per-app System DPI awareness
New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -ValueName "EnablePerProcessSystemDPI" -PropertyType DWord -Value 1 -Force
##########################################################
######                  Action Center               ######
##########################################################
# Turn off Action Center Notifications
#New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Wndows\Explorer" -ValueName "DisableNotificationCenter" -PropertyType Dword -Value 1 -Force
# Turn off Action Center Sidebar
# New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" -ValueName "UseActionCenterExperience " -PropertyType DWord -Value 0 -Force
# Turn on Action Center Push Notifications
#Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -ValueName "DisableNotificationCenter" -ErrorAction SilentlyContinue
#Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" -ValueName "ToastEnabled" -ErrorAction SilentlyContinue
# Turn off Battery Fly-out UI
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" -ValueName "UseWin32BatteryFlyout " -PropertyType DWord -Value 1 -Force
# Turn off Network Fly-out UI
# 0 = Default fly-out
# 1 = Opens Network Settings window
# 2 = Windows 8/8.1 style sidebar
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Control Panel\Settings\Network" -ValueName "ReplaceVan" -PropertyType DWord -Value 2 -Force
# Turn off New Volume Control
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\MTCUVC" -ValueName "EnableMtcUvc" -PropertyType DWord -Value 0 -Force
#
#
#
##########################################################
######                      Time                    ######
##########################################################
# Turn off NTP Client (DO NOT disable NTP, better use a secure server instead)
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient" -ValueName "Enabled" -PropertyType DWord -Value 0 -Force
# Turn on BIOS time (UTC)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -ValueName "RealTimeIsUniversal" -PropertyType DWord -Value 1
# Turn on BIOS time (local time)
#Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -ValueName "RealTimeIsUniversal" -ErrorAction SilentlyContinue
# Change NTP server to pool.ntp.org
w32tm /config /syncfromflags:manual /manualpeerlist:"0.pool.ntp.org 1.pool.ntp.org 2.pool.ntp.org 3.pool.ntp.org"
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\W32time\Parameters" -ValueName "NtpServer" -PropertyType String -Value "pool.ntp.org,0x8" -Force
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\W32time\Parameters" -ValueName "NTP" -PropertyType DWord -Value 3 (fixme)
#Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient" -ValueName "CrossSiteSyncFlags" -PropertyType DWord -Value 2 -Force
#Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient" -ValueName "ResolvePeerBackoffMaxTimes" -PropertyType DWord -Value 7 -Force
#Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient" -ValueName "ResolvePeerBackoffMinutes" -PropertyType DWord -Value 15 -Force
#Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient" -ValueName "SpecialPollInterval" -PropertyType DWord -Value 1024 -Force
#
#
#
#################################################################
###### DNS (Cloudflare, enforce DNS via Router/PI always!) ######
#################################################################
# Set custom Windows DNS (Cloudflare example)
Get-NetAdapter -Physical | Set-DnsClientServerAddress -ServerAddresses 1.1.1.1,1.0.0.1,2606:4700:4700::1111,2606:4700:4700::1001
#
#
#
#
##########################################################
######              Task Scheduler                   #####
##########################################################
# Turn off Task Scheduler migrates several security problems but is problematic to disable (fixme)
#Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\Schedule" -ValueName "Start" -PropertyType DWord -Value 4 -Force
# Create a task via Task Scheduler to clear the "\SoftwareDistribution\Download" folder automatically every 4 weeks (Monday).
$action = New-ScheduledTaskAction -Execute powershell.exe -Argument @"
	`$getservice = Get-Service -ValueName wuauserv
	`$getservice.WaitForStatus("Stopped", "01:00:00")
	Get-ChildItem -Path `$env:SystemRoot\SoftwareDistribution\Download -Recurse -Force | Remove-Item -Recurse -Force
"@
$trigger = New-JobTrigger -Weekly -WeeksInterval 4 -DaysOfWeek Monday -At 11am
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

# (fixme)
#Get-ScheduledTask | Where-Object {$_.TaskName -match "{Telemetry, Application Experience"} | Unregister-ScheduledTask -Confirm:$false
# Unregister every task
# Tasks are been stored here: `C:\Windows\System32\Tasks` if you want to delete everything use `C:\Windows\System32\tasks\ {*}"`
Get-ScheduledTask | Where-Object {$_.TaskName -match "{*"} | Unregister-ScheduledTask -Confirm:$false


## Disable all controversial scheduler tasks, it's enough to disable them, no need to remove them.
# Some are not integrated or by default disabled in LTSC e.g. BthSQM, just ignore the warnings!
# https://docs.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask?view=win10-ps
#Disable-ScheduledTask -TaskName "\Microsoft\Windows\Application Experience\CreateObjectTask"                            # License Validation
Disable-ScheduledTask -TaskName "\Microsoft\Office\OfficeTelemetry\AgentFallBack2016"
Disable-ScheduledTask -TaskName "\Microsoft\Office\OfficeTelemetry\Office Automatic Updates 2.0"                        # Stop automatic automatic updates
Disable-ScheduledTask -TaskName "\Microsoft\Office\OfficeTelemetry\OfficeTelemetryAgentLogOn2016"
Disable-ScheduledTask -TaskName "\Microsoft\Office\OfficeTelemetryAgentFallBack"
Disable-ScheduledTask -TaskName "\Microsoft\Office\OfficeTelemetryAgentLogOn"
Disable-ScheduledTask -TaskName "\Microsoft\Windows\AppID\SmartScreenSpecific"
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Application Experience\AitAgent"
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Application Experience\ProgramDataUpdater"
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Application Experience\StartupAppTask"
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Autochk\Proxy"
Disable-ScheduledTask -TaskName "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask"
Disable-ScheduledTask -TaskName "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
Disable-ScheduledTask -TaskName "\Microsoft\Windows\DiskFootprint\Diagnostics"
Disable-ScheduledTask -TaskName "\Microsoft\Windows\FileHistory\File History (maintenance mode)"
Disable-ScheduledTask -TaskName "\Microsoft\Windows\NetTrace\GatherNetworkInfo"
Disable-ScheduledTask -TaskName "\Microsoft\Windows\PI\Sqm-Tasks"
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem"
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Speech\SpeechModelDownloadTask"
Disable-ScheduledTask -TaskName "\Microsoft\Windows\UpdateOrchestrator\Maintenance Install"
Disable-ScheduledTask -TaskName "\Microsoft\Windows\UpdateOrchestrator\Reboot"
Disable-ScheduledTask -TaskName "\Microsoft\Windows\User Profile Service\HiveUploadTask"
Disable-ScheduledTask -TaskName "\StartIsBack health check"                                                             # Startisback++ update & maintainance check
Get-ScheduledTask -TaskPath "\Microsoft\Office\Office 15 Subscription Heartbeat\" | Disable-ScheduledTask
Get-ScheduledTask -TaskPath "\Microsoft\Office\Office 16 Subscription Heartbeat\" | Disable-ScheduledTask
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\" | Disable-ScheduledTask       # Consolidator & UsbCeip
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Feedback\Siuf" | Disable-ScheduledTask                                  # SIUF strings & SIUF settings
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Location" | Disable-ScheduledTask
Get-ScheduledTask -TaskPath "\Microsoft\Windows\RemoteAssistance" | Disable-ScheduledTask
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Shell\FamilySafetyMonitor\" | Disable-ScheduledTask
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Shell\FamilySafetyRefresh\" | Disable-ScheduledTask
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Shell\FamilySafetyUpload\" | Disable-ScheduledTask
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Windows Error Reporting\QueueReporting\" | Disable-ScheduledTask
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Workplace Join" | Disable-ScheduledTask
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
# https://docs.microsoft.com/en-us/windows-server/security/tls/manage-tls#configuring-tls-cipher-suite-order
# https://www.acunetix.com/blog/articles/tls-ssl-cipher-hardening/
# For Windows to CP:
# ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256
# Disable-TlsCipherSuite -ValueName "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P256"
# Disable-TlsCipherSuite -ValueName "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P384"
# Disable-TlsCipherSuite -ValueName "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256"
# Disable-TlsCipherSuite -ValueName "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P384"
# Disable-TlsCipherSuite -ValueName "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P256"
# Disable-TlsCipherSuite -ValueName "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P384"
# Disable-TlsCipherSuite -ValueName "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
# Disable-TlsCipherSuite -ValueName "TLS_RSA_WITH_AES_128_CBC_SHA"
# Disable-TlsCipherSuite -ValueName "TLS_RSA_WITH_AES_128_CBC_SHA256"
# Disable-TlsCipherSuite -ValueName "TLS_RSA_WITH_AES_256_CBC_SHA"
# Disable-TlsCipherSuite -ValueName "TLS_RSA_WITH_AES_256_CBC_SHA256"
#
# Only for older OS Builds!
# Path does not exist on an cipher updated system!
# SCHANNEL is empty unless you request it e.g. VMWare or in case you use a Windows Server
# Set but do not enforce!
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128" -ValueName "Enabled" -PropertyType DWord -Value ffffffff
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256" -ValueName "Enabled" -PropertyType DWord -Value ffffffff
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56" -ValueName "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL" -ValueName "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128" -ValueName "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128" -ValueName "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128" -ValueName "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128" -ValueName "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128" -ValueName "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128" -ValueName "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128" -ValueName "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168" -ValueName "Enabled" -PropertyType DWord -Value 0
# Key Exchanges
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" -ValueName "Enabled" -PropertyType DWord -Value ffffffff
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\ECDH" -ValueName "Enabled" -PropertyType DWord -Value ffffffff
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS" -ValueName "Enabled" -PropertyType DWord -Value ffffffff
# Hashes
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5" -ValueName "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA" -ValueName "Enabled" -PropertyType DWord -Value ffffffff
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA256" -ValueName "Enabled" -PropertyType DWord -Value ffffffff
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA384" -ValueName "Enabled" -PropertyType DWord -Value ffffffff
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA512" -ValueName "Enabled" -PropertyType DWord -Value ffffffff
# Protocols
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client" -ValueName "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client" -ValueName "DisabledByDefault" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server" -ValueName "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server" -ValueName "DisabledByDefault" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client" -ValueName "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client" -ValueName "DisabledByDefault" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server" -ValueName "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server" -ValueName "DisabledByDefault" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -ValueName "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -ValueName "DisabledByDefault" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -ValueName "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -ValueName "DisabledByDefault" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -ValueName "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -ValueName "DisabledByDefault" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -ValueName "Enabled" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -ValueName "DisabledByDefault" -PropertyType DWord -Value 1
#Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -ValueName "Enabled" -PropertyType DWord -Value ffffffff
#Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -ValueName "DisabledByDefault" -PropertyType DWord -Value 0
#Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -ValueName "Enabled" -PropertyType DWord -Value ffffffff
#Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -ValueName "DisabledByDefault" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -ValueName "Enabled" -PropertyType DWord -Value ffffffff
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -ValueName "DisabledByDefault" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -ValueName "Enabled" -PropertyType DWord -Value ffffffff
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -ValueName "DisabledByDefault" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -ValueName "Enabled" -PropertyType DWord -Value ffffffff
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -ValueName "DisabledByDefault" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -ValueName "Enabled" -PropertyType DWord -Value ffffffff
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -ValueName "DisabledByDefault" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" -ValueName "Enabled" -PropertyType DWord -Value ffffffff
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" -ValueName "DisabledByDefault" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -ValueName "Enabled" -PropertyType DWord -Value ffffffff
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -ValueName "DisabledByDefault" -PropertyType DWord -Value 0
# Cipher Suites (order) (fixme)
Set-ItemProperty -Path "HKLM:\HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -ValueName "Functions" -PropertyType String -Value TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002] (fixme)
"EccCurves"=hex(7):4e,00,69,00,73,00,74,00,50,00,33,00,38,00,34,00,00,00,4e,00,\
  69,00,73,00,74,00,50,00,32,00,35,00,36,00,00,00,00,00


##########################################################
###### 					Java Hardening               #####
###### (fixme) check if installed or not
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
###### 					Network Stack                #####
##########################################################
# Turn off Teredo (fixme, not a dword)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition" -ValueName "Teredo_State" -PropertyType DWord -Value Disabled -Force
# Disable TCP/IP Auto-Tuning
# See here, http://technet.microsoft.com/en-us/magazine/2007.01.cableguy.aspx
netsh.exe interface tcp set global autotuninglevel= disabled
# IPv6
# Turn off IP source routing protection level
# 0000000 = No additional protection, source routed packets are allowed
# 0000001 = Medium, source routed packets ignored when IP forwarding is enabled
# 0000002 = Highest protection, source routing is completely disabled (CIS)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -ValueName "DisableIpSourceRouting" -PropertyType DWord -Value 2 -Force
# IPv4
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -ValueName "DisableIPSourceRouting" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -ValueName "EnableICMPRedirect" -PropertyType DWord -Value 0 -Force

# Enforce NetBIOS is disabled
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -ValueName "NoNameReleaseOnDemand" -PropertyType DWord -Value 1 -Force
# GLobal TCP stack hardening (fixme)
Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -ValueName "EnableDeadGWDetect" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -ValueName "EnableICMPRedirect" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -ValueName "IPEnableRouter" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -ValueName "KeepAliveTime" -PropertyType REG_DWORD -Value 0x000493E0 -Force
Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -ValueName "SynAttackProtect" -PropertyType DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -ValueName "TcpMaxHalfOpen" -PropertyType DWord -Value 64 -Force
Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -ValueName "TcpMaxHalfOpenRetried" -PropertyType DWord -Value 50 -Force


# Turn off all "useless" network adapter protocols
# http://techgenix.com/using-powershell-disable-network-adapter-bindings/
# https://community.idera.com/database-tools/powershell/ask_the_experts/f/powershell_for_windows-12/13716/disable-unnecessary-network-features-as-internet-protocol-version-6
# https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/enable-or-disable-a-server-network-protocol?view=sql-server-2017
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
		Enable-NetAdapterBinding -ValueName "*" -DisplayName $Component -ErrorAction SilentlyContinue | Out-Null
	}

}
#####
### Debunking: https://www.speedguide.net/articles/gaming-tweaks-5812
#####
# Turn off LargeSystemCache
# This is an XP tweak, the value is always 0 unless the driver gives an intent to Windows (10) to change it, there is no benefit changing it.
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -ValueName "LargeSystemCache" -PropertyType DWord -Value 0
#
# Nagle's Algorithm
# This tweak is useless since Windows 8.1+, because the Algorithm was replaced by a more efficent one. The default values are usually fine,
# I'm not aware of any professional gamer which still uses such a tweak or an outdated OS.
#
# Network Throttling Index & System Responsiveness
# SystemResponsiveness & NetworkThrottlingIndex <-> done by the OS itself and does not change anything
# https://msdn.microsoft.com/en-us/library/ms684247.aspx
# I enabled so that you can do a backup, apply the tweak, and see nothing happens.
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -ValueName "NetworkThrottlingIndex" -PropertyType DWord -Value 4294967295
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -ValueName "SystemResponsiveness" -PropertyType DWord -Value 20
# Multimedia Class Scheduler Service (MMCSS) tweaks
# https://msdn.microsoft.com/en-us/library/windows/desktop/ms684247.aspx
# default: 0, recommended: 0. Both 0x00 and 0xFFFFFFFF
# Affinity is OS controlled and never CPU, same like e.g. Core Parking and C-states.
# Application should exclusively ask MMCSS for its help otherwise nothing will be changed because the OS never knows if the app is MMCSS "optimized" or not.
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -ValueName "Affinity" -PropertyType DWord -Value 0
# (fixme) Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -ValueName "Background Only" -PropertyType REG_SZ "False"
# (fixme) Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -ValueName "Scheduling Category" -PropertyType REG_SZ "High"
# (fixme) Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -ValueName "SFIO Priority" -PropertyType REG_SZ "High"
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -ValueName "GPU Priority" -PropertyType DWord -Value 8
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -ValueName "Priority" -PropertyType DWord  -Value 2
# Turn off ECN Capability
# As per RFC3168 http://tools.ietf.org/html/rfc3168
Set-NetTCPSetting -SettingName InternetCustom -EcnCapability Disabled | Out-Null
# Turn off Receive Segment Coalescing State (RSC)
Disable-NetAdapterRsc -ValueName * | Out-Null
# Turn off Large Send Offload (LSO)
Disable-NetAdapterLso -ValueName * | Out-Null
# Turn off Receive-Side Scaling State (RSS)
netsh int tcp set global rss=disabled | Out-Null
##########################################################
###### 				PowerShell hardening             #####
##########################################################
# (fixme)
#for /R %f in (powershell*.exe) do (
#netsh advfirewall firewall add rule name=“PS-Allow-LAN (%f)" dir=out remoteip=localsubnet action=allow program=“%f" enable=yes
#netsh advfirewall firewall add rule name=“PS-Deny-All (%f)" dir=out action=block program=“%f" enable=yes
#)
#netsh advfirewall firewall add rule name=“PS-Allow-LAN" dir=out \ remoteip=localsubnet action=allow program="c:\windows\system32\WindowsPowerShell\v2.0\powershell.exe" \ enable=yes
#netsh advfirewall firewall add rule name=“PS-Deny-All" dir=out \ action=block program="c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe" \ enable=yes
#Set-NetFirewallProfile -Profiel Domain,Public,Private -Enabled true
# Turn off PowerShell Core telemetry (fixme)
# https://news.ycombinator.com/item?id=18629942
# https://docs.microsoft.com/en-us/powershell/scripting/whats-new/what-s-new-in-powershell-core-61?view=powershell-6#telemetry-can-only-be-disabled-with-an-environment-variable
##########################################################
###### 		Firewall (ignore the warnings)           #####
# Public profile should be used (privacy reasons)
# Following the CIS standards
##########################################################
# Turn off Remote Desktop
Disable-NetFirewallRule -DisplayGroup "Remote Desktop"
# Enforce that Firewall is running and enabled
Set-NetFirewallProfile -Profile * -Enabled True
<# Enforce Domain Profile defaults & CIS rec.
# Turn on Windows Firewall: Domain - Firewall state <-> 'On (recommended)'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" -ValueName "EnableFirewall" -PropertyType DWord -Value 1 -Force
# Enforce 'Windows Firewall: Domain: Inbound connections <-> 'Block (default)'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" -ValueName "DefaultInboundAction" -PropertyType DWord -Value 1 -Force
# Enforce 'Windows Firewall: Domain: Outbound connections <-> 'Allow (default)'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" -ValueName "DefaultOutboundAction" -PropertyType DWord -Value 1 -Force
# 'Windows Firewall: Domain: Settings: Display a notification <-> 'No'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" -ValueName "DisableNotifications" -PropertyType DWord -Value 0 -Force
# Set 'Windows Firewall: Domain: Logging: Name <-> '%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -ValueName "LogFilePath" -PropertyType String -Value "%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log" -Force
# Set 'Windows Firewall: Domain: Logging: Size limit (KB) <-> '16,384 KB or greater'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -ValueName "LogFileSize" -PropertyType DWord -Value 400 -Force
# Set 'Windows Firewall: Domain: Logging: Log dropped packets <-> 'Yes'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -ValueName "LogDroppedPackets" -PropertyType DWord -Value 1 -Force
# Set 'Windows Firewall: Domain: Logging: Log successful connections <-> 'Yes'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -ValueName "LogSuccessfulConnections" -PropertyType DWord -Value 1 -Force
#>

<# Enforce Private Profile defaults & CIS rec.
# Turn on Windows Firewall: Private - Firewall state <-> 'On (recommended)'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" -ValueName "EnableFirewall" -PropertyType DWord -Value 1 -Force
# Enforce 'Windows Firewall: Private: Inbound connections <-> 'Block (default)'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" -ValueName "DefaultInboundAction" -PropertyType DWord -Value 1 -Force
# Enforce 'Windows Firewall: Private: Outbound connections <-> 'Allow (default)'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" -ValueName "DefaultOutboundAction" -PropertyType DWord -Value 1 -Force
# 'Windows Firewall: Private: Settings: Display a notification <-> 'No'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" -ValueName "DisableNotifications" -PropertyType DWord -Value 0 -Force
# Set 'Windows Firewall: Private: Logging: Name <-> '%SYSTEMROOT%\System32\logfiles\firewall\Privatefw.log'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -ValueName "LogFilePath" -PropertyType String -Value "%SYSTEMROOT%\System32\logfiles\firewall\Privatefw.log" -Force
# Set 'Windows Firewall: Private: Logging: Size limit (KB) <-> '16,384 KB or greater'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -ValueName "LogFileSize" -PropertyType DWord -Value 400 -Force
# Set 'Windows Firewall: Private: Logging: Log dropped packets <-> 'Yes'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -ValueName "LogDroppedPackets" -PropertyType DWord -Value 1 -Force
# Set 'Windows Firewall: Private: Logging: Log successful connections <-> 'Yes'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -ValueName "LogSuccessfulConnections" -PropertyType DWord -Value 1 -Force
#>

<# Enforce Public Profile defaults & CIS rec.
# Turn on Windows Firewall: Public - Firewall state <-> 'On (recommended)'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" -ValueName "EnableFirewall" -PropertyType DWord -Value 1 -Force
# Enforce 'Windows Firewall: Public: Inbound connections <-> 'Block (default)'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" -ValueName "DefaultInboundAction" -PropertyType DWord -Value 1 -Force
# Enforce 'Windows Firewall: Public: Outbound connections <-> 'Allow (default)'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" -ValueName "DefaultOutboundAction" -PropertyType DWord -Value 1 -Force
# 'Windows Firewall: Public: Settings: Display a notification <-> 'No'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" -ValueName "DisableNotifications" -PropertyType DWord -Value 0 -Force
# Set 'Windows Firewall: Public: Logging: Name <-> '%SYSTEMROOT%\System32\logfiles\firewall\Publicfw.log'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -ValueName "LogFilePath" -PropertyType String -Value "%SYSTEMROOT%\System32\logfiles\firewall\Publicfw.log" -Force
# Set 'Windows Firewall: Public: Logging: Size limit (KB) <-> '16,384 KB or greater'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -ValueName "LogFileSize" -PropertyType DWord -Value 400 -Force
# Set 'Windows Firewall: Public: Logging: Log dropped packets <-> 'Yes'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -ValueName "LogDroppedPackets" -PropertyType DWord -Value 1 -Force
# Set 'Windows Firewall: Public: Logging: Log successful connections <-> 'Yes'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -ValueName "LogSuccessfulConnections" -PropertyType DWord -Value 1 -Force
#>
# 'Prohibit installation and configuration of Network Bridge on your DNS domain network <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -ValueName "NC_AllowNetBridge_NLA" -PropertyType DWord -Value 0 -Force
# 'Prohibit use of Internet Connection Sharing on your DNS domain network <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -ValueName "NC_ShowSharedAccessUI" -PropertyType DWord -Value 0 -Force
# 'Require domain users to elevate when setting a network's location <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -ValueName "NC_StdDomainUserSetLocatio" -PropertyType DWord -Value 1 -Force
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
	"checkappexec.microsoft.com"
	"d2k03kvdk5cku0.cloudfront.net"
	"d6wjo2hisqfy2.cloudfront.net"
	"drcwo519tnci7.cloudfront.net"
	"modern.watson.data.microsoft.com.akadns.net"
	"rad.live.com"
	"rad.msn.com"
	"redir.metaservices.microsoft.com"
	"schemas.microsoft.akadns.net"
	"storecatalogrevocation.storequality.microsoft.com"
	"v10.events.data.microsoft.com"
	"v10.vortex-win.data.microsoft.com"
	"v20.events.data.microsoft.com"
	"watson.microsoft.com"
	"wes.df.telemetry.microsoft.com"
	"www.bing.com"
	"www.msftconnecttest.com"
    "184-86-53-99.deploy.static.akamaitechnologies.com"
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
    "a978.i6g1.akamai.net"
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
    "adservice.google.com"
    "adservice.google.de"
    "aidps.atdmt.com"
    "aka-cdn-ns.adtech.de"
    "any.edge.bing.com"
    "apps.skype.com"
    "az361816.vo.msecnd.net"
    "az512334.vo.msecnd.net"
    "b.ads1.msn.com"
    "b.ads2.msads.net"
    "b.rad.msn.com"
    "bingads.microsoft.com"
    "bs.serving-sys.com"
    "c.atdmt.com"
    "c.msn.com"
    "cdn.atdmt.com"
    "cds26.ams9.msecn.net"
    "choice.microsoft.com.nsatc.net"
    "choice.microsoft.com"
    "client.wns.windows.com"
    "compatexchange.cloudapp.net"
    "corp.sts.microsoft.com"
    "corpext.msitadfs.glbdns2.microsoft.com"
    "cs1.wpc.v0cdn.net"
    "cy2.vortex.data.microsoft.com.akadns.net"
    "db3aqu.atdmt.com"
    "df.telemetry.microsoft.com"
    "diagnostics.support.microsoft.com"
    "e87.dspb.akamaidege.net"
    "e2835.dspb.akamaiedge.net"
    "e3843.g.akamaiedge.net"
    "e7341.g.akamaiedge.net"
    "e7502.ce.akamaiedge.net"
    "e8218.ce.akamaiedge.net"
    "e9483.a.akamaiedge.net"
    "ec.atdmt.com"
    "fe2.update.microsoft.com.akadns.net"
    "feedback.microsoft-hohm.com"
    "feedback.search.microsoft.com"
    "feedback.windows.com"
    "flex.msn.com"
    "flightingserviceweurope.cloudapp.net"
    "g.msn.com"
    "googleads.g.doubleclick.net"
    "h1.msn.com"
    "h2.msn.com"
    "hostedocsp.globalsign.com"
    "hubspot.net.edge.net"
    "hubspot.net.edgekey.net"
    "i1.services.social.microsoft.com.nsatc.net"
    "i1.services.social.microsoft.com"
    "insiderppe.cloudapp.net"
    "insiderservice.microsoft.com"
    "insiderservice.trafficmanager.net"
    "ipv6.msftncsi.com.edgesuite.net"
    "ipv6.msftncsi.com"
    "lb1.www.ms.akadns.net"
    "live.rads.msn.com"
    "livetileedge.dsx.mp.microsoft.com"
    "m.adnxs.com"
    "m.hotmail.com"
    "msedge.net"
    "msftncsi.com"
    "msnbot-65-55-108-23.search.msn.com"
    "msntest.serving-sys.com"
    "oca.telemetry.microsoft.com.nsatc.net"
    "oca.telemetry.microsoft.com"
    "onesettings-db5.metron.live.nsatc.net"
    "p.static.ads-twitter.com"
    "pagead46.l.doubleclick.net"
    "pre.footprintpredict.com"
    "preview.msn.com"
    "pricelist.skype.com"
    "reports.wes.df.telemetry.microsoft.com"
    "s.gateway.messenger.live.com"
    "s0.2mdn.net"
    "secure.adnxs.com"
    "secure.flashtalking.com"
    "services.wes.df.telemetry.microsoft.com"
    "settings-sandbox.data.microsoft.com"
    "settings-ssl.xboxlive.com-c.edgekey.net.globalredir.akadns.net"
    "settings-ssl.xboxlive.com-c.edgekey.net"
    "settings-ssl.xboxlive.com"
    "sls.update.microsoft.com.akadns.net"
    "sqm.df.telemetry.microsoft.com"
    "sqm.telemetry.microsoft.com.nsatc.net"
    "sqm.telemetry.microsoft.com"
    "ssw.live.com"
    "static.2mdn.net"
    "static.ads-twitter.com"
    "stats.g.doubleclick.net"
    "stats.l.doubleclick.net"
    "statsfe1.ws.microsoft.com"
    "statsfe2.update.microsoft.com.akadns.net"
    "statsfe2.ws.microsoft.com"
    "survey.watson.microsoft.com"
    "telecommand.telemetry.microsoft.com.nsatc.net"
    "telecommand.telemetry.microsoft.com"
    "telemetry.appex.bing.net"
    "telemetry.microsoft.com"
    "telemetry.urs.microsoft.com"
    "ui.skype.com"
    "view.atdmt.com"
    "vortex-bn2.metron.live.com.nsatc.net"
    "vortex-cy2.metron.live.com.nsatc.net"
    "vortex-sandbox.data.microsoft.com"
    "vortex-win.data.microsoft.com"
    "vortex.data.microsoft.com"
    "watson.live.com"
    "watson.microsoft.com"
    "watson.ppe.telemetry.microsoft.com"
    "watson.telemetry.microsoft.com.nsatc.net"
    "watson.telemetry.microsoft.com"
    "wdcpalt.microsoft.com"
    "wes.df.telemetry.microsoft.com"
    "win10.ipv6.microsoft.com"
    "www-google-analytics.l.google.com"
    "www.bingads.microsoft.com"
    "www.go.microsoft.akadns.net"
    "www.msftncsi.com"
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
$ips = @(
    # Too many IPs will cause svchost.exe to freak out
    # we are excluding AMS, Cloudfront & other CDN's.
    "2.22.61.43"
    "2.22.61.66"
    "23.218.212.69"
    "64.4.54.254"
    "65.39.117.230"
    "65.55.108.23"
    "134.170.30.202"
    "137.116.81.24"
    "157.56.106.189"
    "184.86.53.99"
    "204.79.197.200"
)
# Check firewall ruls and remove if already set
Remove-NetFirewallRule -DisplayName "Anti-Telemetry IPs" -ErrorAction SilentlyContinue
# Write new rules and give it a name
New-NetFirewallRule -DisplayName "Anti-Telemetry IPs" -Direction Outbound ` -Action Block -RemoteAddress ([string[]]$ips)
# Block Cortana via Firewall Rule (fixme)
New-NetFirewallRule -DisplayName "Anti Cortana Web Access" -Direction Outbound -Program "%windir%\systemapps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe" -Action Block
# Add local IPSec rules if IPSec is enabled.
netsh.exe advfirewall consec add rule name=Testing-IPSec-NETSH endpoint1=any port1=any endpoint2=localsubnet port2=3389,135,139,445,21,20,23 protocol=tcp profile=any action=requireinrequestout interfacetype=any auth1=computerpsk auth1psk=$ThePreSharedKey enable=yes
##########################################################
######              Bitlocker (VeraCrypt)           ######
# If you use VeraCrypt the entries are not written in reg
##########################################################
# Turn on machine account lockout threshold'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "MaxDevicePasswordFailedAttempts" -PropertyType DWord -Value 000000a -Force
# Prevent installation of devices that match any of these device IDs"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -ValueName "DenyDeviceIDs" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Prevent installation of devices that match any of these device IDs: Prevent installation of devices that match any of these device IDs <-> 'PCI\CC_0C0A' (fixme)
# Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -ValueName "1" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Prevent installation of devices that match any of these device IDs: Also apply to matching devices that are already installed. <-> 'True' (fixme)
# Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -ValueName "DenyDeviceIDsRetroactive" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Prevent installation of devices using drivers that match these device setup classes <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -ValueName "DenyDeviceClasses" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Prevent installation of devices using drivers that match these device setup classes: Prevent installation of devices using drivers for these device setup (fixme)
# {d48179be-ec20-11d1-b6b8-00c04fa372a7} - IEEE 1394 devices that support the SBP2 Protocol Class
# {7ebefbc0-3200-11d2-b4c2-00a0C9697d07} - IEEE 1394 devices that support the IEC-61883 Protocol Class
# {c06ff265-ae09-48f0-812c-16753d7cba83} - IEEE 1394 devices that support the AVC Protocol Class
# {6bdd1fc1-810f-11d0-bec7-08002be2092f} - IEEE 1394 Host Bus Controller Class
# Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -ValueName "DenyDeviceClasses" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
# "1"="{d48179be-ec20-11d1-b6b8-00c04fa372a7}"
# "1"="{7ebefbc0-3200-11d2-b4c2-00a0C9697d07}"
# "1"="{c06ff265-ae09-48f0-812c-16753d7cba83}"
# "1"="{6bdd1fc1-810f-11d0-bec7-08002be2092f}"
# Prevent installation of devices using drivers that match these device setup classes: Also apply to matching devices that are already installed. <-> 'True' (fixme)
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -ValueName "DenyDeviceClassesRetroactive" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab" -ValueName "DCSettingIndex" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
# (fixme) in case of no TPM chip, is there a Windows 10 without tpm which got the certification? I don't think so.
#
# Allow standby states (S1-S3) when sleeping (plugged-in)
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab" -ValueName "ACSettingIndex" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Allow access to BitLocker-protected fixed data drives from earlier versions of Windows <-> 'Disabled
Remove-Item -Path "HKLM:\Software\Policies\Microsoft\FVE" -ValueName "DVDiscoveryVolumeType" -PropertyType String -Value "" -Force
# Choose how BitLocker-protected fixed drives can be recovered <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "FDVRecovery" -PropertyType DWord -Value 1 -Force
# Allow data recovery agent
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "FDVManageDRA" -PropertyType DWord -Value 1 -Force
# Allow 48-Bit Recovery Password
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "FDVRecoveryPassword" -PropertyType DWord -Value 2 -Force
# Recovery Key <-> 'Enabled: Allow 256-bit recovery key'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "FDVRecoveryKey" -PropertyType DWord -Value 2 -Force
# Disable additional recovery options from the BitLocker setup wizard <-> 'Enabled: True'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "FDVHideRecoveryPage" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Save BitLocker recovery information to AD DS for fixed data drives <-> 'Enabled: False'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "FDVActiveDirectoryBackup" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Configure storage of BitLocker recovery information to AD DS <-> 'Enabled: Backup recovery passwords and key packages'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "FDVActiveDirectoryInfoToStore" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Do not enable BitLocker until recovery information is stored to AD DS for fixed data drives <-> 'Enabled: False'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "FDVRequireActiveDirectoryBackup" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Use of hardware-based encryption for fixed data drives <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "FDVHardwareEncryption" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Use of hardware-based encryption for fixed data drives: Use BitLocker software-based encryption when hardware encryption is not available <-> 'Enabled: True'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "FDVAllowSoftwareEncryptionFailover" -PropertyType DWord -Value 1 -Force
# Configure use of hardware-based encryption for fixed data drives: Restrict encryption algorithms and cipher suites allowed for hardware-based encryption <-> 'Enabled: False'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "FDVRestrictHardwareEncryptionAlgorithms" -PropertyType DWord -Value 0 -Force
# Restrict crypto algorithms or cipher suites to the following: <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "FDVAllowedHardwareEncryptionAlgorithms" -PropertyType hex -Value 32,00,2e,00,31,00,36,00,2e,00,38,00,34,00,30,00,2e,00,31,00,2e,00,31,00,30,00,31,00,2e,00,33,00,2e,00,34,00,2e,00,31,00,2e,00,32,00,3b,00,32,00,2e,00,31,00,36,00,2e,00,38,00,34,00,30,00,2e,00,31,00,2e,00,31,00,30,00,31,00,2e,00,33,00,2e,00,34,00,2e,00,31,00,2e,00,34,00,32,00,00,00,00,00 -Force -PropertyType hex -Value 00,00 -Force
# Configure use of passwords for fixed data drives <-> 'Disabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "FDVPassphrase" -PropertyType DWord -Value 0 -Force
# Configure use of smart cards on fixed data drives <-> 'Enabled' (no effect if no smart card was detected)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "FDVAllowUserCert" -PropertyType DWord -Value 1 -Force
# Require use of smart cards on fixed data drives <-> 'Enabled: True'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "FDVEnforceUserCert" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Allow enhanced PINs for startup <-> 'Enabled' (fixme)
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "UseEnhancedPin" -PropertyType DWord -Value 1 -Force
# Allow Secure Boot for integrity validation <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "OSAllowSecureBootForIntegrity" -PropertyType DWord -Value 1 -Force
# Choose how BitLocker-protected operating system drives can be recovered <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "OSRecovery" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Allow data recovery agent <-> 'Enabled: False'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "OSManageDRA" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Require 48-digit recovery password
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "OSRecoveryPassword" -PropertyType DWord -Value 2 -Force -ErrorAction SilentlyContinue
# Recovery Key <-> 'Enabled: Do not allow 256-bit recovery key'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "OSRecoveryKey" -PropertyType DWord -Value 2 -Force -ErrorAction SilentlyContinue
# Hide the recovery page from non adminstrators
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "OSHideRecoveryPage" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Save BitLocker recovery information to AD DS for operating system drives <-> 'Enabled: True'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "OSActiveDirectoryBackup" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Configure storage of BitLocker recovery information to AD DS <-> 'Enabled: Store recovery passwords and key packages'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "OSActiveDirectoryInfoToStore" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Do not enable BitLocker until recovery information is stored to AD DS for operating system drives <-> 'Enabled: True'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "OSRequireActiveDirectoryBackup" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Configure minimum PIN length for startup <-> 'Enabled: 7 or more characters'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "MinimumPIN" -PropertyType DWord -Value 20 -Force -ErrorAction SilentlyContinue
# Turn on ardware-based encryption for operating systemm drives
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "OSHardwareEncryption" -PropertyType DWord -Value 1 -Force
# Use BitLocker software-based encryption when hardware encryption is not available <-> 'Enabled: True'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "OSAllowSoftwareEncryptionFailover" -PropertyType DWord -Value 1 -Force
# Restrict encryption algorithms and cipher suites allowed for hardware-based encryption <-> 'Enabled: False'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "OSRestrictHardwareEncryptionAlgorithms" -PropertyType DWord -Value 0 -Force
# Restrict crypto algorithms or cipher suites to the following: <-> 'Enabled`
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "OSAllowedHardwareEncryptionAlgorithms" -PropertyType hex -Value 32,00,2e,00,31,00,36,00,2e,00,38,00,34,00,30,00,2e,00,31,00,2e,00,31,00,30,00,31,00,2e,00,33,00,2e,00,34,00,2e,00,31,00,2e,00,32,00,3b,00,32,00,2e,00,31,00,36,00,2e,00,38,00,34,00,30,00,2e,00,31,00,2e,00,31,00,30,00,31,00,2e,00,33,00,2e,00,34,00,2e,00,31,00,2e,00,34,00,32,00,00,00,00,00 -Force
# Passwords for operating system drives <-> 'Disabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "OSPassphrase" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Require additional authentication at startup <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "UseAdvancedStartup" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Allow BitLocker without a compatible TPM <-> 'Enabled: False'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "EnableBDEWithNoTPM" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Configure TPM startup <-> 'Enabled: 'Do not allow TPM'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "UseTPM" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Configure TPM startup PIN <-> 'Enabled: Require startup PIN with TPM'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "UseTPMPIN" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Configure TPM startup key: <-> 'Enabled: Do not allow startup key with TPM'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "UseTPMKey" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Configure TPM startup key and PIN <-> 'Enabled: Do not allow startup key and PIN with TPM'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "UseTPMKeyPIN" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Allow access to BitLocker-protected removable data drives from earlier versions of Windows <-> 'Disabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "RDVDiscoveryVolumeType" -PropertyType String -Value "" -Force
# BitLocker-protected removable drives can be recovered <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "RDVRecovery" -PropertyType DWord -Value 1 -Force
# BitLocker-protected removable drives can be recovered: Allow data recovery agent <-> 'Enabled: True'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "RDVManageDRA" -PropertyType DWord -Value 1 -Force
# BitLocker-protected removable drives can be recovered: Recovery Password <-> 'Enabled: Do not allow 48-digit recovery password'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "RDVRecoveryPassword" -PropertyType DWord -Value 2 -Force -ErrorAction SilentlyContinue
# BitLocker-protected removable drives can be recovered: Recovery Key <-> 'Enabled: Do not allow 256-bit recovery key'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "RDVRecoveryKey" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Omit recovery options from the BitLocker setup wizard <-> 'Enabled: True'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "RDVHideRecoveryPage" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Save BitLocker recovery information to AD DS for removable data drives <-> 'Enabled: False'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "RDVActiveDirectoryBackup" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Configure storage of BitLocker recovery information to AD DS: <-> 'Enabled: Backup recovery passwords and key packages'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "RDVActiveDirectoryInfoToStore" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Do not enable BitLocker until recovery information is stored to AD DS for removable data drives <-> 'Enabled: False'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "RDVRequireActiveDirectoryBackup" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Configure use of hardware-based encryption for removable data drives <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "RDVHardwareEncryption" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
# BitLocker software-based encryption when hardware encryption is not available <-> 'Enabled: True'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "RDVAllowSoftwareEncryptionFailover" -PropertyType DWord -Value 1 -Force
# Restrict encryption algorithms and cipher suites allowed for hardware-based encryption <-> 'Enabled: False'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "RDVRestrictHardwareEncryptionAlgorithms" -PropertyType DWord -Value 0 -Force
# Restrict crypto algorithms or cipher suites
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "RDVAllowedHardwareEncryptionAlgorithms" -PropertyType hex -Value 32,00,2e,00,31,00,36,00,2e,00,38,00,34,00,30,00,2e,00,31,00,2e,00,31,00,30,00,31,00,2e,00,33,00,2e,00,34,00,2e,00,31,00,2e,00,32,00,3b,00,32,00,2e,00,31,00,36,00,2e,00,38,00,34,00,30,00,2e,00,31,00,2e,00,31,00,30,00,31,00,2e,00,33,00,2e,00,34,00,2e,00,31,00,2e,00,34,00,32,00,00,00,00,00 -Force
# Passwords for removable data drives <-> 'Disabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "RDVPassphrase" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Smart cards on removable data drives <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "RDVAllowUserCert" -PropertyType DWord -Value 1 -Force
# Require use of smart cards on removable data drives <-> 'Enabled: True'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "RDVEnforceUserCert" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Deny write access to removable drives not protected by BitLocker <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "RDVDenyWriteAccess" -PropertyType DWord -Value 1 -Force
# Do not allow write access to devices configured in another organization <-> 'Enabled: False'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "RDVDenyCrossOrg" -PropertyType DWord -Value 1 -Force
# Drive encryption method and cipher strength (AES)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "EncryptionMethodWithXtsOs" -PropertyType DWord -Value 7 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ValueName "EncryptionMethodWithXtsRdv" -PropertyType DWord -Value 4 -Force
##########################################################
######              MS Office (LibreOffice)         ######
##########################################################
<#
# Turn on Microsoft Office Updates
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate" -ValueName "enableautomaticupdates" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate" -ValueName "hideenabledisableupdates" -PropertyType DWord -Value 1 -Force
# Block Macros by default in Office
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\access\security" -ValueName "blockcontentexecutionfrominternet" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\access\security" -ValueName "excelbypassencryptedmacroscan" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\access\security" -ValueName "vbawarnings" -PropertyType DWord -Value 4 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" -ValueName "excelbypassencryptedmacroscan" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\ms project\securit" -ValueName "vbawarnings" -PropertyType DWord -Value 4 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\ms project\security" -ValueName "level" -PropertyType DWord -Value 4 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" -ValueName "level" -PropertyType DWord -Value 4 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security" -ValueName "vbawarnings" -PropertyType DWord -Value 4 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\publisher\security" -ValueName "vbawarnings" -PropertyType DWord -Value 4 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\visio\security" -ValueName "blockcontentexecutionfrominternet" -PropertyType DWord -Value 4 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\visio\security" -ValueName "vbawarnings" -PropertyType DWord -Value 4 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\word\security" -ValueName "vbawarnings" -PropertyType DWord -Value 4 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\word\security" -ValueName "wordbypassencryptedmacroscan" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\common\security" -ValueName "automationsecurity" -PropertyType DWord -Value 0 -Force
# Turn off Office Fax services
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\services\fax" -ValueName "nofax" -PropertyType DWord -Value 1 -Force
# Turn off all Office Internet connections (Updates are still possible)
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\internet" -ValueName "useonlinecontent" -PropertyType DWord -Value 0 -Force
# Turn off One Drive login in Office
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\general" -ValueName "skydrivesigninoption" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\signin" -ValueName "signinoptions" -PropertyType DWord -Value 3 -Force
# Turn off Office Feedback
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\15.0\common\feedback" -ValueName "enabled" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\15.0\common\feedback" -ValueName "includescreenshot" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback" -ValueName "enabled" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback" -ValueName "includescreenshot" -PropertyType DWord -Value 0 -Force
# Turn off Data Collection
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\general" -ValueName "notrack" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\general" -ValueName "optindisable" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\general" -ValueName "shownfirstrunoptin" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\general" -ValueName "ptwoptin" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\general" -ValueName "bootedrtm" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\general" -ValueName "disablemovie" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\general" -ValueName "EnableFileObfuscation" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\general" -ValueName "Enablelogging" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm" -ValueName "EnableUpload" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -ValueName "accesssolution" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -ValueName "olksolution" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -ValueName "onenotesolution" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -ValueName "pptsolution" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -ValueName "projectsolution" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -ValueName "publishersolution" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -ValueName "visiosolution" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -ValueName "wdsolution" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -ValueName "xlsolution" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -ValueName "agave" -PropertyType DWord  -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -ValueName "appaddins" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -ValueName "comaddins" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -ValueName "documentfiles" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -ValueName "templatefiles" -PropertyType DWord -Value 1 -Force
# Turn off loading of external content in Office
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\outlook\options\mail" -ValueName "blockextcontent" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\outlook\options\mail" -ValueName "junkmailenablelinks" -PropertyType DWord -Value 0 -Force
# Turn off Online repair in Office
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate" -ValueName "onlinerepair" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate" -ValueName "fallbacktocdn" -PropertyType DWord -Value 0 -Force
# Turn off Telemetry agent
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Common" -ValueName "qmenable" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Common" -ValueName "sendcustomerdata" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Common" -ValueName "updatereliabilitydata" -PropertyType DWord -Value 0 -Force
#>

# (Dynamic Data Exchange) DDE Migration
# Not needed in LibreOffice
# https://wiki.documentfoundation.org/Feature_Comparison:_LibreOffice_-_Microsoft_Office#Spreadsheet_applications:_LibreOffice_Calc_vs._Microsoft_Excel
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Word\Options" -ValueName "DontUpdateLinks" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\15.0\Word\Options" -ValueName "DontUpdateLinks" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\14.0\Word\Options" -ValueName "DontUpdateLinks" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Word\Options\WordMail" -ValueName "DontUpdateLinks" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\15.0\Word\Options\WordMail" -ValueName "DontUpdateLinks" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\14.0\Word\Options\WordMail" -ValueName "DontUpdateLinks" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\OneNote\Options" -ValueName "DisableEmbeddedFiles" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\15.0\OneNote\Options" -ValueName "DisableEmbeddedFiles" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\14.0\OneNote\Options" -ValueName "DisableEmbeddedFiles" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Excel\Options" -ValueName "DontUpdateLinks" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Excel\Options" -ValueName "DDEAllowed" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Excel\Options" -ValueName "DDECleaned" -PropertyType DWord -Value 279 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\15.0\Excel\Options" -ValueName "DontUpdateLinks" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\15.0\Excel\Options" -ValueName "DDEAllowed" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\15.0\Excel\Options" -ValueName "DDECleaned" -PropertyType DWord -Value 117 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\14.0\Excel\Options" -ValueName "DontUpdateLinks" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\14.0\Excel\Options" -ValueName "DDEAllowed" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\14.0\Excel\Options" -ValueName "DDECleaned" -PropertyType DWord -Value 117 -Force


# Turn off Macros in Microsoft Office
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\word\security" -ValueName "blockcontentexecutionfrominternet" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" -ValueName "blockcontentexecutionfrominternet" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security" -ValueName "blockcontentexecutionfrominternet" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\15.0\word\security" -ValueName "blockcontentexecutionfrominternet" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\15.0\excel\security" -ValueName "blockcontentexecutionfrominternet" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\15.0\powerpoint\security" -ValueName "blockcontentexecutionfrominternet" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\14.0\msproject\security" -ValueName "VBAWarnings" -PropertyType DWord -Value 2 -Force

# Turn off Office Packer Objects (OLE) (fixme)
# https://blog.trendmicro.com/trendlabs-security-intelligence/new-cve-2014-4114-attacks-seen-one-week-after-fix/
# https://docs.microsoft.com/en-us/office365/troubleshoot/activation/control-block-ole-com
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\Microsoft\Office\16.0\Common\COM Compatibility" -ValueName "ActivationFilterOverride " -PropertyType DWord -Value 1 -Force


##########################################################
###### 				USer Account Control (UAC)      ######
##########################################################
# Turn on Admin Approval Mode
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "FilterAdministratorToken" -Value 1 -Force
# Enable LUA
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "EnableLUA" -Value 1 -Force
# Set UAC to high
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "ConsentPromptBehaviorAdmin" -PropertyType DWord -Value 5
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "PromptOnSecureDesktop" -PropertyType DWord -Value 1
# Make UAC Great Again (MUGA)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "ConsentPromptBehaviorUser" -PropertyType DWord -Value 3
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "DenyDeviceIDs" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "DisableAutomaticRestartSignOn" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "DSCAutomationHostEnabled" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "EnableCursorSuppression" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "EnableFullTrustStartupTasks" -PropertyType DWord -Value 2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "EnableInstallerDetection" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "EnableSecureUIAPaths" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "EnableUIADesktopToggle" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "EnableUwpStartupTasks" -PropertyType DWord -Value 2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "EnableVirtualization" -PropertyType DWord -Value 2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "ShutdownWithoutLogon" -PropertyType DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "SupportFullTrustStartupTasks" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "SupportUwpStartupTasks" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "undockwithoutlogon" -PropertyType DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "ValidateAdminCodeSignatures" -PropertyType DWord -Value 0
#################################################################################################################
###### 					Services                                                                           ######
###### 			Overview services (not all!)                                                                ######
# http://www.blackviper.com/service-configurations/black-vipers-windows-10-service-configurations/         ######
# Todo: Find a way to detect and disable all _xxx services automatically.                                  ######
# Todo: Sysrep needs dmwappushserivce.                                                                     ######
#################################################################################################################
# Turn off Autologger and clear the content
#Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger" -ValueName "AutoLogger-Diagtrack-Listener" -PropertyType Dword -Value 0
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
	"BcastDVRUserService_*"						# GameDVR and Broadcast User Service (fixme)
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
    "lfsvc"								    	# Geolocation Service   | Telemetry
    "MapsBroker"								# Downloaded Maps Manager   | Privacy
    "ndu"								        # Windows Network Data Usage Monitor    | Privacy (data leakage?)
    "NetTcpPortSharing"							# Net.Tcp Port Sharing Service
    "RemoteAccess"								# Routing and Remote Access
    "RemoteRegistry"							# Remote Registry | Security
    "SharedAccess"								# Internet Connection Sharing (ICS)
    "TrkWks"								    # Distributed Link Tracking Client
    "WbioSrvc"								    # Windows Biometric Service (required for Fingerprint reader / facial detection)
    "WMPNetworkSvc"								# Windows Media Player Network Sharing Service
    "wscsvc"								    # Windows Security Center Service
    "wlidsvc"                                   # Disable ability to use Microsoft Accounts
    #"BFE"										# Base Filtering Engine - Disable only if you don't use Windows Firewall e.g. for Comodo
	#"Dnscache "								# DNS Client (only if you use other DNS systems like Unbound/DNSCrypt) | Security & Telemetry
	#"EventSystem"								# COM+ Event System (security but problematic)
	#"iphlpsvc"									# IP Helper (IPv6 translation
	#"IpxlatCfgSvc"								# IP Translation Configuration Service
	#"Winmgmt"									# Windows Management Instrumentation | Security -> problematic
    #"AppMgmt"									# Application Management (needed for GPO software)
    #"WlanSvc"                                 	# WLAN AutoConfig | Security
    #"WSearch"                                 	# Windows Search used by e.g. Cortana & file index
)

# Hyper-V (Sandbox/VT/VM/WD/etc. basically the upper layer of Windows 10 new security concept, HVhost is the minimum which must run otherwise WD will cry: Mommy?)
<#
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

foreach ($services in $services) {
    Write-Output "Disabling $services"
    Get-Service -ValueName $services | Set-Service -StartupType Disabled
}


##########################################################
###### 				termsrv.dll Patching            ######
######				Against GitHub/MS ToS?          ######
##########################################################
# Todo
# (fixme)
# store errors / warnings (debug) in a sep. file in order to improve the script
# several other things, secret secret ....
# WHy no "undo" script and option? - The goal is to provide an all-in-one script which does not need to be reverted,
# other tweaks which might be critical to apply should be comment out or seperated into another file.
# Integrate OSbuilder? https://www.osdeploy.com/osbuilder/overview



##########################################################
###### 	Auto import all reg. files in same folder   ######
###### Todo: get rid of reg import?                 ######
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
###### Ensure you put the script under `C:\Scripts\`
# Todo: Copy script directtly to Windows folder and mark it as read-only?!
##########################################################
$Trigger= New-ScheduledTaskTrigger -At 11:30am –Weekly
$User= "NT AUTHORITY\SYSTEM"
# We don't need any W8 workaround here since we are on PS v6
$Action= New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "C:\Scripts\CK.ps1"
Register-ScheduledTask -TaskName "CKsWin10Hardening" -Trigger $Trigger -User $User -Action $Action -RunLevel Highest –Force



##########################################################
###### 		Environment variables editor            ######
######		http://www.rapidee.com/en/download
##########################################################
# (fixme)


##########################################################
###### 		Grab OpenVPN file automatically         ######
######		Example (for the lazy ones)             ######
##########################################################
#New-Item -ItemType Directory -Force -Path "~\OpenVPN\config"
#Invoke-WebRequest "https://insert-your-link-here.ovpn" -OutFile "~\OpenVPN\config\US East, Ashburn.ovpn"


###############################################
###### 		    (Audit) Logging          ######
###############################################
# Audit the default logging policy via auditpol.exe (fixme)
# auditpol.exe /get /category:*
# auditpol.exe /get /subcategory:"MPSSVC rule-level Policy Change,Filtering Platform policy change,IPsec Main Mode,IPsec Quick Mode,IPsec Extended Mode,IPsec Driver,Other System Events,Filtering Platform Packet Drop,Filtering Platform Connection"
auditpol.exe /set /subcategory:"MPSSVC rule-level Policy Change,Filtering Platform policy change,IPsec Main Mode,IPsec Quick Mode,IPsec Extended Mode,IPsec Driver,Other System Events,Filtering Platform Packet Drop,Filtering Platform Connection" /success:Enable /failure:Enable
# Disable logging via:
# auditpol.exe /set /subcategory:"MPSSVC rule-level Policy Change,Filtering Platform policy change,IPsec Main Mode,IPsec Quick Mode,IPsec Extended Mode,IPsec Driver,Other System Events,Filtering Platform Packet Drop,Filtering Platform Connection" /success:Disable /failure:Disable
#
# IPSec audit logging
Set-ItemProperty "HKLM\SYSTEM\CurrentControlSet\Services\PolicyAgent\Oakley" -ValueName "EnableLogging" -PropertyType DWord -Value 1 -Force
# Remove the default Autologger file (created by DiagTrack) and restrict access, this will not work on ARM versions (fixme).
$autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
If (Test-Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl") {
    Remove-Item "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl"
}
icacls $autoLoggerDir /deny SYSTEM:`(OI`)`(CI`)F | Out-Null




########################################################################
######              Local Group Policy Editor changes             ######
######            Not all changes are in registry hives!          ######
#       (fixme)
######                   Policy file Editor                       ######
# https://www.powershellgallery.com/packages/PolicyFileEditor/2.0.2    #
########################################################################
# Disable all Online tips
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "AllowOnlineTips" -PropertyType DWord -Data 0 Start-Sleep 2
# Turn off Tailored Experiences
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -ValueName "TailoredExperiencesWithDiagnosticDataEnabled" -PropertyType DWord -Data 0
Start-Sleep 2
# Enable encrypted NTFS pagefile
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "System\CurrentControlSet\Policies" -ValueName "NtfsEncryptPagingFile" -PropertyType DWord -Data 1
Start-Sleep 2
# Disable (global) Telemetry
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\DataCollection" -ValueName "AllowTelemetry" -PropertyType DWord -Data 0
Start-Sleep 2
# Turn off Windows Sidebar
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar" -ValueName "TurnOffSidebar" -PropertyType DWord -Data 1
Start-Sleep 2
# Do not allow Active Help
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" -ValueName "NoActiveHelp" -PropertyType DWord -Data 1
Start-Sleep 2
# Turn off Biometrics
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Biometrics" -ValueName "Enabled" -PropertyType DWord -Data 1
Start-Sleep 2
# Turn off Remote Desktop (fixme)
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Conferencing" -ValueName "NoRDS" -PropertyType DWord -Data 1
Start-Sleep 2
# Turn off Input personalization
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\InputPersonalization" -ValueName "AllowInputPersonalization" -PropertyType DWord -Data 0
Start-Sleep 2
# Turn off usage of geo location in Internet Explorer
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Internet Explorer\Geolocation" -ValueName "PolicyDisableGeolocation" -PropertyType DWord -Data 1
Start-Sleep 2
# Turn off Internet Explorer Update check
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Internet Explorer\Infodelivery\Restrictions" -ValueName "NoUpdateCheck" -PropertyType DWord -Data 1
Start-Sleep 2
# Turn off Internet Explorer Do not Track (DnT) Feature
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -ValueName "DoNotTrack" -PropertyType DWord -Data 0
Start-Sleep 2
# Turn off Internet Explorer "inPrivate Browsing" (similar to Incognito Mode or Private Browsing Mode)
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Internet Explorer\Privacy" -ValueName "EnableInPrivateBrowsing" -PropertyType DWord -Data 0
Start-Sleep 2
# Turn off SQM "Customer Improvement Program"
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Internet Explorer\SQM" -ValueName "DisableCustomerImprovementProgram" -PropertyType DWord -Data 0
Start-Sleep 2
# Turn off CEIP
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Messenger\Client" -ValueName "CEIP" -PropertyType DWord -Data 2
Start-Sleep 2
# Turn off AutoRun
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Messenger\Client" -ValueName "PreventAutoRun" -PropertyType DWord -Data 1
Start-Sleep 2
# Set Microsoft Edge default Cookie policy (disallow cookies)
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -ValueName "Cookies" -PropertyType DWord -Data 2
Start-Sleep 2
# Turn off MS Edge Error Reporting Feature
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" -ValueName "DoReport" -PropertyType DWord -Data 0
Start-Sleep 2
# Turn off MS Edge Queue Mode for Error Reports
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" -ValueName "ForceQueueMode" -PropertyType DWord -Data 0
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" -ValueName "DWFileTreeRoot" -PropertyType String -Data ""
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" -ValueName "DWNoExternalURL" -PropertyType DWord -Data 1
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" -ValueName "DWNoFileCollection" -PropertyType DWord -Data 1
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" -ValueName "DWNoSecondLevelCollection" -PropertyType DWord -Data 1
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" -ValueName "DWReporteeName" -PropertyType String -Data ""
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\SearchCompanion" -ValueName "DisableContentFileUpdates" -PropertyType DWord -Data 1
Start-Sleep 2
# Turn off SQM CEIP (global)
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\SQMClient\Windows" -ValueName "CEIPEnable" -PropertyType DWord -Data 0
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0080000000F0000F0D0B4EB5D3C24F17D10AE531C7DCEF4A94F4A085AD0D4C88B75082573E36F857A" -ValueName "Category" -PropertyType DWord -Data 1
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0080000000F0000F0D0B4EB5D3C24F17D10AE531C7DCEF4A94F4A085AD0D4C88B75082573E36F857A" -ValueName "CategoryReadOnly" -PropertyType DWord -Data 0
Start-Sleep 2
# Turn off Registration
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control" -ValueName "NoRegistration" -PropertyType DWord -Data 1
Start-Sleep 2
# Turn off KMS GenTicket (This will NOT break KMS)
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -ValueName "NoGenTicket" -PropertyType DWord -Data 1
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows NT\IIS" -ValueName "PreventIISInstall" -PropertyType DWord -Data 1
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows NT\Printers" -ValueName "PhysicalLocation" -PropertyType String -Data anonymous
Start-Sleep 2
# Turn off Consumer Experience
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\CloudContent" -ValueName "DisableWindowsConsumerFeatures" -PropertyType DWord -Data 1
Start-Sleep 2
# Turn off Advertising ID
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -ValueName "DisabledByGroupPolicy" -PropertyType DWord -Data 1
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\AppCompat" -ValueName "AITEnable" -PropertyType DWord -Data 0
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\AppCompat" -ValueName "DisableInventory" -PropertyType DWord -Data 1
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\AppCompat" -ValueName "DisableUAR" -PropertyType DWord -Data 1
Start-Sleep 2
# Turn off getting device info from Web
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -ValueName "PreventDeviceMetadataFromNetwork" -PropertyType DWord -Data 1
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" -ValueName "DisableSendGenericDriverNotFoundToWER" -PropertyType DWord -Data 1
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" -ValueName "DisableSendRequestAdditionalSoftwareToWER" -PropertyType DWord -Data 1
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Explorer" -ValueName "NoUseStoreOpenWith" -PropertyType DWord -Data 1
Start-Sleep 2
# Turn off downloads of additional Game Infos
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\GameUX" -ValueName "DownloadGameInfo" -PropertyType DWord -Data 0
Start-Sleep 2
# Turn off the "Do you want to update your Game" notification
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\GameUX" -ValueName "GameUpdateOptions" -PropertyType DWord -Data 0
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\GameUX" -ValueName "ListRecentlyPlayed" -PropertyType DWord -Data 0
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard" -ValueName "ExitOnMSICW" -PropertyType DWord -Data 1
Start-Sleep 2
# Turn off Location Provider
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -ValueName "DisableLocation" -PropertyType DWord -Data 1
Start-Sleep 2
# Turn off OneDrive Sync
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\OneDrive" -ValueName "DisableFileSyncNGSC" -PropertyType DWord -Data 1
Start-Sleep 2
# Silence OneDrive (fixme - GPO or reg?!)
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "Software\Microsoft\OneDrive" -ValueName "PreventNetworkTrafficPreUserSignIn" -PropertyType DWord -Data 1
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\PowerShell" -ValueName "EnableScripts" -PropertyType DWord -Data 1
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\PowerShell" -ValueName "ExecutionPolicy" -PropertyType String -Data "RemoteSigned"
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -ValueName "**del.EnableExperimentation" -PropertyType String -Data ""
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -ValueName "AllowBuildPreview" -PropertyType DWord -Data 0
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -ValueName "EnableConfigFlighting" -PropertyType DWord -Data 0
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "AsyncScriptDelay" -PropertyType DWord -Data 1
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "EnableLogonScriptDelay" -PropertyType DWord -Data 1
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{186f47ef-626c-4670-800a-4a30756babad}" -ValueName "ScenarioExecutionEnabled" -PropertyType DWord -Data 0
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{2698178D-FDAD-40AE-9D3C-1371703ADC5B}" -ValueName "**del.EnabledScenarioExecutionLevel" -PropertyType String -Data ""
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{2698178D-FDAD-40AE-9D3C-1371703ADC5B}" -ValueName "ScenarioExecutionEnabled" -PropertyType DWord -Data 0
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{67144949-5132-4859-8036-a737b43825d8}" -ValueName "**del.EnabledScenarioExecutionLevel" -PropertyType String -Data ""
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{67144949-5132-4859-8036-a737b43825d8}" -ValueName "ScenarioExecutionEnabled" -PropertyType DWord -Data 0
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{86432a0b-3c7d-4ddf-a89c-172faa90485d}" -ValueName "ScenarioExecutionEnabled" -PropertyType DWord -Data 0
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" -ValueName "ScenarioExecutionEnabled" -PropertyType DWord -Data 0
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{a7a5847a-7511-4e4e-90b1-45ad2a002f51}" -ValueName "**del.EnabledScenarioExecutionLevel" -PropertyType String -Data ""
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{a7a5847a-7511-4e4e-90b1-45ad2a002f51}" -ValueName "ScenarioExecutionEnabled" -PropertyType DWord -Data 0
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{C295FBBA-FD47-46ac-8BEE-B1715EC634E5}" -ValueName "ScenarioExecutionEnabled" -PropertyType DWord -Data 0
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{dc42ff48-e40d-4a60-8675-e71f7e64aa9a}" -ValueName "EnabledScenarioExecutionLevel" -PropertyType DWord -Data 1
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{dc42ff48-e40d-4a60-8675-e71f7e64aa9a}" -ValueName "ScenarioExecutionEnabled" -PropertyType DWord -Data 0
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{ecfb03d1-58ee-4cc7-a1b5-9bc6febcb915}" -ValueName "ScenarioExecutionEnabled" -PropertyType DWord -Data 0
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{ffc42108-4920-4acf-a4fc-8abdcc68ada4}" -ValueName "**del.EnabledScenarioExecutionLevel" -PropertyType String -Data ""
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{ffc42108-4920-4acf-a4fc-8abdcc68ada4}" -ValueName "ScenarioExecutionEnabled" -PropertyType DWord -Data 0
Start-Sleep 2
# Turn off Windows Errror Reporting
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -ValueName "Disabled" -PropertyType DWord -Data 1
Start-Sleep 2
# Do not send additional telemetry data
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -ValueName "DontSendAdditionalData" -PropertyType DWord -Data 1
Start-Sleep 2
# Disable Cortana
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ValueName "AllowCortana" -PropertyType DWord -Data 0
Start-Sleep 2
# Do not allow the usage of "Location"
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ValueName "AllowSearchToUseLocation" -PropertyType DWord -Data 0
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ValueName "ConnectedSearchPrivacy" -PropertyType DWord -Data 3
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ValueName "ConnectedSearchSafeSearch" -PropertyType DWord -Data 3
Start-Sleep 2
# Disabled connected Web search
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ValueName "ConnectedSearchUseWeb" -PropertyType DWord -Data 0
Start-Sleep 2
# Disable connected Web search behind metered connections
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ValueName "ConnectedSearchUseWebOverMeteredConnections" -PropertyType DWord -Data 0
Start-Sleep 2
# Disable the use of Web search
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ValueName "DisableWebSearch" -PropertyType DWord -Data 1
Start-Sleep 2
# Defer Windows upgrades (feature updates) - You still can manually install them!
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "DeferUpgrade" -PropertyType DWord -Data 1
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "DoNotConnectToWindowsUpdateInternetLocations" -PropertyType DWord -Data 1
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "**del.AutomaticMaintenanceEnabled" -PropertyType String -Data ""
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "**del.DetectionFrequency" -PropertyType String -Data ""
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "AUOptions" -PropertyType DWord -Data 2
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "DetectionFrequencyEnabled" -PropertyType DWord -Data 0
Start-Sleep 2
# Enable offering "featured updates"
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "EnableFeaturedSoftware" -PropertyType DWord -Data 1
Start-Sleep 2
# Do not auto-update (disabled)
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "NoAutoUpdate" -PropertyType DWord -Data 0
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "ScheduledInstallDay" -PropertyType DWord -Data 0
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "ScheduledInstallTime" -PropertyType DWord -Data 3
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\WMDRM" -ValueName "DisableOnline" -PropertyType DWord -Data 1
Start-Sleep 2
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\User\registry.pol -Key "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoInstrumentation" -PropertyType DWord -Data 1
Start-Sleep 2
# Turn off Internet Explorer internal logging
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\User\registry.pol -Key "Software\Policies\Microsoft\Internet Explorer\Safety\PrivacIE" -ValueName "DisableLogging" -PropertyType DWord -Data 1
Start-Sleep 2
# Turn off Windows tips (global)
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\User\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\CloudContent" -ValueName "DisableSoftLanding" -PropertyType DWord -Data 1
Start-Sleep 2
# Turn off MFU Tracing
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\User\registry.pol -Key "Software\Policies\Microsoft\Windows\EdgeUI" -ValueName "DisableMFUTracking" -PropertyType DWord -Data 1
# Ensure new GPO rules are been immediantly applied
gpupdate /force




##########################################################
###### 		        LockScreen                      ######
##########################################################
# Turn off Lock Screen app notifications
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "DisableLockScreenAppNotifications" -PropertyType DWord -Value 1
# Turn on Lock Screen
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -ValueName "NoLockScreen" -PropertyType DWord -Value 0
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -ValueName "NoLockScreen" -ErrorAction SilentlyContinue
# Turn off Lock Screen Image
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -ValueName "LockScreenOverlaysDisabled" -PropertyType DWord -Value 1
# Set your own Lock Screen image (fixme)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -ValueName "LockScreenImage" -PropertyType DWord -Value "C:\windows\web\screen\lockscreen.jpg"













###############################################################################
#                   OPTIONAL STUFF a.k.a. my fetish                           #
###############################################################################

##########################################################
###### 		        Compress OS & NTFS              ######
#    DO NOT USE IT, it's better to compress Wimlib/ESD   #
# (fixme) Compression negatively influcens security?!    #
##########################################################
# Compact.exe /F /CompactOS:always
# $tempfolders = @(“C:\Windows\Temp\*”, “C:\Windows\Prefetch\*”, “C:\Documents and Settings\*\Local Settings\temp\*”, “C:\Users\*\Appdata\Local\Temp\*”)
# NTFS comprssion can cause security problems.
# Remove-Item $tempfolders -force -recurse
# Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "System\CurrentControlSet\Policies" -ValueName NtfsDisableCompression -PropertyType DWord -Data 0


##########################################################
#    Optional usability tweaks and changed defaults      #
#       Needs to be enabled (uncomment) manually         #
##########################################################
# Enable Windows 10 F8 boot menu options #
# bcdedit /set `{current`} bootmenupolicy Legacy | Out-Null
# Workaround for DPI scaling issue with displays set to 125% (fixme) -> resets after reboot (explorer.exe restart) and shell crash
#New-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\Control Panel\Desktop" -ValueName "DpiScalingVer" -Value "0x00001018" -PropertyType DWORD -Force
#New-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\Control Panel\Desktop" -ValueName "Win8DpiScaling" -Value "0x00000001" -PropertyType DWORD -Force
#New-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\Control Panel\Desktop" -ValueName "LogPixels" -Value "0x00000078" -PropertyType DWORD -Force
# Show Computer shortcut on Desktop
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -ValueName "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -PropertyType DWord -Value 0
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -ValueName "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -PropertyType DWord -Value 0
# Add Desktop icon on Desktop
#New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}"
# Disable Superfetch
#Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -ValueName "EnableSuperfetch" -PropertyType DWord -Value 0 -Force
# Disable Windows Prefetcher
#Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -ValueName "EnablePrefetcher" -PropertyType DWord -Value 0 -Force
# Disable CLoud Notification
#Set-ItemProperty "HKLM:\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -ValueName "NoCloudApplicationNotification" -PropertyType DWord -Value 1 -Force
#Set-ItemProperty "HKCU:\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -ValueName "NoCloudApplicationNotification" -PropertyType DWord -Value 1 -Force
# Disable Disk Health Update Model
#Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\StorageHealth" -ValueName "AllowDiskHealthModelUpdates" -PropertyType DWord -Value 0 -Force
#Set-ItemProperty "HKCU:\Software\Policies\Microsoft\Windows\StorageHealth" -ValueName "AllowDiskHealthModelUpdates" -PropertyType DWord -Value 0 -Force



##########################################################
#                   Optional removal                     #
#       Needs to be enabled (uncomment) manually         #
##########################################################
# Remove "Computer" shortcut from Desktop
#Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -ValueName "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
#Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -ValueName "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
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

#########################################
#           Restart blah warning        #
# (fixme) Restart or crash explorer.exe #
#########################################
Write-Host "Yo kid, listen up push a button to restart your system..." -ForegroundColor Black -BackgroundColor White
$key = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
Write-Host "Restarting..."
Restart-Computer
}
