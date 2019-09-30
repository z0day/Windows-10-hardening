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
        Version  : 0.2 (public version) ALPHA

#>


<#
       .SYNOPSIS
                        - Windows 10 hardening with some extra candy -

       .DESCRIPTION
        This PowerShell script aims to harden & tweak Windows 10 LTSC (EntS) & Ent.
        All tweaks are explained and there will be no "undo" script or option, just do a backup!
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
			-> Provided AS IS without warranty of any kind.
                                ========== DO NOT README ==========

       .LINK
           https://github.com/CHEF-KOCH/Windows-10-hardening/blob/master/PowerShell/CK.ps1
#>


# We need admin rights!
#Requires -RunAsAdministrator
# Remove all text from the current PowerShell session
Clear-Host
# Сlear $Error variable in PowerShell
$Error.Clear()
# Enforce UTF-8 without BOM
$OutputEncoding = [System.Console]::OutputEncoding = [System.Console]::InputEncoding = [System.Text.Encoding]::UTF8
#
# Missing Variables
# (fixme) New-Variable -Name
#
# Execution
# Set-ExecutionPolicy Unrestricted
# ls -Recurse *.ps1 | Unblock-File
# ls -Recurse *.psm1 | Unblock-File
#
# Aditional workaround for gaining root in registry
# Todo:
#
##########################################################################################
######      	Telemetry & Feedback, Ads & Fingerprinting Migration				######
# Overview: https://docs.microsoft.com/en-us/windows/privacy/manage-windows-1809-endpoints
# German "audit" 						https://files.catbox.moe/ugqngv.pdf (bullshit)
# Windows Editions Diff:                https://en.wikipedia.org/wiki/Windows_10_editions
##########################################################################################
# Turn off telemetry for Service Provider Foundation
# https://docs.microsoft.com/en-us/powershell/module/spfadmin/set-scspftelemetry?view=systemcenter-ps-2019
Set-SCSPFTelemetry -Enabled $False
# Prevent non-administrators from using Safe Mode
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "SafeModeBlockNonAdmins" -PropertyType DWord -Value 1 -Force
# Turn off Turn Help Experience Improvement Program
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" -Name "NoImplicitFeedback" -PropertyType DWord -Value 0 -Force
# Turn off App based Customer Experience Improvement Program (CEIP)
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\AppV\CEIP" -Name "CEIPEnable" -PropertyType DWord -Value 0 -Force
# Turn off WMP Telemetry (meta data)
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventCDDVDMetadataRetrieval" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventMusicFileMetadataRetrieval" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventRadioPresetsRetrieval" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "DisableOnline" -PropertyType DWord -Value 1 -Force
# Turn off Data Collection ( not needed since 1603+)
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitEnhancedDiagnosticDataWindowsAnalytics" -PropertyType DWord -Value 1 -Force
# Turn off KMS Client Online AVS Validation (Telemetry)
# https://getadmx.com/?Category=Windows_10_2016&Policy=Microsoft.Policies.SoftwareProtectionPlatform::NoAcquireGT
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\SOFTWARE Protection Platform" -Name "NoGenTicket" -Type DWord -Value 0
# Turn off "Shared Experiences"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" -Name "RomeSdkChannelUserAuthzPolicy" -Type DWord -Value 0
# Turn off automatic connecting to open Wi-Fi networks
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -PropertyType DWord -Value 0 -Force
# Turn off Microsoft consumer experiences
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
# Turn off additional data requests from Microsoft in response to a windows error reporting event
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
# Turn off "Location information" usage & Sensors
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\PolicyManager\default\System\AllowLocation" -Name "value" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -PropertyType DWord -Value 1 -Force
# Turn off "Show me the Windows welcome experience after updates and occasionally when I sign in to highlight what’s new and suggested"
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -PropertyType DWord -Value 0 -Force
# Turn off "File Explorer ads" (Home/Pro users only!)
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Type DWord -Value 0
# Turn off handwriting personalization data sharing
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -PropertyType DWord -Value 1 -Force
# Turn off Windows Customer Experience Improvement Program
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -PropertyType DWord -Value 0 -Force
# Turn off location tracking for this device
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0
# Turn off "Connected User Experiences and Telemetry" service (DiagTrack)
Get-Service -Name DiagTrack | Stop-Service -Force
Get-Service -Name DiagTrack | Set-Service -StartupType Disabled
# Turn off the Autologger session at the next computer restart
Update-AutologgerConfig -Name AutoLogger-Diagtrack-Listener -Start 0
# Turn off the SQMLogger session at the next computer restart
Update-AutologgerConfig -Name SQMLogger -Start 0
# Set the operating system diagnostic data level to "Security" (Ent./Edu. + LTSB/LTSC only)
# 0 = Security: Security data only (CIS L1)
# 1 = Basic: Security + basic system and quality data
# 2 = Enhanced: Basic + enhanced insights and advanced reliability data
# 3 = Full: Enhanced + full diagnostics data
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "DoNotShowFeedbackNotifications" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "MaxTelemetryAllowed" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
# Turn off Windows Error Reporting
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "DoReport" -PropertyType DWord -Value 0 -Force
# Change Windows Feedback frequency to "Never"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1 -Force
# Turn off tailored experiences with diagnostic data
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -PropertyType DWord -Value 0 -Force
# Turn off Find my device
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Settings\FindMyDevice" -Name "LocationSyncEnabled" -PropertyType DWord -Value 0 -Force
##########################################################
######   				Explorer.exe				######
##########################################################
# Turn off Jump Lists
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "EnableXamlJumpView" -Type DWord -Value 1 -Force
# Turn off Xaml
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "EnableXamlStartMenu" -Type DWord -Value 0
# Turn off Experimental Login Screen
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\TestHooks" -Name "Threshold" -Type DWord -Value 1 -Force
# Turn off "People Bar" in Explorer (not needed since 1603+)
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HidePeopleBar" -Type DWord -Value 1
# Hide "Remove Hardware and Eject Media" Button until next reboot
# https://superuser.com/questions/12955/how-can-i-remove-the-option-to-eject-sata-drives-from-the-windows-7-tray-icon
Set-ItemProperty -Path "KCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\SysTray called Services" -Name "Services " -Type DWord -Value 29
# Turn off Thumbs.db thumbnail cache files only on network folders
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbsDBOnNetworkFolders" -Type DWord -Value 1
# Turn on thumbnails
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "IconsOnly" -Type DWord -Value 0
# Turn off thumbnail cache files
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbnailCache" -Type DWord -Value 1
# Turn off restoring previous folder windows at logon
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "PersistBrowsers" -ErrorAction SilentlyContinue
# Turn on "Enable navigation pane expanding to current folder"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneExpandToCurrentFolder" -Type DWord -Value 1
# Turn on Classic Control Panel Icons (small)
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Type DWord -Value 1
# Turn off 'How do you want to open this file?' prompt
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -Type DWord -Value 1
# Turn off NumLock (usually the keyboard driver/SOFTWARE controls it)
Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483648
#New-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name InitialKeyboardIndicators -PropertyType DWord -Value 2 -Force
#New-ItemProperty -Path "HKCU:\.DEFAULT\Control Panel" -Name "InitialKeyboardIndicators" -PropertyType DWord -Value 2 -Force
# Launch folder in a separate process
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SeparateProcess" -Type DWord -Value 1
# Show accent color on the title bars and window borders
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\DWM" -Name "ColorPrevalence" -Type DWord -Value 1
# Turn off "F1 Help"
New-ItemProperty -Path "HKCU:\SOFTWARE\Classes\Typelib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Name "(default)" -PropertyType String -Value "" -Force
# Turn off Sticky keys prompt (after pressing 5x ALT)
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506"
# Turn off Sharing Wizard
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SharingWizardOn" -Type DWord -Value 0
# Turn off JPEG desktop wallpaper import quality compression
New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "JPEGImportQuality" -PropertyType DWord -Value 100 -Force
# Turn on "Ribbon" in File Explorer
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Ribbon" -Name "MinimizedStateTabletModeOff" -PropertyType DWord -Value 0 -Force
# Turn on Show Control shortcut on Desktop
New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -Type DWord -Value 0
# Turn off User Folder shortcut from Desktop
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -ErrorAction SilentlyContinue
# Turn off 3D Objects icon from This PC
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue
New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
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
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSecondsInSystemClock" -PropertyType DWord -Value 1 -Force
# Turn off app launch tracking to improve Start menu and search results
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -PropertyType DWord -Value 0 -Force
# Turn off "This PC" on Desktop
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -ErrorAction SilentlyContinue
# Show "more details" by default in file transfer dialog
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -PropertyType DWord -Value 1 -Force
# Turn off AutoPlay for all media and devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255
#Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1
# Turn off the "- Shortcut" name extension for new shortcuts
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "link" -Type Binary -Value ([byte[]](0,0,0,0))
# Turn off shortcut icon arrow
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" -Name "29" -Type String -Value "%SystemRoot%\System32\imageres.dll,-1015"
#Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" -Name "29" -ErrorAction SilentlyContinue
# Remove the "Previous Versions" (ShadoCopy) tab from properties context menu
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
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -PropertyType DWord -Value 0 -Force
# Remove 3D Objects folder in "This PC" and in the navigation pane
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -PropertyType String -Value "Hide" -Force
# Theme color (Dark) for default Windows mode
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "ColorPrevalence" -PropertyType DWord -Value 1 -Force
# Dark Theme Color for Default Windows Mode
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -PropertyType DWord -Value 0 -Force
# Turn off thumbnail cache removal (controll via Storage Sense or CCleaner)
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" -Name "Autorun" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" -Name "Autorun" -PropertyType DWord -Value 0 -Force
# Change environment variable from $env:TEMP to $env:SystemDrive\Temp
# I RamDrive or Sandbox /Temp, that's the reason.
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
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernateEnabled" -Type DWord -Value 0
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
# Add "Run as Administrator" context menu for .ps1 files
New-Item -Path "Registry::HKEY_CLASSES_ROOT\Microsoft.PowershellScript.1\Shell\runas\command" -Force -Name '' -Value '"c:\windows\system32\windowspowershell\v1.0\powershell.exe" -noexit -file "%1"'
# Turn on Photo Viewer 'Open with...'
If (!(Test-Path "HKCR:")) {
    New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
}
New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Force | Out-Null
New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\DropTarget" -Force | Out-Null
Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open" -Name "MuiVerb" -Type String -Value "@photoviewer.dll,-3043"
Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open\DropTarget" -Name "Clsid" -Type String -Value "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}"
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
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Type DWord -Value 1
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
# Turn off Connect Now Wizard (not in LTSB/LTSC and 1603+)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "DisableFlashConfigRegistrar" -Type DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "DisableInBand802DOT11Registrar" -Type DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "DisableUPnPRegistrar" -Type DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "DisableWPDRegistrar" -Type DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "EnableRegistrars" -Type DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI" -Name "DisableWcnUi" -Type DWord -Value 1 -Force
# Turn off downloads of Map data (not in LTSB/LTSC)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps" -Name "AllowUntriggeredNetworkTrafficOnSettingsPage" -Type DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps" -Name "AutoDownloadAndUpdateMapData" -Type DWord -Value 0 -Force
# Turn off Consumer Features
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1 -Force
# Turn off Windows Tips
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Type DWord -Value 1 -Force
# Turn off all running backgrounds apps
# Basically a master toggle for GPO based settings
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivac" -Name "LetAppsRunInBackground" -Type DWord -Value 2 -Force
# Turn off app access to personal data (force deny)
# You should always use "force deny" instead of disabled!
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessAccountInfo" -Type DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCalendar" -Type DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCallHistory" -Type DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCamera" -Type DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessContacts" -Type DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessEmail" -Type DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessLocation" -Type DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMessaging" -Type DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMicrophone" -Type DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMotion" -Type DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessNotifications" -Type DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessPhone" -Type DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessRadios" -Type DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessTasks" -Type DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessTrustedDevices" -Type DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsGetDiagnosticInfo" -Type DWord -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsSyncWithDevices" -Type DWord -Value 2 -Force
# Turn off Maps auto updates
Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0
# Turn off Activity History Feed
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0
# Turn off "Automatic installation apps"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
# Turn off Shared Experiences: "I can share and receive from"
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" -Name "CdpSessionUserAuthzPolicy" -PropertyType DWord -Value 0 -Force
# Turn off "My devices only" for Nearby sharing: "I can share and receive from"
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" -Name "NearShareChannelUserAuthzPolicy" -PropertyType DWord -Value 0 -Force
# Turn off "Let apps share and sync with wireless devices" (fixme)
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" -Name "Value" -PropertyType hex -Value Deny -Force
# Turn off automatic installing suggested apps
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -PropertyType DWord -Value 0 -Force
# Dark theme color for default app mode
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 0
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 0
# Turn off Inventory (1603 and below)
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompa" -Name "DisableInventory" -PropertyType DWord -Value 1 -Force
# Do not allow apps to use advertising ID
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1
# Turn off Cortana
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI" -Name "DisableWcnUi" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0 -Force
# Turn off "Let Cortana respond to "Hey Cortana""
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences" -Name "VoiceActivationOn" -PropertyType DWord -Value 0 -Force
# Turn off "Use Cortana even when my device is locked"
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences" -Name "VoiceActivationEnableAboveLockscreen" -PropertyType DWord -Value 0 -Force
# Turn off "Let Cortana listen for my commands when I press the Windows logo key + C"
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "VoiceShortcut" -PropertyType DWord -Value 0 -Force
#
# Remove all apps except Windows Store incl. Xbox (Enterprise (N) LTSC 2019)
# The Windows Store however does not run in the background since we enforce to disable all background apps.
# (fixme) Add XBOX 360 driver workaround (1909 fixed? - needs more tests)
Get-AppxPackage -AllUsers | where-object {$_.name –notlike "*store*"} | Remove-AppxPackage
##########################################################
######              Start Menu                      ######
#               I use StartisBack++
##########################################################
# Turn off Sleep & keyboard button in Start Menu
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowSleepOption" -Type DWord -Value 0
#powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0
#powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0
# Turn off Help and Support"
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
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -Type DWord -Value 1
# Turn off 'Most used' apps list from the Start Menu
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoStartMenuMFUprogramsList" -Type DWord -Value 1
# Turn off app suggestions on Start menu e.g. Windows Ink Workspace
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -PropertyType DWord -Value 0 -Force
# Hide "Recent folders" in Quick access
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name ShowFrequent -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name ShowFrequent -PropertyType DWord -Value 0 -Force
# Hide search box or search icon on taskbar
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
# Unpin all Start Menu tiles
$key = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\*start.tilegrid`$windows.data.curatedtilecollection.tilecollection\Current"
$data = $key.Data[0..25] + ([byte[]](202,50,0,226,44,1,1,0,0))
Set-ItemProperty -Path $key.PSPath -Name "Data" -Type Binary -Value $data
Stop-Process -Name "ShellExperienceHost" -Force -ErrorAction SilentlyContinue
#New-ItemProperty -Path $tilecollection.PSPath -Name "Data" -PropertyType Binary -Value $unpin -Force
# Turn off Task View button
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
# Turn on small Taskbar icons
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Type DWord -Value 1
# Turn on taskbar buttons - SHow label & never combine
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Type DWord -Value 2
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MMTaskbarGlomLevel" -Type DWord -Value 2
##########################################################
######      Microsoft Edge (old non Chomium)        ######
##########################################################
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
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "PreventLiveTileDataCollection" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\EdgeUI" -Name "DisableMFUTracking" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\EdgeUI" -Name "DisableRecentApps" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\EdgeUI" -Name "TurnOffBackstack" -Type DWord -Value 1
# Turn off Do Not Track (DNT) in Microsoft Edge
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "DoNotTrack" -Type DWord -Value 2
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "DoNotTrack" -Type DWord -Value 2
# Turn off third-party cookies in Microsoft Edge
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "Cookies" -Type DWord -Value 1
# Turn on override prevention "SmartScreen for Windows Store apps"
# New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "PreventOverride" -PropertyType DWord -Value 1 -Force
# Turn on (set to Warning) "SmartScreen for Windows Store apps" (fixme)
#New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -PropertyType DWord -Value 1 -Force
#  Turn on (set to Warning) "SmartScreen for Microsoft Edge" (fixme)
#New-ItemProperty -Path "HKCU:\SOFTWARE\Classes\Local Settings\SOFTWARE\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -PropertyType DWord -Value "1" -Force
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
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Name "AllowTabPreloading" -Type DWord -Value 0
# Prevent Microsoft Edge to pre-launch at Windows startup, when the OS idle, and each time Microsoft Edge is closed
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "DisableEdgeDesktopShortcutCreation" -Type DWord -Value 1
# Hide notification about disabled Smartscreen for Microsoft Edge
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows Security Health\State" -Name "AppAndBrowser_EdgeSmartScreenOff" -PropertyType DWord -Value 0 -Force
##########################################################
######          Storage Sense 1703+                 ######
##########################################################
# Turn off scheduled defragmentation task
Disable-ScheduledTask -TaskName "Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null
# Turn on Storage Sense to automatically free up space
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name 01 -PropertyType DWord -Value 1 -Force
# Run Storage Sense every month | Otherwise use CCleaner incl. Winapp2.ini which is the alternative to Storage Sense.
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name 2048 -PropertyType DWord -Value 30 -Force
##########################################################
######              SmartScreen                     ######
##########################################################
# Turn off SmartScreen for apps and files
# Block = Block execution/opening (Secure)
# Warn = Warn before execution/opening (Default)
# Off = Turn off
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -PropertyType String -Value "Off" -Force
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "ShellSmartScreenLevel" -Type DWord -Value 0 (fixme) -Force
# reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v "ShellSmartScreenLevel" /t REG_SZ /d "Warn" /f  ^^^^^^^^^^
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Type DWord -Value 0 -Force
# Turn off Windows Defender SmartScreen (phising filter) for Microsoft Edge
New-ItemProperty -Path "HKCU:\SOFTWARE\Classes\Local Settings\SOFTWARE\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$edge\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Classes\Local Settings\SOFTWARE\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$edge\MicrosoftEdge\PhishingFilter" -Name "PreventOverride" -PropertyType DWord -Value 0 -Force
# Ensure 'Prevent bypassing Windows Defender SmartScreen prompts for sites to 'Enabled'
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "PreventOverride" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "PreventOverrideAppRepUnknown" -PropertyType DWord -Value 1 -Force
##########################################################
###### 			    Windows Defender (WD)           ######
##########################################################
# Turn off MRT Telemetry
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\MRT" -Name "DontReportInfectionInformation" -Value 1 -Force
# Turn on protection against Potentially Unwanted Applications
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" -Name "MpEnablePus" -PropertyType DWord -Value 1 -Force
# Turn off driver scanning
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisableRemovableDriveScanning" -PropertyType DWord -Value 0 -Force
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
# Uninstall Windows Defender (install_wim_tweak method Build <=1703)
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
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1
#If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
#    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -ErrorAction SilentlyContinue
#} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 15063) {
#    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -ErrorAction SilentlyContinue
#}
#}
# Turn on blocking of downloaded files
#Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Type DWord -Value 1
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -ErrorAction SilentlyContinue
# Turn on Windows Defender Account Protection Warnings
Remove-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows Security Health\State" -Name "AccountProtection_MicrosoftAccount_Disconnected" -ErrorAction SilentlyContinue
# Turn off Account Protection Notifications
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows Security Health\State" -Name "AccountProtection_MicrosoftAccount_Disconnected" -Type DWord -Value 1
# Turn on Windows Defender AppGuard
Enable-WindowsOptionalFeature -online -FeatureName "Windows-Defender-ApplicationGuard" -NoRestart -WarningAction SilentlyContinue | Out-Null
# Turn on Core Isolation Memory Integrity
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Type DWord -Value 1
# Turn on Defender Exploit Guard
Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue
# Turn off Windows Defender
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1
# Turn off submission of Windows Defender Samples
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\SubmitSamplesConsent" -Name "value" -PropertyType DWord -Value 2 -Force
# Turn off Windows Defender Trayicon
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" -Name "HideSystray" -Type DWord -Value 1
# Turn off Windows Defender Cloud & Sample submission
# https://docs.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=win10-ps#parameters
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Type DWord -Value 2
# Turn on "Windows Defender Exploit Guard Network Protection"
Set-MpPreference -EnableNetworkProtection Enabled
# Turn on Windows Defender Sandbox
setx /M MP_FORCE_USE_SANDBOX=1
# Turn on "Windows Defender PUA Protection"
Set-MpPreference -PUAProtection Enabled
# Turn off WD "Firewall & Network protection"
# I use my Router & AdGuard Home as shield
#Set-NetFirewallProfile -Enabled false
# Turn on Windows Defender Exploit Protection Settings
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" -Name "DisallowExploitProtectionOverride" -ErrorAction SilentlyContinue
# Allow malicious app/website connections (now part off "Windows Defender Exploit Guard Network Protection")
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Name "EnableNetworkProtection" -Type DWord -Value 0
# Turn on Windows Defender Behavior Monitoring ()
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -PropertyType DWord -Value 1 -Force
# Turn off Generic malware reports
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" -Name "DisableGenericRePorts" -PropertyType DWord -Value 0 -Force
# Turn on "Block at first seen"
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "DisableBlockAtFirstSeen" -PropertyType DWord -Value 0 -Force
##########################################################
######                      Taskbar                 ######
##########################################################
# Turn on all tray icons
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutoTrayNotify" -Type DWord -Value 1
# Turn off People icon
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0
# Always show all icons in the notification area
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -PropertyType DWord -Value 0 -Force
# Show seconds on taskbar clock
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSecondsInSystemClock" -PropertyType DWord -Value 1 -Force
# Hide People button on the taskbar
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "AutoCheckSelect" -Type DWord -Value 0
# Turn off "Windows Ink Workspace" button
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PenWorkspace" -Name "PenWorkspaceButtonDesiredVisibility" -PropertyType DWord -Value 0 -Force
# Turn on acrylic taskbar transparency
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "UseOLEDTaskbarTransparency" -PropertyType DWord -Value 1 -Force
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
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging" -Name "AllowMessageSync" -PropertyType DWord -Value 0 -Force
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
# Manage single or multiple sessions per user (RDP) - Prevent multiple sessions at once
#New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fSingleSessionPerUser" -PropertyType DWord -Value 1 -Force
# Strict DLL search order
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "CWDIllegalInDllSearch" -PropertyType DWord -Value 0 -Force
# Turn off WMDRM
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM" -Name "DisableOnline" -PropertyType DWord -Value 1 -Force
# Prevent users from sharing files within their profile
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoInplaceSharing" -PropertyType DWord -Value 1 -Force
# Turn off "Notify antivirus programs when opening attachments"
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "ScanWithAntiVirus" -PropertyType DWord -Value 1 -Force
# Turn off taskbar live thumbnail previews
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisablePreviewWindow" -PropertyType DWord -Value 0 -Force
# Turn off taskbar live thumbnail Aero peek
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -PropertyType DWord -Value 0 -Force
# Turn off Mobile Device Management (MDM) enrollment (does not exists on LTSB(C))
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM" -Name "DisableRegistration" -PropertyType DWord -Value 1 -Force
# Turn off projecting (Connect) to the device, and ensure it requires pin for pairing
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "AllowProjectionToPC" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "RequirePinForPairing" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WirelessDisplay" -Name "EnforcePinBasedPairing" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\PresentationSettings" -Name "NoPresentationSettings" -PropertyType DWord -Value 1 -Force
# Turn off Steps Recorder
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableUAR" -PropertyType DWord -Value 1 -Force
# Turn off speech recognition udpates
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Speech" -Name "AllowSpeechModelUpdate" -PropertyType DWord -Value 0 -Force
# Turn off "Search Companion" from downloading files from Microsoft
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion" -Name "DisableContentFileUpdates" -PropertyType DWord -Value 1 -Force
# Turn off Error Reporting
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "DontSendAdditionalData" -PropertyType DWord -Value 1 -Force
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
# Turn off Microsoft Account user authentication
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftAccount" -Name "DisableUserAuth" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "NoConnectedUser" -PropertyType DWord -Value 3 -Force
# Turn off Network Connectivity Status Indicator active test (possible data leakage)
# Info:
# msftconnecttest.com + ipv6.msftconnecttest.com
# dns.msftncsi.com looking + 131.107.255.255
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" -Name "NoActiveProbe" -Type DWord -Value 1
# Turn on cleaning of recent used files
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ClearRecentDocsOnExit" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -Type DWord -Value 1 -Force
# Turn off MS Messenger (not needed since 1603+)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client" -Name "CEIP" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Messenger\Client" -Name "CEIP" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client" -Name "PreventRun" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Messenger\Client" -Name "PreventRun" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client" -Name "PreventAutoRun" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Messenger\Client" -Name "PreventAutoRun" -Type DWord -Value 1
# Turn off Spotlight (not needed since 1603+)
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "ConfigureWindowsSpotlight" -PropertyType DWord -Value 2 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableThirdPartySuggestions" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightOnActionCenter" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightWindowsWelcomeExperience" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "IncludeEnterpriseSpotlight" -PropertyType DWord -Value 0 -Force
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
#Microsoft-Windows-InternetExplorer-Optional-Package
Disable-WindowsOptionalFeature -Online -FeatureName "Internet-Explorer-Optional-$env:PROCESSOR_ARCHITECTURE" -NoRestart -WarningAction SilentlyContinue | Out-Null
# Turn off Password Reveal Button in Internet Explorer (not needed since 1603+)
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CredUI" -Name "DisablePasswordReveal" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "DisablePasswordReveal" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI" -Name "DisablePasswordReveal" -PropertyType DWord -Value 1 -Force
# Turn off "Help" in Microsoft Edge
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EdgeUI" -Name "DisableHelpSticker" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\EdgeUI" -Name "DisableHelpSticker" -Type DWord -Value 1
# Turn off Search Suggestions in Microsoft Edge
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\SearchScopes" -Name "ShowSearchSuggestionsGlobal" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\SearchScopes" -Name "ShowSearchSuggestionsGlobal" -Type DWord -Value 1
# Turn on HTTP/2 in Internet Explorer
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "EnableHTTP2" -Type DWord -Value 1
# Turn off SSLv3 & suppress certificate errors in Internet Explorer
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "CallLegacyWCMPolicies" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "EnableSSL3Fallback" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "PreventIgnoreCertErrors" -Type DWord -Value 1
# Turn on automatic browsing history cleaning in Internet Explorer
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Privacy" -Name "ClearBrowsingHistoryOnExit" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\Privacy" -Name "ClearBrowsingHistoryOnExit" -Type DWord -Value 1
# Turn off Do Not Track (DNT) in Internet Explorer
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "DoNotTrack" -Type DWord -Value 0
# Turn off automatic crash Detection in Internet Explorer
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Restrictions" -Name "NoCrashDetection" -Type DWord -Value 1
# Turn off Internet Explorer prefetching
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\PrefetchPrerender" -Name "Enabled" -Type DWord -Value 0
# Turn on DEP in Internet Explorer
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "DEPOff" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "Isolation64Bit" -Type DWord -Value 1
# Turn off Geolocation in IE
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Geolocation" -Name "PolicyDisableGeolocation" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\Geolocation" -Name "PolicyDisableGeolocation" -Type DWord -Value 1
# Turn off Internet Explorer suggestions
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Name "AllowServicePoweredQSA" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\DomainSuggestion" -Name "Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\SearchScopes" -Name "TopResult" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Suggested Sites" -Name "Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "AutoSearch" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\WindowsSearch" -Name "EnabledScopes" -Type DWord -Value 0
# Turn off "Sync your settings: Internet Explorer settings"
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" -Name "Enabled" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" -Name "Enabled" -PropertyType DWord -Value 0 -Force
# Turn off Internet Explorer continues browsing
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\ContinuousBrowsing" /v "Enabled" /t REG_DWORD /d 0 /f
# Turn off Internet Explorer SQM (now known as CEIP)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\SQM" -Name "DisableCustomerImprovementProgram" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\SQM" -Name "DisableCustomerImprovementProgram" -Type DWord -Value 0
# Turn off Internet Explorer "In-Private" logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Safety\PrivacIE" -Name "DisableLogging" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\Safety\PrivacIE" -Name "DisableLogging" -Type DWord -Value 1
# Turn on Internet Explorer phising filter
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter" -Name "EnabledV9" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter" -Name "EnabledV9" -Type DWord -Value 1
# Turn off Internet Explorer "First run" wizard
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Type DWord -Value 1
# Turn off Internet Explorer Adobe Flash
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Name "DisableFlashInIE" -Type DWord -Value 1
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -Name "FlashPlayerEnabled" -Type DWord -Value 0
###############################################
###### 				Security             ######
###############################################
# CredSSP Patch Causing RDP Authentication Error due to Encryption Oracle Remediation
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP" -Name "AllowEncryptionOracle" -Type DWord -Value 2 -Force
# Delete Pagefile.sys at Shutdown
Set-ItemProperty -Path "HKLM:\SYSTEM\Current\ControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutDown" -Type DWord -Value 1 -Force
<# Server
# https://support.microsoft.com/en-us/help/3000483/ms15-011-vulnerability-in-group-policy-could-allow-remote-code-execution
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -Name "RequireMutualAuthentication" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -Name "RequireIntegrity" -Type DWord -Value 1
# https://support.microsoft.com/en-us/help/3116180/ms15-124-cumulative-security-update-for-internet-explorer-december-8-2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\InternetExplorer\Main\FeatureControl" -Name "FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\InternetExplorer\Main\FeatureControl" -Name "FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING" -Type DWord -Value 1
# https://support.microsoft.com/en-us/help/3140245/update-to-enable-tls-1-1-and-tls-1-2-as-default-secure-protocols-in-wi
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\InternetExplorer\Main\FeatureControl" -Name "FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING" -Type DWord -Value 1

# Server only - Clear plain-text passwords from WDigest memory
# https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2016/2871997
# https://support.microsoft.com/kb/2871997
#Remove-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Type DWord -Value 0 -Force

# Server only - Block unsafe ticket-granting (fixme)
# https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/ADV190006
# https://support.microsoft.com/en-us/help/4490425/updates-to-tgt-delegation-across-incoming-trusts-in-windows-server
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
# https://docs.microsoft.com/en-us/azure/active-directory/devices/hybrid-azuread-join-manual-steps + KB3165191 (MS16-077)
# AdGuard Home
#0.0.0.0 wpad wpad.my.home
#:: wpad wpad.my.home
# Win WPAD HOSTS
#0.0.0.0 wpad
#0.0.0.0 wpad.my.home
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\WinHttpAutoProxySvc" -Name "Start" -Type DWord -Value 4 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -Type DWord -Value 0 -Force
# Turn off Homegroup (obsolete HG was removed)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HomeGroup" -Name "DisableHomeGroup" -Type DWord -Value 1 -Force
# Turn off Sidebar Gadgets (obsolete but still in gpedit)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar" -Name "TurnOffSidebar" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar" -Name "TurnOffUnsignedGadgets" -Type DWord -Value 1
# Turn off "Active Desktop"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ForceActiveDesktopOn" -Type DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoActiveDesktop" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoActiveDesktopChanges" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" -Name "NoAddingComponents" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" -Name "NoComponents" -Type DWord -Value 1 -Force
# Turn on certificate checks for apps (does not exists on LTSB(C))
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers" -Name "authenticodeenabled" -Type DWord -Value 1 -Force
# Turn off Lock Screen app notifications
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableLockScreenAppNotifications" -Type DWord -Value 1
# Turn on Lock Screen
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -Type DWord -Value 0
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -ErrorAction SilentlyContinue
# Turn off network options from Lock Screen
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -Type DWord -Value 1
# Turn off shutdown options from Lock Screen
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Type DWord -Value 0
# Turn on Data Execution Prevention (DEP)
bcdedit /set `{current`} nx OptOut | Out-Null
#bcdedit /set `{current`} nx OptIn | Out-Null
# Turn off Windows Script Host
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Type DWord -Value 0
# Turn on Windows Firewall
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -ErrorAction SilentlyContinue
# Turn off automatic installation of new network devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Type DWord -Value 0
# Enable network profile -> public (disables file sharing, device discovery, and more...)
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Name "Category" -ErrorAction SilentlyContinue
# Set unknown networks profiles to public
Set-NetConnectionProfile -NetworkCategory Public
# Turn off Hotspot reports
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "value" -PropertyType DWord -Value 0 -Force
# Disallow Autoplay for non-volume devices'
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoAutoplayfornonVolume" -PropertyType DWord -Value 1 -Force
# Turn off Clipboard History Feature
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Clipboard" -Name "EnableClipboardHistory" -PropertyType DWord -Value 0 -Force
# Allowed to format and eject removable media <-> 'Administrators and Interactive Users'
# <deleted> = (Default)
# 0000000 = Administrators only
# 0000001 = Administrators and power users
# 0000002 = Administrators and interactive users (CIS)
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AllocateDASD2" -PropertyType DWord -Value 2 -Force
# Turn off verbose start
#New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system" -Name verbosestatus -PropertyType DWord -Value 1 -Force
# Turn off unsafe online help functions
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "HelpQualifiedRootDir" -PropertyType hex -Value 00,00 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "HelpQualifiedRootDir" -PropertyType hex -Value 00,00 -Force
# Disable search via web from within apps
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchToUseLocation" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchPrivacy" -PropertyType DWord -Value 3 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchSafeSearch" -PropertyType DWord -Value 3 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWebOverMeteredConnections" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "PreventRemoteQueries" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWeb" -PropertyType DWord -Value 0 -Force
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
# Turn off Domain Name Devolution
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "UseDomainNameDevolution" -PropertyType DWord -Value 0 -Force
# Turn off Fast Restart (Hibernate/Sleep instead of shutting down) to prevent disk encryption errors with third party tools (fixed in 1909+?)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0
# Turn off Clipboard History capability
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowClipboardHistory" -PropertyType DWord -Value 0 -Force
# Turn on untrusted Font blocking (WD controlled)
# <deleted> = (Default)
# 00,10,a5,d4,e8,00,00,00 (1000000000000) = Block untrusted fonts and log events (CIS)
# 00,20,4a,a9,d1,01,00,00 (2000000000000) = Do not block untrusted fonts
# 00,30,ef,7d,ba,02,00,00 (3000000000000) = Log events without blocking untrusted fonts
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\MitigationOptions" -Name "MitigationOptions_FontBocking" -PropertyType hex -Value 00,10,a5,d4,e8,00,00,00 -Force
# Turn on "Prevent enabling lock screen camera"
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera" -PropertyType DWord -Value 1 -Force
# Turn off all Online Tips
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "AllowOnlineTips" -PropertyType DWord -Value 0 -Force
# Turn off SMB v1 (removed in 1709)
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
#New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -PropertyType DWord -Value 0 -Force
Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force
# Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
# Turn on Structured Exception Handling Overwrite Protection (SEHOP - default on)
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -PropertyType DWord -Value 0 -Force
# Turn off IP source routing protection level (IPv6)
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisableIPSourceRouting" -PropertyType DWord -Value 2 -Force
# Turn off IP source routing protection level
# 0000000 = No additional protection, source routed packets are allowed
# 0000001 = Medium, source routed packets ignored when IP forwarding is enabled
# 0000002 = Highest protection, source routing is completely disabled (CIS)
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -PropertyType DWord -Value 2 -Force
# Turn on Safe DLL search mode (SafeDllSearchMode)
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "SafeDllSearchMode" -PropertyType DWord -Value 1 -Force
# Turn off Enable Font Providers
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableFontProviders" -PropertyType DWord -Value 0 -Force
# Turn off Microsoft Peer-to-Peer Networking Services
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Peernet" -Name "Disabled" -PropertyType DWord -Value 1 -Force
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
#New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" -Name DisabledComponents -PropertyType DWord -Value 000000a -Force
# Turn off Turn off handwriting recognition error reporting
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" -Name PreventHandwritingErrorReports -PropertyType DWord -Value 1 -Force
# Turn off the "Order Prints" picture task
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoOnlinePrintsWizard -PropertyType DWord -Value 1 -Force
# Turn off "Publish to Web" task for files and folders
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoPublishingWizard -PropertyType DWord -Value 1 -Force
# Turn off User Activities
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name UploadUserActivities -PropertyType DWord -Value 0 -Force
# Turn off "Offer Remote Assistance"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "CreateEncryptedOnlyTickets" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "AllowFullControl" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "AllowToGetHelp" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "EnableChatControl" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "MaxTicketExpiry" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "MaxTicketExpiryUnits" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnection" -PropertyType DWord -Value 1 -Force
# Turn on Enhanced anti-spoofing for Facial Detection
# New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" -Name EnhancedAntiSpoofing -PropertyType DWord -Value 1 -Force
# Turn off Facial Biometrics
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics" -Name "Enabled" -PropertyType DWord -Value 0 -Force
# Turn on and enforce Data Execution Prevention
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableHHDEP" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoDataExecutionPrevention" -PropertyType DWord -Value 0 -Force
# Prevent Remote Desktop Services
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 1
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
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type DWord -Value 0
# Turn on Retpoline to migrate Spectre v2
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverride -PropertyType DWord -Value 1024 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverrideMask -PropertyType DWord -Value 1024 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -Name "cadca5fe-87d3-4b96-b7fb-a231484277cc" -Type DWord -Value 0
# Turn on Admin Approval Mode for administrators
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name ConsentPromptBehaviorAdmin -PropertyType DWord -Value 1 -Force
# Turn off access to mapped drives from app running with elevated permissions with Admin Approval Mode enabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -Type DWord -Value 0
# Turn off Windows Script Host
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name Enabled -PropertyType DWord -Value 0 -Force
# Do not let any Website provide locally relevant content by accessing language list
Set-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Type DWord -Value 1
# Turn off Administrative Shares
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -Type DWord -Value 0
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareServer" -PropertyType DWord -Value 0 -Force
# Turn off Domain Picture Passwords
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "BlockDomainPicturePassword" -PropertyType DWord -Value 1 -Force
##########################################################
###### 					Task Manager                ######
##########################################################
# Turn off Task Manager details (I use Process Hacker)
$preferences = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
If ($preferences) {
	$preferences.Preferences[28] = 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $preferences.Preferences
}
# Group svchost.exe processes
$ram = (Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1kb
##########################################################
###### 					.NET Framework              ######
##########################################################
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name SvcHostSplitThresholdInKB -PropertyType DWord -Value $ram -Force
# Enforce on .NET 4 runtime for all apps
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework -Name OnlyUseLatestCLR" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework" -Name OnlyUseLatestCLR -PropertyType DWord -Value 1 -Force
# Improve cryptography for .NET Framework v4+
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Type DWord -Value 1
##########################################################
###### 						Login                   ######
##########################################################
# Turn off System Recovery and Factory reset
reagentc /disable 2>&1 | Out-Null
# Turn off automatic recovery mode during boot
# bcdedit /set `{current`} BootStatusPolicy IgnoreAllFailures | Out-Null
# Turn off insecure guest logons
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -Name "AllowInsecureGuestAuth" -PropertyType DWord -Value 0 -Force
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
# Turn on automatic backups of registry to `\System32\config\RegBack` folder
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" -Name "EnablePeriodicBackup" -PropertyType DWord -Value 1 -Force
##########################################################
###### 					Windows Features            ######
##########################################################
# Turn off Battery Fly-out UI
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" -Name "UseWin32BatteryFlyout " -PropertyType DWord -Value 1 -Force
# Turn off Network Fly-out UI
# 0 = Default fly-out
# 1 = Opens Network Settings window
# 2 = Windows 8/8.1 style sidebar
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Control Panel\Settings\Network" -Name "ReplaceVan" -PropertyType DWord -Value 2 -Force
# Turn off New Volume Control
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\MTCUVC" -Name "EnableMtcUvc" -PropertyType DWord -Value 0 -Force
# Turn off Touchpad Sensitivity
# 0 = Most sensitive
# 1 = High sensitivity
# 2 = Medium sensitivity (default)
# 3 = Low sensitivity
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PrecisionTouchPad" -Name "AAPThreshold " -PropertyType DWord -Value 99 -Force
# Turn off Remote Desktop
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "AllowSignedFiles" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "DisablePasswordSaving" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Conferencing" -Name "NoRDS" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "AllowSignedFiles" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "AllowSignedFiles" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "AllowUnsignedFiles" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "CreateEncryptedOnlyTickets" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "DisablePasswordSaving" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowUnsolicited" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDenyTSConnections" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fEnableUsbBlockDeviceBySetupClass" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fEnableUsbNoAckIsochWriteToDevice" -PropertyType Dword -Value 80 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fEnableUsbSelectDeviceByInterface" -PropertyType Dword -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" -Name "AllowRemoteShellAccess" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\RemoteAdminSettings" -Name "Enabled" -PropertyType Dword -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\RemoteDesktop" -Name "Enabled" -PropertyType Dword -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\UPnPFramework" -Name "Enabled" -PropertyType Dword -Value 0 -Force
# Uninstall Microsoft XPS Document Writer
Disable-WindowsOptionalFeature -Online -FeatureName "Printing-XPSServices-Features" -NoRestart -WarningAction SilentlyContinue | Out-Null
# Turn on Photo Viewer association
New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
New-Item -Path $("HKCR:\$type\shell\open") -Force | Out-Null
New-Item -Path $("HKCR:\$type\shell\open\command") | Out-Null
Set-ItemProperty -Path $("HKCR:\$type\shell\open") -Name "MuiVerb" -Type ExpandString -Value "@%ProgramFiles%\Windows Photo Viewer\photoviewer.dll,-3043"
Set-ItemProperty -Path $("HKCR:\$type\shell\open\command") -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
# Uninstall .NET Framework 2.0 3.5 runtimes (I use abdh. offline installer because the online installer waste around 400+ MB after extraction)
Disable-WindowsOptionalFeature -Online -FeatureName "NetFx3" -NoRestart -WarningAction SilentlyContinue | Out-Null
Uninstall-WindowsFeature -Name "NET-Framework-Core" -WarningAction SilentlyContinue | Out-Null
# Install Hyper-V (needed for Sandbox, WD etc.)
Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-All" -NoRestart -WarningAction SilentlyContinue | Out-Null
Install-WindowsFeature -Name "Hyper-V" -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null
# Uninstall Microsoft Print to PDF
Disable-WindowsOptionalFeature -Online -FeatureName "Printing-PrintToPDFServices-Features" -NoRestart -WarningAction SilentlyContinue | Out-Null
# Install Install Linux "Subsystem"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowDevelopmentWithoutDevLicense" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -Type DWord -Value 1
Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -NoRestart -WarningAction SilentlyContinue | Out-Null
# Install PowerShell 2.0 (will be replaced by PowerShell Core)
Enable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -NoRestart -WarningAction SilentlyContinue | Out-Null
Install-WindowsFeature -Name "PowerShell-V2" -WarningAction SilentlyContinue | Out-Null
# Uninstall "Work Folders" Client
Disable-WindowsOptionalFeature -Online -FeatureName "WorkFolders-Client" -NoRestart -WarningAction SilentlyContinue | Out-Null
# Uninstall WMP
Disable-WindowsOptionalFeature -Online -FeatureName "WindowsMediaPlayer" -NoRestart -WarningAction SilentlyContinue | Out-Null
# Turn on Aero Shake
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisallowShaking" -ErrorAction SilentlyContinue
# Turn off Disable Maintenance
#New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Name MaintenanceDisabled -PropertyType DWord -Value 1 -Force
# DisableWifi Sense
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager" -Name WiFiSenseCredShared -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager" -Name WiFiSenseOpen -PropertyType DWord -Value 0 -Force
#New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name value -PropertyType DWord -Value 0 -Force
# Uninstall Windows Fax and Scan Services
Disable-WindowsOptionalFeature -Online -FeatureName "FaxServicesClientPackage" -NoRestart -WarningAction SilentlyContinue | Out-Null
# Turn off Windows Compatibility Manager
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name DisablePCA -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name DisablePCA -PropertyType DWord -Value 1 -Force
# Use the "PrtScn" button to open screen snipping
#New-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name PrintScreenKeyForSnippingEnabled -PropertyType DWord -Value 1 -Force
# Remove default printers "Microsoft XPS Document Writer" & "Microsoft Print to PDF
Remove-Printer -Name Fax, "Microsoft XPS Document Writer", "Microsoft Print to PDF" -ErrorAction SilentlyContinue
# Turn off Game Information downloads
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameUX" -Name "DownloadGameInfo" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameUX" -Name "GameUpdateOptions" -PropertyType DWord -Value 0 -Force
# Turn off Windows Game Recording & Broadcasting
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowgameDVR" -PropertyType DWord -Value 0 -Force
# Turn off Game Bar
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name AppCaptureEnabled -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\System\GameConfigStore -Name GameDVR_Enabled" -PropertyType DWord -Value 0 -Force
# Turn off Game Mode
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\GameBar" -Name AllowAutoGameMode -PropertyType DWord -Value 0 -Force
# Turn off Game Bar tips
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\GameBar" -Name ShowStartupPanel -PropertyType DWord -Value 0 -Force
# Uninstall Default Fax Printer Service
Remove-Printer -Name "Fax" -ErrorAction SilentlyContinue
##########################################################
###### 					MS One Drive                ######
##########################################################
Stop-Process -Name OneDrive -Force -ErrorAction SilentlyContinue
Start-Process -FilePath "$env:SystemRoot\SysWOW64\OneDriveSetup.exe" -ArgumentList "/uninstall" -Wait
Stop-Process -Name explorer
IF (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"))
{
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Force
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1
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
Unregister-ScheduledTask -TaskName *OneDrive* -Confirm:$false
##########################################################
###### 						Sound                   ######
##########################################################
# Turn off sound scheme
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoChangingSoundScheme" -Type DWord -Value 1
# Turn off Windows Startup sound
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" -Name "DisableStartupSound" -Type DWord -Value 1
# Disable sounds and set it to "No Sounds" (fixme)
$SoundScheme = ".None"
	Get-ChildItem -Path "HKCU:\AppEvents\Schemes\Apps\*\*" | ForEach-Object {
		If (!(Test-Path "$($_.PsPath)\$($SoundScheme)")) {
			New-Item -Path "$($_.PsPath)\$($SoundScheme)" | Out-Null
		}
		If (!(Test-Path "$($_.PsPath)\.Current")) {
			New-Item -Path "$($_.PsPath)\.Current" | Out-Null
		}
		$Data = (Get-ItemProperty -Path "$($_.PsPath)\$($SoundScheme)" -Name "(Default)" -ErrorAction SilentlyContinue)."(Default)"
		Set-ItemProperty -Path "$($_.PsPath)\$($SoundScheme)" -Name "(Default)" -Type String -Value $Data
		Set-ItemProperty -Path "$($_.PsPath)\.Current" -Name "(Default)" -Type String -Value $Data
	}
Set-ItemProperty -Path "HKCU:\AppEvents\Schemes" -Name "(Default)" -Type String -Value $SoundScheme
##########################################################
###### 						Mouse                   ######
##########################################################
# Turn on enhanced mouse pointer precision
#Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Type String -Value 1
#Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Type String -Value 6
#Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Type String -Value 10
##########################################################
###### 					Windows Updates             ######
##########################################################
# Turn off all Windows Updates (forever)
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "SetDisableUXWUAccess" -Type DWord -Value 1 -Force
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Type DWord -Value 1 -Force
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" -Name "DisableWindowsUpdateAccess" -Type DWord -Value 1 -Force
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" -Name "DisableWindowsUpdateAccessMode" -Type DWord -Value 0 -Force
# Turn off new Windows Update UI (I use WuMgr)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX" -Name "IsConvergedUpdateStackEnabled" -Type DWord -Value 0 -Force
# Turn off Windows Update deferrals (fixme)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdates" -Type DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdates" -Type DWord -Value 0 -Force
# Turn off driver updates (obsolete in 1909+)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -Type DWord -Value 0 -Force
# Turn off Malicious SOFTWARE Removal Tool
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -Type DWord -Value 0
# Turn off device metadata retrieval from Internet
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type DWord -Value 1
# Disable Preview Builds  (fixme)
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "EnableExperimentation" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "EnablePreviewBuilds" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\SOFTWARE\Microsoft\WindowsSelfHost\Applicability" -Name "EnablePreviewBuilds" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\SOFTWARE\Microsoft\WindowsSelfHost\Applicability" -Name "ThresholdFlightsDisabled" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\SOFTWARE\Microsoft\WindowsSelfHost\Applicability" -Name "Ring" -PropertyType string -Value "Disabled" -Force
# Turn on automatic updates for other Microsoft products e.g. Office
(New-Object -ComObject Microsoft.Update.ServiceManager).AddService2("7971f918-a847-4430-9279-4a52d1efe18d", 7, "")
# Turn off Windows Update restart notification
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name RestartNotificationsAllowed2 -PropertyType DWord -Value 0 -Force
# Turn off and delete reserved storage after the next update installation
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" -Name "BaseHardReserveSize" -PropertyType QWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" -Name "BaseSoftReserveSize" -PropertyType QWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" -Name "HardReserveAdjustment" -PropertyType QWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" -Name "MinDiskSize" -PropertyType QWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" -Name "ShippedWithReserves" -PropertyType DWord -Value 0 -Force
# Disable P2P Updates (1703+)
# dword:00000000 = off
# dword:00000002 = lan only
# dword:00000003 = lan and web
# Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DownloadMode" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -PropertyType DWord -Value 0 -Force
# Turn off Windows Update automatic restart
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -Type DWord -Value 0
##########################################################
###### 					Language                    ######
##########################################################
# Set default Code page to UTF-8
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Nls\CodePage" -Name "ACP" -Type String -Value 65001
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Nls\CodePage" -Name "OEMCP" -Type String -Value 65001
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Nls\CodePage" -Name "MACCP" -Type String -Value 65001
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
#$langs = Get-WinUserLanguageList
#Set-WinUserLanguageList ($langs | Where-Object {$_.LanguageTag -ne "en-US"}) -Force
##########################################################
######      Performance & Cleaning + Compression    ######
##########################################################
# Changing OS Timer Resolution
# The timer is limited by CPU not GPU.
# Windows 10 changes timer resolution every x seconds automatically, this requires to run a script or tool in the background
# however whenever a game/application requests a higher resolution e.g. Discord then this would make the whole utility/script useless.
# This is a myth because
# Disable memory compression
Disable-MMAgent -mc
# Enable-MMAgent -mc
# Disable Swap File to free 256 MB
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "SwapfileControl" -Type Dword -Value 0
# Turn on all Visual Effects (i like them this is in GPU, disabling it does overall change not much)
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 1
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value 400
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](158,30,7,128,18,0,0,0))
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 1
Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 1
# Turn off NTFS Last Access Time stamps
fsutil behavior set DisableLastAccess 0 | Out-Null
# Turn off Modern UI swap file (get around 256 MB extra space)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "SwapfileControl" -Type Dword -Value 0
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
# Disable Windows Startup Delay (fixme) (needs investigation)
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\Current\Version\Explorer\Serialize" -Name "StartupDelayInMSec" -Type Dword -Value 0 -Force
# Turn off display and sleep mode timeouts via powercfg
powercfg /X monitor-timeout-ac 0
powercfg /X monitor-timeout-dc 0
powercfg /X standby-timeout-ac 0
powercfg /X standby-timeout-dc 0
# Enable per-app System DPI awareness
New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "EnablePerProcessSystemDPI" -PropertyType DWord -Value 1 -Force
# Save screenshots by pressing Win+PrtScr to the Desktop
$value = Get-ItemPropertyValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name Desktop
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{b7bede81-df94-4682-a7d8-57a52620b86f}" -Name "RelativePath" -PropertyType String -Value $value -Force
##########################################################
######                  Action Center               ######
##########################################################
# Turn off Action Center
#New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Wndows\Explorer" -Name "DisableNotificationCenter" -PropertyType Dword -Value 1 -Force
# Turn off Action Center Sidebar
# New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" -Name "UseActionCenterExperience " -PropertyType DWord -Value 0 -Force
# Turn on Action Center
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -ErrorAction SilentlyContinue
#
#
#
##########################################################
######                      Time                    ######
##########################################################
# Turn on BIOS time (UTC)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -Type DWord -Value 1
# Turn on BIOS time (local time)
#Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -ErrorAction SilentlyContinue
# Change NTP server to pool.ntp.org
w32tm /config /syncfromflags:manual /manualpeerlist:"0.pool.ntp.org 1.pool.ntp.org 2.pool.ntp.org 3.pool.ntp.org"
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\W32time\Parameters" -Name "NtpServer" -PropertyType String -Value "pool.ntp.org,0x8" -Force
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\W32time\Parameters" -Name "NTP" -Type DWord -Value 3 (fixme)
#Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient" -Name "CrossSiteSyncFlags" -Type DWord -Value 2 -Force
#Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient" -Name "ResolvePeerBackoffMaxTimes" -Type DWord -Value 7 -Force
#Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient" -Name "ResolvePeerBackoffMinutes" -Type DWord -Value 15 -Force
#Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient" -Name "SpecialPollInterval" -Type DWord -Value 1024 -Force
#
#
#
#################################################################
###### DNS (Cloudflare, enforce DNS via Router/PI always!) ######
#################################################################
# Set custom DNS on NetAdapter
Get-NetAdapter -Physical | Set-DnsClientServerAddress -ServerAddresses 1.1.1.1,1.0.0.1,2606:4700:4700::1111,2606:4700:4700::1001
#
#
#
#
##########################################################
######              Task Scheduler                   #####
##########################################################
# Turn off Task Scheduler migrates several security problems but is problematic to disable (fixme)
#Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\Schedule" -Name "Start" -Type DWord -Value 4 -Force
# Create a task via Task Scheduler to clear the "\SoftwareDistribution\Download" folder automatically every 4 weeks (Monday).
$action = New-ScheduledTaskAction -Execute powershell.exe -Argument @"
	`$getservice = Get-Service -Name wuauserv
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
Disable-ScheduledTask -TaskName "\Microsoft\Office\OfficeTelemetry\AgentFallBack2016"
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
Get-ScheduledTask -TaskPath "\Microsoft\Office\Office 15 Subscription Heartbeat\" | Disable-ScheduledTask
Get-ScheduledTask -TaskPath "\Microsoft\Office\Office 16 Subscription Heartbeat\" | Disable-ScheduledTask
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Shell\FamilySafetyMonitor\" | Disable-ScheduledTask
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Shell\FamilySafetyRefresh\" | Disable-ScheduledTask
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Shell\FamilySafetyUpload\" | Disable-ScheduledTask
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Windows Error Reporting\QueueReporting\" | Disable-ScheduledTask
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\" | Disable-ScheduledTask


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
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128" -Name "Enabled" -Type DWord -Value ffffffff
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256" -Name "Enabled" -Type DWord -Value ffffffff
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56" -Name "Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL" -Name "Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128" -Name "Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128" -Name "Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128" -Name "Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128" -Name "Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128" -Name "Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128" -Name "Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128" -Name "Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168" -Name "Enabled" -Type DWord -Value 0
# Key Exchanges
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" -Name "Enabled" -Type DWord -Value ffffffff
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\ECDH" -Name "Enabled" -Type DWord -Value ffffffff
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS" -Name "Enabled" -Type DWord -Value ffffffff
# Hashes
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5" -Name "Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA" -Name "Enabled" -Type DWord -Value ffffffff
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA256" -Name "Enabled" -Type DWord -Value ffffffff
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA384" -Name "Enabled" -Type DWord -Value ffffffff
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA512" -Name "Enabled" -Type DWord -Value ffffffff
# Protocols
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client" -Name "Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client" -Name "DisabledByDefault" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server" -Name "Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server" -Name "DisabledByDefault" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client" -Name "Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client" -Name "DisabledByDefault" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server" -Name "Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server" -Name "DisabledByDefault" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Name "Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Name "DisabledByDefault" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name "Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name "DisabledByDefault" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Name "Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Name "DisabledByDefault" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name "Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name "DisabledByDefault" -Type DWord -Value 1
#Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name "Enabled" -Type DWord -Value ffffffff
#Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name "DisabledByDefault" -Type DWord -Value 0
#Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "Enabled" -Type DWord -Value ffffffff
#Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "DisabledByDefault" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name "Enabled" -Type DWord -Value ffffffff
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name "DisabledByDefault" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "Enabled" -Type DWord -Value ffffffff
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "DisabledByDefault" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "Enabled" -Type DWord -Value ffffffff
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "DisabledByDefault" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -Type DWord -Value ffffffff
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "DisabledByDefault" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" -Name "Enabled" -Type DWord -Value ffffffff
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" -Name "DisabledByDefault" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Name "Enabled" -Type DWord -Value ffffffff
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Name "DisabledByDefault" -Type DWord -Value 0
# Cipher Suites (order) (fixme)
Set-ItemProperty -Path "HKLM:\HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Name "Functions" -Type String -Value TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA
##########################################################
###### 					Network Stack                #####
##########################################################
# Turn off all "useless" network adapter protocols
# http://techgenix.com/using-powershell-disable-network-adapter-bindings/
# https://community.idera.com/database-tools/powershell/ask_the_experts/f/powershell_for_windows-12/13716/disable-unnecessary-network-features-as-internet-protocol-version-6
# https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/enable-or-disable-a-server-network-protocol?view=sql-server-2017
# https://www.tenforums.com/tutorials/90033-enable-disable-ipv6-windows.html
function DisableUnneededProtocols {
	$Components = @('Client for Microsoft Networks'
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
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "LargeSystemCache" -Type DWord -Value 0
#
# Nagle's Algorithm
# This tweak is useless since Windows 8.1+, because the Algorithm was replaced by a more efficent one. The default values are usually fine,
# I'm not aware of any professional gamer which still uses such a tweak or an outdated OS.
#
# Network Throttling Index & System Responsiveness
# SystemResponsiveness & NetworkThrottlingIndex <-> done by the OS itself and does not change anything
# https://msdn.microsoft.com/en-us/library/ms684247.aspx
# I enabled so that you can do a backup, apply the tweak, and see nothing happens.
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Type DWord -Value 4294967295
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Type DWord -Value 20
# Multimedia Class Scheduler Service (MMCSS) tweaks
# https://msdn.microsoft.com/en-us/library/windows/desktop/ms684247.aspx
# default: 0, recommended: 0. Both 0x00 and 0xFFFFFFFF
# Affinity is OS controlled and never CPU, same like e.g. Core Parking and C-states.
# Application should exclusively ask MMCSS for its help otherwise nothing will be changed because the OS never knows if the app is MMCSS "optimized" or not.
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Affinity" -Type DWord -Value 0
# (fixme) Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Background Only" -Type REG_SZ "False"
# (fixme) Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Scheduling Category" -Type REG_SZ "High"
# (fixme) Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "SFIO Priority" -Type REG_SZ "High"
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "GPU Priority" -Type DWord -Value 8
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -Type DWord  -Value 2
# Turn off ECN Capability
# As per RFC3168 http://tools.ietf.org/html/rfc3168
Set-NetTCPSetting -SettingName InternetCustom -EcnCapability Disabled | Out-Null
# Turn off Receive Segment Coalescing State (RSC)
Disable-NetAdapterRsc -Name * | Out-Null
# Turn off Large Send Offload (LSO)
Disable-NetAdapterLso -Name * | Out-Null
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
# Turn off Telemetry Data in .NET Core
# https://www.michaelcrump.net/part12-aspnetcore/
setx -Ux DOTNET_CLI_TELEMETRY_OPTOUT=1 | Out-Null
setx -Ux DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 | Out-Null
##########################################################
###### 		Firewall (ignore the warnings)           #####
# Public profile should be used (privacy reasons)
# Following the CIS standards
##########################################################
<# Enforce Domain Profile defaults & CIS rec.
# Turn on Windows Firewall: Domain - Firewall state <-> 'On (recommended)'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "EnableFirewall" -Type DWord -Value 1 -Force
# Enforce 'Windows Firewall: Domain: Inbound connections <-> 'Block (default)'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "DefaultInboundAction" -Type DWord -Value 1 -Force
# Enforce 'Windows Firewall: Domain: Outbound connections <-> 'Allow (default)'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "DefaultOutboundAction" -Type DWord -Value 1 -Force
# 'Windows Firewall: Domain: Settings: Display a notification <-> 'No'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "DisableNotifications" -Type DWord -Value 0 -Force
# Set 'Windows Firewall: Domain: Logging: Name <-> '%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -Name "LogFilePath" -Type String -Value "%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log" -Force
# Set 'Windows Firewall: Domain: Logging: Size limit (KB) <-> '16,384 KB or greater'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -Name "LogFileSize" -Type DWord -Value 400 -Force
# Set 'Windows Firewall: Domain: Logging: Log dropped packets <-> 'Yes'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -Name "LogDroppedPackets" -Type DWord -Value 1 -Force
# Set 'Windows Firewall: Domain: Logging: Log successful connections <-> 'Yes'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -Name "LogSuccessfulConnections" -Type DWord -Value 1 -Force
#>

<# Enforce Private Profile defaults & CIS rec.
# Turn on Windows Firewall: Domain - Firewall state <-> 'On (recommended)'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "EnableFirewall" -Type DWord -Value 1 -Force
# Enforce 'Windows Firewall: Domain: Inbound connections <-> 'Block (default)'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "DefaultInboundAction" -Type DWord -Value 1 -Force
# Enforce 'Windows Firewall: Domain: Outbound connections <-> 'Allow (default)'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "DefaultOutboundAction" -Type DWord -Value 1 -Force
# 'Windows Firewall: Domain: Settings: Display a notification <-> 'No'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "DisableNotifications" -Type DWord -Value 0 -Force
# Set 'Windows Firewall: Domain: Logging: Name <-> '%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -Name "LogFilePath" -Type String -Value "%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log" -Force
# Set 'Windows Firewall: Domain: Logging: Size limit (KB) <-> '16,384 KB or greater'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -Name "LogFileSize" -Type DWord -Value 400 -Force
# Set 'Windows Firewall: Domain: Logging: Log dropped packets <-> 'Yes'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -Name "LogDroppedPackets" -Type DWord -Value 1 -Force
# Set 'Windows Firewall: Domain: Logging: Log successful connections <-> 'Yes'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -Name "LogSuccessfulConnections" -Type DWord -Value 1 -Force
#>

<# Enforce Public Profile defaults & CIS rec.
# Turn on Windows Firewall: Domain - Firewall state <-> 'On (recommended)'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "EnableFirewall" -Type DWord -Value 1 -Force
# Enforce 'Windows Firewall: Domain: Inbound connections <-> 'Block (default)'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "DefaultInboundAction" -Type DWord -Value 1 -Force
# Enforce 'Windows Firewall: Domain: Outbound connections <-> 'Allow (default)'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "DefaultOutboundAction" -Type DWord -Value 1 -Force
# 'Windows Firewall: Domain: Settings: Display a notification <-> 'No'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "DisableNotifications" -Type DWord -Value 0 -Force
# Set 'Windows Firewall: Domain: Logging: Name <-> '%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Name "LogFilePath" -Type String -Value "%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log" -Force
# Set 'Windows Firewall: Domain: Logging: Size limit (KB) <-> '16,384 KB or greater'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Name "LogFileSize" -Type DWord -Value 400 -Force
# Set 'Windows Firewall: Domain: Logging: Log dropped packets <-> 'Yes'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Name "LogDroppedPackets" -Type DWord -Value 1 -Force
# Set 'Windows Firewall: Domain: Logging: Log successful connections <-> 'Yes'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Name "LogSuccessfulConnections" -Type DWord -Value 1 -Force
#>
# 'Prohibit installation and configuration of Network Bridge on your DNS domain network <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_AllowNetBridge_NLA" -Type DWord -Value 0 -Force
# 'Prohibit use of Internet Connection Sharing on your DNS domain network <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_ShowSharedAccessUI" -Type DWord -Value 0 -Force
# 'Require domain users to elevate when setting a network's location <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_StdDomainUserSetLocatio" -Type DWord -Value 1 -Force
#
# Null route Source IP for e.g. Pi-Hole or AdGuard Home
#route -p add 131.253.18.253 MASK 255.255.255.255 0.0.0.0
#
## Add anti-telemetry domains to hosts incl. LTSB/LTSC 2019
#
#
# Todo: Sort, redundant check + check if rules exists
# Todo: Maybe null route instead of blocking (HOSTS bypass by Windows own DNS system?)
# Todo: ASN block Skype, apps etc. Cloudfront?
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
    "statsfe2.update.microsoft.com.akadns.net"
    "statsfe2.ws.microsoft.com"
    "survey.watson.microsoft.com"
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
    "watson.ppe.telemetry.microsoft.com"
    "watson.telemetry.microsoft.com.nsatc.net"
    "watson.telemetry.microsoft.com.nsatc.net"
    "watson.telemetry.microsoft.com"
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
Remove-NetFirewallRule -DisplayName "Anti-Telemetry IPs" -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "Anti-Telemetry IPs" -Direction Outbound ` -Action Block -RemoteAddress ([string[]]$ips)


# Block Cortana via Firewall Rule (fixme)
New-NetFirewallRule -DisplayName "Anti Cortana Web Access" -Direction Outbound -Program "%windir%\systemapps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe" -Action Block
##########################################################
######              Bitlocker (VeraCrypt)            #####
# If you use VeraCrypt the entries are not written in reg
##########################################################
# Turn on machine account lockout threshold'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "MaxDevicePasswordFailedAttempts" -Type DWord -Value 000000a -Force
# Prevent installation of devices that match any of these device IDs"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceIDs" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Prevent installation of devices that match any of these device IDs: Prevent installation of devices that match any of these device IDs <-> 'PCI\CC_0C0A' (fixme)
# Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "1" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Prevent installation of devices that match any of these device IDs: Also apply to matching devices that are already installed. <-> 'True' (fixme)
# Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceIDsRetroactive" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Prevent installation of devices using drivers that match these device setup classes <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceClasses" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Prevent installation of devices using drivers that match these device setup classes: Prevent installation of devices using drivers for these device setup (fixme)
# {d48179be-ec20-11d1-b6b8-00c04fa372a7} - IEEE 1394 devices that support the SBP2 Protocol Class
# {7ebefbc0-3200-11d2-b4c2-00a0C9697d07} - IEEE 1394 devices that support the IEC-61883 Protocol Class
# {c06ff265-ae09-48f0-812c-16753d7cba83} - IEEE 1394 devices that support the AVC Protocol Class
# {6bdd1fc1-810f-11d0-bec7-08002be2092f} - IEEE 1394 Host Bus Controller Class
# Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceClasses" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue
# "1"="{d48179be-ec20-11d1-b6b8-00c04fa372a7}"
# "1"="{7ebefbc0-3200-11d2-b4c2-00a0C9697d07}"
# "1"="{c06ff265-ae09-48f0-812c-16753d7cba83}"
# "1"="{6bdd1fc1-810f-11d0-bec7-08002be2092f}"
# Prevent installation of devices using drivers that match these device setup classes: Also apply to matching devices that are already installed. <-> 'True' (fixme)
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceClassesRetroactive" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue
#Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab" -Name "DCSettingIndex" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
# (fixme) in case of no TPM chip, is there a Windows 10 without tpm which got the certification? I don't think so.
#
# Allow standby states (S1-S3) when sleeping (plugged in)
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab" -Name "ACSettingIndex" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Allow access to BitLocker-protected fixed data drives from earlier versions of Windows <-> 'Disabled
Remove-Item -Path "HKLM:\Software\Policies\Microsoft\FVE" -Name "DVDiscoveryVolumeType" -Type String -Value "" -Force
# Choose how BitLocker-protected fixed drives can be recovered <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVRecovery" -Type DWord -Value 1 -Force
# Allow data recovery agent
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVManageDRA" -Type DWord -Value 1 -Force
# Allow 48-Bit Recovery Password
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVRecoveryPassword" -Type DWord -Value 2 -Force
# Recovery Key <-> 'Enabled: Allow 256-bit recovery key'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVRecoveryKey" -Type DWord -Value 2 -Force
# Omit recovery options from the BitLocker setup wizard <-> 'Enabled: True'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVHideRecoveryPage" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Save BitLocker recovery information to AD DS for fixed data drives <-> 'Enabled: False'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVActiveDirectoryBackup" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Configure storage of BitLocker recovery information to AD DS <-> 'Enabled: Backup recovery passwords and key packages'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVActiveDirectoryInfoToStore" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Do not enable BitLocker until recovery information is stored to AD DS for fixed data drives <-> 'Enabled: False'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVRequireActiveDirectoryBackup" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Use of hardware-based encryption for fixed data drives <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVHardwareEncryption" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Use of hardware-based encryption for fixed data drives: Use BitLocker software-based encryption when hardware encryption is not available <-> 'Enabled: True'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVAllowSoftwareEncryptionFailover" -Type DWord -Value 1 -Force
# Configure use of hardware-based encryption for fixed data drives: Restrict encryption algorithms and cipher suites allowed for hardware-based encryption <-> 'Enabled: False'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVRestrictHardwareEncryptionAlgorithms" -Type DWord -Value 0 -Force
# Restrict crypto algorithms or cipher suites to the following: <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVAllowedHardwareEncryptionAlgorithms" -PropertyType hex -Value 32,00,2e,00,31,00,36,00,2e,00,38,00,34,00,30,00,2e,00,31,00,2e,00,31,00,30,00,31,00,2e,00,33,00,2e,00,34,00,2e,00,31,00,2e,00,32,00,3b,00,32,00,2e,00,31,00,36,00,2e,00,38,00,34,00,30,00,2e,00,31,00,2e,00,31,00,30,00,31,00,2e,00,33,00,2e,00,34,00,2e,00,31,00,2e,00,34,00,32,00,00,00,00,00 -Force -PropertyType hex -Value 00,00 -Force
# Configure use of passwords for fixed data drives <-> 'Disabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVPassphrase" -Type DWord -Value 0 -Force
# Configure use of smart cards on fixed data drives <-> 'Enabled' (no effect if no smart card was detected)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVAllowUserCert" -Type DWord -Value 1 -Force
# Require use of smart cards on fixed data drives <-> 'Enabled: True'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVEnforceUserCert" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Allow enhanced PINs for startup <-> 'Enabled' (fixme)
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseEnhancedPin" -Type DWord -Value 1 -Force
# Allow Secure Boot for integrity validation <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSAllowSecureBootForIntegrity" -Type DWord -Value 1 -Force
# Choose how BitLocker-protected operating system drives can be recovered <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSRecovery" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Allow data recovery agent <-> 'Enabled: False'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSManageDRA" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Require 48-digit recovery password
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSRecoveryPassword" -Type DWord -Value 2 -Force -ErrorAction SilentlyContinue
# Recovery Key <-> 'Enabled: Do not allow 256-bit recovery key'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSRecoveryKey" -Type DWord -Value 2 -Force -ErrorAction SilentlyContinue
# Omit recovery options from the BitLocker setup wizard <-> 'Enabled: True'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSHideRecoveryPage" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Save BitLocker recovery information to AD DS for operating system drives <-> 'Enabled: True'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSActiveDirectoryBackup" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Configure storage of BitLocker recovery information to AD DS <-> 'Enabled: Store recovery passwords and key packages'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSActiveDirectoryInfoToStore" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Do not enable BitLocker until recovery information is stored to AD DS for operating system drives <-> 'Enabled: True'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSRequireActiveDirectoryBackup" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Configure minimum PIN length for startup <-> 'Enabled: 7 or more characters'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "MinimumPIN" -Type DWord -Value 20 -Force -ErrorAction SilentlyContinue
# Turn on ardware-based encryption for operating systemm drives
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSHardwareEncryption" -Type DWord -Value 1 -Force
# Use BitLocker software-based encryption when hardware encryption is not available <-> 'Enabled: True'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSAllowSoftwareEncryptionFailover" -Type DWord -Value 1 -Force
# Turn on BitLocker software-based encryption when hardware encryption is not available <-> 'Enabled: True' (fallback)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSAllowSoftwareEncryptionFailover" -Type DWord -Value 1 -Force
# Restrict encryption algorithms and cipher suites allowed for hardware-based encryption <-> 'Enabled: False'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSRestrictHardwareEncryptionAlgorithms" -Type DWord -Value 0 -Force
# Restrict crypto algorithms or cipher suites to the following: <-> 'Enabled`
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSAllowedHardwareEncryptionAlgorithms" -PropertyType hex -Value 32,00,2e,00,31,00,36,00,2e,00,38,00,34,00,30,00,2e,00,31,00,2e,00,31,00,30,00,31,00,2e,00,33,00,2e,00,34,00,2e,00,31,00,2e,00,32,00,3b,00,32,00,2e,00,31,00,36,00,2e,00,38,00,34,00,30,00,2e,00,31,00,2e,00,31,00,30,00,31,00,2e,00,33,00,2e,00,34,00,2e,00,31,00,2e,00,34,00,32,00,00,00,00,00 -Force
# Passwords for operating system drives <-> 'Disabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSPassphrase" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Require additional authentication at startup <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseAdvancedStartup" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Allow BitLocker without a compatible TPM <-> 'Enabled: False'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "EnableBDEWithNoTPM" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Configure TPM startup <-> 'Enabled: 'Do not allow TPM'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseTPM" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Configure TPM startup PIN <-> 'Enabled: Require startup PIN with TPM'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseTPMPIN" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Configure TPM startup key: <-> 'Enabled: Do not allow startup key with TPM'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseTPMKey" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Configure TPM startup key and PIN <-> 'Enabled: Do not allow startup key and PIN with TPM'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseTPMKeyPIN" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Allow access to BitLocker-protected removable data drives from earlier versions of Windows <-> 'Disabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVDiscoveryVolumeType" -Type String -Value "" -Force
# BitLocker-protected removable drives can be recovered <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVRecovery" -Type DWord -Value 1 -Force
# BitLocker-protected removable drives can be recovered: Allow data recovery agent <-> 'Enabled: True'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVManageDRA" -Type DWord -Value 1 -Force
# BitLocker-protected removable drives can be recovered: Recovery Password <-> 'Enabled: Do not allow 48-digit recovery password'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVRecoveryPassword" -Type DWord -Value 2 -Force -ErrorAction SilentlyContinue
# BitLocker-protected removable drives can be recovered: Recovery Key <-> 'Enabled: Do not allow 256-bit recovery key'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVRecoveryKey" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Omit recovery options from the BitLocker setup wizard <-> 'Enabled: True'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVHideRecoveryPage" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Save BitLocker recovery information to AD DS for removable data drives <-> 'Enabled: False'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVActiveDirectoryBackup" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Configure storage of BitLocker recovery information to AD DS: <-> 'Enabled: Backup recovery passwords and key packages'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVActiveDirectoryInfoToStore" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Do not enable BitLocker until recovery information is stored to AD DS for removable data drives <-> 'Enabled: False'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVRequireActiveDirectoryBackup" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Configure use of hardware-based encryption for removable data drives <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVHardwareEncryption" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue
# BitLocker software-based encryption when hardware encryption is not available <-> 'Enabled: True'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVAllowSoftwareEncryptionFailover" -Type DWord -Value 1 -Force
# Restrict encryption algorithms and cipher suites allowed for hardware-based encryption <-> 'Enabled: False'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVRestrictHardwareEncryptionAlgorithms" -Type DWord -Value 0 -Force
# Restrict crypto algorithms or cipher suites
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVAllowedHardwareEncryptionAlgorithms" -PropertyType hex -Value 32,00,2e,00,31,00,36,00,2e,00,38,00,34,00,30,00,2e,00,31,00,2e,00,31,00,30,00,31,00,2e,00,33,00,2e,00,34,00,2e,00,31,00,2e,00,32,00,3b,00,32,00,2e,00,31,00,36,00,2e,00,38,00,34,00,30,00,2e,00,31,00,2e,00,31,00,30,00,31,00,2e,00,33,00,2e,00,34,00,2e,00,31,00,2e,00,34,00,32,00,00,00,00,00 -Force
# Passwords for removable data drives <-> 'Disabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVPassphrase" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
# Smart cards on removable data drives <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVAllowUserCert" -Type DWord -Value 1 -Force
# Require use of smart cards on removable data drives <-> 'Enabled: True'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVEnforceUserCert" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue
# Deny write access to removable drives not protected by BitLocker <-> 'Enabled'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVDenyWriteAccess" -Type DWord -Value 1 -Force
# Do not allow write access to devices configured in another organization <-> 'Enabled: False'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVDenyCrossOrg" -Type DWord -Value 1 -Force
# Drive encryption method and cipher strength (AES)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "EncryptionMethodWithXtsOs" -Type DWord -Value 7 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "EncryptionMethodWithXtsRdv" -Type DWord -Value 4 -Force
##########################################################
######              MS Office (LibreOffice)          #####
##########################################################
<#
# Turn on Microsoft Office Updates
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate" -Name "enableautomaticupdates" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate" -Name "hideenabledisableupdates" -Type DWord -Value 1 -Force
# Block Macros by default in Office
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\access\security" -Name "blockcontentexecutionfrominternet" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\access\security" -Name "excelbypassencryptedmacroscan" -Type DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\access\security" -Name "vbawarnings" -Type DWord -Value 4 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" -Name "excelbypassencryptedmacroscan" -Type DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\ms project\securit" -Name "vbawarnings" -Type DWord -Value 4 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\ms project\security" -Name "level" -Type DWord -Value 4 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" -Name "level" -Type DWord -Value 4 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security" -Name "blockcontentexecutionfrominternet" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security" -Name "vbawarnings" -Type DWord -Value 4 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\publisher\security" -Name "vbawarnings" -Type DWord -Value 4 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\visio\security" -Name "blockcontentexecutionfrominternet" -Type DWord -Value 4 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\visio\security" -Name "vbawarnings" -Type DWord -Value 4 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\word\security" -Name "blockcontentexecutionfrominternet" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\word\security" -Name "vbawarnings" -Type DWord -Value 4 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\word\security" -Name "wordbypassencryptedmacroscan" -Type DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\common\security" -Name "automationsecurity" -Type DWord -Value 0 -Force
# Turn off Office Fax services
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\services\fax" -Name "nofax" -Type DWord -Value 1 -Force
# Turn off all Office Internet connections (Updates are still possible)
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\internet" -Name "useonlinecontent" -Type DWord -Value 0 -Force
# Turn off One Drive login in Office
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\general" -Name "skydrivesigninoption" -Type DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\signin" -Name "signinoptions" -Type DWord -Value 3 -Force
# Turn off Office Feedback
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\15.0\common\feedback" -Name "enabled" -Type DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\15.0\common\feedback" -Name "includescreenshot" -Type DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback" -Name "enabled" -Type DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback" -Name "includescreenshot" -Type DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\17.0\common\feedback" -Name "enabled" -Type DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\17.0\common\feedback" -Name "includescreenshot" -Type DWord -Value 0 -Force
# Turn off Data Collection
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\general" -Name "notrack" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\general" -Name "optindisable" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\general" -Name "shownfirstrunoptin" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\general" -Name "ptwoptin" -Type DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\general" -Name "bootedrtm" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\general" -Name "disablemovie" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\general" -Name "enablefileobfuscation" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\general" -Name "enablelogging" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm" -Name "enableupload" -Type DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -Name "accesssolution" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -Name "olksolution" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -Name "onenotesolution" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -Name "pptsolution" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -Name "projectsolution" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -Name "publishersolution" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -Name "visiosolution" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -Name "wdsolution" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -Name "xlsolution" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -Name "agave" -Type DWord  -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -Name "appaddins" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -Name "comaddins" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -Name "documentfiles" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplication" -Name "templatefiles" -Type DWord -Value 1 -Force
# Turn off loading of external content in Office
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\outlook\options\mail" -Name "blockextcontent" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\outlook\options\mail" -Name "junkmailenablelinks" -Type DWord -Value 0 -Force
# Turn off Online repair in Office
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate" -Name "onlinerepair" -Type DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate" -Name "fallbacktocdn" -Type DWord -Value 0 -Force
#>

# (Dynamic Data Exchange) DDE Migration
# Not needed in LibreOffice
# https://wiki.documentfoundation.org/Feature_Comparison:_LibreOffice_-_Microsoft_Office#Spreadsheet_applications:_LibreOffice_Calc_vs._Microsoft_Excel
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Word\Options" -Name "DontUpdateLinks" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\15.0\Word\Options" -Name "DontUpdateLinks" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\14.0\Word\Options" -Name "DontUpdateLinks" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Word\Options\WordMail" -Name "DontUpdateLinks" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\15.0\Word\Options\WordMail" -Name "DontUpdateLinks" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\14.0\Word\Options\WordMail" -Name "DontUpdateLinks" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\OneNote\Options" -Name "DisableEmbeddedFiles" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\15.0\OneNote\Options" -Name "DisableEmbeddedFiles" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\14.0\OneNote\Options" -Name "DisableEmbeddedFiles" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Excel\Options" -Name "DontUpdateLinks" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Excel\Options" -Name "DDEAllowed" -Type DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Excel\Options" -Name "DDECleaned" -Type DWord -Value 279 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\15.0\Excel\Options" -Name "DontUpdateLinks" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\15.0\Excel\Options" -Name "DDEAllowed" -Type DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\15.0\Excel\Options" -Name "DDECleaned" -Type DWord -Value 117 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\14.0\Excel\Options" -Name "DontUpdateLinks" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\14.0\Excel\Options" -Name "DDEAllowed" -Type DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\14.0\Excel\Options" -Name "DDECleaned" -Type DWord -Value 117 -Force


# Turn off Macros in Microsoft Office
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\word\security" -Name "blockcontentexecutionfrominternet" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" -Name "blockcontentexecutionfrominternet" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security" -Name "blockcontentexecutionfrominternet" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\15.0\word\security" -Name "blockcontentexecutionfrominternet" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\15.0\excel\security" -Name "blockcontentexecutionfrominternet" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\15.0\powerpoint\security" -Name "blockcontentexecutionfrominternet" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\14.0\msproject\security" -Name "VBAWarnings" -Type DWord -Value 2 -Force

# Turn off Office Packer Objects (OLE) (fixme)
# https://blog.trendmicro.com/trendlabs-security-intelligence/new-cve-2014-4114-attacks-seen-one-week-after-fix/
# https://docs.microsoft.com/en-us/office365/troubleshoot/activation/control-block-ole-com
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\Microsoft\Office\16.0\Common\COM Compatibility" -Name "ActivationFilterOverride " -Type DWord -Value 1 -Force


##########################################################
###### 				USer Account Control (UAC)       #####
##########################################################
# Turn on Admin Approval Mode
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken" -Value 1 -Force
# EnableLUA
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Force
# Set UAC to high
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 5
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1

# Make UAC Great Again (MUGA)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Type DWord -Value 3
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DenyDeviceIDs" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableAutomaticRestartSignOn" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DSCAutomationHostEnabled" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableCursorSuppression" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFullTrustStartupTasks" -Type DWord -Value 2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableInstallerDetection" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableSecureUIAPaths" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableUIADesktopToggle" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableUwpStartupTasks" -Type DWord -Value 2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableVirtualization" -Type DWord -Value 2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "SupportFullTrustStartupTasks" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "SupportUwpStartupTasks" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "undockwithoutlogon" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ValidateAdminCodeSignatures" -Type DWord -Value 0
##########################################################
###### 					Services                     #####
###### 			Overview services (not all)
# http://www.blackviper.com/service-configurations/black-vipers-windows-10-service-configurations/
# Todo: Find a way to detect and disable all _xxx services automatically.
# Todo: Sysrep needs dmwappushserivce.
##########################################################
# Turn off Autologger (workaround)
New-Item "%ProgramData%\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl" -ItemType File -Force
# Geolocation (workaround)
Remove-Item -Path "HKCU:\SYSTEM\CurrentControlSet\Services\lfsvc\TriggerInfo\3*" -Recurse
# Turn off all unwanted services
$services = @(
	"AJRouter"									# AllJoyn Router Service | Privacy
	"ALG"										# Application Layer Gateway Service | Privacy
	"AxInstSV"									# ActiveX Installer (AxInstSV)
	"AxInstSVGroup"								# AxInstSVGroup
	"BcastDVRUserService_*"						# GameDVR and Broadcast User Service (fixme)
	"BDESVC"									# Bitlocker
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
	"XboxNetApiSvc"								# Xbox Live Networking Service | Privacy
    "diagnosticshub.standardcollector.service" 	# Microsoft (R) Diagnostics Hub Standard Collector Service
    "DiagTrack"								    # Connected User Experiences and Telemetry (Diagnostics)  | Telemetry
    "dmwappushservice"							# WAP Push Message Routing Service (see known issues) | Telemetry
    "HomeGroupListener"							# HomeGroup Listener  | Telemetry
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
    "XblAuthManager"							# Xbox Live Auth Manager
    "XblGameSave"								# Xbox Live Game Save Service
	"XboxNetApiSvc"								# Xbox Live Networking Service
	#"AppMgmt"									# Application Management (needed for GPO software)
	#"BFE"										# Base Filtering Engine - Disable only if you don't use Windows Firewall e.g. for Comodo
	#"Dnscache "								# DNS Client (only if you use other DNS systems like Unbound/DNSCrypt) | Security & Telemetry
	#"EventSystem"								# COM+ Event System (security but problematic)
	#"iphlpsvc"									# IP Helper (IPv6 translation
	#"IpxlatCfgSvc"								# IP Translation Configuration Service
	#"Winmgmt"									# Windows Management Instrumentation | Security -> problematic
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

foreach ($service in $services) {
    Write-Output "Disabling $service"
    Get-Service -Name $service | Set-Service -StartupType Disabled
}


##########################################################
###### 				termsrv.dll Patching             #####
######				Against GitHub/MS ToS?
##########################################################
# Todo
# (fixme)
# store errors / warnings (debug) in a sep. file in order to improve the script
# several other things, secret secret ....


##########################################################
###### 				Run this script as weekly task   #####
###### Ensure you put the script under `C:\Scripts\`
# Todo: Copy script directtly to Windows folder and mark it as read-only?!
##########################################################
$Trigger= New-ScheduledTaskTrigger -At 11:30am –Weekly
$User= "NT AUTHORITY\SYSTEM"
# We don't need any W8 workaround here since we are on PS v6
$Action= New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "C:\Scripts\CK.ps1"
Register-ScheduledTask -TaskName "CKsWin10Hardening" -Trigger $Trigger -User $User -Action $Action -RunLevel Highest –Force



##########################################################
###### 		Environment variables editor             #####
######		http://www.rapidee.com/en/download
##########################################################
