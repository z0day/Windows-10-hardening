# Windows Ent. 1909+
# v0.1 ALPHA
# EMET Mode = No Cloud features
# ATP

# We need admin rights, ask for elevated permissions first.
# We are going to supress all errors and silently continue.
$ErrorActionPreference= 'silentlycontinue'

If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

#######################
#  Backup exclusions  #
#######################
# Backup file based extensions
$RegKey = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions')
$RegKey.PSObject.Properties | ForEach-Object {
  If($_.Name -like '*.*'){
    Write-Host $_.Name
  }
}

# Backup file and path based rules
$RegKey = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths')
$RegKey.PSObject.Properties | ForEach-Object {
  If($_.Name -like '*:\*'){
    Write-Host $_.Name
  }
}

# Backup process based exclusions
$RegKey = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes')
$RegKey.PSObject.Properties | ForEach-Object {
  If($_.Name -like '*.*'){
    Write-Host $_.Name
  }
}

# Backup ASR Rules
$RegKey = (Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR')
$RegKey.PSObject.Properties | ForEach-Object {
  If($_.Name -like '*.*'){
    Write-Host $_.Name
  }
}

#######################
#      Exclusions     #
#######################
# Enable default auto exclusions
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions" -Name "Exclusions" -PropertyType DWord -Value 1 -Force
# Exclusions Extensions
# fixme New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions" -Name "Exclusions_Extensions" -Value 1 -Force
# Exclusions Extensions
# fixme New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions" -Name "Exclusions_Extensions" -Value 1 -Force
# Exclusion Paths
# fixme New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions" -Name "Exclusions_Paths" -Value 1 -Force
# Exclusion Processes
# fixme New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions" -Name "Exclusions_Processes" -Value 1 -Force
#######################
#      WD Common      #
#######################
# Enable Fast Startup Service
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "AllowFastServiceStartup" -PropertyType DWord -Value 1 -Force
# Enable AntiSpyware Defender (Windows Defender)
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "AntiSpywareDefender" -PropertyType DWord -Value 1 -Force
# Disable Local Admin Merge
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableLocalAdminMerge" -PropertyType DWord -Value 0 -Force
# Disable Routinely Taking Action
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableRoutinelyTakingAction" -PropertyType DWord -Value 0 -Force
# Proxy Bypass
# New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "ProxyBypass" -Value "" -Force
# PAC URL
# New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "ProxyPacUrl" -Value "" -Force
# Proxy Server
# New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "ProxyServer" -Value "" -Force
# Randomize Schedule Task Times
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "RandomizeScheduleTaskTimes" -Value 1 -Force
# Do not keep WD alive (if not needed)
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "ServiceKeepAlive" -Value 0 -Force
# PUA Protection
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "PUAProtection" -Value 1 -Force
# Disable Protocol Recognition
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\NIS" -Name "DisableProtocolRecognition" -Value 0 -Force
# Consumers IPS Disable Signature Retirement
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\IPS" -Name "DisableSignatureRetirement" -Value 0 -Force
# Consumers IPS SKU differentiation Signature Set Guid
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\IPS" -Name "Nis_Consumers_IPS_sku_differentiation_Signature_Set_Guid" -Value 0 -Force
#######################
#      Quarantine     #
#######################
# Quarantine - Local Setting Override Purge Items After Delay
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Quarantine" -Name "LocalSettingOverridePurgeItemsAfterDelay" -Value 0 -Force
# Quarantine - Purge Items After Delay
# Min = 0
# Max = 10000000
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Quarantine" -Name "PurgeItemsAfterDelay" -Value 10000000 -Force
#######################
# Behavior Monitoring #
#######################
# Disable Behavior Monitoring
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 0 -Force
#######################
# Realtime Protection #
#######################
# Realtime Protection - Disable IOAV Protection
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableIOAVProtection" -Value 0 -Force
# Realtime Protection - Disable On Access Protection
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 0 -Force
# Realtime Protection - Disable Raw Write Notification
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRawWriteNotification" -Value 1 -Force
# Realtime Protection - Disable Realtime Monitoring
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 0 -Force
# Realtime Protection - Disable Scan On Realtime Enable
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 0 -Force
# Realtime Protection - IO AV Max Size
# Min = 0
# Max = 10000000
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "IOAVMaxSize" -Value 100 -Force
# Realtime Protection - Local Setting Override Disable Behavior Monitoring
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "LocalSettingOverrideDisableBehaviorMonitoring" -Value 0 -Force
# Realtime Protection - Local Setting Override Disable On Access Protection
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "LocalSettingOverrideDisableOnAccessProtection" -Value 0 -Force
# Realtime Protection - Local Setting Override Disable IO AV Protection
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "LocalSettingOverrideDisableIOAVProtection" -Value 0 -Force
# Realtime Protection - Local Setting Override Disable Real-time Monitoring
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "LocalSettingOverrideDisableRealtimeMonitoring" -Value 0 -Force
# Realtime Protection - Local Setting Override Realtime Scan Direction
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "LocalSettingOverrideRealtimeScanDirection" -Value 0 -Force
# Realtime Protection - Realtime Scan Direction
# 0 = ScanDirection_0
# 1 = ScanDirection_1
# 2 = ScanDirection_2
# New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "RealtimeScanDirection" -Value 0 -Force
#######################
#     Remediation     #
#######################
# Local Setting Override Scan - ScheduleTime
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Remediation" -Name "LocalSettingOverrideScan_ScheduleTime" -Value 0 -Force
# Scan-ScheduleDay
# Value: 1 -> 7 = Scan_ScheduleDay_1..2..3.. etc
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Remediation" -Name "Scan_ScheduleDay" -Value 2 -Force
# Scan-ScheduleTime
# Min = 0
# Max = 1440
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Remediation" -Name "Scan_ScheduleTime" -Value 2 -Force
#######################
#      Reporting      #
#######################
# Additional Action Timeout
# Min = 0
# Max = 4294967295
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Reporting" -Name "AdditionalActionTimeout" -Value 4563 -Force
# Critical Failure Timeout
# Min = 0
# Max = 4294967295
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Reporting" -Name "CriticalFailureTimeout" -Value 4563 -Force
# Disable generic Reports
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Reporting" -Name "DisableGenericRePorts" -Value 1 -Force
# Non Critical Timeout
# Min = 0
# Max = 4294967295
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Reporting" -Name "NonCriticalTimeout" -Value 4563 -Force
# Recently Cleaned Timeout
# Min = 0
# Max = 4294967295
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Reporting" -Name "RecentlyCleanedTimeout" -Value 4563 -Force
# Wpp Tracing Components
# Min = 0
# Max = 4294967295
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Reporting" -Name "WppTracingComponents" -Value 4563 -Force
# Wpp Tracing Level
# Min = 0
# Max = 4294967295
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Reporting" -Name "WppTracingLevel" -Value 4563 -Force
# Disable Enhanced Notifications
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Reporting" -Name "DisableEnhancedNotifications" -Value 0 -Force
#######################
#        Scan         #
#######################
# Disable Enhanced Notifications
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" -Name "AllowPause" -PropertyType DWord -Value 1 -Force
# Archive Max Depth
# Min = 0
# Max = 4294967295
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" -Name "ArchiveMaxDepth" -Value 150 -Force
# Archive Max Size
# Min = 0
# Max = 4294967295
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" -Name "ArchiveMaxDepth" -Value 1294967 -Force
# Avg CPU Load Factor
# Min = 0
# Max = 100
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" -Name "AvgCPULoadFactor" -Value 47 -Force
# Check For Signatures Before Running Scan
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" -Name "AvgCPULoadFactor" -Value 0 -Force
# Check For Signatures Before Running Scan
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" -Name "DisableArchiveScanning" -Value 0 -Force
# Disable Catchup Full Scan
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" -Name "DisableCatchupFullScan" -Value 0 -Force
# Disable Catchup Quick Scan
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" -Name "DisableCatchupQuickScan" -Value 0 -Force
# Disable Email Scanning
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" -Name "DisableEmailScanning" -Value 0 -Force
# Disable Heuristics
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" -Name "DisableHeuristics" -Value 0 -Force
# Disable Packed Exe Scanning
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" -Name "DisablePackedExeScanning" -Value 0 -Force
# Disable Removable Drive Scanning
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" -Name "DisableRemovableDriveScanning" -Value 0 -Force
# Disable Reparse Point Scanning
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" -Name "DisableReparsePointScanning" -Value 0 -Force
# Disable Restore Point
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" -Name "DisableRestorePoint" -PropertyType DWord -Value 0 -Force
# Disable Scanning Mapped Network Drives For Full Scan
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" -Name "DisableScanningMappedNetworkDrivesForFullScan" -PropertyType DWord -Value 0 -Force
# Disable Scanning Network Files
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" -Name "DisableScanningNetworkFiles" -PropertyType DWord -Value 1 -Force
# Local Setting Override Scan Parameters
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" -Name "LocalSettingOverrideScanParameters" -PropertyType DWord -Value 1 -Force
# Local Setting Override Schedule Day
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" -Name "LocalSettingOverrideScheduleDay" -PropertyType DWord -Value 0 -Force
# Local Setting Override Schedule Quick Scan Time
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" -Name "LocalSettingOverrideScheduleQuickScanTime" -PropertyType DWord -Value 0 -Force
# Local Setting Override Schedule Time
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" -Name "LocalSettingOverrideScheduleTime" -PropertyType DWord -Value 0 -Force
# Purge Items After Delay
# Min = 0
# Max = 4294967295
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" -Name "PurgeItemsAfterDelay" -PropertyType DWord -Value 0 -Force
# Quick Scan Interval
# Min = 0
# Max = 24
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" -Name "PurgeItemsAfterDelay" -PropertyType DWord -Value 12 -Force
# Scan Only If Idle
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" -Name "ScanOnlyIfIdle" -PropertyType DWord -Value 1 -Force
#  Scan Only If Idle
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" -Name "ScanParameters" -PropertyType DWord -Value 1 -Force
# Schedule Day
# 1 - 7 -> Scan_ScheduleDay_0, Scan_ScheduleDay_1, etc
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" -Name "ScheduleDay" -PropertyType DWord -Value 3 -Force
# Schedule Quick Scan Time
# Min = 0
# Max = 1440
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" -Name "ScheduleQuickScanTime" -PropertyType DWord -Value 1 -Force
# Schedule Time
# Min = 0
# Max = 1440
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" -Name "ScheduleTime" -PropertyType DWord -Value 1 -Force
# Missed Scheduled Scan Count Before Catchup
# Min = 2
# Max = 20
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" -Name "MissedScheduledScanCountBeforeCatchup" -PropertyType DWord -Value 4 -Force
# Missed Scheduled Scan Count Before Catchup
# Min = 2
# Max = 20
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" -Name "MissedScheduledScanCountBeforeCatchup" -PropertyType DWord -Value 4 -Force
# Low CPU Priority
# Min = 0
# Max = 1440
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" -Name "LowCpuPriority" -PropertyType DWord -Value 1 -Force
#######################
#  Signature Update   #
#######################
# AS Signature Due
# Min = 0
# Max = 4294967295
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates" -Name "ASSignatureDue" -PropertyType DWord -Value 14 -Force
# AS Signature Due
# Min = 0
# Max = 4294967295
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates" -Name "ASSignatureDue" -PropertyType DWord -Value 14 -Force
# Definition Update File Shares Sources
# Min = 0
# Max = 4294967295
# fixme New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates" -Name "ASSignatureDue" -PropertyType DWord -Value 14 -Force
# SharedSignatureRoot
# fixme New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates" -Name "SharedSignatureRoot" -PropertyType DWord -Value 14 -Force
# Disable Scan On Update
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates" -Name "DisableScanOnUpdate" -PropertyType DWord -Value 1 -Force
# Disable Scheduled Signature Updateon Battery
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates" -Name "DisableScheduledSignatureUpdateOnBattery" -PropertyType DWord -Value 1 -Force
# Disable Update On Startup Without Engine
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates" -Name "DisableUpdateOnStartupWithoutEngine" -PropertyType DWord -Value 1 -Force
# Fallback Order
# fixme New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates" -Name "FallbackOrder" -PropertyType DWord -Value 1 -Force
# Force Update From MU
# fixme New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates" -Name "ForceUpdateFromMU" -PropertyType DWord -Value 1 -Force
# Real-time signature delivery
# fixme New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates" -Name "RealtimeSignatureDelivery" -PropertyType DWord -Value 1 -Force
# Schedule Day
# 0 - 7, ScheduleDay_0, ScheduleDay_1, etc
# fixme New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates" -Name "ScheduleDay" -PropertyType DWord -Value 1 -Force
# Schedule Time
# Min = 0
# Max = 1440
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates" -Name "ScheduleTime" -PropertyType DWord -Value 1 -Force
# Signature Disable Notification
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates" -Name "SignatureDisableNotification" -PropertyType DWord -Value 1 -Force
# Signature Update Catchup Interval
# Min = 0
# Max = 4294967295
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates" -Name "SignatureUpdateCatchupInterval" -PropertyType DWord -Value 1 -Force
# Signature Update Interval (in hours)
# Min = 0
# Max = 24
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates" -Name "SignatureUpdateInterval" -PropertyType DWord -Value 6 -Force
# Signature Update Interval (in hours)
# Min = 0
# Max = 24
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates" -Name "SignatureUpdateInterval" -PropertyType DWord -Value 6 -Force
# Update On Startup
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates" -Name "UpdateOnStartUp" -PropertyType DWord -Value 1 -Force
# Disable Block At First Seen
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates" -Name "DisableBlockAtFirstSeen" -PropertyType DWord -Value 1 -Force
#################################################
#                     SpyNet                    #
#       Community based sample sumbissions      #
#################################################
# Local Setting Override Spynet Reporting
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet" -Name "LocalSettingOverrideSpynetReporting" -PropertyType DWord -Value 0 -Force
# Disable Block At First Seen
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet" -Name "DisableBlockAtFirstSeen" -PropertyType DWord -Value 0 -Force
# Disable SpyNet reporting
# 0 = Disabled
# 1 = Basic
# 2 = Advanced
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -PropertyType DWord -Value 0 -Force
# Disable Sample Sumbission
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -PropertyType DWord -Value 0 -Force
###############################
#           Threats           #
###############################
# Threat Id Default Action
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Threats" -Name "Threats_ThreatIdDefaultAction" -PropertyType DWord -Value 0 -Force
# Threat Id Default Action
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Threats" -Name "Threats_ThreatSeverityDefaultAction" -PropertyType DWord -Value 0 -Force
# Threat Configuration UI Lockdown
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\UX Configuration" -Name "UILockdown" -PropertyType DWord -Value 0 -Force
# Suppress Reboot Notification
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\UX Configuration" -Name "SuppressRebootNotification" -PropertyType DWord -Value 1 -Force
# Suppress Reboot Notification Suppress
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\UX Configuration" -Name "Notification_Suppress" -PropertyType DWord -Value 1 -Force
# Suppress Custom Default Action Toast String
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\UX Configuration" -Name "CustomDefaultActionToastString" -PropertyType DWord -Value 1 -Force
###############################
#           Cloud             #
###############################
# Mp Cloud Block Level
# 0 = Default
# 2 = High Level
# 4 = High Plus Level
# 6 = Zero Tolerance Level
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\MpEngine" -Name "MpCloudBlockLevel" -PropertyType DWord -Value 0 -Force
# Mp Bafs Extended Timeout
# Min = 0
# Max = 50
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\MpEngine" -Name "MpBafsExtendedTimeout" -PropertyType DWord -Value 0 -Force
# Enable Network Protection
# 0 = Enable Controlled Folder Access - Disable
# 1 = Enable Controlled Folder Access - Block
# 2 = Enable Controlled Folder Access - Audit
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Name "EnableNetworkProtection" -PropertyType DWord -Value 0 -Force
###############################
#         Exploit Guard       #
###############################
# Controlled FolderAccess - Enable Controlled Folder Access
# 0 = Enable Controlled Folder Access - Disable
# 1 = Enable Controlled Folder Access - Block
# 2 = Enable Controlled Folder Access - Audit
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access" -Name "EnableControlledFolderAccess" -PropertyType DWord -Value 0 -Force
# Controlled FolderAccess - Enable Controlled Folder Access
# 0 = Enable Controlled Folder Access - Disable
# 1 = Enable Controlled Folder Access - Block
# 2 = Enable Controlled Folder Access - Audit
# 3 = Enable Controlled Folder Access - Block Disk Modifications
# 4 = Enable Controlled Folder Access - Audit Disk Modifications
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access" -Name "EnableControlledFolderAccess" -PropertyType DWord -Value 0 -Force
# ExploitGuard - ASR Rules
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -Name "ExploitGuard_ASR_Rules" -PropertyType DWord -Value 0 -Force
# ExploitGuard - ASR Rules - ASR Only Exclusions
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -Name "ExploitGuard_ASR_ASROnlyExclusions" -PropertyType DWord -Value 0 -Force
###############################
#        Folder Access       #
###############################
# Controlled Folder Access - Allowed Applications
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access" -Name "ExploitGuard_ControlledFolderAccess_AllowedApplications" -PropertyType DWord -Value 0 -Force
# Controlled Folder Access - Protected Folders
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access" -Name "ExploitGuard_ControlledFolderAccess_ProtectedFolders" -PropertyType DWord -Value 0 -Force
###############################
#  Enable Tamper Protection   #
###############################
# Enable Tamper Protection
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -PropertyType DWord -Value 5 -Force
