# Windows Ent. 1909+
# v0.1 ALPHA
# Totally disable WD incl. all features!

# We need admin rights, ask for elevated permissions first.
# We are going to supress all errors and silently continue.
$ErrorActionPreference= 'silentlycontinue'

If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

#######################
#     Disable WD      #
#######################
<#
# Realtime Protection - Disable Tamper Protection
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -Value 0 -Force
# Disable WD Engine
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -Force
# Disable Behavior Monitoring
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 1 -Force
# Disable On Access Protection
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 1 -Force
# Disable Scan On Real-time
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 1 -Force
#>
# Disable everything
# https://docs.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=win10-ps
Set-MpPreference -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableRealtimeMonitoring $true -DisableScriptScanning $true -EnableControlledFolderAccess Disabled -EnableNetworkProtection AuditMode -Force -MAPSReporting Disabled -SubmitSamplesConsent NeverSend

#######################
#       Services      #
#######################
<# Old way
Set-ItemProperty -Path "HKLM:\System\ControlSet001\Services\WdFilter" -Name "Start" -PropertyType DWord -Value 4 -Force
Set-ItemProperty -Path "HKLM:\System\ControlSet001\Services\WdNisDrv" -Name "Start" -PropertyType DWord -Value 4 -Force
Set-ItemProperty -Path "HKLM:\System\ControlSet001\Services\WdNisSvc" -Name "Start" -PropertyType DWord -Value 4 -Force
Set-ItemProperty -Path "HKLM:\System\ControlSet001\Services\WinDefend" -Name "Start" -PropertyType DWord -Value 4 -Force
Set-ItemProperty -Path "HKLM:\System\ControlSet001\Services\WinDefend" -Name "Start" -PropertyType DWord -Value 4 -Force
Set-ItemProperty -Path "HKLM:\System\ControlSet002\Services\WdFilter" -Name "Start" -PropertyType DWord -Value 4 -Force
Set-ItemProperty -Path "HKLM:\System\ControlSet002\Services\WdNisDrv" -Name "Start" -PropertyType DWord -Value 4 -Force
Set-ItemProperty -Path "HKLM:\System\ControlSet002\Services\WdNisSvc" -Name "Start" -PropertyType DWord -Value 4 -Force
Set-ItemProperty -Path "HKLM:\System\ControlSet002\Services\WinDefend" -Name "Start" -PropertyType DWord -Value 4 -Force
Set-ItemProperty -Path "HKLM:\System\ControlSet002\Services\WinDefend" -Name "Start" -PropertyType DWord -Value 4 -Force
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\WdBoot" -Name "Start" -PropertyType DWord -Value 4 -Force
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\WdFilter" -Name "Start" -PropertyType DWord -Value 4 -Force
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\WdNisDrv" -Name "Start" -PropertyType DWord -Value 4 -Force
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\WdNisSvc" -Name "Start" -PropertyType DWord -Value 4 -Force
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\WinDefend" -Name "Start" -PropertyType DWord -Value 4 -Force
#>
Get-Service WinDefend | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service WdNisDrv | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service WdNisSvc | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service WdFilter | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service WdBoot | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service WdNisDrv | Stop-Service -PassThru | Set-Service -StartupType Disabled

#######################
#       Updates       #
#######################
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" -Name "UpdateOnStartUp" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" -Name "UpdateOnStartUp" -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -PropertyType DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -PropertyType DWord -Value 1 -Force

###############################
#   Security Health Service   #
###############################
Set-ItemProperty -Path "HKCU:\SYSTEM\CurrentControlSet\Services" -Name "SecurityHealthService" -PropertyType DWord -Value 4 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services" -Name "SecurityHealthService" -PropertyType DWord -Value 4 -Force
