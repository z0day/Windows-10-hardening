@echo off
cd /d "%~dp0"
rem
rem Background, source code & mod based on: https://erdentec.com/pausing-windows-10-updates-indefinitely/
rem Windows Update error code list: https://support.microsoft.com/en-us/search?query=error%2080240FFF
rem Latest WUMT version: https://goo.gl/F3z3xo (credits to the original dev for this tool!)
rem Requires WUMT or WuMgr (rename wumgr.exe to wumt) and works for Home/Pro Windows Users!
rem Set WUMT/WuMgr "Automatic Updates" to "Notification Mode"
rem Executing the script resumes Windows Updates, launches WUMT and at the completion of WUMT pauses the updates again.
set "params=Problem_with_elevating_UAC_for_Administrator_Privileges"&if exist "%temp%\getadmin.vbs" del "%temp%\getadmin.vbs"
fsutil dirty query %systemdrive%  >nul 2>&1 || (
rem Avoid infinite loops if elevating UAC for Administrator privileges failed
If "%1"=="%params%" echo Elevating UAC for Administrator Privileges failed&echo Right click on the script and select 'Run as administrator'&echo Press any key to exit...&pause>nul&exit
cmd /u /c echo Set UAC = CreateObject^("Shell.Application"^) : UAC.ShellExecute "%~0", "%params%", "", "runas", 0 > "%temp%\getadmin.vbs"&"%temp%\getadmin.vbs"&del "%temp%\getadmin.vbs"&exit)
rem
rem Get Windows OS build number first
for /f "tokens=2 delims==" %%a in ('wmic path Win32_OperatingSystem get BuildNumber /value') do set /a WinBuild=%%a
if %winbuild% LEQ 9600 (echo.&echo This is not Windows 10. Press a key to exit...&pause>nul&exit)
rem
rem Check OS type 32 or 64 bit and set variables accordingly
wmic cpu get AddressWidth /value|find "32">nul&&set "wumt=wumt_x86.exe"||set "wumt=wumt_x64.exe"
(
echo Windows Registry Editor Version 5.00
echo [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings]
echo "PauseFeatureUpdatesStartTime"=-
echo "PauseQualityUpdatesStartTime"=-
echo "PauseUpdatesExpiryTime"=-
echo "PauseFeatureUpdatesEndTime"=-
echo "PauseQualityUpdatesEndTime"=-
echo [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\Settings]
echo "PausedQualityStatus"=dword:00000000
echo "PausedFeatureStatus"=dword:00000000
)>resumewindowsupdates.reg
(
echo Windows Registry Editor Version 5.00
echo [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings]
echo "PauseFeatureUpdatesStartTime"="2019-03-15T14:34:30Z"
echo "PauseQualityUpdatesStartTime"="2019-01-15T22:13:35Z"
echo "PauseUpdatesExpiryTime"="2099-11-11T16:38:59Z"
echo "PauseFeatureUpdatesEndTime"="2099-11-11T11:11:11Z"
echo "PauseQualityUpdatesEndTime"="2099-11-11T11:11:11Z"
echo [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\Settings]
echo "PausedQualityStatus"=dword:00000001
echo "PausedFeatureStatus"=dword:00000001
)>pausewindowsupdate.reg
regedit -s resumewindowsupdates.reg
start "" "%wumt%" "-onclose regedit -s pausewindowsupdate.reg"
exit