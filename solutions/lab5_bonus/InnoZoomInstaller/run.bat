@echo off
echo Downloading ZIP file to C:\Temp...

:: Create C:\Temp directory if it doesn't exist
if not exist "C:\Temp" mkdir "C:\Temp"

:: Download using .NET WebClient (no special modules required)
powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; (New-Object System.Net.WebClient).DownloadFile('https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1036/bin/T1036.zip', 'C:\Temp\T1036.zip')}"

:: Check if download was successful
if exist "C:\Temp\T1036.zip" (
    echo Download completed successfully.
    echo File saved to C:\Temp\T1036.zip
) else (
    echo Download failed.
)

msiexec /i C:\Users\Administrator\Downloads\ZoomInstallerFull.msi /quiet /qn /norestart /log install.log