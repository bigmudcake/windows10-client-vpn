@rem PowerShell.exe -ExecutionPolicy UnRestricted -File "%~dpn0.ps1"
@rem To keep script window open for debugging, add the argument -NoExit before -File in the command below
Powershell.exe -Command "& {Start-Process Powershell.exe -ArgumentList '-ExecutionPolicy UnRestricted -File %~dpn0.ps1' -Verb RunAs}"
exit