@echo off
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\Program Files\OpenPrime\OpenPrimeRMM-WU-Lab-Launcher.ps1" -Mode Scan -TimeoutSec 180
exit /b %errorlevel%
