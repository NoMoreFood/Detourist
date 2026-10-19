@ECHO OFF
SETLOCAL
SET COPYCMD=/Y
SET STAGEDIR=%~dp0PackageStage
POWERSHELL -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0Build.ps1" -StageDirectory "%STAGEDIR%" %*
EXIT /B %ERRORLEVEL%
