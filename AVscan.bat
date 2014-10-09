@echo off
:: -------------------------------------------------------------------------------------------------------
:: Script for running Malware detection and scanners
::
::  Usage:   AVscan.bat [log destination]

	
:: Run TDSSKiller by Kaspersky
:: TDSSKiller will create the log directories.  If this is removed, then they need to be created
:: for the other tools to function properly
scan\tdsskiller.exe -accepteula -sigcheck -l %1\avscan-%username%\tdss.log -tdlfs -qpath %1\avscan-%username%\quarantine -qmbr -qsus

:: Run McAfee Stinger
if %PROCESSOR_ARCHITECTURE% == x86 (scan\stinger32.exe --go --reportpath=%1\avscan-%username%) else ( scan\stinger64.exe --go --reportpath=%1\avscan-%username%) 
	
