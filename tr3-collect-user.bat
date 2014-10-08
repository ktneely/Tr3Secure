@echo off
:: --------------------------------------------------------------------------------------------------------------------------
:: TR3Secure Data Collection Script for a User Account
::
:: v1.0
::
:: tr3-collect-user is a batch script to automate the collection of volatile data and select artifacts from live Windows systems
::
:: Change history
::
:: References
::
::
:: Copyright 2013 Corey Harrell (Journey Into Incident Response)
:: 
:: --------------------------------------------------------------------------------------------------------------------------
:: Syntax
:: --------------------------------------------------------------------------------------------------------------------------
:: This section explains the command-line syntax for running tr3-collect.bat
::
:: tr3-collect-user.bat [path to store collected data] [user profile name]
::
::		[path to store collected data] = the path to store the collected data without any quotes or spaces
::		[user profile name] = the user account's profile name to collect data from
::
:: i.e.  tr3-collect-user.bat F:\Data-demo2\computername-08.12.13-19.14 jsmith
:: 
:: --------------------------------------------------------------------------------------------------------------------------
:: Declare and Set Variables
:: --------------------------------------------------------------------------------------------------------------------------
:: This section configures the variables used thoughout the script
::
:: Setting variables for command-line options
set c_path=%1
set c_user=%2
:: --------------------------------------------------------------------------------------------------------------------------
:: Operating System Environment Variables
:: --------------------------------------------------------------------------------------------------------------------------
	:: Determining the System Architecture (another Troy Larson idea incorporated)
	if "%PROCESSOR_ARCHITECTURE%" == "x86" set arch=32
	if "%PROCESSOR_ARCHITECTURE%" == "AMD64" set arch=64
	:: Determining the operating system since file paths between XP/2003/2000 and 7/2008 are different
	:: references http://malektips.com/xp_dos_0025.html and http://msdn.microsoft.com/en-us/library/ms724832(VS.85).aspx
	ver | %WINDIR%\System32\find.exe "5.0" > nul
	if %ERRORLEVEL% == 0 set os=legacy
	ver | %WINDIR%\System32\find.exe  "5.1" > nul
	if %ERRORLEVEL% == 0 set os=legacy
	ver | %WINDIR%\System32\find.exe  "5.2" > nul
	if %ERRORLEVEL% == 0 set os=legacy
	:: if statement below sets the userpath variable
	if %os% == legacy (set userpath=%systemdrive%\Documents and Settings) else (set userpath=%systemdrive%\Users)
:: --------------------------------------------------------------------------------------------------------------------------
:: Creating Log
:: --------------------------------------------------------------------------------------------------------------------------
:: This section sets up the logging function of the script
::
:createlog
cls
:: Creates the directory on the collection drive to store data if it isn't already present
if not exist %c_path%\%c_user%_data (
	echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create the output folder %c_user%_data
	echo:
	tools\mkdir.exe %c_path%\%c_user%_data
	)
:: Will create the log file if it's not present and start logging 
if not exist %c_path%\%c_user%_data\Collection.log (
	echo ****************************************************************************************** > %c_path%\%c_user%_data\Collection.log
	echo Collection Log for User Profile %c_user% >> %c_path%\%c_user%_data\Collection.log
	echo ****************************************************************************************** >> %c_path%\%c_user%_data\Collection.log
	echo Log Created at %DATE% %TIME% >> %c_path%\%c_user%_data\Collection.log
	echo: >> %c_path%\%c_user%_data\Collection.log
	echo: >> %c_path%\%c_user%_data\Collection.log
	)
echo ------------------------------------------------------------------------------------------ >> %c_path%\%c_user%_data\Collection.log
echo %DATE% %TIME% - Logging initiated for %c_user% on %COMPUTERNAME% >> %c_path%\%c_user%_data\Collection.log
echo %DATE% %TIME% - Logging initiated for %c_user% on %COMPUTERNAME%
echo %DATE% %TIME% - Logging started for %c_user% on %COMPUTERNAME% by user account %USERDOMAIN%\%USERNAME%  >> %c_path%\%c_user%_data\Collection.log
echo %DATE% %TIME% - The path for storing the collection data is %c_path%: >> %c_path%\%c_user%_data\Collection.log
echo:
cls
goto :main
:: --------------------------------------------------------------------------------------------------------------------------
:: Main Processing Area
:: --------------------------------------------------------------------------------------------------------------------------
:: This section performs the data collection from the user profile system
::
:main
	::Creating output directories
	if not exist %c_path%\%c_user%_data\Recent (
		echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store the Recent folder
		echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store the Recent folder >> %c_path%\%c_user%_data\Collection.log
		tools\mkdir.exe %c_path%\%c_user%_data\Recent
		)
	if not exist %c_path%\%c_user%_data\Office_Recent (
		echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store the Office Recent folder
		echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store the Office Recent folder >> %c_path%\%c_user%_data\Collection.log
		tools\mkdir.exe %c_path%\%c_user%_data\Office_Recent
		)
	if not exist %c_path%\%c_user%_data\Network_Recent (
		echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store the Network Recent folder
		echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store the Network Recent folder >> %c_path%\%c_user%_data\Collection.log
		tools\mkdir.exe %c_path%\%c_user%_data\Network_Recent
		)
	if not exist %c_path%\%c_user%_data\temp (
		echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store the temp folder
		echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store the temp folder >> %c_path%\%c_user%_data\Collection.log
		tools\mkdir.exe %c_path%\%c_user%_data\temp
		)
	if not exist %c_path%\%c_user%_data\Temporary_Internet_Files (
		echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store the Temporary Internet Files
		echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store the Temporary Internet Files >> %c_path%\%c_user%_data\Collection.log
		tools\mkdir.exe %c_path%\%c_user%_data\Temporary_Internet_Files
		)
	if not exist %c_path%\%c_user%_data\PrivacIE (
		echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store the PrivacIE folder
		echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store the PrivacIE folder >> %c_path%\%c_user%_data\Collection.log
		tools\mkdir.exe %c_path%\%c_user%_data\PrivacIE
		)
	if not exist %c_path%\%c_user%_data\Cookies (
		echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store the Cookies folder
		echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store the Cookies folder >> %c_path%\%c_user%_data\Collection.log
		tools\mkdir.exe %c_path%\%c_user%_data\Cookies
		)
	if not exist %c_path%\%c_user%_data\java_cache (
		echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store the Java Cache folder
		echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store the Java Cache folder >> %c_path%\%c_user%_data\Collection.log
		tools\mkdir.exe %c_path%\%c_user%_data\java_cache
		)
	:: ****************************************************************************************************************************
	:: Collecting the Recent folder
	::
	echo %DATE% %TIME% - Running tools\Robocopy.exe on %COMPUTERNAME% to collect the Recent folder
	echo %DATE% %TIME% - Running tools\Robocopy.exe on %COMPUTERNAME% to collect the Recent folder  >> %c_path%\%c_user%_data\Collection.log
	:: The following are the robocopy switches: /zb  Tries to copy files in restartable mode, 
	::  /copy:DAT copy file data, timestamps, and attributes /r:0  retry 0 times,
	:: /ts source timestamps in log, /FP displays full pathnames in output,
	:: /np progress indicator turned off and /log  creates log file by overwriting one if already exists
	if %os% == legacy (
	tools\robocopy.exe "%userpath%\%c_user%\Recent" %c_path%\%c_user%_data\Recent /ZB /copy:DAT /r:0 /ts /FP /np /E /log:%c_path%\%c_user%_data\robocopy-log_recent.txt
	) else (
	tools\robocopy.exe "%userpath%\%c_user%\AppData\Roaming\Microsoft\Windows\Recent" %c_path%\%c_user%_data\Recent /ZB /copy:DAT /r:0 /ts /FP /np /E /log:%c_path%\%c_user%_data\robocopy-log_recent.txt
	)
	:: ****************************************************************************************************************************
	:: Collecting the Office Recent folder
	::
	echo %DATE% %TIME% - Running tools\Robocopy.exe on %COMPUTERNAME% to collect the Office Recent folder
	echo %DATE% %TIME% - Running tools\Robocopy.exe on %COMPUTERNAME% to collect the Office Recent folder  >> %c_path%\%c_user%_data\Collection.log
	if %os% == legacy (
	tools\robocopy.exe "%userpath%\%c_user%\Application Data\Microsoft\Office\Recent" %c_path%\%c_user%_data\Office_Recent /ZB /copy:DAT /r:0 /ts /FP /np /E /log:%c_path%\%c_user%_data\robocopy-log_office-recent.txt
	) else (
	tools\robocopy.exe "%userpath%\%c_user%\AppData\Roaming\Microsoft\Office\Recent" %c_path%\%c_user%_data\Office_Recent /ZB /copy:DAT /r:0 /ts /FP /np /E /log:%c_path%\%c_user%_data\robocopy-log_office-recent.txt
	)
	:: ****************************************************************************************************************************
	:: Collecting the Network Shares Recent folder
	::
	echo %DATE% %TIME% - Running tools\Robocopy.exe on %COMPUTERNAME% to collect the Network Shares Recent folder
	echo %DATE% %TIME% - Running tools\Robocopy.exe on %COMPUTERNAME% to collect the Network Shares Recent folder  >> %c_path%\%c_user%_data\Collection.log
	if %os% == legacy (
	tools\robocopy.exe "%userpath%\%c_user%\Nethood" %c_path%\%c_user%_data\Network_Recent /ZB /copy:DAT /r:0 /ts /FP /np /E /log:%c_path%\%c_user%_data\robocopy-log_network-recent.txt
	) else (
	tools\robocopy.exe "%userpath%\%c_user%\AppData\Roaming\Microsoft\Windows\Network Shortcuts" %c_path%\%c_user%_data\Network_Recent /ZB /copy:DAT /r:0 /ts /FP /np /E /log:%c_path%\%c_user%_data\robocopy-log_network-recent.txt
	)
	:: ****************************************************************************************************************************
	:: Collecting the Temporary folder
	::
	echo %DATE% %TIME% - Running tools\Robocopy.exe on %COMPUTERNAME% to collect the Temp folder
	echo %DATE% %TIME% - Running tools\Robocopy.exe on %COMPUTERNAME% to collect the Temp folder  >> %c_path%\%c_user%_data\Collection.log
	if %os% == legacy (
	tools\robocopy.exe "%userpath%\%c_user%\Local Settings\Temp" %c_path%\%c_user%_data\temp /ZB /copy:DAT /r:0 /ts /FP /np /E /log:%c_path%\%c_user%_data\robocopy-log_temp.txt
	) else (
	tools\robocopy.exe "%userpath%\%c_user%\AppData\Local\Temp" %c_path%\%c_user%_data\temp /ZB /copy:DAT /r:0 /ts /FP /np /E /log:%c_path%\%c_user%_data\robocopy-log_temp.txt
	)
	:: ****************************************************************************************************************************
	:: Collecting the Temporary Internet Files folder
	::
	echo %DATE% %TIME% - Running tools\Robocopy.exe on %COMPUTERNAME% to collect the Temporary Internet Files folder
	echo %DATE% %TIME% - Running tools\Robocopy.exe on %COMPUTERNAME% to collect the Temporary Internet Files folder  >> %c_path%\%c_user%_data\Collection.log
	if %os% == legacy (
	tools\robocopy.exe "%userpath%\%c_user%\Local Settings\Temporary Internet Files" %c_path%\%c_user%_data\Temporary_Internet_Files /ZB /copy:DAT /r:0 /ts /FP /np /E /log:%c_path%\%c_user%_data\robocopy-log_tif.txt
	) else (
	tools\robocopy.exe "%userpath%\%c_user%\AppData\Local\Microsoft\Windows\Temporary Internet Files" %c_path%\%c_user%_data\Temporary_Internet_Files /ZB /copy:DAT /r:0 /ts /FP /np /E /log:%c_path%\%c_user%_data\robocopy-log_tif.txt
	)
	:: ****************************************************************************************************************************
	:: Collecting the PrivacIE folder
	::
	echo %DATE% %TIME% - Running tools\Robocopy.exe on %COMPUTERNAME% to collect the PrivacIE folder
	echo %DATE% %TIME% - Running tools\Robocopy.exe on %COMPUTERNAME% to collect the PrivacIE folder  >> %c_path%\%c_user%_data\Collection.log
	if %os% == legacy (
	tools\robocopy.exe "%userpath%\%c_user%\PrivacIE" %c_path%\%c_user%_data\PrivacIE /ZB /copy:DAT /r:0 /ts /FP /np /E /log:%c_path%\%c_user%_data\robocopy-log_privacie.txt
	) else (
	tools\robocopy.exe "%userpath%\%c_user%\AppData\Roaming\Microsoft\Windows\PrivacIE" %c_path%\%c_user%_data\PrivacIE /ZB /copy:DAT /r:0 /ts /FP /np /E /log:%c_path%\%c_user%_data\robocopy-log_privacie.txt
	)
	:: ****************************************************************************************************************************
	:: Collecting the Cookies folder
	::
	echo %DATE% %TIME% - Running tools\Robocopy.exe on %COMPUTERNAME% to collect the Cookies folder
	echo %DATE% %TIME% - Running tools\Robocopy.exe on %COMPUTERNAME% to collect the Cookies folder  >> %c_path%\%c_user%_data\Collection.log
	if %os% == legacy (
	tools\robocopy.exe "%userpath%\%c_user%\Cookies" %c_path%\%c_user%_data\Cookies /ZB /copy:DAT /r:0 /ts /FP /np /E /log:%c_path%\%c_user%_data\robocopy-log_cookies.txt
	) else (
	tools\robocopy.exe "%userpath%\%c_user%\AppData\Roaming\Microsoft\Windows\Cookies" %c_path%\%c_user%_data\Cookies /ZB /copy:DAT /r:0 /ts /FP /np /E /log:%c_path%\%c_user%_data\robocopy-log_cookies.txt
	)
	:: ****************************************************************************************************************************
	:: Collecting the Java Cache folder
	::
	echo %DATE% %TIME% - Running tools\Robocopy.exe on %COMPUTERNAME% to collect the Java Cache folder
	echo %DATE% %TIME% - Running tools\Robocopy.exe on %COMPUTERNAME% to collect the Java Cache folder  >> %c_path%\%c_user%_data\Collection.log
	if %os% == legacy (
	tools\robocopy.exe "%userpath%\%c_user%\Application Data\Sun\Java\Deployment\cache" %c_path%\%c_user%_data\java_cache /ZB /copy:DAT /r:0 /ts /FP /np /E /log:%c_path%\%c_user%_data\robocopy-log_java.txt
	) else (
	tools\robocopy.exe "%userpath%\%c_user%\AppData\LocalLow\Sun\Java\Deployment\cache" %c_path%\%c_user%_data\java_cache /ZB /copy:DAT /r:0 /ts /FP /np /E /log:%c_path%\%c_user%_data\robocopy-log_java.txt
	)
echo:
goto :exit
:: --------------------------------------------------------------------------------------------------------------------------
:: Exit Processing Area
:: --------------------------------------------------------------------------------------------------------------------------
:: This section performs some additional documentation before the script exits 
::
:: Below is the error message for when the script is run without administrative privileges
:: Source: Troy Larson came up with the idea to check for admin rights and I'm only incorporating his work into my script
:noadmin
	cls
	set noadmin=1
	echo You are running this script without administrative privileges
	echo.
	echo.
	echo You must run this script using an user account with administrative privileges
	echo.
	echo.
	pause
	cls
	goto :exit
:exit
	:: The lines below makes the script exit when ran without administrative privileges
	if %noadmin% == 1 goto :EOF
	:: The lines below document when the script exited
	echo.
	echo.
	echo Completed acquring %c_user%'s data
	pause
	cls
	echo %DATE% %TIME% - Exiting user collection script for and stopping logging for computer %COMPUTERNAME% >> %c_path%\%c_user%_data\Collection.log
:: --------------------------------------------------------------------------------------------------------------------------