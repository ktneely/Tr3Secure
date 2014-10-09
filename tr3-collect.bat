@echo off
:: --------------------------------------------------------------------------------------------------------------------------
:: TR3Secure Data Collection Script
::
:: v2.0
::
:: tr3-collect is a batch script to automate the collection of volatile data and select artifacts from live Windows systems
::
:: Change history
::
:: References
::
:: 		Malware Forensics: Investigating and Analyzing Malicious Code by Cameron H. Malin, Eoghan Casey, and James M. Aquilina 
:: 		Windows Forensics Analysis (WFA) Second Edition by Harlan Carvey
:: 		RFC 3227 - Guidelines for Evidence Collection and Archiving http://www.faqs.org/rfcs/rfc3227.html
::		Dual Purpose Volatile Data Collection Script http://journeyintoir.blogspot.com/2012/01/dual-purpose-volatile-data-collection.html

::
:: Copyright 2013 Corey Harrell (Journey Into Incident Response)
:: 
:: --------------------------------------------------------------------------------------------------------------------------
:: Syntax
:: --------------------------------------------------------------------------------------------------------------------------
:: This section explains the command-line syntax for running tr3-collect.bat
::
:: tr3-collect.bat [case number] [drive letter for storing collected data] [menu selection #]
::
::		[case number] = the unique identifier for the case
::		[drive letter for storing collected data] = drive letter of where the collected data is to be stored
::		[menu selection] = optional field and can be used to collect the following:
::				1 = Acquire Memory Forensic Image
::				2 = Acquire Volatile Data 
::				3 = Acquire Non-Volatile Data 
::				4 = Acquire Volatile and Non-Volatile Data (default)
::				5 = Acquire Memory Forensic Image, Volatile, and Non-Volatile Data 
::
:: i.e.  tr3-collect.bat 2012-09-14_1 F
:: 		 tr3-collect.bat 2012-09-14_1 F 3
:: 
:: --------------------------------------------------------------------------------------------------------------------------
:: Declare and Set Variables
:: --------------------------------------------------------------------------------------------------------------------------
:: This section configures the variables used thoughout the script
::
:: Setting variables for command-line options
set case=%1
set c_drive=%2
set selection=%3
:: The current default selection is 4 but this can be changed on lines 51 and 60
IF "%3" == "" ( 
	set selection=4 
	goto :variable
	)
IF DEFINED selection (
	IF %selection% == 1 goto :variable
	IF %selection% == 2 goto :variable
	IF %selection% == 3 goto :variable
	IF %selection% == 4 goto :variable
	IF %selection% == 5 goto :variable
	set selection=5 
	goto :variable
	)
:: ****************************************************************************************************************************
:: Declaring all variables for the script and setting them as null
:variable
	set noadmin=""
	set m=""
	set d=""
	set y=""
	set hh=""
	set mm=""
	set timestamp=""
	set mem_outpath=""
	set vol_outpath=""
	set os=""
	set nonvol_outpath=""
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
:: --------------------------------------------------------------------------------------------------------------------------
:: Creating Log
:: --------------------------------------------------------------------------------------------------------------------------
:: This section sets up the logging function of the script
::
:createlog
cls
:: Creates the directory on the collection drive to store data if it isn't already present
if not exist %c_drive%:\Data-%case% (
	echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create the case output folder Data-%case%
	echo:
	tools\mkdir.exe %c_drive%:\Data-%case%
	)
:: Will create the log file if it's not present and start logging 
if not exist %c_drive%:\Data-%case%\Collection.log (
	echo ****************************************************************************************** > %c_drive%:\Data-%case%\Collection.log
	echo Collection Log for Case %case% >> %c_drive%:\Data-%case%\Collection.log
	echo ****************************************************************************************** >> %c_drive%:\Data-%case%\Collection.log
	echo Log Created at %DATE% %TIME% >> %c_drive%:\Data-%case%\Collection.log
	echo: >> %c_drive%:\Data-%case%\Collection.log
	echo: >> %c_drive%:\Data-%case%\Collection.log
	)
echo ------------------------------------------------------------------------------------------ >> %c_drive%:\Data-%case%\Collection.log
echo %DATE% %TIME% - Logging initiated for %COMPUTERNAME% >> %c_drive%:\Data-%case%\Collection.log
echo %DATE% %TIME% - Logging initiated for %COMPUTERNAME%
echo %DATE% %TIME% - Logging started on %COMPUTERNAME% by user account %USERDOMAIN%\%USERNAME%  >> %c_drive%:\Data-%case%\Collection.log
echo %DATE% %TIME% - The drive letter for the volume storing the collection data is %c_drive%: >> %c_drive%:\Data-%case%\Collection.log
echo:
cls
	:: Logs the selection made
	if %selection% == 1 echo %DATE% %TIME% - Selection was made to acquire memory forensic image for %COMPUTERNAME% >> %c_drive%:\Data-%case%\Collection.log
	if %selection% == 2 echo %DATE% %TIME% - Selection was made to acquire volatile data for %COMPUTERNAME% >> %c_drive%:\Data-%case%\Collection.log
	if %selection% == 3 echo %DATE% %TIME% - Selection was made to acquire non-volatile data for %COMPUTERNAME% >> %c_drive%:\Data-%case%\Collection.log
	if %selection% == 4 echo %DATE% %TIME% - Selection was made to acquire volatile and non-volatile data for %COMPUTERNAME% >> %c_drive%:\Data-%case%\Collection.log
	if %selection% == 5 echo %DATE% %TIME% - Selection was made to acquire memory forensic image, volatile, and non-volatile data for %COMPUTERNAME% >> %c_drive%:\Data-%case%\Collection.log
	goto :main
:: --------------------------------------------------------------------------------------------------------------------------
:: Main Processing Area
:: --------------------------------------------------------------------------------------------------------------------------
:: This section performs the data collection from the system
::
:main
	:: The main function creates the output folder, preserves the computer's prefetch files, and preserves the user account ntuser.dat file
	:: Preserving the prefetch files and ntuser.dat file prevents them from being overwritten
	::
	:: The collection output folder's name is based on the computer's name and the timestamp of when the data was collected
	:: 
	:: Setting up a timestamp variable because %date% and %time% variables contain characters that cannot be used in folder names
	:: Below sets up variables for the date by getting the month, day, and year in two digits
	set m=%date:~4,2%
	set d=%date:~7,2%
	set y=%date:~12,2%
	:: Below sets up variables for the time by getting the hour and minute in two digits
	set hh=%time:~0,2%
	set mm=%time:~3,2%
	:: below accounts for single digit hours since Microsoft uses a blank and not zero
	if "%hh:~0,1%" == " " set hh=0%hh:~1,1%
	:: Creates the date/time variable for naming folders
	set timestamp=%m%.%d%.%y%-%hh%.%mm%
	:: Creating directory for output data. The naming convention allows the script to be 
	:: executed numerous times without overwriting previous output data
	if not exist %c_drive%:\Data-%case%\%computername%-%timestamp% (
		echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create the output directory %computername%-%timestamp%
		echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create the output directory %computername%-%timestamp% >> %c_drive%:\Data-%case%\Collection.log
		tools\mkdir.exe %c_drive%:\Data-%case%\%computername%-%timestamp%
		)
:: ****************************************************************************************************************************
:: Preserving Files
::
	:: Acquire Memory Forensic Image Only option does not preserve the prefetch files or the user account's ntuser.dat 
		if %selection% == 1 goto :acquire_memory
	:: Creates directory to store preserved prefetch files
		echo %DATE% %TIME% - Running tools\mkdir.exe -p on %COMPUTERNAME% to create directory to store preserved Prefetch files
		echo %DATE% %TIME% - Running tools\mkdir.exe -p on %COMPUTERNAME% to create directory to store preserved Prefetch files >> %c_drive%:\Data-%case%\Collection.log
		tools\mkdir.exe -p %c_drive%:\Data-%case%\%computername%-%timestamp%\preserved-files\Prefetch
		echo %DATE% %TIME% - Running tools\mkdir.exe -p on %COMPUTERNAME% to create directory for active profile (%USERPROFILE%) ntuser.dat hive
		echo %DATE% %TIME% - Running tools\mkdir.exe -p on %COMPUTERNAME% to directory for active profile (%USERPROFILE%) ntuser.dat hive >> %c_drive%:\Data-%case%\Collection.log
		tools\mkdir.exe -p %c_drive%:\Data-%case%\%computername%-%timestamp%\preserved-files\NTUSER_DAT
		echo %DATE% %TIME% - Running tools\mkdir.exe -p on %COMPUTERNAME% to create directory for RecentFileCache.bcf
		echo %DATE% %TIME% - Running tools\mkdir.exe -p on %COMPUTERNAME% to directory for RecentFileCache.bcf >> %c_drive%:\Data-%case%\Collection.log
		tools\mkdir.exe -p %c_drive%:\Data-%case%\%computername%-%timestamp%\preserved-files\AppCompat
	:: robocopy preserves the prefetch files 
		echo %DATE% %TIME% - Running tools\robocopy.exe on %COMPUTERNAME% to preserve prefetch files
		echo %DATE% %TIME% - Running tools\robocopy.exe on %COMPUTERNAME% to preserve prefetch files >> %c_drive%:\Data-%case%\Collection.log
		:: The following are the robocopy swithes: /zb  Tries to copy files in restartable mode, 
		::  /copy:DAT copy file data, timestamps, and attribute /r:0  retry 0 times,
		:: /ts source timestamps in log, /FP displays full pathnames in output,
		:: /np progress indicator turned off and /log  creates log file by overwriting one if already exists
		tools\robocopy.exe %WINDIR%\Prefetch %c_drive%:\Data-%case%\%computername%-%timestamp%\preserved-files\Prefetch\ *.pf /ZB /copy:DAT /r:0 /ts /FP /np /log:%c_drive%:\Data-%case%\%computername%-%timestamp%\preserved-files\pretch-robocopy-log.txt
	::RawCopy collects protected files from a live system including registry hives
		echo %DATE% %TIME% - Running tools\RawCopy.exe on %COMPUTERNAME% to preserve active profile's ntuser.dat hive located in %USERPROFILE%
		echo %DATE% %TIME% - Running tools\RawCopy.exe on %COMPUTERNAME% to preserve active profile's ntuser.dat hive located in %USERPROFILE% >> %c_drive%:\Data-%case%\Collection.log
		if %arch% == 32 (tools\RawCopy.exe "%USERPROFILE%\NTUSER.DAT" %c_drive%:\Data-%case%\%computername%-%timestamp%\preserved-files\NTUSER_DAT) else (tools\RawCopy64.exe "%USERPROFILE%\NTUSER.DAT" %c_drive%:\Data-%case%\%computername%-%timestamp%\preserved-files\NTUSER_DAT)
	::RawCopy collects protected files from a live system 
		echo %DATE% %TIME% - Running tools\RawCopy.exe on %COMPUTERNAME% to preserve the RecentFileCache.bcf located in C:\Windows\AppCompat\Programs
		echo %DATE% %TIME% - Running tools\RawCopy.exe on %COMPUTERNAME% to preserve the RecentFileCache.bcf located in C:\Windows\AppCompat\Programs >> %c_drive%:\Data-%case%\Collection.log
		if %arch% == 32 (tools\RawCopy.exe %WINDIR%\AppCompat\Programs\RecentFileCache.bcf %c_drive%:\Data-%case%\%computername%-%timestamp%\preserved-files\AppCompat) else (tools\RawCopy64.exe %WINDIR%\AppCompat\Programs\RecentFileCache.bcf %c_drive%:\Data-%case%\%computername%-%timestamp%\preserved-files\AppCompat)
	:: Calls the option selected
	if %selection% == 1 goto :acquire_memory
	if %selection% == 2 goto :acquire_volatile
	if %selection% == 3 goto :acquire_nonvolatile
	if %selection% == 4 goto :acquire_volatile
	if %selection% == 5 goto :acquire_memory
:: ****************************************************************************************************************************
:: Acquiring Memory Image
::	
:acquire_memory
	:: The acquire_memory function forensically images the computer's memory.
	:: The script uses win32dd but can be modified to uses any memory image program of choice (for Mandiant's Memoryze contact me for instructions)
	::
	:: Creating output folder for the memory image
		if not exist %c_drive%:\Data-%case%\%computername%-%timestamp%\memory-image (
			echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store the memory image
			echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store the memory image >> %c_drive%:\Data-%case%\Collection.log
			tools\mkdir.exe %c_drive%:\Data-%case%\%computername%-%timestamp%\memory-image
			)
	:: Creating a variable to the memory-image directory to shorten the code
		set mem_outpath=%c_drive%:\Data-%case%\%computername%-%timestamp%\memory-image
	echo %DATE% %TIME% - Running tools\winpmem.exe on %COMPUTERNAME% to create memory image
	echo %DATE% %TIME% - Running tools\winpmem.exe on %COMPUTERNAME% to create memory image >> %c_drive%:\Data-%case%\Collection.log
	tools\winpmem.exe %mem_outpath%\physmem.bin
	echo %DATE% %TIME% - Completed imaging the memory for %COMPUTERNAME%
	echo %DATE% %TIME% - Completed imaging the memory for %COMPUTERNAME% >> %c_drive%:\Data-%case%\Collection.log
	if %selection% == 5 goto :acquire_volatile
	goto :exit
:acquire_volatile
	:: The acquire_volatile function obtains volatile data from the system
	:: RFC 3227's section Order of Volatilty was taken into consideration when specifying the sequence of the data collection
	::
	:: For additional information about the tools used or why the tools' output is important then 
	:: read the comments in this batch file since I noted the exact page numbers 
	:: in my references where the information is covered
	::
	:: The naming convention for the output files is as follows: TypeInfo_#_data-name
		:: The TypeInfo specifies the collected information such as NetworkInfo
		:: The number is the order that the file could be reviewed. For those with a different prefence just ignore the numbers
		:: The data name is the volatile data that was collected such as active-connections
	:: Creating output directory
	if not exist %c_drive%:\Data-%case%\%computername%-%timestamp%\volatile-data (
		echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store the volatile data
		echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store the volatile data >> %c_drive%:\Data-%case%\Collection.log
		tools\mkdir.exe %c_drive%:\Data-%case%\%computername%-%timestamp%\volatile-data
		)
	:: Creating a variable to the volatile-data directory to shorten the code
	set vol_outpath=%c_drive%:\Data-%case%\%computername%-%timestamp%\volatile-data
	:: Collecting process information
		echo %DATE% %TIME% - Collecting process information from %COMPUTERNAME% volatile data
		echo %DATE% %TIME% - Collecting process information from %COMPUTERNAME% volatile data >> %c_drive%:\Data-%case%\Collection.log
		:: Listing the running processes
		:: pslist.exe reference: Malware Forensics page 35 or WFA page 26
			echo Command Executed: pslist.exe /accepteula > %vol_outpath%\ProcessInfo_1_running-processes.txt
			echo: >> %vol_outpath%\ProcessInfo_1_running-processes.txt
			echo %DATE% %TIME% - Running tools\pslist.exe /accepteula on %COMPUTERNAME% to obtain the running processes
			echo %DATE% %TIME% - Running tools\pslist.exe /accepteula on %COMPUTERNAME% to obtain the running processes >> %c_drive%:\Data-%case%\Collection.log
			tools\pslist.exe /accepteula >> %vol_outpath%\ProcessInfo_1_running-processes.txt
		:: Listing the running processes including memory usage
		:: tasklist.exe reference: Malware Forensics page 36 and WFA page 26
			echo Command Executed: tasklist.exe > %vol_outpath%\ProcessInfo_1_running-processes-memory-usage.txt
			echo: >> %vol_outpath%\ProcessInfo_1_running-processes-memory-usage.txt
			echo %DATE% %TIME% - Running %WINDIR%\System32\tasklist.exe on %COMPUTERNAME% to obtain the running processes including memory usage
			echo %DATE% %TIME% - Running %WINDIR%\System32\tasklist.exe on %COMPUTERNAME% to obtain the running processes including memory usage >> %c_drive%:\Data-%case%\Collection.log	
			%WINDIR%\System32\tasklist.exe >> %vol_outpath%\ProcessInfo_1_running-processes-memory-usage.txt
		:: Listing the processes to user mapping
		:: cprocess.exe  /stext reference: Malware Forensics page 38
			echo %DATE% %TIME% - Running tools\cprocess.exe  /stext on %COMPUTERNAME% to obtain the processes to user mapping
			echo %DATE% %TIME% - Running tools\cprocess.exe  /stext on %COMPUTERNAME% to obtain the processes to user mapping >> %c_drive%:\Data-%case%\Collection.log	
			tools\cprocess.exe  /stext %vol_outpath%\ProcessInfo_3_process-to-user-mapping.txt
		:: Listing the processes to user mapping in tab-delimited text file
		:: cprocess.exe  /stab reference: Malware Forensics page 38
			echo %DATE% %TIME% - Running tools\cprocess.exe  /stab on %COMPUTERNAME% to obtain the processes to user mapping in tab-delimited text file
			echo %DATE% %TIME% - Running tools\cprocess.exe  /stab on %COMPUTERNAME% to obtain the processes to user mapping in tab-delimited text file >> %c_drive%:\Data-%case%\Collection.log	
			tools\cprocess.exe  /stab %vol_outpath%\ProcessInfo_3_process-to-user-mapping_tab.csv
		:: Listing the child processes
		:: pslist.exe -t reference: Malware Forensics page 40 or WFA page 26
			echo Command Executed: pslist.exe -t /accepteula > %vol_outpath%\ProcessInfo_4_child-processes.txt
			echo: >> %vol_outpath%\ProcessInfo_4_child-processes.txt
			echo %DATE% %TIME% - Running %WINDIR%\System32\pslist.exe -t /accepteula on %COMPUTERNAME% to obtain the child processes
			echo %DATE% %TIME% - Running %WINDIR%\System32\pslist.exe -t /accepteula on %COMPUTERNAME% to obtain the child processes >> %c_drive%:\Data-%case%\Collection.log
			tools\pslist.exe -t /accepteula >> %vol_outpath%\ProcessInfo_4_child-processes.txt
		:: Listing the processes' file handles
		:: handle.exe reference: Malware Forensics page 42 or WFA page 27
			echo Command Executed: handle.exe /accepteula > %vol_outpath%\ProcessInfo_5_processe-file-handles.txt
			echo: >> %vol_outpath%\ProcessInfo_5_processe-file-handles.txt
			echo %DATE% %TIME% - Running tools\handle.exe /accepteula on %COMPUTERNAME% to obtain the processes' file handles
			echo %DATE% %TIME% - Running tools\handle.exe /accepteula on %COMPUTERNAME% to obtain the processes' file handles >> %c_drive%:\Data-%case%\Collection.log
			tools\handle.exe /accepteula >> %vol_outpath%\ProcessInfo_5_processe-file-handles.txt
		:: Listing the processes' dependencies
		:: listdlls.exe reference: Malware Forensics page 44 or WFA page 26
			echo Command Executed: listdlls.exe /accepteula > %vol_outpath%\ProcessInfo_6_processe-dependencies.txt
			echo: >> %vol_outpath%\ProcessInfo_6_processe-dependencies.txt
			echo %DATE% %TIME% - Running tools\listdlls.exe /accepteula on %COMPUTERNAME% to obtain the processes' dependencies
			echo %DATE% %TIME% - Running tools\listdlls.exe /accepteula on %COMPUTERNAME% to obtain the processes' dependencies >> %c_drive%:\Data-%case%\Collection.log
			tools\listdlls.exe /accepteula >> %vol_outpath%\ProcessInfo_6_processe-dependencies.txt
	:: Collecting network information
		echo %DATE% %TIME% - Collecting network information from %COMPUTERNAME% volatile data
		echo %DATE% %TIME% - Collecting network information from %COMPUTERNAME% volatile data >> %c_drive%:\Data-%case%\Collection.log
		:: Listing the active network connection
		:: netstat.exe -ano reference: Malware Forensics page 26 or WFA page 21
			echo Command Executed: netstat.exe -ano > %vol_outpath%\NetworkInfo_1_active-connections.txt
			echo: >> %vol_outpath%\NetworkInfo_1_active-connections.txt
			echo %DATE% %TIME% - Running %WINDIR%\System32\netstat.exe -ano on %COMPUTERNAME% to obtain the active network connections
			echo %DATE% %TIME% - Running %WINDIR%\System32\netstat.exe -ano on %COMPUTERNAME% to obtain the active network connections >> %c_drive%:\Data-%case%\Collection.log
			%WINDIR%\System32\netstat.exe -ano >> %vol_outpath%\NetworkInfo_1_active-connections.txt
		:: Listing the DNS queries cache
		:: ipconfig.exe /displaydns reference: Malware Forensics page 27 
			echo Command Executed: ipconfig.exe /displaydns > %vol_outpath%\NetworkInfo_2_dns-queries-cache.txt
			echo: >> %vol_outpath%\NetworkInfo_2_dns-queries-cache.txt
			echo %DATE% %TIME% - Running %WINDIR%\System32\ipconfig.exe /displaydns on %COMPUTERNAME% to obtain DNS queries cache
			echo %DATE% %TIME% - Running %WINDIR%\System32\ipconfig.exe /displaydns on %COMPUTERNAME% to obtain DNS queries cache >> %c_drive%:\Data-%case%\Collection.log
			%WINDIR%\System32\ipconfig.exe /displaydns >> %vol_outpath%\NetworkInfo_2_dns-queries-cache.txt
		:: Listing the netbios sessions
		:: nbtstat.exe -s reference: Malware Forensics page 29
			echo Command Executed: nbtstat.exe -s > %vol_outpath%\NetworkInfo_3_netbios-sessions.txt
			echo: >> %vol_outpath%\NetworkInfo_3_netbios-sessions.txt
			echo %DATE% %TIME% - Running %WINDIR%\System32\nbtstat.exe -s on %COMPUTERNAME% to obtain NetBios sessions
			echo %DATE% %TIME% - Running %WINDIR%\System32\nbtstat.exe -s on %COMPUTERNAME% to obtain NetBios sessions >> %c_drive%:\Data-%case%\Collection.log
			%WINDIR%\System32\nbtstat.exe -s >> %vol_outpath%\NetworkInfo_3_netbios-sessions.txt
		:: Listing the netbios cache
		:: nbtstat.exe -c reference: Malware Forensics page 30 or WFA page 20
			echo Command Executed: nbtstat.exe -c > %vol_outpath%\NetworkInfo_4_netbios-cache.txt
			echo: >> %vol_outpath%\NetworkInfo_4_netbios-cache.txt
			echo %DATE% %TIME% - Running %WINDIR%\System32\nbtstat.exe -c on %COMPUTERNAME% to obtain NetBios cache
			echo %DATE% %TIME% - Running %WINDIR%\System32\nbtstat.exe -c on %COMPUTERNAME% to obtain NetBios cache >> %c_drive%:\Data-%case%\Collection.log
			%WINDIR%\System32\nbtstat.exe -c >> %vol_outpath%\NetworkInfo_4_netbios-cache.txt
		:: Listing the recently transered files over Netbios
		:: net.exe file reference: Malware Forensics page 30 
			echo Command Executed: net.exe file > %vol_outpath%\NetworkInfo_5_file-transfer-over-netbios.txt
			echo: >> %vol_outpath%\NetworkInfo_5_file-transfer-over-netbios.txt
			echo %DATE% %TIME% - Running %WINDIR%\System32\net.exe file on %COMPUTERNAME% to obtain the recently transered files over Netbios
			echo %DATE% %TIME% - Running %WINDIR%\System32\net.exe file on %COMPUTERNAME% to obtain the recently transered files over Netbios >> %c_drive%:\Data-%case%\Collection.log
			%WINDIR%\System32\net.exe file >> %vol_outpath%\NetworkInfo_5_file-transfer-over-netbios.txt
		:: Listing the arp cache
		:: arp.exe -a reference: Malware Forensics page 31
			echo Command Executed: arp.exe -a > %vol_outpath%\NetworkInfo_6_arp-cache.txt
			echo: >> %vol_outpath%\NetworkInfo_6_arp-cache.txt
			echo %DATE% %TIME% - Running %WINDIR%\System32\arp.exe -a on %COMPUTERNAME% to obtain arp cache
			echo %DATE% %TIME% - Running %WINDIR%\System32\arp.exe -a on %COMPUTERNAME% to obtain arp cache >> %c_drive%:\Data-%case%\Collection.log
			%WINDIR%\System32\arp.exe -a >> %vol_outpath%\NetworkInfo_6_arp-cache.txt
		:: Listing the routing table
		:: netstate.exe -r reference: WFA page 23
			echo Command Executed: netstat.exe -r > %vol_outpath%\NetworkInfo_7_routing-table.txt
			echo: >> %vol_outpath%\NetworkInfo_7_routing-table.txt
			echo %DATE% %TIME% - Running %WINDIR%\System32\netstat.exe -r on %COMPUTERNAME% to obtain the routing table
			echo %DATE% %TIME% - Running %WINDIR%\System32\netstat.exe -r on %COMPUTERNAME% to obtain the routing table >> %c_drive%:\Data-%case%\Collection.log
			%WINDIR%\System32\netstat.exe -r >> %vol_outpath%\NetworkInfo_7_routing-table.txt
		:: Listing the port to process mapping
		:: openports.exe -lines -path reference: Malware Forensics page 49
			echo Command Executed: openports.exe -lines -path > %vol_outpath%\NetworkInfo_8_port-to-process-mapping_grouped.txt
			echo: >> %vol_outpath%\NetworkInfo_8_port-to-process-mapping_grouped.txt
			echo %DATE% %TIME% - Running tools\openports.exe -lines -path on %COMPUTERNAME% to obtain the port to process mapping grouped together
			echo %DATE% %TIME% - Running tools\openports.exe -lines -path on %COMPUTERNAME% to obtain the port to process mapping grouped together >> %c_drive%:\Data-%case%\Collection.log
			tools\openports.exe -lines -path >> %vol_outpath%\NetworkInfo_8_port-to-process-mapping_grouped.txt
		:: Listing the port to process mapping
		:: tcpvcon -a -c reference: WFA page 32
			echo %DATE% %TIME% - Running tools\tcpvcon.exe -a -c /accepteula on %COMPUTERNAME% to obtain the port to process mapping in csv format
			echo %DATE% %TIME% - Running tools\tcpvcon.exe -a -c /accepteula on %COMPUTERNAME% to obtain the port to process mapping in csv format >> %c_drive%:\Data-%case%\Collection.log
			tools\tcpvcon.exe -a -c /accepteula >> %vol_outpath%\NetworkInfo_8_port-to-process-mapping_csv.csv
	:: Collecting logged on users information
		echo %DATE% %TIME% - Collecting logged on users information from %COMPUTERNAME% volatile data
		echo %DATE% %TIME% - Collecting logged on users information from %COMPUTERNAME% volatile data >> %c_drive%:\Data-%case%\Collection.log
		:: Listing the locally and remotely logged on users including those accessing resource shares
		:: psloggedon.exe reference: Malware Forensics page 24 or WFA page 17
			echo Command Executed: psloggedon.exe /accepteula > %vol_outpath%\UserInfo_1_locally-remotely-logged-on-users.txt
			echo: >> %vol_outpath%\UserInfo_1_locally-remotely-logged-on-users.txt
			echo %DATE% %TIME% - Running tools\psloggedon.exe /accepteula on %COMPUTERNAME% to obtain the locally and remotely logged on users including those accessing resource shares
			echo %DATE% %TIME% - Running tools\psloggedon.exe /accepteula on %COMPUTERNAME% to obtain the locally and remotely logged on users including those accessing resource shares >> %c_drive%:\Data-%case%\Collection.log
			tools\psloggedon.exe /accepteula >> %vol_outpath%\UserInfo_1_locally-remotely-logged-on-users.txt
		:: Listing the remote users IP addresses
		:: net.exe sessions reference: WFA page 17 
			echo Command Executed: net.exe sessions > %vol_outpath%\UserInfo_2_remote-users-ip-addresses.txt
			echo: >> %vol_outpath%\UserInfo_2_remote-users-ip-addresses.txt
			echo %DATE% %TIME% - Running %WINDIR%\System32\net.exe sessions on %COMPUTERNAME% to obtain the remote users IP addresses
			echo %DATE% %TIME% - Running %WINDIR%\System32\net.exe sessions on %COMPUTERNAME% to obtain the remote users IP addresses >> %c_drive%:\Data-%case%\Collection.log
			%WINDIR%\System32\net.exe sessions >> %vol_outpath%\UserInfo_2_remote-users-ip-addresses.txt
		:: Listing the active logon sessions
		:: logonsessions.exe reference: Malware Forensics page 25 or WFA page 18
			echo Command Executed: logonsessions.exe /accepteula > %vol_outpath%\UserInfo_3_active-logon-sessions.txt
			echo: >> %vol_outpath%\UserInfo_3_active-logon-sessions.txt
			echo %DATE% %TIME% - Running tools\logonsessions.exe /accepteula on %COMPUTERNAME% to obtain the active logon sessions
			echo %DATE% %TIME% - Running tools\logonsessions.exe /accepteula on %COMPUTERNAME% to obtain the active logon sessions >> %c_drive%:\Data-%case%\Collection.log
			tools\logonsessions.exe /accepteula >> %vol_outpath%\UserInfo_3_active-logon-sessions.txt
	:: Collecting opened files information
		echo %DATE% %TIME% - Collecting opened files information from %COMPUTERNAME% volatile data
		echo %DATE% %TIME% - Collecting opened files information from %COMPUTERNAME% volatile data >> %c_drive%:\Data-%case%\Collection.log
		:: Listing the open files on the computer
		:: openedfilesview.exe /stext reference: Malware Forensics page 58 and WFA page 19
			echo %DATE% %TIME% - Running tools\openedfilesview.exe /stext on %COMPUTERNAME% to obtain the open files on the computer
			echo %DATE% %TIME% - Running tools\openedfilesview.exe /stext on %COMPUTERNAME% to obtain the open files on the computer >> %c_drive%:\Data-%case%\Collection.log	
			START /WAIT tools\openedfilesview.exe /stext %vol_outpath%\OpenedFilesInfo_1_opened-files.txt
		:: Listing the remotely opened files
		:: psfile.exe reference: Malware Forensics page 59 or WFA page 19
			echo Command Executed: psfile.exe /accepteula > %vol_outpath%\OpenedFilesInfo_2_remotely-opened-files.txt
			echo: >> %vol_outpath%\OpenedFilesInfo_2_remotely-opened-files.txt
			echo %DATE% %TIME% - Running tools\psfile.exe /accepteula on %COMPUTERNAME% to obtain the remotely opened files
			echo %DATE% %TIME% - Running tools\psfile.exe /accepteula on %COMPUTERNAME% to obtain the remotely opened files >> %c_drive%:\Data-%case%\Collection.log
			tools\psfile.exe /accepteula >> %vol_outpath%\OpenedFilesInfo_2_remotely-opened-files.txt
	:: Collecting misc information
		echo %DATE% %TIME% - Collecting misc information from %COMPUTERNAME% volatile data
		echo %DATE% %TIME% - Collecting misc information from %COMPUTERNAME% volatile data >> %c_drive%:\Data-%case%\Collection.log
		:: Listing the clipboard contents on the computer
		:: pclip.exe reference: Malware Forensics page 63 and WFA page 37
			echo Command Executed: pclip.exe > %vol_outpath%\MiscInfo_1_clipboard-contents.txt
			echo: >> %vol_outpath%\MiscInfo_1_clipboard-contents.txt
			echo %DATE% %TIME% - Running tools\pclip.exe on %COMPUTERNAME% to obtain the clipboard contents on the computer
			echo %DATE% %TIME% - Running tools\pclip.exe on %COMPUTERNAME% to obtain the clipboard contents on the computer >> %c_drive%:\Data-%case%\Collection.log
			tools\pclip.exe >> %vol_outpath%\MiscInfo_1_clipboard-contents.txt
	:: Collecting system information
		echo %DATE% %TIME% - Collecting system information from %COMPUTERNAME% volatile data
		echo %DATE% %TIME% - Collecting system information from %COMPUTERNAME% volatile data >> %c_drive%:\Data-%case%\Collection.log
		:: Listing the operating system version
		:: ver reference: Malware Forensics page 19
			echo Command Executed: ver.exe > %vol_outpath%\SystemInfo_1_os-version.txt
			echo: >> %vol_outpath%\SystemInfo_1_os-version.txt
			echo %DATE% %TIME% - Running ver on %COMPUTERNAME% to obtain the operating system version
			echo %DATE% %TIME% - Running ver on %COMPUTERNAME% to obtain the operating system version >> %c_drive%:\Data-%case%\Collection.log
			ver >> %vol_outpath%\SystemInfo_1_os-version.txt
		:: Listing the system's uptime
		:: uptime.exe reference: Malware Forensics page 21
			echo Command Executed: uptime.exe > %vol_outpath%\SystemInfo_2_system-uptime.txt
			echo: >> %vol_outpath%\SystemInfo_2_system-uptime.txt
			:: Documenting the date and time in output to help calculate the uptime
			FOR /F "tokens=*" %%i in ('date /t') do set _date=%%i 
			echo %COMPUTERNAME% date for comparison: %_date% >> %vol_outpath%\SystemInfo_2_system-uptime.txt
			FOR /F "tokens=*" %%i in ('time /t') do set _time=%%i 
			echo %COMPUTERNAME% time for comparison: %_time% >> %vol_outpath%\SystemInfo_2_system-uptime.txt
			echo: >> %vol_outpath%\SystemInfo_2_system-uptime.txt
			echo: >> %vol_outpath%\SystemInfo_2_system-uptime.txt
			:: Continuing with getting the uptime
			echo %DATE% %TIME% - Running tools\uptime.exe on %COMPUTERNAME% to obtain the system's uptime
			echo %DATE% %TIME% - Running tools\uptime.exe on %COMPUTERNAME% to obtain the system's uptime >> %c_drive%:\Data-%case%\Collection.log
			tools\uptime.exe >> %vol_outpath%\SystemInfo_2_system-uptime.txt
		:: Listing the network configuration
		:: ipconfig /all reference: Malware Forensics page 19 and WFA page 34
			echo Command Executed: ipconfig /all > %vol_outpath%\SystemInfo_3_network-configuration.txt
			echo: >> %vol_outpath%\SystemInfo_3_network-configuration.txt
			echo %DATE% %TIME% - Running ipconfig /all on %COMPUTERNAME% to obtain the network configuration
			echo %DATE% %TIME% - Running ipconfig /all on %COMPUTERNAME% to obtain the network configuration >> %c_drive%:\Data-%case%\Collection.log
			%WINDIR%\System32\ipconfig /all >> %vol_outpath%\SystemInfo_3_network-configuration.txt
		:: Listing the enabled network protocols
		:: urlprotocolview.exe /stext reference: Malware Forensics page 20
			echo %DATE% %TIME% - Running tools\urlprotocolview.exe /stext on %COMPUTERNAME% to obtain the enabled network protocols
			echo %DATE% %TIME% - Running tools\urlprotocolview.exe /stext on %COMPUTERNAME% to obtain the enabled network protocols >> %c_drive%:\Data-%case%\Collection.log	
			tools\urlprotocolview.exe /stext %vol_outpath%\SystemInfo_4_enabled-network-protocols.txt
		:: Listing the enabled network protocols
		:: urlprotocolview.exe /stab reference: Malware Forensics page 20
			echo %DATE% %TIME% - Running tools\urlprotocolview.exe /stab on %COMPUTERNAME% to obtain the enabled network protocols in tab-delimited text file
			echo %DATE% %TIME% - Running tools\urlprotocolview.exe /stab on %COMPUTERNAME% to obtain the enabled network protocolsin tab-delimited text file >> %c_drive%:\Data-%case%\Collection.log	
			tools\urlprotocolview.exe /stab %vol_outpath%\SystemInfo_4_enabled-network-protocols_tab.csv
		:: Listing the network adapters in promiscuous mode
		:: promiscdetect.exe reference: Malware Forensics page 19 and WFA page 35
			echo Command Executed: promiscdetect.exe > %vol_outpath%\SystemInfo_5_promiscuous-adapters.txt
			echo: >> %vol_outpath%\SystemInfo_5_promiscuous-adapters.txt
			echo %DATE% %TIME% - Running tools\promiscdetect.exe on %COMPUTERNAME% to obtain the network adapters in promiscuous mode
			echo %DATE% %TIME% - Running tools\promiscdetect.exe on %COMPUTERNAME% to obtain the network adapters in promiscuous mode >> %c_drive%:\Data-%case%\Collection.log
			tools\promiscdetect.exe >> %vol_outpath%\SystemInfo_5_promiscuous-adapters.txt	
	echo:
	echo %DATE% %TIME% - Completed acquring %COMPUTERNAME%'s volatile data
	echo %DATE% %TIME% - Completed acquring %COMPUTERNAME%'s volatile data >> %c_drive%:\Data-%case%\Collection.log
	echo:
	:: Exiting the acquire_memory function
	if %selection% == 4 goto :acquire_nonvolatile
	if %selection% == 5 goto :acquire_nonvolatile
	goto :exit
:acquire_nonvolatile
	:: The acquire_nonvolatile function obtains select data from the system to help with triage
	:: The naming convention for the output folders is as follows: TypeInfo
		:: The TypeInfo specifies the collected information such as AutorunInfo
	:: Creating output directory
	if not exist %c_drive%:\Data-%case%\%computername%-%timestamp%\nonvolatile-data (
		echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store the non-volatile data
		echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store the non-volatile data >> %c_drive%:\Data-%case%\Collection.log
		tools\mkdir.exe %c_drive%:\Data-%case%\%computername%-%timestamp%\nonvolatile-data
		)
	::Creating output directories
	if not exist %c_drive%:\Data-%case%\%computername%-%timestamp%\nonvolatile-data\mbr (
		echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store the MBR non-volatile data
		echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store the MBR non-volatile data >> %c_drive%:\Data-%case%\Collection.log
		tools\mkdir.exe %c_drive%:\Data-%case%\%computername%-%timestamp%\nonvolatile-data\mbr
		)
		if not exist %c_drive%:\Data-%case%\%computername%-%timestamp%\nonvolatile-data\registry (
		echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store the registry hives
		echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store the registry hives >> %c_drive%:\Data-%case%\Collection.log
		tools\mkdir.exe %c_drive%:\Data-%case%\%computername%-%timestamp%\nonvolatile-data\registry
		)
		if not exist %c_drive%:\Data-%case%\%computername%-%timestamp%\nonvolatile-data\ntfs (
		echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store the NTFS artifacts
		echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store the NTFS artifacts >> %c_drive%:\Data-%case%\Collection.log
		tools\mkdir.exe %c_drive%:\Data-%case%\%computername%-%timestamp%\nonvolatile-data\ntfs
		)
		if not exist %c_drive%:\Data-%case%\%computername%-%timestamp%\nonvolatile-data\autoruns (
		echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store the autoruns non-volatile data
		echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store the autoruns non-volatile data >> %c_drive%:\Data-%case%\Collection.log
		tools\mkdir.exe %c_drive%:\Data-%case%\%computername%-%timestamp%\nonvolatile-data\autoruns
		)
		if not exist %c_drive%:\Data-%case%\%computername%-%timestamp%\nonvolatile-data\logs (
		echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store log files
		echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store log files >> %c_drive%:\Data-%case%\Collection.log
		tools\mkdir.exe %c_drive%:\Data-%case%\%computername%-%timestamp%\nonvolatile-data\logs
		)
		if not exist %c_drive%:\Data-%case%\%computername%-%timestamp%\nonvolatile-data\group-policy (
		echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store the group-policy non-volatile data
		echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store the group-policy non-volatile data >> %c_drive%:\Data-%case%\Collection.log
		tools\mkdir.exe %c_drive%:\Data-%case%\%computername%-%timestamp%\nonvolatile-data\group-policy
		)
	:: Creating a variable to the volatile-data directory to shorten the code
		set nonvol_outpath=%c_drive%:\Data-%case%\%computername%-%timestamp%\nonvolatile-data
	:: Collecting non-volatile system information
		echo %DATE% %TIME% - Collecting non-volatile system information from %COMPUTERNAME%
		echo %DATE% %TIME% - Collecting non-volatile system information from %COMPUTERNAME% >> %c_drive%:\Data-%case%\Collection.log
	:: Collecting the System's Boot Record Information
		:: Documenting the partition information
		echo %DATE% %TIME% - Running tools\mmls.exe \\.\PHYSICALDRIVE0 on %COMPUTERNAME% to document the partition information
		echo %DATE% %TIME% - Running tools\mmls.exe \\.\PHYSICALDRIVE0 on %COMPUTERNAME% to document the partition information >> %c_drive%:\Data-%case%\Collection.log
		tools\mmls.exe \\.\PHYSICALDRIVE0 >> %nonvol_outpath%\mbr\%COMPUTERNAME%_partition-info.txt
		:: Imaging the MBR in sector 0
		echo %DATE% %TIME% - Running tools\dd.exe if=\\.\PHYSICALDRIVE0 of=path-mbr.bin bs=512 count=1 on %COMPUTERNAME% to document obtain the MBR
		echo %DATE% %TIME% - Runningtools\dd.exe if=\\.\PHYSICALDRIVE0 of=path-mbr.bin bs=512 count=1 on %COMPUTERNAME% to document obtain the MBR >> %c_drive%:\Data-%case%\Collection.log
		tools\dd.exe if=\\.\PHYSICALDRIVE0 of=%nonvol_outpath%\mbr\%COMPUTERNAME%_mbr.bin bs=512 count=1
		:: Imaging the sectors before the first partition
		echo %DATE% %TIME% - Running tools\dd.exe if=\\.\PHYSICALDRIVE0 of=path-bytes.bin  bs=512 count=63 or count-2048 on %COMPUTERNAME% to obtain sectors before first partition
		echo %DATE% %TIME% - Running tools\dd.exe if=\\.\PHYSICALDRIVE0 of=path-bytes.bin  bs=512 count=63 or count-2048 on %COMPUTERNAME% to obtain sectors before first partition >> %c_drive%:\Data-%case%\Collection.log
		if %os% == legacy (tools\dd.exe if=\\.\PHYSICALDRIVE0 of=%nonvol_outpath%\mbr\winXP_2003-63-bytes.bin bs=512 count=63) else (tools\dd.exe if=\\.\PHYSICALDRIVE0 of=%nonvol_outpath%\mbr\win7_2008-2048-bytes.bin bs=512 count=2048)
	:: Collecting the System's Registry Hives
		:: Collecting the registry hives in the config folder
		echo %DATE% %TIME% - Running tools\RawCopy.exe on %COMPUTERNAME% to obtain the SAM, SECURITY, SOFTWARE, and SYSTEM registry hives
		echo %DATE% %TIME% - Running tools\RawCopy.exe on %COMPUTERNAME% to obtain the SAM, SECURITY, SOFTWARE, and SYSTEM registry hives >> %c_drive%:\Data-%case%\Collection.log
		if %arch% == 32 (
			tools\RawCopy.exe %WINDIR%\System32\config\SAM %nonvol_outpath%\registry
			tools\RawCopy.exe %WINDIR%\System32\config\SECURITY %nonvol_outpath%\registry
			tools\RawCopy.exe %WINDIR%\System32\config\SOFTWARE %nonvol_outpath%\registry
			tools\RawCopy.exe %WINDIR%\System32\config\SYSTEM %nonvol_outpath%\registry
			)
		if %arch% == 64 (
			tools\RawCopy64.exe %WINDIR%\System32\config\SAM %nonvol_outpath%\registry
			tools\RawCopy64.exe %WINDIR%\System32\config\SECURITY %nonvol_outpath%\registry
			tools\RawCopy64.exe %WINDIR%\System32\config\SOFTWARE %nonvol_outpath%\registry
			tools\RawCopy64.exe %WINDIR%\System32\config\SYSTEM %nonvol_outpath%\registry
			)
		if  NOT %os% == legacy (
			if not exist %nonvol_outpath%\registry\RegBack (
				echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create the RegBack directory
				echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create the RegBack directory >> %c_drive%:\Data-%case%\Collection.log
				tools\mkdir.exe %nonvol_outpath%\registry\RegBack
			)
			echo %DATE% %TIME% - Running tools\RawCopy.exe on %COMPUTERNAME% to obtain the SAM, SECURITY, SOFTWARE, and SYSTEM registry hives in RegBack folder
			echo %DATE% %TIME% - Running tools\RawCopy.exe on %COMPUTERNAME% to obtain the SAM, SECURITY, SOFTWARE, and SYSTEM registry hives in RegBack folder >> %c_drive%:\Data-%case%\Collection.log
			if %arch% == 32 (
				tools\RawCopy.exe %WINDIR%\System32\config\RegBack\SAM %nonvol_outpath%\registry\RegBack
				tools\RawCopy.exe %WINDIR%\System32\config\RegBack\SECURITY %nonvol_outpath%\registry\RegBack
				tools\RawCopy.exe %WINDIR%\System32\config\RegBack\SOFTWARE %nonvol_outpath%\registry\RegBack
				tools\RawCopy.exe %WINDIR%\System32\config\RegBack\SYSTEM %nonvol_outpath%\registry\RegBack
				tools\RawCopy.exe %WINDIR%\System32\config\RegBack\SYSTEM %nonvol_outpath%\registry\RegBack
			)
			if %arch% == 64 (
				tools\RawCopy64.exe %WINDIR%\System32\config\RegBack\SAM %nonvol_outpath%\registry\RegBack
				tools\RawCopy64.exe %WINDIR%\System32\config\RegBack\SECURITY %nonvol_outpath%\registry\RegBack
				tools\RawCopy64.exe %WINDIR%\System32\config\RegBack\SOFTWARE %nonvol_outpath%\registry\RegBack
				tools\RawCopy64.exe %WINDIR%\System32\config\RegBack\SYSTEM %nonvol_outpath%\registry\RegBack
				tools\RawCopy64.exe %WINDIR%\System32\config\RegBack\DEFAULT %nonvol_outpath%\registry\RegBack
			)
		)
	:: Collecting each user's registry hive
		:: The dir command is used to identify the ntuser.dat files. As a result the directories are changed during the operation
		::
		:: if statement below sets the userpath variable
		if %os% == legacy (set userpath=%systemdrive%\Documents and Settings) else (set userpath=%systemdrive%\Users)
		:: If statement below stores the current drive letter and directory into variables
		set script_drive=%~d0
		set script_path=%~dp0
		:: Below changes directory for the dir command
		echo %DATE% %TIME% - Changing to the %userpath% directory for collecting the ntuser.dat registry hives
		echo %DATE% %TIME% - Changing to the %userpath% directory for collecting the ntuser.dat registry hives >> %c_drive%:\Data-%case%\Collection.log
		%systemdrive%
		cd "%userpath%"
		:: Troy Larson wrote the for loop below and I incorporated it into my script
		:: The for loop below locates and copies out every ntuser.dat file
		for /f "tokens=*" %%i in ('dir /ah /b /s ntuser.dat') do @for /f "tokens=3 delims=\" %%j in ("%%i") do @for /f "tokens=4 delims=\" %%h in ("%%i") do (
			if not exist %nonvol_outpath%\registry\%%j (
				echo %DATE% %TIME% - Running tools\mkdir on %COMPUTERNAME% to create the collection for the registry\%%j folder
				echo %DATE% %TIME% - Running tools\mkdir on %COMPUTERNAME% to create the collection for the registry\%%j folder >> %c_drive%:\Data-%case%\Collection.log
				"%script_path%\tools\mkdir.exe" %nonvol_outpath%\registry\%%j
			)
			echo %DATE% %TIME% - Running tools\RawCopy.exe %%i on %COMPUTERNAME% to extract the NTUSER.DAT for %%j
			echo %DATE% %TIME% - Running tools\RawCopy.exe %%i on %COMPUTERNAME% to extract the NTUSER.DAT for %%j  >> %c_drive%:\Data-%case%\Collection.log
			if %arch% == 32 ("%script_path%\tools\RawCopy.exe" "%%i" %nonvol_outpath%\registry\%%j)
			if %arch% == 64 ("%script_path%\tools\RawCopy64.exe" "%%i" %nonvol_outpath%\registry\%%j)
		)
		:: The for loop below locates and copies out every usrclass.dat file
		if NOT %os% == legacy (
			for /f %%i in ('dir /ah /b /s usrclass.dat') do @for /f "tokens=3 delims=\" %%j in ("%%i") do @for /f "tokens=8 delims=\" %%h in ("%%i") do (
			if not exist %nonvol_outpath%\registry\%%j (
				echo %DATE% %TIME% - Running tools\mkdir on %COMPUTERNAME% to create the collection for the registry\%%j folder
				echo %DATE% %TIME% - Running tools\mkdir on %COMPUTERNAME% to create the collection for the registry\%%j folder >> %c_drive%:\Data-%case%\Collection.log
				"%script_path%\tools\mkdir.exe" %nonvol_outpath%\registry\%%j
				)
			echo %DATE% %TIME% - Running tools\RawCopy.exe %%i on %COMPUTERNAME% to extract the UsrClass.dat for %%j
			echo %DATE% %TIME% - Running tools\RawCopy.exe %%i on %COMPUTERNAME% to extract the UsrClass.dat for %%j  >> %c_drive%:\Data-%case%\Collection.log
			if %arch% == 32 ("%script_path%\tools\RawCopy.exe" "%%i" %nonvol_outpath%\registry\%%j)
			if %arch% == 64 ("%script_path%\tools\RawCopy64.exe" "%%i" %nonvol_outpath%\registry\%%j)
			)
		)
		:: Below changes directory back
		echo %DATE% %TIME% - Changing to the %script_path% directory since ntuser.dat files have been collected
		echo %DATE% %TIME% - Changing to the %script_path% directory since ntuser.dat files have been collected >> %c_drive%:\Data-%case%\Collection.log
		%script_drive%
		cd "%script_path%"
	:: Collecting NTFS artifacts
		echo %DATE% %TIME% - Collecting NTFS artifacts from %COMPUTERNAME%
		echo %DATE% %TIME% - Collecting NTFS artifacts from %COMPUTERNAME% >> %c_drive%:\Data-%case%\Collection.log
		:: Collecting the $MFT record
		echo %DATE% %TIME% - Running tools\RawCopy.exe %SYSTEMDRIVE%\$MFT on %COMPUTERNAME% to extract the $MFT
		echo %DATE% %TIME% - Running tools\RawCopy.exe %SYSTEMDRIVE%\$MFT on %COMPUTERNAME% to extract the $MFT  >> %c_drive%:\Data-%case%\Collection.log
		if %arch% == 32 (tools\RawCopy.exe %SYSTEMDRIVE%0 %nonvol_outpath%\ntfs) else (tools\RawCopy64.exe %SYSTEMDRIVE%0 %nonvol_outpath%\ntfs)
		:: Collecting the $LogFile record
		echo %DATE% %TIME% - Running tools\RawCopy.exe %SYSTEMDRIVE%\$LogFile on %COMPUTERNAME% to extract the $LogFile
		echo %DATE% %TIME% - Running tools\RawCopy.exe %SYSTEMDRIVE%\$LogFile on %COMPUTERNAME% to extract the $LogFile  >> %c_drive%:\Data-%case%\Collection.log
		if %arch% == 32 (tools\RawCopy.exe %SYSTEMDRIVE%2 %nonvol_outpath%\ntfs) else (tools\RawCopy64.exe %SYSTEMDRIVE%2 %nonvol_outpath%\ntfs)
	:: Collecting autostarting locations
		echo %DATE% %TIME% - Collecting autostarting locations information from %COMPUTERNAME%
		echo %DATE% %TIME% - Collecting autostarting locations information from %COMPUTERNAME% >> %c_drive%:\Data-%case%\Collection.log
		:: Listing the system's autostarting locations
		:: autorunsc.exe reference: Malware Forensics page 69 or WFA page 44
			echo Command Executed: autorunsc.exe -a /accepteula > %nonvol_outpath%\autoruns\%COMPUTERNAME%-autostarting-locations.txt
			echo: >> %nonvol_outpath%\autoruns\%COMPUTERNAME%-autostarting-locations.txt
			echo %DATE% %TIME% - Running tools\autorunsc.exe -a -v /accepteula on %COMPUTERNAME% to obtain the autostarting locations
			echo %DATE% %TIME% - Running tools\autorunsc.exe -a -v /accepteula on %COMPUTERNAME% to obtain the autostarting locations >> %c_drive%:\Data-%case%\Collection.log
			tools\autorunsc.exe -a /accepteula >> %nonvol_outpath%\autoruns\%COMPUTERNAME%-autostarting-locations.txt
		:: Listing the system's autostarting locations in csv format
		:: autorunsc.exe reference: Malware Forensics page 69 or WFA page 44
			echo %DATE% %TIME% - Running tools\autorunsc.exe -a -c -v /accepteula on %COMPUTERNAME% to obtain the autostarting locations in csv format
			echo %DATE% %TIME% - Running tools\autorunsc.exe -a -c -v /accepteula on %COMPUTERNAME% to obtain the autostarting locations in csv format >> %c_drive%:\Data-%case%\Collection.log
			tools\autorunsc.exe -a -c /accepteula >> %nonvol_outpath%\autoruns\%COMPUTERNAME%-autostarting-locations_csv.csv
		:: Collecting at.exe scheduled task information
			echo %DATE% %TIME% - Running %windir%\System32\at.exe on %COMPUTERNAME% to obtain scheduled task information
			echo %DATE% %TIME% - Running %windir%\System32\at.exe on %COMPUTERNAME% to obtain scheduled task information >> %c_drive%:\Data-%case%\Collection.log
			%windir%\System32\at.exe >> %nonvol_outpath%\autoruns\%COMPUTERNAME%-at_info.txt
		:: Collecting scheduled task information
			echo %DATE% %TIME% - Running %windir%\System32\schtasks.exe on %COMPUTERNAME% to obtain scheduled task information
			echo %DATE% %TIME% - Running %windir%\System32\schtasks.exe on %COMPUTERNAME% to obtain scheduled task information >> %c_drive%:\Data-%case%\Collection.log
			%windir%\System32\schtasks.exe /query >> %nonvol_outpath%\autoruns\%COMPUTERNAME%-schtasks_info.txt
		:: Collecting scheduled task log and/or folder
			echo %DATE% %TIME% - Running tools (RawCopy.exe or Robocopy.exe) on %COMPUTERNAME% to obtain the scheduled task log and/or folder
			echo %DATE% %TIME% - Running tools (RawCopy.exe or Robocopy.exe) on %COMPUTERNAME% to obtain the scheduled task log and/or folder >> %c_drive%:\Data-%case%\Collection.log
			if %os% == legacy (
				if %arch% == 32 (tools\RawCopy.exe %WINDIR%\SchedLgU.txt %nonvol_outpath%\autoruns)
				if %arch% == 64 (tools\RawCopy64.exe %WINDIR%\SchedLgU.txt %nonvol_outpath%\autoruns)
			) else (
				echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store tasks
				echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store tasks >> %c_drive%:\Data-%case%\Collection.log
				tools\mkdir.exe %c_drive%:\Data-%case%\%computername%-%timestamp%\nonvolatile-data\autoruns\Tasks_folder
				echo %DATE% %TIME% - Running tools\robocopy.exe on %COMPUTERNAME% to collect the Task folder
				echo %DATE% %TIME% - Running tools\robocopy.exe on %COMPUTERNAME% to collect the Task folder >> %c_drive%:\Data-%case%\Collection.log
				:: The following are the robocopy swithes: /zb  Tries to copy files in restartable mode, 
				::  /copy:DAT copy file data, timestamps, and attribute /r:0  retry 0 times,
				:: /ts source timestamps in log, /FP displays full pathnames in output,
				:: /np progress indicator turned off and /log  creates log file by overwriting one if already exists
				tools\robocopy.exe %WINDIR%\Tasks %nonvol_outpath%\autoruns\Tasks_folder\ /ZB /copy:DAT /r:0 /ts /FP /np /log:%nonvol_outpath%\autoruns\tasks-robocopy-log.txt
				)
		:: Listing all installed device drivers and their properties
			echo %DATE% %TIME% - Running %WINDIR%\System32\driverquery.exe /fo csv /si on %COMPUTERNAME% to obtain installed device drivers and their properties
			echo %DATE% %TIME% - Running %WINDIR%\System32\driverquery.exe /fo csv /si on %COMPUTERNAME% to obtain installed device drivers and their properties >> %c_drive%:\Data-%case%\Collection.log
			%WINDIR%\System32\driverquery.exe /fo csv /si >> %nonvol_outpath%\autoruns\%COMPUTERNAME%-driverquery_info.txt
	:: Collecting log files
		echo %DATE% %TIME% - Collecting log files from %COMPUTERNAME%
		echo %DATE% %TIME% - Collecting log files from %COMPUTERNAME% >> %c_drive%:\Data-%case%\Collection.log
		:: Collecting the event logs
		if not exist %c_drive%:\Data-%case%\%computername%-%timestamp%\nonvolatile-data\logs\event-logs (
		echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store event logs
		echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store event logs >> %c_drive%:\Data-%case%\Collection.log
		tools\mkdir.exe %c_drive%:\Data-%case%\%computername%-%timestamp%\nonvolatile-data\logs\event-logs
		)
		if %os% == legacy (
			echo %DATE% %TIME% - Running tools\RawCopy.exe on %COMPUTERNAME% to extract the AppEvent.Evt, SecEvent.Evt, and SysEvent.Evt logs
			echo %DATE% %TIME% - Running tools\RawCopy.exe on %COMPUTERNAME% to extract the AppEvent.Evt, SecEvent.Evt, and SysEvent.Evt logs  >> %c_drive%:\Data-%case%\Collection.log
			if %arch% == 32 (
				tools\RawCopy.exe %WINDIR%\System32\config\AppEvent.Evt %nonvol_outpath%\logs\event-logs
				tools\RawCopy.exe %WINDIR%\System32\config\SecEvent.Evt %nonvol_outpath%\logs\event-logs
				tools\RawCopy.exe %WINDIR%\System32\config\SysEvent.Evt %nonvol_outpath%\logs\event-logs
			)
			if %arch% == 64 (
				tools\RawCopy64.exe %WINDIR%\System32\config\AppEvent.Evt %nonvol_outpath%\logs\event-logs
				tools\RawCopy64.exe %WINDIR%\System32\config\SecEvent.Evt %nonvol_outpath%\logs\event-logs
				tools\RawCopy64.exe %WINDIR%\System32\config\SysEvent.Evt %nonvol_outpath%\logs\event-logs
			)
		) else (
			echo %DATE% %TIME% - Running tools\RawCopy.exe on %COMPUTERNAME% to collect the event logs
			echo %DATE% %TIME% - Running tools\RawCopy.exe on %COMPUTERNAME% to collect the event logs >> %c_drive%:\Data-%case%\Collection.log
			if %arch% == 32 (
				tools\RawCopy.exe %WINDIR%\System32\winevt\Logs\Application.evtx %nonvol_outpath%\logs\event-logs
				tools\RawCopy.exe %WINDIR%\System32\winevt\Logs\Security.evtx %nonvol_outpath%\logs\event-logs
				tools\RawCopy.exe %WINDIR%\System32\winevt\Logs\System.evtx %nonvol_outpath%\logs\event-logs
			)
			if %arch% == 64 (
				tools\RawCopy64.exe %WINDIR%\System32\winevt\Logs\Application.evtx %nonvol_outpath%\logs\event-logs
				tools\RawCopy64.exe %WINDIR%\System32\winevt\Logs\Security.evtx %nonvol_outpath%\logs\event-logs
				tools\RawCopy64.exe %WINDIR%\System32\winevt\Logs\System.evtx %nonvol_outpath%\logs\event-logs
			)
		)
		:: Collecting the Log folder for non Windows legacy systems
 		if /I not %os% == legacy (
			echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store Logs folder
			echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store Logs folder >> %c_drive%:\Data-%case%\Collection.log
			tools\mkdir.exe %c_drive%:\Data-%case%\%computername%-%timestamp%\nonvolatile-data\logs\Logs_folder
			echo %DATE% %TIME% - Running tools\robocopy.exe on %COMPUTERNAME% to collect the Log folder
			echo %DATE% %TIME% - Running tools\robocopy.exe on %COMPUTERNAME% to collect the Log folder >> %c_drive%:\Data-%case%\Collection.log
			:: The following are the robocopy swithes: /zb  Tries to copy files in restartable mode, 
			::  /copy:DAT copy file data and timestamps /r:0  retry 0 times,
			:: /ts source timestamps in log, /FP displays full pathnames in output, /E copy subfolders
			:: /np progress indicator turned off and /log  creates log file by overwriting one if already exists
			tools\robocopy.exe %SYSTEMDRIVE%\Windows\Logs\ %nonvol_outpath%\logs\Logs_folder /ZB /copy:DAT /r:0 /ts /FP /np /E /log:%nonvol_outpath%\logs\logs-robocopy-log.txt 
		)
		:: Collecting the McAfee log and quarantine folders
		if not exist %c_drive%:\Data-%case%\%computername%-%timestamp%\nonvolatile-data\logs\McAfee (
			echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store McAfee log folder
			echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store McAfee log folder >> %c_drive%:\Data-%case%\Collection.log
			tools\mkdir.exe %c_drive%:\Data-%case%\%computername%-%timestamp%\nonvolatile-data\logs\McAfee
		)
		if not exist %c_drive%:\Data-%case%\%computername%-%timestamp%\nonvolatile-data\logs\McAfee\Quarantine (
			echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store McAfee Quarantine folder
			echo %DATE% %TIME% - Running tools\mkdir.exe on %COMPUTERNAME% to create directory to store McAfee Quarantine folder >> %c_drive%:\Data-%case%\Collection.log
			tools\mkdir.exe %c_drive%:\Data-%case%\%computername%-%timestamp%\nonvolatile-data\logs\McAfee\Quarantine
		)
		if %os% == legacy (
			echo %DATE% %TIME% - Running tools\robocopy.exe on %COMPUTERNAME% to collect the McAfee log folder
			echo %DATE% %TIME% - Running tools\robocopy.exe on %COMPUTERNAME% to collect the McAfee log folder >> %c_drive%:\Data-%case%\Collection.log
			:: The following are the robocopy swithes: /zb  Tries to copy files in restartable mode, 
			::  /copy:DAT copy file data, timestamps, and attribute /r:0  retry 0 times,
			:: /ts source timestamps in log, /FP displays full pathnames in output, /E copy subfolders
			:: /np progress indicator turned off and /log  creates log file by overwriting one if already exists
			tools\robocopy.exe "%SYSTEMDRIVE%\Documents and Settings\All Users\Application Data\McAfee\DesktopProtection" %nonvol_outpath%\logs\McAfee /ZB /copy:DAT /r:0 /ts /FP /np /E /log:%nonvol_outpath%\logs\logs-robocopy-log.txt
			echo %DATE% %TIME% - Running tools\robocopy.exe on %COMPUTERNAME% to collect the McAfee Quarantine folder
			echo %DATE% %TIME% - Running tools\robocopy.exe on %COMPUTERNAME% to collect the McAfee Quarantine folder >> %c_drive%:\Data-%case%\Collection.log
			:: The following are the robocopy swithes: /zb  Tries to copy files in restartable mode, 
			::  /copy:DAT copy file data, timestamps, and attribute /r:0  retry 0 times,
			:: /ts source timestamps in log, /FP displays full pathnames in output, /E copy subfolders
			:: /np progress indicator turned off and /log  creates log file by overwriting one if already exists
			tools\robocopy.exe "%SYSTEMDRIVE%\Documents and Settings\All Users\Application Data\McAfee\Quarantine" %nonvol_outpath%\logs\McAfee\Quarantine /ZB /copy:DAT /r:0 /ts /FP /np /E /log:%nonvol_outpath%\logs\McAfee\quarantine-robocopy-log.txt
			) else (
				echo %DATE% %TIME% - Running tools\robocopy.exe on %COMPUTERNAME% to collect the McAfee log folder
				echo %DATE% %TIME% - Running tools\robocopy.exe on %COMPUTERNAME% to collect the McAfee log folder >> %c_drive%:\Data-%case%\Collection.log
				:: The following are the robocopy swithes: /zb  Tries to copy files in restartable mode, 
				:: /copy:DAT copy file data and timestamps /r:0  retry 0 times,
				:: /ts source timestamps in log, /FP displays full pathnames in output, /E copy subfolders
				:: /np progress indicator turned off and /log  creates log file by overwriting one if already exists
				tools\robocopy.exe %SYSTEMDRIVE%\ProgramData\McAfee\DesktopProtection %nonvol_outpath%\logs\McAfee /ZB /copy:DAT /r:0 /ts /FP /np /E /log:%nonvol_outpath%\logs\logs-robocopy-log.txt
				echo %DATE% %TIME% - Running tools\robocopy.exe on %COMPUTERNAME% to collect the McAfee Quarantine folder
				echo %DATE% %TIME% - Running tools\robocopy.exe on %COMPUTERNAME% to collect the McAfee Quarantine folder >> %c_drive%:\Data-%case%\Collection.log
				:: The following are the robocopy swithes: /zb  Tries to copy files in restartable mode, 
				:: /copy:DAT copy file data and timestamps /r:0  retry 0 times,
				:: /ts source timestamps in log, /FP displays full pathnames in output, /E copy subfolders
				:: /np progress indicator turned off and /log  creates log file by overwriting one if already exists
			:: McAfee logs
			::	tools\robocopy.exe %SYSTEMDRIVE%\ProgramData\McAfee\Virusscan\Quarantine %nonvol_outpath%\logs\McAfee\Quarantine /ZB /copy:DAT /r:0 /ts /FP /np /E /log:%nonvol_outpath%\logs\McAfee\quarantine-robocopy-log.txt
			:: Malicious Software Removal Toolkit logs
			tools\robocopy.exe /ZB /copy:DAT /r:0 /ts /FP /np /E %SystemRoot%\debug\mrt.log %nonvol_outpath%\logs\Microsoft\
			)
	:: Collecting the group policy information applied to the system
		echo %DATE% %TIME% - Collecting group policy information from %COMPUTERNAME%
		echo %DATE% %TIME% - Collecting group policy information from %COMPUTERNAME% >> %c_drive%:\Data-%case%\Collection.log
		:: gplist.exe reference: Malware Forensics page 73
			echo Command Executed: gplist.exe > %nonvol_outpath%\group-policy\%COMPUTERNAME%-group-policy-listing.txt
			echo: >> %nonvol_outpath%\group-policy\%COMPUTERNAME%-group-policy-listing.txt
			echo %DATE% %TIME% - Running tools\gplist.exe on %COMPUTERNAME% to obtain the computer's group policy listing 
			echo %DATE% %TIME% - Running tools\gplist.exe on %COMPUTERNAME% to obtain the computer's group policy listing >> %c_drive%:\Data-%case%\Collection.log
			tools\gplist.exe >> %nonvol_outpath%\group-policy\%COMPUTERNAME%-group-policy-listing.txt
		:: gpresult.exe reference: Malware Forensics page 73
			echo Command Executed: gpresult /Z > %nonvol_outpath%\group-policy\%COMPUTERNAME%-group-policy-RSoP.txt
			echo: >> %nonvol_outpath%\group-policy\%COMPUTERNAME%-group-policy-RSoP.txt
			echo %DATE% %TIME% - Running gpresult /Z on %COMPUTERNAME% to obtain the computer's group policy Resultant Set of Policy (RSoP) information
			echo %DATE% %TIME% - Running gpresult /Z on %COMPUTERNAME% to obtain the computer's group policy Resultant Set of Policy (RSoP) information >> %c_drive%:\Data-%case%\Collection.log
			gpresult /Z >> %nonvol_outpath%\group-policy\%COMPUTERNAME%-group-policy-RSoP.txt
	echo:
	echo %DATE% %TIME% - Completed acquring %COMPUTERNAME%'s non-volatile data >> %c_drive%:\Data-%case%\Collection.log
	echo:
	:: Exiting the :acquire_nonvolatile function
	goto :exit
:: --------------------------------------------------------------------------------------------------------------------------
:: Exit Processing Area
:: --------------------------------------------------------------------------------------------------------------------------
:: This section performs some additional documentation before the script exits 
:exit
	:: The lines below makes the script exit when ran without administrative privileges
	if %noadmin% == 1 goto :EOF
	:: The lines below document when the script exited
	echo.
	echo.
	echo Completed acquring %COMPUTERNAME%'s data
	pause
	cls
	echo %DATE% %TIME% - Exiting collection script and stopping logging for computer %COMPUTERNAME% >> %c_drive%:\Data-%case%\Collection.log
	
:: --------------------------------------------------------------------------------------------------------------------------