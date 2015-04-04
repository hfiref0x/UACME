# UACMe
* Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
* More info http://www.kernelmode.info/forum/viewtopic.php?f=11&t=3643

# System Requirements

* x86-32/x64 Windows 7/8/8.1/10.
* Admin account with UAC set on default settings required.

# Usage

Run executable from command line with following keys (watch debug ouput with dbgview or similar for more info):
* 1 - Leo Davidson sysprep method, this will work only on Windows 7 and Windows 8, used in multiple malware;
* 2 - Tweaked Leo Davidson sysprep method, this will work only on Windows 8.1;
* 3 - Leo Davidson method tweaked by WinNT/Pitou developers, works from Windows 7 up to Windows 10 b10041;
* 4 - Application Compatibility Shim RedirectEXE method, from WinNT/Gootkit. Works from Windows 7 up to Windows 8.1;
* 5 - ISecurityEditor WinNT/Simda method, used to turn off UAC, works from Windows 7 up to Windows 10 b10041;
* 6 - Wusa method used by Win32/Carberp, tweaked to work with Windows 8/8.1 also;
* 7 - Wusa method, tweaked to work from Windows 7 up to Windows 10 b10041;
* 8 - Slightly modified Leo Davidson method used by Win32/Tilon, works only on Windows 7.

Note:
* Methods (1), (2), (3), (5), (8) require process injection, so they won't work from wow64, you need either Heavens gate or use x64 edition of this tool;
* Method (4) unavailable in 64 bit edition because of Shim restriction.
* Method (6) unavailable in wow64 environment starting from Windows 8. Also target application absent in recent Windows 10 TP 10041 build.

Run examples:
* akagi32.exe 1
* akagi64.exe 3

# Warning
* Using (5) method will permanently turn off UAC (after reboot), make sure to do this in test environment or don't forget to re-enable UAC after tool usage;
* This tool is not intended for AV tests and not tested to work in aggressive AV environment, if you still plan to use it with installed bloatware AV soft - you use it at your own risk.

# Protection
* UAC turned on maximum level and full awareness about every window it will show;
* Account without administrative privileges.

# Build 

* UACMe comes with full source code, written in C.
* In order to build from source you need Microsoft Visual Studio 2013 U4 and later versions.
 
# Authors

(c) 2014 - 2015 UACMe Project
