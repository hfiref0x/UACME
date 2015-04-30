# UACMe
* Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
* More info http://www.kernelmode.info/forum/viewtopic.php?f=11&t=3643

# System Requirements

* x86-32/x64 Windows 7/8/8.1/10.
* Admin account with UAC set on default settings required.

# Usage

Run executable from command line with following keys (watch debug ouput with dbgview or similar for more info):
* 1 - Leo Davidson sysprep method, this will work only on Windows 7 and Windows 8, used in multiple malware;
* 2 - Tweaked Leo Davidson sysprep method, this will work only on Windows 8.1.9600;
* 3 - Leo Davidson method tweaked by WinNT/Pitou developers, works from Windows 7 up to 10.0.10061;
* 4 - Application Compatibility Shim RedirectEXE method, from WinNT/Gootkit. Works from Windows 7 up to 8.1.9600;
* 5 - ISecurityEditor WinNT/Simda method, used to turn off UAC, works from Windows 7 up to Windows 10.0.10061;
* 6 - Wusa method used by Win32/Carberp, tweaked to work with Windows 8/8.1 also;
* 7 - Wusa method, tweaked to work from Windows 7 up to 10.0.10061;
* 8 - Slightly modified Leo Davidson method used by Win32/Tilon, works only on Windows 7;
* 9 - Hybrid method, combination of WinNT/Simda and Win32/Carberp + AVrf, works from Windows 7 up to 10.0.10061;
* 10 - Hybrid method, abusing appinfo.dll way of whitelisting autoelevated applications and KnownDlls cache changes, works from Windows 7 up to 10.0.10061;
* 11 - WinNT/Gootkit second method based on the memory patching from MS "Fix it" patch shim (and as side effect - arbitrary dll injection), works from Windows 7 up to 8.1.9600;
* 12 - Windows 10 sysprep method, abusing different dll dependency added in Windows 10.

Note:
* Methods (1), (2), (3), (5), (8), (9), (12) require process injection, so they won't work from wow64, you need either Heavens gate or use x64 edition of this tool;
* Method (4) unavailable in 64 bit edition because of Shim restriction;
* Method (6) unavailable in wow64 environment starting from Windows 8. Also target application absent in recent Windows 10 TP 10061 build;
* Method (11) implemented in x86-32 version;
* Methods (4), (11) targeted by MS April patch by removing autoelevation from sdbinst.

Run examples:
* akagi32.exe 1
* akagi64.exe 3

# Warning
* Using (5) method will permanently turn off UAC (after reboot), make sure to do this in test environment or don't forget to re-enable UAC after tool usage;
* Using (5), (9) methods will permanently compromise security of target keys (UAC Settings key for (5) and IFEO for (9)), if you do tests on your real machine - restore keys security manually after you complete this tool usage;
* This tool is not intended for AV tests and not tested to work in aggressive AV environment, if you still plan to use it with installed bloatware AV soft - you use it at your own risk.

# Protection
* UAC turned on maximum level and full awareness about every window it will show;
* Account without administrative privileges.

# Build 

* UACMe comes with full source code, written in C;
* In order to build from source you need Microsoft Visual Studio 2013 U4 and later versions.
 
# Authors

(c) 2014 - 2015 UACMe Project
