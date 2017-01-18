# UACMe
* Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.

# System Requirements

* x86-32/x64 Windows 7/8/8.1/10TH1/10TH2/10RS1 (client, some methods however works on server version too).
* Admin account with UAC set on default settings required.

# Usage

Run executable from command line: akagi32 [Key] [Param] or akagi64 [Key] [Param]. See "Run examples" below for more info.

First param is number of method to use, second is optional command (executable file name including full path) to run. Second param can be empty - in this case program will execute elevated cmd.exe from system32 folder.

Keys (watch debug ouput with dbgview or similar for more info):
* 1 - Leo Davidson sysprep method, this will work only on Windows 7 and Windows 8, used in multiple malware;
* 2 - Tweaked Leo Davidson sysprep method, this will work only on Windows 8.1.9600;
* 3 - Leo Davidson method tweaked by WinNT/Pitou developers, works from Windows 7 up to 10th2 10532;
* 4 - Application Compatibility Shim RedirectEXE method, from WinNT/Gootkit. Works from Windows 7 up to 8.1.9600;
* 5 - ISecurityEditor WinNT/Simda method, used to turn off UAC, works from Windows 7 up to Windows 10th1 100136;
* 6 - Wusa method used by Win32/Carberp, tweaked to work with Windows 8/8.1 also;
* 7 - Wusa method, tweaked to work from Windows 7 up to 10th1 10136;
* 8 - Slightly modified Leo Davidson method used by Win32/Tilon, works only on Windows 7;
* 9 - Hybrid method, combination of WinNT/Simda and Win32/Carberp + AVrf, works from Windows 7 up to 10th1 10136;
* 10 - Hybrid method, abusing appinfo.dll way of whitelisting autoelevated applications and KnownDlls cache changes, works from Windows 7 up to 10th2 10532;
* 11 - WinNT/Gootkit second method based on the memory patching from MS "Fix it" patch shim (and as side effect - arbitrary dll injection), works from Windows 7 up to 8.1.9600;
* 12 - Windows 10 sysprep method, abusing different dll dependency added in Windows 10 (works up to 10th2 10558);
* 13 - Hybrid method, abusing Microsoft Management Console and EventViewer missing dependency, works from Windows 7 up to 10rs1 14295;
* 14 - WinNT/Sirefef method, abusing appinfo.dll way of whitelisting OOBE.exe, works from Windows 7 up to 10th2 10558;
* 15 - Win32/Addrop method, also used in Metasploit uacbypass module, works from Windows 7 up to 10rs1 14295;
* 16 - Hybrid method working together with Microsoft GWX backdoor, works from Windows 7 up to 10rs1 14295;
* 17 - Hybrid method, abuses appinfo whitelist/logic/API choice&usage, works from Windows 8.1 (9600) up to 10rs1 14367;
* 18 - Hybrid method, abuses SxS undocumented backdoor used to fix (1) and appinfo whitelist, works from Windows 7 up to 10rs1 14367;
* 19 - Hybrid method, using InetMgr IIS module and based on 10 & 16 MS fixes, works from Windows 7 up to 10rs1 14372;
* 20 - Hybrid method, abusing Microsoft Management Console and incorrect dll loading scheme, works from Windows 7 up to 10rs2 14997;
* 21 - Hybrid method, abusing SxS DotLocal and targeting sysprep, works from Windows 7 up to 10rs2 14997;
* 22 - Hybrid method, abusing SxS DotLocal and targeting consent to gain system privileges, works from Windows 7 up to 10rs2 14997;
* 23 - Hybrid method, abusing Package Manager and DISM, works from Windows 7 up to 10rs2 14997;
* 24 - Original Comet method from BreakingMalware, abuses current user environment variables and CompMgmtLauncher.exe, works from Windows 7 up to 10rs2 15007;
* 25 - Original method from Enigma0x3, abuses shell command execution logic used by autoelevated applications, works from Windows 7 up to 10rs2 15007.

Note:
* Several methods require process injection, so they won't work from wow64, use x64 edition of this tool;
* Method (4) unavailable in 64 bit edition because of Shim restriction;
* Method (6) unavailable in wow64 environment starting from Windows 8.
* Method (11) implemented in x86-32 version;
* Method (13) (19) and above implemented only in x64 version.

Run examples:
* akagi32.exe 1
* akagi64.exe 3
* akagi32 1 c:\windows\system32\calc.exe
* akagi64 3 c:\windows\system32\charmap.exe

# Warning
* This tool shows ONLY popular UAC bypass method used by malware, and reimplement some of them in a different way improving original concepts. There are exists different, not yet known to general public methods, be aware of this;  
* Using (5) method will permanently turn off UAC (after reboot), make sure to do this in test environment or don't forget to re-enable UAC after tool usage;
* Using (5), (9) methods will permanently compromise security of target keys (UAC Settings key for (5) and IFEO for (9)), if you do tests on your real machine - restore keys security manually after you complete this tool usage;
* This tool is not intended for AV tests and not tested to work in aggressive AV environment, if you still plan to use it with installed bloatware AV soft - you use it at your own risk;
* Some AV may flag this tool as HackTool, MSE/WinDefender constantly marks it as malware, nope;
* If you run this program on real computer remember to remove all program leftovers after usage, for more info about files it drops to system folders see source code;
* Since 2.4 all added methods/code will be strictly x64. I don't see any sense in supporting 32 bit versions of Windows in 2016 year.

# Microsoft countermeasures
Methods fixed:
* 1 - Windows 8.1 release and above, still work on Windows 7;
* 2 - Windows 10 starting from earlier preview builds;
* 3 - Windows 10 TH2 starting from 1055X builds;
* 4 - Windows 10 starting from first preview builds, earlier OS versions got KB3045645/KB3048097 fix;
* 5 - Windows 10 starting from 10147 build;
* 6 - Windows 10 starting from 10147 build;
* 7 - Windows 10 starting from 10147 build;
* 8 - Windows 8.1 release and above, still work on Windows 7;
* 9 - Windows 10 starting from 10147 build;
* 10 - Windows 10 TH2 starting from build 10548;
* 11 - Windows 10 starting from first preview builds, earlier OS versions got KB3045645/KB3048097 fix;
* 12 - Windows 10 TH2 starting from 10565 build;
* 13 - Windows 10 RS1 starting from public 14316 build;
* 14 - Windows 10 TH2 starting from 10548 build;
* 15 - Windows 10 RS1 starting from public 14316 build;
* 16 - Windows 10 RS1 starting from public 14316 build;
* 17 - Windows 10 RS1 starting from public 14371 build;
* 18 - Windows 10 RS1 starting from public 14371 build;
* 19 - Windows 10 RS1 starting from public 14376 build;
* 20 - Windows 10 RS2 starting from public 1500X build (delivery interface altered, method itself still work);
* 21 - Windows 10 RS2 starting from public 1500X build (delivery interface altered, method itself still work);
* 22 - Windows 10 RS2 starting from public 1500X build (delivery interface altered, method itself still work);
* 23 - Windows 10 RS2 starting from public 1500X build (delivery interface altered, method itself still work).

** 24, 25 are not fixed as at 18 January 2017.


If you wondering why this still exist and work here is the explanation, an official Microsoft WHITEFLAG (including totally incompetent statements as bonus)
https://blogs.msdn.microsoft.com/oldnewthing/20160816-00/?p=94105


# Protection
* UAC turned on maximum level and full awareness about every window it will show;
* Account without administrative privileges.

# Malware usage
* It is currently known that UACMe used by Adware/Multiplug (9), by Win32/Dyre (3), by Win32/Empercrypt (10 & 13). We do  not take any responsibility for this tool usage in the malicious purposes. It is free, open-source and provided AS-IS for everyone.

# Other usage
* Currently used as "signature" by "THOR APT" scanner (handmade pattern matching fraudware from Germany). We do  not take any responsibility for this tool usage in the fraudware;
* In July 2016 so-called "security company" Cymmetria released report about script-kiddie malware bundle called "Patchwork" and false flagged it as APT. They stated it was using "UACME method", which in fact is just slightly and unprofessionally modified injector dll from UACMe v1.9 and was using Carberp/Pitou hybrid method in malware self-implemented way. We do not take any responsibility for UACMe usage in the dubious advertising campaigns from third party "security companies".

# VirusTotal reference report

* Akagi32 https://www.virustotal.com/en/file/2c3639e512a4726e3a7d6a82a23db8dda079482584bc4987b66efe45a652981e/analysis/
* Akagi64 https://www.virustotal.com/en/file/4a90948c7ac0c09d7340f5cfb0801285fe5ca4d2ed713c5e82b2799bb80feea1/analysis/

# Build 

* UACMe comes with full source code, written in C;
* In order to build from source you need Microsoft Visual Studio 2013/2015 U2 and later versions.

# References

* Windows 7 UAC whitelist, http://www.pretentiousname.com/misc/win7_uac_whitelist2.html
* Malicious Application Compatibility Shims, https://www.blackhat.com/docs/eu-15/materials/eu-15-Pierce-Defending-Against-Malicious-Application-Compatibility-Shims-wp.pdf
* Junfeng Zhang from WinSxS dev team blog, https://blogs.msdn.microsoft.com/junfeng/
* Beyond good ol' Run key, series of articles, http://www.hexacorn.com/blog
* KernelMode.Info UACMe thread, http://www.kernelmode.info/forum/viewtopic.php?f=11&t=3643
* Command Injection/Elevation - Environment Variables Revisited, https://breakingmalware.com/vulnerabilities/command-injection-and-elevation-environment-variables-revisited
* "Fileless" UAC Bypass Using eventvwr.exe and Registry Hijacking, https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/

 
# Authors

(c) 2014 - 2017 UACMe Project


# Discontinued

Project discontinued http://www.kernelmode.info/forum/viewtopic.php?p=28872#p28872. However you are free to fork and continue.
