# UACMe
* Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.

# System Requirements

* x86-32/x64 Windows 7/8/8.1/10TH1/10TH2/10RS1/10RS2 (client, some methods however works on server version too).
* Admin account with UAC set on default settings required.

# Usage

Run executable from command line: akagi32 [Key] [Param] or akagi64 [Key] [Param]. See "Run examples" below for more info.

First param is number of method to use, second is optional command (executable file name including full path) to run. Second param can be empty - in this case program will execute elevated cmd.exe from system32 folder.

Keys (watch debug ouput with dbgview or similar for more info):
|  # |                       Author                      |              Type              |                Method               |                                                 Target                                                |                     Components                     | Initial Windows working build | Fixed Windows build |                                  Fix info                                  |
|:--:|:-------------------------------------------------:|:------------------------------:|:-----------------------------------:|:-----------------------------------------------------------------------------------------------------:|:--------------------------------------------------:|:-----------------------------:|:-------------------:|:--------------------------------------------------------------------------:|
|  1 | Leo Davidson                                      | Dll Hijack                     | IFileOperation                      | systemroot\system32\sysprep\sysprep.exe                                                               | Cryptbase.dll                                      |              7600             |         9600        | sysprep.exe hardened LoadFrom manifest                                     |
|  2 | Leo Davidson derivative                           | Dll Hijack                     | IFileOperation                      | systemroot\system32\sysprep\sysprep.exe                                                               | ShCore.dll                                         |              9600             |        >9600        | ShCore.dll added to \KnownDlls                                             |
|  3 | Leo Davidson, WinNT/Pitou                         | Dll Hijack                     | IFileOperation                      | systemroot\system32\oobe\setupsqm.exe                                                                 | WdsCore.dll                                        |              7600             |        10532        | OOBE redesign                                                              |
|  4 | Jon Ericson, WinNT/Gootkit, mzH                   | AppCompat                      | RedirectEXE Shim                    | systemroot\system32\cliconfg.exe                                                                      | -                                                  |              7600             |         9600        | Sbdinst.exe autoelevation removed, KB3045645/KB3048097                     |
|  5 | WinNT/Simda                                       | Elevated COM interface         | ISecurityEditor                     | Registry Keys                                                                                         | -                                                  |              7600             |        10136        | COM interface altered                                                      |
|  6 | Win32/Carberp                                     | Dll Hijack                     | WUSA                                | systemroot\ehome\mcx2prov.exe systemroot\system32\migwiz\migwiz.exe                                   | WdsCore.dll CryptBase.dll CryptSP.dll              |              7600             |        10147        | WUSA /extract option removed                                               |
|  7 | Win32/Carberp derivative                          | Dll Hijack                     | WUSA                                | systemroot\system32\cliconfg.exe                                                                      | ntwdblib.dll                                       |              7600             |        10147        | WUSA /extract option removed                                               |
|  8 | Leo Davidson Win32/Tilon                          | Dll Hijack                     | IFileOperation                      | systemroot\system32\sysprep\sysprep.exe                                                               | Actionqueue.dll                                    |              7600             |         9600        | sysprep.exe hardened LoadFrom manifest                                     |
|  9 | Leo Davidson WinNT/Simda Win32/Carberp derivative | Application Verifier           | IFileOperation ISecurityEditor WUSA | IFEO registry keys  systemroot\system32\cliconfg.exe                                                  | Attacker defined Application Verifier Dll          |              7600             |        10147        | WUSA /extract option removed ISecurityEditor interface altered             |
| 10 | WinNT/Pitou Win32/Carberp derivative              | Dll Hijack                     | IFileOperation WUSA                 | systemroot\system32\<New>or<Existing>\<autoelevated>.exe, e.g. systemroot\system32\sysprep\winsat.exe | Attacker defined dll,  e.g. PowProf.dll DevObj.dll |              7600             |        10548        | AppInfo elevated application path control hardedning                       |
| 11 | Jon Ericson, WinNT/Gootkit, mzH                   | AppCompat                      | Shim Memory Patch                   | systemroot\system32\iscsicli.exe                                                                      | Attacker prepared shellcode                        |              7600             |         9600        | Sbdinst.exe autoelevation removed, KB3045645/KB3048097                     |
| 12 | Leo Davidson derivative                           | Dll Hijack                     | IFileOperation                      | systemroot\system32\sysprep\sysprep.exe                                                               | dbgcore.dll                                        |             10240             |        10565        | sysprep.exe manifest updated                                               |
| 13 | Leo Davidson derivative                           | Dll Hijack                     | IFileOperation                      | systemroot\system32\mmc.exe EventVwr.msc                                                              | elsext.dll                                         |              7600             |        14316        | Missing dependency removed                                                 |
| 14 | Leo Davidson WinNT/Sirefef derivative             | Dll Hijack                     | IFileOperation                      | systemroot\system\credwiz.exe systemroot\system32\wbem\oobe.exe                                       | netutils.dll                                       |              7600             |        10548        | AppInfo elevated application path control hardedning                       |
| 15 | Leo Davidson Win32/Addrop Metasploit derivative   | Dll Hijack                     | IFileOperation                      | systemroot\system32\cliconfg.exe                                                                      | ntwdblib.dll                                       |              7600             |        14316        | Cliconfg.exe autoelevation removed                                         |
| 16 | Leo Davidson derivative                           | Dll Hijack                     | IFileOperation                      | systemroot\system32\GWX\GWXUXWorker.exe -> systemroot\system32\inetsrv\inetmgr.exe                    | SLC.dll                                            |              7600             |        14316        | AppInfo elevated application path control and inetmgr executable hardening |
| 17 | Leo Davidson derivative                           | Dll Hijack (Import Forwarding) | IFileOperation                      | systemroot\system32\sysprep\sysprep.exe                                                               | unbcl.dll                                          |              9600             |        14371        | sysprep.exe manifest updated                                               |
| 18 | Leo Davidson derivative                           | Dll Hijack (Manifest)          | IFileOperation                      | systemroot\system32\taskhost.exe systemroot\system32\tzsync.exe                                       | Attacker defined dll                               |              7600             |        14371        | Manifest parsing logic reviewed                                            |
| 19 | Leo Davidson derivative                           | Dll Hijack                     | IFileOperation                      | systemroot\system32\inetsrv\inetmgr.exe                                                               | MsCoree.dll                                        |              7600             |        14376        | inetmgr.exe executable manifest hardening                                  |
| 20 | Leo Davidson derivative                           | Dll Hijack                     | IFileOperation                      | systemroot\system32\mmc.exe Rsop.msc                                                                  | WbemComn.dll                                       |              7600             |                     |                                                                            |
| 21 | Leo Davidson derivative                           | Dll Hijack                     | IFileOperation SxS DotLocal         | systemroot\system32\sysprep\sysprep.exe                                                               | comctl32.dll                                       |              7600             |                     |                                                                            |
| 22 | Leo Davidson derivative                           | Dll Hijack                     | IFileOperation SxS DotLocal         | systemroot\system32\consent.exe                                                                       | comctl32.dll                                       |              7600             |                     |                                                                            |
| 23 | Leo Davidson derivative                           | Dll Hijack                     | IFileOperation                      | systemroot\system32\pkgmgr.exe                                                                        | DismCore.dll                                       |              7600             |                     |                                                                            |
| 24 | BreakingMalware                                   | Shell API                      | Environment variables expansion     | systemroot\system32\CompMgmtLauncher.exe                                                              | Attacker defined application                       |              7600             |        15031        | CompMgmtLauncher.exe autoelevation removed                                 |
| 25 | Enigma0x3                                         | Shell API                      | Registry key manipulation           | systemroot\system32\EventVwr.exe systemroot\system32\CompMgmtLauncher.exe                             | Attacker defined application                       |              7600             |        15031        | EventVwr.exe redesigned CompMgmtLauncher.exe autoelevation removed         |
| 26 | Enigma0x3                                         | Race Condition                 | File overwrite                      | %temp%\\$GUID$\dismhost.exe                                                                           | LogProvider.dll                                    |             10240             |        15031        | File security permission altered                                           |
| 27 | ExpLife                                           | Elevated COM interface         | IARPUninstallStringLauncher         | Attacker defined application                                                                          | Attacker defined components                        |              7600             |                     |                                                                            |
Note:
* Several methods require process injection, so they won't work from wow64, use x64 edition of this tool;
* Method (4) unavailable in 64 bit edition because of Shim restriction;
* Method (6) unavailable in wow64 environment starting from Windows 8.
* Method (11) implemented in x86-32 version;
* Method (13) (19) and above implemented only in x64 version.
* Method (26) is still working, however it main advantage was UAC bypass on AlwaysNotify level. Since 15031 it is gone.

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
* Most of methods created for x64, with no x86-32 support in mind. I don't see any sense in supporting 32 bit versions of Windows or wow64, however with small tweaks most of them will run under wow64 as well.

If you wondering why this still exist and work here is the explanation, an official Microsoft WHITEFLAG (including totally incompetent statements as bonus)
https://blogs.msdn.microsoft.com/oldnewthing/20160816-00/?p=94105


# Protection
* UAC turned on maximum level and full awareness about every window it will show;
* Account without administrative privileges.

# Malware usage
* It is currently known that UACMe used by Adware/Multiplug (9), by Win32/Dyre (3), by Win32/Empercrypt (10 & 13). We do  not take any responsibility for this tool usage in the malicious purposes. It is free, open-source and provided 

AS-IS for everyone.

# Other usage
* Currently used as "signature" by "THOR APT" scanner (handmade pattern matching fraudware from Germany). We do  not take any responsibility for this tool usage in the fraudware;
* In July 2016 so-called "security company" Cymmetria released report about script-kiddie malware bundle called "Patchwork" and false flagged it as APT. They stated it was using "UACME method", which in fact is just slightly and unprofessionally modified injector dll from UACMe v1.9 and was using Carberp/Pitou hybrid method in malware self-implemented way. We do not take any responsibility for UACMe usage in the dubious advertising campaigns from third party "security companies".

# VirusTotal reference report

* Akagi32 https://www.virustotal.com/en/file/9bc91fedd02769705f7b8716a2e40e34fc081c1a12493a7826eb4243f371e589/analysis/
* Akagi64 https://www.virustotal.com/en/file/4de0aeb3a2ec4ad6bacd0b35b47c6ba709199a8d0687cc6e4a421fdb64ba6108/analysis/

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
* Bypassing UAC on Windows 10 using Disk Cleanup, https://enigma0x3.net/2016/07/22/bypassing-uac-on-windows-10-using-disk-cleanup/
* Using IARPUninstallStringLauncher COM interface to bypass UAC, http://www.freebuf.com/articles/system/116611.html
 
# Authors

(c) 2014 - 2017 UACMe Project
