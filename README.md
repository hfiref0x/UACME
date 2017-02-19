# UACMe
* Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.

# System Requirements

* x86-32/x64 Windows 7/8/8.1/10TH1/10TH2/10RS1/10RS2 (client, some methods however works on server version too).
* Admin account with UAC set on default settings required.

# Usage

Run executable from command line: akagi32 [Key] [Param] or akagi64 [Key] [Param]. See "Run examples" below for more info.

First param is number of method to use, second is optional command (executable file name including full path) to run. Second param can be empty - in this case program will execute elevated cmd.exe from system32 folder.

Keys (watch debug ouput with dbgview or similar for more info):

1. Author: Leo Davidson
   * Type: Dll Hijack
   * Method: IFileOperation
   * Target(s): \system32\sysprep\sysprep.exe
   * Component(s): cryptbase.dll
   * Works from: Windows 7 (7600)
   * Fixed in: Windows 8.1 (9600)
      * How: sysprep.exe hardened LoadFrom manifest elements
2. Author: Leo Davidson derivative
   * Type: Dll Hijack
   * Method: IFileOperation
   * Target(s): \system32\sysprep\sysprep.exe
   * Component(s): ShCore.dll
   * Works from: Windows 8.1 (9600)
   * Fixed in: Windows 10 TP (> 9600)
      * How: Side effect of ShCore.dll moving to \KnownDlls
3. Author: Leo Davidson derivative by WinNT/Pitou
   * Type: Dll Hijack
   * Method: IFileOperation
   * Target(s): \system32\oobe\setupsqm.exe
   * Component(s): WdsCore.dll
   * Works from: Windows 7 (7600)
   * Fixed in: Windows 10 TH1 (10558)
      * How: side effect of OOBE redesign
4. Author: Jon Ericson, WinNT/Gootkit, mzH
   * Type: AppCompat
   * Method: RedirectEXE Shim
   * Target(s): \system32\cliconfg.exe
   * Component(s): -
   * Works from: Windows 7 (7600)
   * Fixed in: Windows 10 TP (> 9600)
      * How: Sbdinst.exe autoelevation removed, KB3045645/KB3048097 for rest Windows versions
5. Author: WinNT/Simda
   * Type: Elevated COM interface
   * Method: ISecurityEditor
   * Target(s): HKLM registry keys
   * Component(s): -
   * Works from: Windows 7 (7600)
   * Fixed in: Windows 10 TH1 (10147)
      * How: ISecurityEditor interface method changed
6. Author: Win32/Carberp
   * Type: Dll Hijack
   * Method: WUSA
   * Target(s): \ehome\mcx2prov.exe, \system32\migwiz\migwiz.exe
   * Component(s): WdsCore.dll, CryptBase.dll, CryptSP.dll
   * Works from: Windows 7 (7600)
   * Fixed in: Windows 10 TH1 (10147)
      * How: WUSA /extract option removed
7. Author: Win32/Carberp derivative
   * Type: Dll Hijack
   * Method: WUSA
   * Target(s): \system32\cliconfg.exe
   * Component(s): ntwdblib.dll
   * Works from: Windows 7 (7600)
   * Fixed in: Windows 10 TH1 (10147)
      * How: WUSA /extract option removed
8. Author: Leo Davidson derivative by Win32/Tilon
   * Type: Dll Hijack
   * Method: IFileOperation
   * Target(s): \system32\sysprep\sysprep.exe
   * Component(s): Actionqueue.dll
   * Works from: Windows 7 (7600)
   * Fixed in: Windows 8.1 (9600)
      * How: sysprep.exe hardened LoadFrom manifest
9. Author: Leo Davidson, WinNT/Simda, Win32/Carberp derivative
   * Type: Dll Hijack
   * Method: IFileOperation, ISecurityEditor, WUSA
   * Target(s): IFEO registry keys, \system32\cliconfg.exe
   * Component(s): Attacker defined Application Verifier Dll
   * Works from: Windows 7 (7600)
   * Fixed in: Windows 10 TH1 (10147)
      * How: WUSA /extract option removed, ISecurityEditor interface method changed
10. Author: WinNT/Pitou, Win32/Carberp derivative
      * Type: Dll Hijack
      * Method: IFileOperation, WUSA
      * Target(s): \system32\\{New}or{Existing}\\{autoelevated}.exe, e.g. winsat.exe
      * Component(s): Attacker defined dll, e.g. PowProf.dll, DevObj.dll
      * Works from: Windows 7 (7600)
      * Fixed in: Windows 10 TH2 (10548) 
        * How: AppInfo elevated application path control hardening
11. Author: Jon Ericson, WinNT/Gootkit, mzH
      * Type: AppCompat
      * Method: Shim Memory Patch
      * Target(s): \system32\iscsicli.exe
      * Component(s): Attacker prepared shellcode
      * Works from: Windows 7 (7600)
      * Fixed in: Windows 8.1 (9600)
         * How: Sbdinst.exe autoelevation removed, KB3045645/KB3048097 for rest Windows versions
12. Author: Leo Davidson derivative
      * Type: Dll Hijack
      * Method: IFileOperation
      * Target(s): \system32\sysprep\sysprep.exe
      * Component(s): dbgcore.dll
      * Works from: Windows 10 TH1 (10240)
      * Fixed in: Windows 10 TH2 (10565)
        * How: sysprep.exe manifest updated
13. Author: Leo Davidson derivative
     * Type: Dll Hijack
     * Method: IFileOperation
     * Target(s): \system32\mmc.exe EventVwr.msc
     * Component(s): elsext.dll
     * Works from: Windows 7 (7600)
     * Fixed in: Windows 10 RS1 (14316)
        * How: Missing dependency removed
14. Author: Leo Davidson, WinNT/Sirefef derivative
     * Type: Dll Hijack
     * Method: IFileOperation
     * Target(s): \system\credwiz.exe, \system32\wbem\oobe.exe
     * Component(s): netutils.dll
     * Works from: Windows 7 (7600)
     * Fixed in: Windows 10 TH2 (10548)
        * How: AppInfo elevated application path control hardening
15. Author: Leo Davidson, Win32/Addrop, Metasploit derivative
     * Type: Dll Hijack
     * Method: IFileOperation
     * Target(s): \system32\cliconfg.exe
     * Component(s): ntwdblib.dll
     * Works from: Windows 7 (7600)
     * Fixed in: Windows 10 RS1 (14316)
        * How: Cliconfg.exe autoelevation removed
16. Author: Leo Davidson derivative
     * Type: Dll Hijack
     * Method: IFileOperation
     * Target(s): \system32\GWX\GWXUXWorker.exe, \system32\inetsrv\inetmgr.exe
     * Component(s): SLC.dll
     * Works from: Windows 7 (7600)
     * Fixed in: Windows 10 RS1 (14316)
        * How: AppInfo elevated application path control and inetmgr executable hardening
17. Author: Leo Davidson derivative
     * Type: Dll Hijack (Import forwarding)
     * Method: IFileOperation
     * Target(s): \system32\sysprep\sysprep.exe
     * Component(s): unbcl.dll
     * Works from: Windows 7 (7600)
     * Fixed in: Windows 10 RS1 (14371)
        * How: sysprep.exe manifest updated
18. Author: Leo Davidson derivative
     * Type: Dll Hijack (Manifest)
     * Method: IFileOperation
     * Target(s): \system32\taskhost.exe, \system32\tzsync.exe (any ms exe without manifest)
     * Component(s): Attacker defined dll
     * Works from: Windows 7 (7600)
     * Fixed in: Windows 10 RS1 (14371)
        * How: Manifest parsing logic reviewed
19. Author: Leo Davidson derivative
     * Type: Dll Hijack
     * Method: IFileOperation
     * Target(s): \system32\inetsrv\inetmgr.exe
     * Component(s): MsCoree.dll
     * Works from: Windows 7 (7600)
     * Fixed in: Windows 10 RS1 (14376)
        * How: inetmgr.exe executable manifest hardening
20. Author: Leo Davidson derivative
     * Type: Dll Hijack
     * Method: IFileOperation
     * Target(s): \system32\mmc.exe, Rsop.msc
     * Component(s): WbemComn.dll
     * Works from: Windows 7 (7600)
     * Fixed in: unfixed :see_no_evil:
        * How: -
21. Author: Leo Davidson derivative
     * Type: Dll Hijack
     * Method: IFileOperation, SxS DotLocal
     * Target(s): \system32\sysprep\sysprep.exe
     * Component(s): comctl32.dll
     * Works from: Windows 7 (7600)
     * Fixed in: unfixed :see_no_evil:
        * How: -
22. Author: Leo Davidson derivative
     * Type: Dll Hijack
     * Method: IFileOperation, SxS DotLocal
     * Target(s): \system32\consent.exe
     * Component(s): comctl32.dll
     * Works from: Windows 7 (7600)
     * Fixed in: unfixed :see_no_evil:
        * How: -
23. Author: Leo Davidson derivative
     * Type: Dll Hijack
     * Method: IFileOperation
     * Target(s): \system32\pkgmgr.exe
     * Component(s): DismCore.dll
     * Works from: Windows 7 (7600)
     * Fixed in: unfixed :see_no_evil:
        * How: -
24. Author: BreakingMalware
     * Type: Shell API
     * Method: Environment variables expansion
     * Target(s): \system32\CompMgmtLauncher.exe
     * Component(s): Attacker defined application
     * Works from: Windows 7 (7600)
     * Fixed in: Windows 10 RS2 (15031)
        * How: CompMgmtLauncher.exe autoelevation removed
25. Author: Enigma0x3
     * Type: Shell API
     * Method: Registry key manipulation
     * Target(s): \system32\EventVwr.exe, \system32\CompMgmtLauncher.exe
     * Component(s): Attacker defined application
     * Works from: Windows 7 (7600)
     * Fixed in: Windows 10 RS2 (15031)
        * How: EventVwr.exe redesigned, CompMgmtLauncher.exe autoelevation removed
26. Author: Enigma0x3
     * Type: Race Condition
     * Method: File overwrite
     * Target(s): %temp%\GUID\dismhost.exe
     * Component(s): LogProvider.dll
     * Works from: Windows 10 TH1 (10240)
     * Fixed in: Windows 10 RS2 (15031)
        * How: File security permissions altered
27. Author: ExpLife
     * Type: Elevated COM interface
     * Method: IARPUninstallStringLauncher
     * Target(s): Attacker defined application
     * Component(s): Attacker defined components
     * Works from: Windows 7 (7600)
     * Fixed in: unfixed :see_no_evil:
        * How: -

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
* It is currently known that UACMe used by Adware/Multiplug (9), by Win32/Dyre (3), by Win32/Empercrypt (10 & 13). We do  not take any responsibility for this tool usage in the malicious purposes. It is free, open-source and provided AS-IS for everyone.

# Other usage
* Currently used as "signature" by "THOR APT" scanner (handmade pattern matching fraudware from Germany). We do  not take any responsibility for this tool usage in the fraudware;
* In July 2016 so-called "security company" Cymmetria released report about script-kiddie malware bundle called "Patchwork" and false flagged it as APT. They stated it was using "UACME method", which in fact is just slightly and unprofessionally modified injector dll from UACMe v1.9 and was using Carberp/Pitou hybrid method in malware self-implemented way. We do not take any responsibility for UACMe usage in the dubious advertising campaigns from third party "security companies".

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
