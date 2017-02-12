# UACMe
* Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.

# System Requirements

* x86-32/x64 Windows 7/8/8.1/10TH1/10TH2/10RS1/10RS2 (client, some methods however works on server version too).
* Admin account with UAC set on default settings required.

# Usage

Run executable from command line: akagi32 [Key] [Param] or akagi64 [Key] [Param]. See "Run examples" below for more info.

First param is number of method to use, second is optional command (executable file name including full path) to run. Second param can be empty - in this case program will execute elevated cmd.exe from system32 folder.

Keys (watch debug ouput with dbgview or similar for more info):

<style type="text/css">
.tg  {border-collapse:collapse;border-spacing:0;}
.tg td{font-family:Arial, sans-serif;font-size:14px;padding:10px 5px;border-style:solid;border-width:1px;overflow:hidden;word-break:normal;}
.tg th{font-family:Arial, sans-serif;font-size:14px;font-weight:normal;padding:10px 5px;border-style:solid;border-width:1px;overflow:hidden;word-break:normal;}
.tg .tg-214n{font-size:11px;text-align:center}
.tg .tg-kr94{font-size:12px;text-align:center}
.tg .tg-pi53{font-weight:bold;font-size:12px;text-align:center}
</style>
<table class="tg">
  <tr>
    <th class="tg-kr94">#</th>
    <th class="tg-pi53">Author</th>
    <th class="tg-pi53">Type</th>
    <th class="tg-pi53">Method</th>
    <th class="tg-pi53">Target</th>
    <th class="tg-pi53">Components</th>
    <th class="tg-pi53">Initial Windows working build<br></th>
    <th class="tg-pi53">Fixed Windows build<br></th>
    <th class="tg-pi53">Fix info<br></th>
  </tr>
  <tr>
    <td class="tg-214n">1</td>
    <td class="tg-214n">Leo Davidson<br></td>
    <td class="tg-214n">Dll Hijack<br></td>
    <td class="tg-214n">IFileOperation</td>
    <td class="tg-214n">systemroot\system32\sysprep\sysprep.exe</td>
    <td class="tg-214n">Cryptbase.dll</td>
    <td class="tg-214n">7600</td>
    <td class="tg-214n">9600<br></td>
    <td class="tg-214n">sysprep.exe hardened LoadFrom manifest<br></td>
  </tr>
  <tr>
    <td class="tg-214n">2</td>
    <td class="tg-214n">Leo Davidson<br>derivative<br></td>
    <td class="tg-214n">Dll Hijack<br></td>
    <td class="tg-214n">IFileOperation</td>
    <td class="tg-214n">systemroot\system32\sysprep\sysprep.exe</td>
    <td class="tg-214n">ShCore.dll<br></td>
    <td class="tg-214n">9600<br></td>
    <td class="tg-214n">&gt;9600<br></td>
    <td class="tg-214n">ShCore.dll added to \KnownDlls</td>
  </tr>
  <tr>
    <td class="tg-214n">3</td>
    <td class="tg-214n">Leo Davidson, WinNT/Pitou<br></td>
    <td class="tg-214n">Dll Hijack<br></td>
    <td class="tg-214n">IFileOperation</td>
    <td class="tg-214n">systemroot\system32\oobe\setupsqm.exe</td>
    <td class="tg-214n">WdsCore.dll</td>
    <td class="tg-214n">7600</td>
    <td class="tg-214n">10532</td>
    <td class="tg-214n">Fix is result of OOBE redesign<br></td>
  </tr>
  <tr>
    <td class="tg-214n">4</td>
    <td class="tg-214n">Jon Ericson, WinNT/Gootkit, mzH<br></td>
    <td class="tg-214n">AppCompat <br></td>
    <td class="tg-214n">RedirectEXE Shim<br></td>
    <td class="tg-214n">systemroot\system32\cliconfg.exe</td>
    <td class="tg-214n">-</td>
    <td class="tg-214n">7600</td>
    <td class="tg-214n">9600</td>
    <td class="tg-214n">Sbdinst.exe autoelevation removed, KB3045645/KB3048097</td>
  </tr>
  <tr>
    <td class="tg-214n">5</td>
    <td class="tg-214n">WinNT/Simda</td>
    <td class="tg-214n">Elevated COM interface<br></td>
    <td class="tg-214n">ISecurityEditor</td>
    <td class="tg-214n">Registry Keys<br></td>
    <td class="tg-214n">-</td>
    <td class="tg-214n">7600</td>
    <td class="tg-214n">10136</td>
    <td class="tg-214n">COM interface altered<br></td>
  </tr>
  <tr>
    <td class="tg-214n">6</td>
    <td class="tg-214n">Win32/Carberp</td>
    <td class="tg-214n">Dll Hijack<br></td>
    <td class="tg-214n">WUSA</td>
    <td class="tg-214n">systemroot\ehome\mcx2prov.exe<br>systemroot\system32\migwiz\migwiz.exe<br></td>
    <td class="tg-214n">WdsCore.dll<br>CryptBase.dll<br>CryptSP.dll<br></td>
    <td class="tg-214n">7600<br></td>
    <td class="tg-214n">10147<br></td>
    <td class="tg-214n">WUSA /extract option removed<br></td>
  </tr>
  <tr>
    <td class="tg-214n">7</td>
    <td class="tg-214n">Win32/Carberp derivative</td>
    <td class="tg-214n">Dll Hijack<br></td>
    <td class="tg-214n">WUSA</td>
    <td class="tg-214n">systemroot\system32\cliconfg.exe<br></td>
    <td class="tg-214n">ntwdblib.dll<br></td>
    <td class="tg-214n">7600<br></td>
    <td class="tg-214n">10147</td>
    <td class="tg-214n">WUSA /extract option removed<br></td>
  </tr>
  <tr>
    <td class="tg-214n">8</td>
    <td class="tg-214n">Leo Davidson<br>Win32/Tilon<br></td>
    <td class="tg-214n">Dll Hijack<br></td>
    <td class="tg-214n">IFileOperation</td>
    <td class="tg-214n">systemroot\system32\sysprep\sysprep.exe</td>
    <td class="tg-214n">Actionqueue.dll</td>
    <td class="tg-214n">7600</td>
    <td class="tg-214n">9600</td>
    <td class="tg-214n">sysprep.exe hardened LoadFrom manifest</td>
  </tr>
  <tr>
    <td class="tg-214n">9</td>
    <td class="tg-214n">Leo Davidson<br>WinNT/Simda<br>Win32/Carberp<br>derivative<br></td>
    <td class="tg-214n">Application Verifier<br></td>
    <td class="tg-214n">IFileOperation<br>ISecurityEditor<br>WUSA<br></td>
    <td class="tg-214n">IFEO registry keys <br>systemroot\system32\cliconfg.exe<br></td>
    <td class="tg-214n">Attacker defined Application Verifier Dll<br></td>
    <td class="tg-214n">7600</td>
    <td class="tg-214n">10147</td>
    <td class="tg-214n">WUSA /extract option removed<br>ISecurityEditor interface altered<br></td>
  </tr>
  <tr>
    <td class="tg-214n">10</td>
    <td class="tg-214n">WinNT/Pitou<br>Win32/Carberp<br>derivative<br></td>
    <td class="tg-214n">Dll Hijack<br></td>
    <td class="tg-214n">IFileOperation<br>WUSA<br></td>
    <td class="tg-214n">systemroot\system32\&lt;New&gt;or&lt;Existing&gt;\&lt;autoelevated&gt;.exe, e.g.<br>systemroot\system32\sysprep\winsat.exe<br></td>
    <td class="tg-214n">Attacker defined dll, <br>e.g. PowProf.dll<br>DevObj.dll<br></td>
    <td class="tg-214n">7600<br></td>
    <td class="tg-214n">10548</td>
    <td class="tg-214n">AppInfo elevated application path control hardedning<br></td>
  </tr>
  <tr>
    <td class="tg-214n">11</td>
    <td class="tg-214n">Jon Ericson, WinNT/Gootkit, mzH</td>
    <td class="tg-214n">AppCompat</td>
    <td class="tg-214n">Shim Memory Patch<br></td>
    <td class="tg-214n">systemroot\system32\iscsicli.exe</td>
    <td class="tg-214n">Attacker prepared shellcode<br></td>
    <td class="tg-214n">7600</td>
    <td class="tg-214n">9600</td>
    <td class="tg-214n">Sbdinst.exe autoelevation removed, KB3045645/KB3048097</td>
  </tr>
  <tr>
    <td class="tg-214n">12</td>
    <td class="tg-214n">Leo Davidson<br>derivative<br></td>
    <td class="tg-214n">Dll Hijack<br></td>
    <td class="tg-214n">IFileOperation</td>
    <td class="tg-214n">systemroot\system32\sysprep\sysprep.exe</td>
    <td class="tg-214n">dbgcore.dll</td>
    <td class="tg-214n">10240</td>
    <td class="tg-214n">10565</td>
    <td class="tg-214n">sysprep.exe manifest updated<br></td>
  </tr>
  <tr>
    <td class="tg-214n">13</td>
    <td class="tg-214n">Leo Davidson<br>derivative</td>
    <td class="tg-214n">Dll Hijack<br></td>
    <td class="tg-214n">IFileOperation</td>
    <td class="tg-214n">systemroot\system32\mmc.exe<br>EventVwr.msc<br></td>
    <td class="tg-214n">elsext.dll</td>
    <td class="tg-214n">7600</td>
    <td class="tg-214n">14316</td>
    <td class="tg-214n">Missing dependency removed<br></td>
  </tr>
  <tr>
    <td class="tg-214n">14</td>
    <td class="tg-214n">Leo Davidson<br>WinNT/Sirefef<br>derivative<br></td>
    <td class="tg-214n">Dll Hijack<br></td>
    <td class="tg-214n">IFileOperation</td>
    <td class="tg-214n">systemroot\system\credwiz.exe<br>systemroot\system32\wbem\oobe.exe</td>
    <td class="tg-214n">netutils.dll</td>
    <td class="tg-214n">7600</td>
    <td class="tg-214n">10548</td>
    <td class="tg-214n">AppInfo elevated application path control hardedning</td>
  </tr>
  <tr>
    <td class="tg-214n">15</td>
    <td class="tg-214n">Leo Davidson<br>Win32/Addrop<br>Metasploit<br>derivative<br></td>
    <td class="tg-214n">Dll Hijack<br></td>
    <td class="tg-214n">IFileOperation</td>
    <td class="tg-214n">systemroot\system32\cliconfg.exe</td>
    <td class="tg-214n">ntwdblib.dll</td>
    <td class="tg-214n">7600</td>
    <td class="tg-214n">14316</td>
    <td class="tg-214n">Cliconfg.exe autoelevation removed<br></td>
  </tr>
  <tr>
    <td class="tg-214n">16</td>
    <td class="tg-214n">Leo Davidson<br>derivative<br></td>
    <td class="tg-214n">Dll Hijack<br></td>
    <td class="tg-214n">IFileOperation</td>
    <td class="tg-214n">systemroot\system32\GWX\GWXUXWorker.exe -&gt; systemroot\system32\inetsrv\inetmgr.exe<br><br></td>
    <td class="tg-214n">SLC.dll</td>
    <td class="tg-214n">7600</td>
    <td class="tg-214n">14316</td>
    <td class="tg-214n">AppInfo elevated application path control and<br>inetmgr executable hardening</td>
  </tr>
  <tr>
    <td class="tg-214n">17<br></td>
    <td class="tg-214n">Leo Davidson derivative<br></td>
    <td class="tg-214n">Dll Hijack (Import Forwarding)<br></td>
    <td class="tg-214n">IFileOperation</td>
    <td class="tg-214n">systemroot\system32\sysprep\sysprep.exe</td>
    <td class="tg-214n">unbcl.dll</td>
    <td class="tg-214n">9600</td>
    <td class="tg-214n">14371</td>
    <td class="tg-214n">sysprep.exe manifest updated<br></td>
  </tr>
  <tr>
    <td class="tg-214n">18</td>
    <td class="tg-214n">Leo Davidson<br>derivative<br></td>
    <td class="tg-214n">Dll Hijack (Manifest)<br></td>
    <td class="tg-214n">IFileOperation</td>
    <td class="tg-214n">systemroot\system32\taskhost.exe<br>systemroot\system32\tzsync.exe<br></td>
    <td class="tg-214n">Attacker defined dll<br></td>
    <td class="tg-214n">7600</td>
    <td class="tg-214n">14371</td>
    <td class="tg-214n">Manifest parsing logic reviewed<br></td>
  </tr>
  <tr>
    <td class="tg-214n">19</td>
    <td class="tg-214n">Leo Davidson<br>derivative<br></td>
    <td class="tg-214n">Dll Hijack<br></td>
    <td class="tg-214n">IFileOperation</td>
    <td class="tg-214n">systemroot\system32\inetsrv\inetmgr.exe</td>
    <td class="tg-214n">MsCoree.dll</td>
    <td class="tg-214n">7600</td>
    <td class="tg-214n">14376</td>
    <td class="tg-214n">inetmgr.exe executable manifest hardening<br></td>
  </tr>
  <tr>
    <td class="tg-214n">20</td>
    <td class="tg-214n">Leo Davidson<br>derivative</td>
    <td class="tg-214n">Dll Hijack<br></td>
    <td class="tg-214n">IFileOperation</td>
    <td class="tg-214n">systemroot\system32\mmc.exe<br>Rsop.msc<br></td>
    <td class="tg-214n">WbemComn.dll</td>
    <td class="tg-214n">7600</td>
    <td class="tg-214n"></td>
    <td class="tg-214n"></td>
  </tr>
  <tr>
    <td class="tg-214n">21</td>
    <td class="tg-214n">Leo Davidson<br>derivative<br></td>
    <td class="tg-214n">Dll Hijack<br></td>
    <td class="tg-214n">IFileOperation<br>SxS DotLocal<br></td>
    <td class="tg-214n">systemroot\system32\sysprep\sysprep.exe</td>
    <td class="tg-214n">comctl32.dll</td>
    <td class="tg-214n">7600</td>
    <td class="tg-214n"></td>
    <td class="tg-214n"></td>
  </tr>
  <tr>
    <td class="tg-214n">22</td>
    <td class="tg-214n">Leo Davidson<br>derivative</td>
    <td class="tg-214n">Dll Hijack<br></td>
    <td class="tg-214n">IFileOperation<br>SxS DotLocal</td>
    <td class="tg-214n">systemroot\system32\consent.exe</td>
    <td class="tg-214n">comctl32.dll</td>
    <td class="tg-214n">7600</td>
    <td class="tg-214n"></td>
    <td class="tg-214n"></td>
  </tr>
  <tr>
    <td class="tg-214n">23</td>
    <td class="tg-214n">Leo Davidson<br>derivative</td>
    <td class="tg-214n">Dll Hijack<br></td>
    <td class="tg-214n">IFileOperation</td>
    <td class="tg-214n">systemroot\system32\pkgmgr.exe</td>
    <td class="tg-214n">DismCore.dll</td>
    <td class="tg-214n">7600</td>
    <td class="tg-214n"></td>
    <td class="tg-214n"></td>
  </tr>
  <tr>
    <td class="tg-214n">24</td>
    <td class="tg-214n">BreakingMalware</td>
    <td class="tg-214n">Shell API<br></td>
    <td class="tg-214n">Environment variables expansion<br></td>
    <td class="tg-214n">systemroot\system32\CompMgmtLauncher.exe</td>
    <td class="tg-214n">Attacker defined application<br></td>
    <td class="tg-214n">7600</td>
    <td class="tg-214n">15031</td>
    <td class="tg-214n">CompMgmtLauncher.exe autoelevation removed<br></td>
  </tr>
  <tr>
    <td class="tg-214n">25</td>
    <td class="tg-214n">Enigma0x3<br></td>
    <td class="tg-214n">Shell API<br></td>
    <td class="tg-214n">Registry key manipulation<br></td>
    <td class="tg-214n">systemroot\system32\EventVwr.exe<br>systemroot\system32\CompMgmtLauncher.exe</td>
    <td class="tg-214n">Attacker defined application<br></td>
    <td class="tg-214n">7600</td>
    <td class="tg-214n">15031</td>
    <td class="tg-214n">EventVwr.exe redesigned<br>CompMgmtLauncher.exe autoelevation removed</td>
  </tr>
  <tr>
    <td class="tg-214n">26</td>
    <td class="tg-214n">Enigma0x3</td>
    <td class="tg-214n">Race Condition<br></td>
    <td class="tg-214n">File overwrite<br></td>
    <td class="tg-214n">%temp%\GUID\dismhost.exe</td>
    <td class="tg-214n">LogProvider.dll</td>
    <td class="tg-214n">10240</td>
    <td class="tg-214n">15031</td>
    <td class="tg-214n">File security permission altered<br></td>
  </tr>
  <tr>
    <td class="tg-214n">27<br></td>
    <td class="tg-214n">ExpLife<br></td>
    <td class="tg-214n">Elevated COM interface<br></td>
    <td class="tg-214n">IARPUninstallStringLauncher</td>
    <td class="tg-214n">Attacker defined application<br></td>
    <td class="tg-214n">Attacker defined components<br></td>
    <td class="tg-214n">7600</td>
    <td class="tg-214n"></td>
    <td class="tg-214n"></td>
  </tr>
</table>

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
