/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2017
*
*  TITLE:       CONSTS.H
*
*  VERSION:     2.72
*
*  DATE:        26 May 2017
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

#define T_APP_PATH                  L"Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\"
#define T_EXEFILE_SHELL             L"Software\\Classes\\exefile\\shell\\runas\\command"
#define T_MSSETTINGS                L"Software\\Classes\\ms-settings"
#define T_SHELL_OPEN_COMMAND        L"\\shell\\open\\command"

#define T_SCHTASKS_CMD              L"/run /tn \"\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup\" /i"
#define T_CLSID_MYCOMPUTER_COMET    L"\\Comet.{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
#define T_SDDL_ALL_FOR_EVERYONE     L"D:(A;;GA;;;WD)"
#define T_PROGRAMDATA               L"ProgramData"
#define T_WINDIR                    L"windir"
#define T_WINDOWSMEDIAPLAYER        L"Windows Media Player"

#define T_ISOLATEDCOMMAND           L"IsolatedCommand"
#define T_DELEGATEEXECUTE           L"DelegateExecute"

#define BINARYPATH_TAG              L"binarypatch01"

#define MSFT_FULL                   L"Microsoft Corporation"
#define MSFT_MIN                    L"Microsoft"

#define INAZUMA_REV                 L"amuzani"

#define MANIFEST_EXT                L".manifest"
#define ELLOCNAK_MSU                L"ellocnak.msu"

#define ACTIONQUEUE_DLL             L"ActionQueue.dll"
#define COMCTL32_DLL                L"comctl32.dll"
#define CRYPTBASE_DLL               L"cryptbase.dll"
#define DBGCORE_DLL                 L"dbgcore.dll"
#define DEVOBJ_DLL                  L"devobj.dll"
#define DISMCORE_DLL                L"dismcore.dll"
#define DUSER_DLL                   L"duser.dll"
#define ELSEXT_DLL                  L"elsext.dll"
#define HIBIKI_DLL                  L"Hibiki.dll"
#define KERNEL32_DLL                L"kernel32.dll"
#define LOGPROVIDER_DLL             L"LogProvider.dll"
#define MSCOREE_DLL                 L"MSCOREE.DLL"
#define NETUTILS_DLL                L"netutils.dll"
#define NTDLL_DLL                   L"ntdll.dll"
#define NTWDBLIB_DLL                L"ntwdblib.dll"
#define OLE32_DLL                   L"ole32.dll"
#define OSKSUPPORT_DLL              L"OskSupport.dll"
#define POWRPROF_DLL                L"powrprof.dll"
#define PROVPROVIDER_DLL            L"ProvProvider.dll"
#define SHCORE_DLL                  L"shcore.dll"
#define SHELL32_DLL                 L"shell32.dll"
#define SLC_DLL                     L"SLC.dll"
#define UNBCL_DLL                   L"unbcl.dll"
#define WBEMCOMN_DLL                L"wbemcomn.dll"
#define WDSCORE_DLL                 L"wdscore.dll"
#define WOW64LOG_DLL                L"wow64log.dll"
#define CMD_EXE                     L"cmd.exe"
#define CLICONFG_EXE                L"cliconfg.exe"
#define COMPMGMTLAUNCHER_EXE        L"CompMgmtLauncher.exe"
#define CONSENT_EXE                 L"consent.exe"
#define CONTROL_EXE                 L"control.exe"
#define CREDWIZ_EXE                 L"credwiz.exe"
#define EVENTVWR_EXE                L"eventvwr.exe"
#define EXPLORER_EXE                L"explorer.exe"
#define FODHELPER_EXE               L"fodhelper.exe"
#define INETMGR_EXE                 L"InetMgr.exe"
#define INFDEFAULTINSTALL_EXE       L"InfDefaultInstall.exe"
#define ISCSICLI_EXE                L"iscsicli.exe"
#define MIGWIZ_EXE                  L"migwiz.exe"
#define MMC_EXE                     L"mmc.exe"
#define OOBE_EXE                    L"oobe.exe"
#define SETUPSQM_EXE                L"oobe\\setupsqm.exe" 
#define OSK_EXE                     L"osk.exe"
#define PKGMGR_EXE                  L"pkgmgr.exe"
#define SCHTASKS_EXE                L"schtasks.exe"
#define SDBINST_EXE                 L"sdbinst.exe"
#define SDCLT_EXE                   L"sdclt.exe"
#define SYSPREP_EXE                 L"sysprep.exe" 
#define TASKHOST_EXE                L"taskhost.exe"
#define TZSYNC_EXE                  L"tzsync.exe"
#define WINSAT_EXE                  L"winsat.exe"
#define WUSA_EXE                    L"wusa.exe"
#define INETSRV_DIR                 L"inetsrv\\"
#define MIGWIZ_DIR                  L"migwiz\\"
#define SYSPREP_DIR                 L"sysprep\\"
#define WBEM_DIR                    L"wbem\\"
#define SYSWOW64_DIR                L"\\syswow64\\"
#define MANAGE_VERB                 L"Manage"
#define RUNAS_VERB                  L"runas"
#define EVENTVWR_MSC                L"eventvwr.msc"
#define RSOP_MSC                    L"rsop.msc"
#define PACKAGE_XML                 L"ellocnak.xml"
#define PACKAGE_INF                 L"ellocnak.inf"

#ifdef _WIN64
#define KONGOU_CD                   L"Kongou64.cd"
#else
#define KONGOU_CD                   L"Kongou32.cd"
#endif

#define MYSTERIOSCUTETHING          L"pe386"

#define T_DEFAULT_CMD               L"%systemroot%\\system32\\cmd.exe"

#define LOCAL_SXS                   L".local"
#define FAKE_LOCAL_SXS              L".hawawa"
#define INETMGR_SXS                 L"microsoft-windows-iis-managementconsole"
#define COMCTL32_SXS                L"microsoft.windows.common-controls"

#define APPCMDLINE                  L"Not a security boundary! Just hack-o-rama. Keep it as is!"
#define PROGRAMTITLE                L"UACMe"
#define WOW64STRING                 L"Wow64 detected, use x64 version of this tool."
#define WOW64WIN32ONLY              L"This method only works with x86-32 Windows or from Wow64"
#define UACFIX                      L"This method fixed/unavailable in the current version of Windows, do you still want to continue?"
#define T_AKAGI_KEY                 L"Software\\Akagi"
#define T_AKAGI_PARAM               L"LoveLetter"
#define T_AKAGI_FLAG                L"Flag"

//
//COM objects elevation.
//
#define T_CLSID_FileOperation                L"{3AD05575-8857-4850-9277-11B85BDB8E09}"
#define T_CLSID_ShellSecurityEditor          L"{4D111E08-CBF7-4f12-A926-2C7920AF52FC}"
#define T_CLSID_UninstallStringLauncher      L"{FCC74B77-EC3E-4DD8-A80B-008A702075A9}"

#define T_IID_ISecurityEditor                L"{14B2C619-D07A-46EF-8B62-31B64F3B845C}"
#define T_IID_IARPUninstallStringLauncher    L"{F885120E-3789-4FD9-865E-DC9B4A6412D2}"
