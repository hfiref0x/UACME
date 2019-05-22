/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2019
*
*  TITLE:       CONSTS.H
*
*  VERSION:     3.19
*
*  DATE:        22 May 2019
*
*  Global consts definition file.
*
*  If you are looking for unique enough pattern look for values/regions marked as "PYSH".
*  Get rid of these values, or customize them otherwise.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#define AKAGI_XOR_KEY               'naka'
#define AKAGI_XOR_KEY2              ' pta'

#pragma region PYSH
#define T_USAGE_HELP                L"Usage: Akagi.exe [Method] [OptionalParamToExecute]"
#define PROGRAMTITLE_VERSION        L"UACMe v 3.1.9.1905"
#define WOW64STRING                 L"Wow64 detected, use x64 version of this tool."
#define WOW64WIN32ONLY              L"This method only works with x86-32 Windows or from Wow64"
#define UACFIX                      L"This method fixed/unavailable in the current version of Windows, do you still want to continue?"
#pragma endregion

#define T_MACHINE                   L"MACHINE\\"

#define T_WINDOWS_CURRENT_VERSION   L"MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
#define T_IFEO                      L"MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
#define T_UACKEY                    L"MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\system"
#define T_COMAUTOAPPROVALLIST       L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\UAC\\COMAutoApprovalList"

#define T_APP_PATH                  L"Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\"
#define T_DISPLAY_CALIBRATION       L"Software\\Microsoft\\Windows NT\\CurrentVersion\\ICM\\Calibration"
#define T_DOTNET_CLIENT             L"Software\\Microsoft\\Windows NT\\CurrentVersion\\KnownFunctionTableDlls"
#define T_UNINSTALL                 L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\"

#define T_MSC_SHELL                 L"Software\\Classes\\mscfile"
#define T_EXEFILE_SHELL             L"Software\\Classes\\exefile"
#define T_MSSETTINGS                L"Software\\Classes\\ms-settings"
#define T_CLASSESFOLDER             L"Software\\Classes\\Folder"
#define T_APPXPACKAGE               L"Software\\Classes\\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2"
#define T_SHELL_OPEN_COMMAND        L"\\shell\\open\\command"
#define T_SHELL_RUNAS_COMMAND       L"\\shell\\runas\\command"

#define T_FILE_PREP                 L"file://"

#define T_SCHTASKS_CMD              L"/run /tn \"\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup\" /i" //PYSH
#define T_CLSID_MYCOMPUTER_COMET    L"\\Comet.{20D04FE0-3AEA-1069-A2D8-08002B30309D}" //PYSH
#define T_SDDL_ALL_FOR_EVERYONE     L"D:(A;;GA;;;WD)"
#define T_PROGRAMDATA               L"ProgramData"
#define T_WINDIR                    L"windir"
#define T_WINDOWSMEDIAPLAYER        L"Windows Media Player"

#define T_ISOLATEDCOMMAND           L"IsolatedCommand"
#define T_DELEGATEEXECUTE           L"DelegateExecute"

#define T_UNINSTALL_STRING          L"UninstallString"

#define BINARYPATH_TAG              L"binarypatch01" //PYSH

#define MSFT_FULL                   L"Microsoft Corporation"
#define MSFT_MIN                    L"Microsoft"

#define INAZUMA_REV                 L"amuzani" //PYSH

#define MANIFEST_EXT                L".manifest"
#define ELLOCNAK_MSU                L"update.msu" //PYSH

#define OBJECT_LOCALSYSTEM          L"LocalSystem"
#define OBJECT_LOCALSERVICE         L"NT AUTHORITY\\LocalService"

#define BDESCRIPTOR_NAME            L"ArisuTsuberuku"  //PYSH
#define AKAGI_SHARED_SECTION        L"AkagiSharedSection" //PYSH
#define AKAGI_COMPLETION_EVENT      L"AkagiCompletionEvent" //PYSH

#define SIGNAL_OBJECT               L"\\BaseNamedObjects\\CZ2128" //PYSH

//
// Unit names and entrypoints.
//
#pragma region PYSH
#define FUBUKI_DLL                      L"Fubuki.dll"
#define FUJINAMI_DLL                    L"Fujinami.dll"
#define HIBIKI_DLL                      L"Hibiki.dll"
#define KUMA_DLL                        L"lzx32.dll"
#define KAMIKAZE_MSC                    L"kmkze.msc" 
#define FUBUKI_EXE                      L"Fubuki.exe"
#define FUBUKI_EXT_ENTRYPOINT           "_FubukiProc1"
#define FUBUKI_WND_HOOKPROC             "_FubukiProc2"
#define FUBUKI_DEFAULT_ENTRYPOINT       "_FubukiProc3"
#define FUBUKI_ENTRYPOINT_UIACCESS2     "_FubukiProc4"
#define FUBUKI_DEFAULT_ENTRYPOINTW      L"_FubukiProc3"
#define CHIYODA_EXT_ENTRYPOINT          "ChiyodaMain"
#pragma endregion

//
// Windows dll names.
//
#define ACTIONQUEUE_DLL             L"ActionQueue.dll"
#define COMCTL32_DLL                L"comctl32.dll"
#define CRYPTBASE_DLL               L"cryptbase.dll"
#define DBGCORE_DLL                 L"dbgcore.dll"
#define DEVOBJ_DLL                  L"devobj.dll"
#define DISMCORE_DLL                L"dismcore.dll"
#define DUSER_DLL                   L"duser.dll"
#define ELSEXT_DLL                  L"elsext.dll"
#define GDIPLUS_DLL                 L"GdiPlus.dll"
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
#define SRRSTR_DLL                  L"srrstr.dll"
#define SLC_DLL                     L"SLC.dll"
#define UNATTEND_DLL                L"unattend.dll"
#define UNBCL_DLL                   L"unbcl.dll"
#define WBEMCOMN_DLL                L"wbemcomn.dll"
#define WDSCORE_DLL                 L"wdscore.dll"
#define WINDOWS_STORAGE_DLL         L"windows.storage.dll"
#define WINMM_DLL                   L"winmm.dll"
#define WOW64LOG_DLL                L"wow64log.dll"
#define W32TIME_DLL                 L"w32time.dll"

//
// Windows executables.
//
#define BITLOCKERWIZARDELEV_EXE     L"BitlockerWizardElev.exe"
#define CMD_EXE                     L"cmd.exe"
#define CLICONFG_EXE                L"cliconfg.exe"
#define COMPMGMTLAUNCHER_EXE        L"CompMgmtLauncher.exe"
#define COMPUTERDEFAULTS_EXE        L"computerdefaults.exe"
#define CONSENT_EXE                 L"consent.exe"
#define CONTROL_EXE                 L"control.exe"
#define CREDWIZ_EXE                 L"credwiz.exe"
#define DCOMCNFG_EXE                L"dcomcnfg.exe"
#define DCCW_EXE                    L"dccw.exe"
#define EVENTVWR_EXE                L"eventvwr.exe"
#define EXPLORER_EXE                L"explorer.exe"
#define FODHELPER_EXE               L"fodhelper.exe"
#define INETMGR_EXE                 L"InetMgr.exe"
#define INFDEFAULTINSTALL_EXE       L"InfDefaultInstall.exe"
#define ISCSICLI_EXE                L"iscsicli.exe"
#define MIGWIZ_EXE                  L"migwiz.exe"
#define MMC_EXE                     L"mmc.exe"
#define MSCONFIG_EXE                L"msconfig.exe"
#define OOBE_EXE                    L"oobe.exe"
#define SETUPSQM_EXE                L"oobe\\setupsqm.exe" 
#define OSK_EXE                     L"osk.exe"
#define RRINSTALLER_EXE             L"rrinstaller.exe"
#define REG_EXE                     L"reg.exe"
#define PERFMON_EXE                 L"perfmon.exe"
#define PKGMGR_EXE                  L"pkgmgr.exe"
#define SCHTASKS_EXE                L"schtasks.exe"
#define SDBINST_EXE                 L"sdbinst.exe"
#define SDCLT_EXE                   L"sdclt.exe"
#define SLUI_EXE                    L"slui.exe"
#define SYSPREP_EXE                 L"sysprep.exe"
#define SYSTEMROPERTIESADVANCED_EXE L"SystemPropertiesAdvanced.exe"
#define TASKHOST_EXE                L"taskhost.exe"
#define TPMINIT_EXE                 L"tpminit.exe"
#define TZSYNC_EXE                  L"tzsync.exe"
#define WINSAT_EXE                  L"winsat.exe"
#define WSRESET_EXE                 L"WSReset.exe"
#define WUSA_EXE                    L"wusa.exe"

//
// Windows subdirectories.
//
#define INETSRV_DIR                 L"inetsrv\\"
#define MIGWIZ_DIR                  L"migwiz\\"
#define SYSPREP_DIR                 L"sysprep\\"
#define SYSTEM32_DIR                L"\\system32\\"
#define SYSWOW64_DIR                L"\\syswow64\\"
#define WBEM_DIR                    L"wbem\\"

//
// Chiyoda part
//
#define W32TIME_SERVICE_NAME        L"w32time"
#define W32TIME_SERVICE_PATH        L"SYSTEM\\CurrentControlSet\\Services\\W32Time"
#define W32TIME_SERVICE_PARAMETERS  L"SYSTEM\\CurrentControlSet\\Services\\W32Time\\Parameters"
#define SVC_SERVICE_DLL             L"ServiceDll"
#define SVC_OBJECT_NAME             L"ObjectName"
#define SVC_REQ_PRIVS               L"RequiredPrivileges"
#define SVC_IMAGE_PATH              L"ImagePath"
#define SVC_TYPE                    L"Type"

//
// Shell Verbs.
//
#define MANAGE_VERB                 L"Manage"
#define RUNAS_VERB                  L"runas"

//
// Windows MMC snap-ins.
//
#define EVENTVWR_MSC                L"eventvwr.msc"
#define RSOP_MSC                    L"rsop.msc"

#define PACKAGE_XML                 L"oemsetup.xml"
#define PACKAGE_INF                 L"oemsetup.inf"

#define RUNDLL_EXE_CMD              L"rundll32.exe " //with space as part of command

#define REG_HKCU                    L"HKEY_CURRENT_USER"
#define T_REG_SZ                    L"REG_SZ"

//
// Units specific values
//
#pragma region PYSH
#ifdef _WIN64
#define KONGOU_CD                   L"Kongou64.cd"
#else
#define KONGOU_CD                   L"Kongou32.cd"
#endif

#define MYSTERIOUSCUTETHING         L"pe386"
#define SOMEOTHERNAME               L"huy32"

#define T_KUREND                    L"KureND"
#define T_SYMLINK                   L"\\Software\\KureND"
#pragma endregion

#define LOCAL_SXS                   L".local"
#define FAKE_LOCAL_SXS              L".hawawa" //PYSH
#define INETMGR_SXS                 L"microsoft-windows-iis-managementconsole"
#define COMCTL32_SXS                L"microsoft.windows.common-controls"
#define GDIPLUS_SXS                 L"microsoft.windows.gdiplus"

#define T_VOLATILE_ENV              L"Volatile Environment"
#define T_SYSTEMROOT_VAR            L"SYSTEMROOT"
#define T_REGISTRY_PREP             L"\\REGISTRY\\" //end slash included

#define COR_PROFILER                L"COR_PROFILER"
#define COR_PROFILER_PATH           L"COR_PROFILER_PATH"
#define COR_ENABLE_PROFILING        L"COR_ENABLE_PROFILING"

#define T_CALIBRATOR_VALUE          L"DisplayCalibrator"

#define T_MONITOR_PROCESS           L"MonitorProcess"
#define T_REPORTING_MODE            L"ReportingMode"
#define T_GLOBAL_FLAG               L"GlobalFlag"
#define T_SILENT_PROCESS_EXIT       L"\\SilentProcessExit\\"  //with slash as part of key path

//
// COM related trash.
//
#define T_REG_SOFTWARECLASSESCLSID  L"Software\\Classes\\CLSID\\"
#define T_REG_INPROCSERVER32        L"\\InProcServer32"
#define T_REG_SHELLFOLDER           L"\\ShellFolder"

#define T_THREADINGMODEL            L"ThreadingModel"
#define T_APARTMENT                 L"Apartment"
#define T_LOADWITHOUTCOM            L"LoadWithoutCOM"
#define T_HIDEONDESKTOPPERUSER      L"HideOnDesktopPerUser"
#define T_ATTRIBUTES                L"Attributes"
#define T_ASSEMBLY                  L"Assembly"
#define T_CLASS                     L"Class"
#define T_CODEBASE                  L"CodeBase"

//
// COM objects elevation.
//
#define T_CLSID_CreateNewLink                L"{1BA783C1-2A30-4ad3-B928-A9A46C604C28}"
#define T_CLSID_ColorDataProxy               L"{D2E7041B-2927-42fb-8E9F-7CE93B6DC937}"
#define T_CLSID_CMSTPLUA                     L"{3E5FC7F9-9A51-4367-9063-A120244FBEC7}"
#define T_CLSID_DateTimeStateWriter          L"{9DF523B0-A6C0-4EA9-B5F1-F4565C3AC8B8}"
#define T_CLSID_FileOperation                L"{3AD05575-8857-4850-9277-11B85BDB8E09}"
#define T_CLSID_FwCplLua                     L"{752438CB-E941-433F-BCB4-8B7D2329F0C8}"
#define T_CLSID_ShellSecurityEditor          L"{4D111E08-CBF7-4f12-A926-2C7920AF52FC}"
#define T_CLSID_SPPLUAObject                 L"{179CC917-3A82-40E7-9F8C-2FC8A3D2212B}"
#define T_CLSID_UninstallStringLauncher      L"{FCC74B77-EC3E-4DD8-A80B-008A702075A9}"
#define T_CLSID_AcCplAdmin                   L"{434A6274-C539-4E99-88FC-44206D942775}"

#ifdef _KUMA_CONTAINER_MODE

#define T_IID_CreateNewLink                  L"{B5AB9C96-C11D-43E7-B44C-79B13EE7AC6F}"
#define T_IID_IColorDataProxy                L"{0A16D195-6F47-4964-9287-9F4BAB6D9827}"
#define T_IID_ICMLuaUtil                     L"{6EDD6D74-C007-4E75-B76A-E5740995E24C}"
#define T_IID_DateTimeState                  L"{500DD1A1-B32A-4A37-9283-1185FB613899}"
#define T_IID_IFwCplLua                      L"{56DA8B35-7FC3-45DF-8768-664147864573}"
#define T_IID_ISecurityEditor                L"{14B2C619-D07A-46EF-8B62-31B64F3B845C}"
#define T_IID_SPPLUAObject                   L"{12FBFECB-7CCE-473E-8737-78EE6C9CCAEB}"
#define T_IID_IARPUninstallStringLauncher    L"{F885120E-3789-4FD9-865E-DC9B4A6412D2}"
#define T_IID_IAcCplAdmin                    L"{97B9F488-B188-4B03-9B27-D74B25755464}"

#endif //_KUMA_CONTAINER_MODE

//
// Moniker(s)
//
#define T_ELEVATION_MONIKER_ADMIN            L"Elevation:Administrator!new:"
#define T_ELEVATION_MONIKER_HIGHEST          L"Elevation:Highest!new:"

//
// COM Handlers hijack.
//
#define T_CLSID_EVENTVWR_BYPASS              L"{0A29FF9E-7F9C-4437-8B11-F424491E3931}"
#define T_MMCFrameworkSnapInFactory          L"{D5AB5662-131D-453D-88C8-9BBA87502ADE}"

#define T_FUJINAMI_ASSEMBLY                  L"Fujinami, Version=0.0.0.0, Culture=neutral" //PYSH
#define T_FUJINAMI_CLASS                     L"Fujinami.EntryPoint" //PYSH
