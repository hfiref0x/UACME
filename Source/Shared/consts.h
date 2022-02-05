/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2022
*
*  TITLE:       CONSTS.H
*
*  VERSION:     3.59
*
*  DATE:        04 Feb 2022
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

//"Usage: Akagi.exe [Method] [OptionalParamToExecute]"
#define IDSB_USAGE_HELP                 0

//"Admin account with limited token required."
#define IDSB_USAGE_ADMIN_REQUIRED       1

//"Please enable UAC for this account."
#define IDSB_USAGE_UAC_REQUIRED         2

//"Wow64 detected, use x64 version of this tool."
#define ISDB_USAGE_WOW_DETECTED         3

//"This method only works with x86-32 Windows or from Wow64"
#define ISDB_USAGE_WOW64WIN32ONLY       4

//"This method fixed/unavailable in the current version of Windows, do you still want to continue?"
#define ISDB_USAGE_UACFIX               5

//"UACMe"
#define ISDB_PROGRAMNAME                6

#define UCM_VERSION_MAJOR       3
#define UCM_VERSION_MINOR       5
#define UCM_VERSION_REVISION    9
#define UCM_VERSION_BUILD       2202

#define SUPRUNPROCESS_TIMEOUT_DEFAULT 12000

//
// A very long list for future use.
//
#define UACME_SHARED_BASE_ID        'sTlA'

//
// Trash end char.
//
#define UCM_TRASH_END_CHAR          L'~'

//
// WORD sized id list.
//
#define AKAGI_COMPLETION_EVENT_ID   'ab'
#define AKAGI_SHARED_SECTION_ID     'cd'
#define AKAGI_BDESCRIPTOR_NAME_ID   'ef'
#define FUBUKI_SYNC_MUTEX_ID        'a1'
#define FUBUKI_PCA_SECTION_ID       '0f'
#define FUBUKI_PCA_EVENT_ID         '1f'

#define FUBUKI_PCA_PAYLOAD_RUN      (0x1)
#define FUBUKI_PCA_LOADER_RUN       (0x2)
#define FUBUKI_PCA_ALL_RUN          (FUBUKI_PCA_PAYLOAD_RUN | FUBUKI_PCA_LOADER_RUN)

//
// Kamikaze consts
//
#define KAMIKAZE_MARKER             "https"
#define WF_MSC                      L"wf.msc"

#define T_DEFAULT_DESKTOP           L"WinSta0\\Default"

#define T_WINDOWS_CURRENT_VERSION   L"MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"

#pragma region PYSH

#define T_DISPLAY_CALIBRATION       L"Software\\Microsoft\\Windows NT\\CurrentVersion\\ICM\\Calibration"
#define T_PCA_STORE                 L"Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store"
#define T_APPCOMPAT_LAYERS          L"Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers"
#define T_PCA_PERSISTED             L"Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Persisted"
#define T_APP_ASSOC_TOASTS          L"Software\\Microsoft\\Windows\\CurrentVersion\\ApplicationAssociationToasts"

#define T_CURVER                    L"CurVer"
#define T_MSSETTINGS                L"ms-settings"
#define T_MSWINDOWSSTORE            L"ms-windows-store"
#define T_CLASSESFOLDER             L"Folder"
#define T_LAUNCHERSYSTEMSETTINGS    L"Launcher.SystemSettings"

#define ELLOCNAK_MSU                L"update.msu"
#define RUN_CMD_COMMAND             L" /c start "

#define T_APPXSVC                   L"AppXSvc"
#define T_PCASVC                    L"PcaSvc"

#pragma endregion

#define T_SOFTWARE_CLASSES          L"Software\\Classes"

#define T_SHELL_OPEN                L"\\shell\\open"
#define T_SHELL_COMMAND             L"command"
#define T_URL_PROTOCOL              L"URL Protocol"

#define T_URL_MS_WIN_STORE          L"URL:ms-windows-store"

#define T_SDDL_ALL_FOR_EVERYONE     L"D:(A;;GA;;;WD)"
#define T_SDDL_EVERYONE_FULL_ACCESS L"D:PAI(A;OICI;FA;;;WD)"
#define T_WINDIR                    L"windir"
#define T_SYSTEMROOT                L"systemroot"
#define T_WINDOWSMEDIAPLAYER        L"Windows Media Player"

#define T_DELEGATEEXECUTE           L"DelegateExecute"

#define T_PROTO_HTTP                L"http"

//
// Unit names and entrypoints
//
#pragma region PYSH
#define KAMIKAZE_MSC                    L"kmkze.msc"
#define KAMIKAZE_LAUNCHER               L"readme.html"

#define FUBUKI_EXT_ENTRYPOINT           "MpManagerOpen"
#define FUBUKI_WND_HOOKPROC             "MpHandleClose"
#define FUBUKI_DEFAULT_ENTRYPOINT       "MpScanStart"
#define FUBUKI_ENTRYPOINT_UIACCESS2     "MpScanControl"
#define FUBUKI_ENTRYPOINT_SXS           "MpThreatOpen"
#define FUBUKI_ENTRYPOINT_PCAEXE        "MpManagerStatusQuery"
#define FUBUKI_ENTRYPOINT_PCADLL        "MpManagerStatusQueryEx"
#pragma endregion

//
// Windows dll names
//
#define APISET_KERNEL32LEGACY       L"api-ms-win-core-kernel32-legacy-l1.DLL"

#define BLUETOOTHDIAGNOSTICUTIL_DLL L"BluetoothDiagnosticUtil.dll"
#define COMCTL32_DLL                L"comctl32.dll"
#define DISMCORE_DLL                L"dismcore.dll"
#define DUSER_DLL                   L"duser.dll"
#define GDIPLUS_DLL                 L"GdiPlus.dll"
#define OSKSUPPORT_DLL              L"OskSupport.dll"
#define PCADM_DLL                   L"pcadm.dll"
#define SHELL32_DLL                 L"shell32.dll"
#define WINMM_DLL                   L"winmm.dll"
#define WOW64LOG_DLL                L"wow64log.dll"

//
// Native image cache targets
//
#define ASSEMBLY_MMCEX              L"MMCEx"
#define MMCEX_NI_DLL                L"MMCEx.ni.dll"
#define MMCEX_NI_DLL_AUX            L"MMCEx.ni.dll.aux"

#define ASSEMBLY_ACCESSIBILITY      L"Accessibility"

//
// Windows executables
//
#define CMD_EXE                     L"cmd.exe"
#define CLIPUP_EXE                  L"Clipup.exe"
#define COMPUTERDEFAULTS_EXE        L"computerdefaults.exe"
#define CONSENT_EXE                 L"consent.exe"
#define DCCW_EXE                    L"dccw.exe"
#define EVENTVWR_EXE                L"eventvwr.exe"
#define EXPLORER_EXE                L"explorer.exe"
#define FODHELPER_EXE               L"fodhelper.exe"
#define MMC_EXE                     L"mmc.exe"
#define MSCONFIG_EXE                L"msconfig.exe"
#define MSCHEDEXE_EXE               L"mschedexe.exe"
#define MSDT_EXE                    L"msdt.exe"
#define OSK_EXE                     L"osk.exe"
#define PKGMGR_EXE                  L"pkgmgr.exe"
#define SDCLT_EXE                   L"sdclt.exe"
#define SLUI_EXE                    L"slui.exe"
#define TASKHOSTW_EXE               L"taskhostw.exe"
#define WINSAT_EXE                  L"winsat.exe"
#define WINVER_EXE                  L"winver.exe"
#define WSRESET_EXE                 L"WSReset.exe"
#define WUSA_EXE                    L"wusa.exe"

//
// Windows subdirectories
//

// system32 only name
#define SYSTEM32_DIR_NAME           L"system32"

// system32 with both sides slash
#define SYSTEM32_DIR                L"\\system32\\"

// syswow64 with both sides slash
#define SYSWOW64_DIR                L"\\syswow64\\"

#define NET2_DIR                    L"v2.0.50727"
#define NET4_DIR                    L"v4.0.30319"
#define MSNETFRAMEWORK_DIR          L"Microsoft.NET\\Framework"
#define MMCEX_DIR                   L"\\MMCEx"

//
// Shell Verbs
//
#define RUNAS_VERB                  L"runas"

//
// Windows MMC snap-ins
//
#define EVENTVWR_MSC                L"eventvwr.msc"

//
// Units specific values
//
#define MYSTERIOUSCUTETHING         L"pe386" //PYSH
#define ABSOLUTEWIN                 L"lzx32" //PYSH

//
// SxS
//
#define LOCAL_SXS                   L".local"  //PYSH
#define FAKE_LOCAL_SXS              L".@" //PYSH
#define COMCTL32_SXS                L"microsoft.windows.common-controls"
#define GDIPLUS_SXS                 L"microsoft.windows.gdiplus"

//
// System consts
//
#define T_SYSTEMROOT_VAR            L"SYSTEMROOT"
#define T_REGISTRY_PREP             L"\\REGISTRY\\" //end slash included

//
// COR profiler
//
#define COR_PROFILER                L"COR_PROFILER"
#define COR_PROFILER_PATH           L"COR_PROFILER_PATH"
#define COR_ENABLE_PROFILING        L"COR_ENABLE_PROFILING"

//
// DCCW calibrator
//
#define T_CALIBRATOR_VALUE          L"DisplayCalibrator" //PYSH

//
// COM related trash
//
#define T_REG_SOFTWARECLASSESCLSID  L"Software\\Classes\\CLSID\\"
#define T_REG_INPROCSERVER32        L"\\InProcServer32"
#define T_REG_SHELLFOLDER           L"\\ShellFolder"

#define T_THREADINGMODEL            L"ThreadingModel"
#define T_APARTMENT                 L"Apartment"

//
// COM objects elevation
//
#pragma region PYSH
#define T_CLSID_ColorDataProxy               L"{D2E7041B-2927-42fb-8E9F-7CE93B6DC937}"
#define T_CLSID_CMSTPLUA                     L"{3E5FC7F9-9A51-4367-9063-A120244FBEC7}"
#define T_CLSID_FwCplLua                     L"{752438CB-E941-433F-BCB4-8B7D2329F0C8}"
#define T_CLSID_FileOperation                L"{3AD05575-8857-4850-9277-11B85BDB8E09}"
#define T_CLSID_ShellSecurityEditor          L"{4D111E08-CBF7-4f12-A926-2C7920AF52FC}"
#define T_CLSID_EditionUpgradeManager        L"{17CCA47D-DAE5-4E4A-AC42-CC54E28F334A}"
#define T_CLSID_IEAAddonInstaller            L"{BDB57FF2-79B9-4205-9447-F5FE85F37312}"
#define T_CLSID_SecurityCenter               L"{E9495B87-D950-4AB5-87A5-FF6D70BF3E90}"
#pragma endregion

//
// Moniker(s)
//
#define T_ELEVATION_MONIKER_ADMIN            L"Elevation:Administrator!new:"


//
// RPC interface UUID
//
#define APPINFO_RPC                         TEXT("201ef99a-7fa0-444c-9399-19ba84f12a1a")
#define PCASVC_RPC                          TEXT("0767a036-0d22-48aa-ba69-b619480f38cb")
