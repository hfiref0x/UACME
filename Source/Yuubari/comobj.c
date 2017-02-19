/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2017
*
*  TITLE:       COMOBJ.C
*
*  VERSION:     1.0F
*
*  DATE:        14 Feb 2017
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include <Shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")

VOID ScanRegistry(
    HKEY RootKey,
    REGCALLBACK OutputCallback
);

/*
* QuerySubKey
*
* Purpose:
*
* Query subkey elevated COM object name.
*
*/
VOID QuerySubKey(
    HKEY RootKey,
    LPWSTR lpKeyName,
    BOOL ElevationKey,
    REGCALLBACK OutputCallback
    )
{
    BOOL    bCond = FALSE;
    LRESULT lRet;
    HKEY    hSubKey = NULL, hAppIdKey = NULL;
    DWORD   dwDataSize, dwEnabled = 0;
    LPWSTR  lpName = NULL, lpAppId = NULL, lpAppIdName = NULL, lpLocalizedString = NULL, t = NULL;

    UAC_REGISTRY_DATA Data;

    if (OutputCallback == NULL)
        return;

    //open each sub key
    lRet = RegOpenKeyEx(RootKey, lpKeyName, 0, KEY_READ, &hSubKey);
    if ((lRet == ERROR_SUCCESS) && (hSubKey != NULL)) {
        if (ElevationKey) {

            do {

                dwDataSize = sizeof(DWORD);
                dwEnabled = 0;

                //query elevation enabled
                lRet = RegQueryValueEx(hSubKey, TEXT("Enabled"), NULL,
                    NULL,
                    (LPBYTE)&dwEnabled,
                    &dwDataSize
                );

                if (lRet != ERROR_SUCCESS)
                    break;

                if (dwEnabled != 1)
                    break;

                //query object name
                lpName = supReadKeyString(RootKey, TEXT(""), &dwDataSize);

                //query localized string and convert it
                dwDataSize = 0;
                t = supReadKeyString(RootKey, TEXT("LocalizedString"), &dwDataSize);
                if (t) {
                    lpLocalizedString = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)MAX_PATH * 2);
                    if (lpLocalizedString) {
                        SHLoadIndirectString(t, lpLocalizedString, MAX_PATH, NULL);
                    }
                    HeapFree(GetProcessHeap(), 0, t);
                }

                //check if AppId present
                dwDataSize = 0;
                t = supReadKeyString(RootKey, TEXT("AppId"), &dwDataSize);
                if (t) {
                    lpAppId = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)dwDataSize + 32);
                    if (lpAppId) {
                        _strcpy(lpAppId, TEXT("AppId\\"));
                        _strcat(lpAppId, t);

                        //open AppId key
                        lRet = RegOpenKeyEx(HKEY_CLASSES_ROOT, lpAppId, 0,
                            KEY_READ, &hAppIdKey);
                        if (lRet == ERROR_SUCCESS) {
                            //check if AccessPermisions present
                            lRet = RegQueryValueEx(hAppIdKey, TEXT("AccessPermission"),
                                NULL, NULL, NULL, NULL);

                            if (lRet == ERROR_SUCCESS) {
                                //if they found query name
                                dwDataSize = 0;
                                lpAppIdName = supReadKeyString(hAppIdKey, TEXT(""), &dwDataSize);
                            }
                            RegCloseKey(hAppIdKey);
                        }
                    }
                    HeapFree(GetProcessHeap(), 0, t);
                }

                //
                // Write output
                //
                RtlSecureZeroMemory(&Data, sizeof(Data));

                if (lpName) {
                    Data.Name = lpName;
                }
                else {
                    Data.Name = TEXT("undefined");
                }

                if (lpAppIdName) {
                    Data.AppId = lpAppIdName;
                }
                else {
                    if (lpAppId) {
                        Data.AppId = lpAppId;
                    }
                    else {
                        Data.AppId = TEXT("undefined");
                    }
                }

                if (lpLocalizedString) {
                    Data.LocalizedString = lpLocalizedString;
                }
                else {
                    Data.LocalizedString = TEXT("undefined");
                }

                Data.Key = supQueryKeyName(RootKey, NULL);

                OutputCallback(&Data);

                if (Data.Key) {
                    HeapFree(GetProcessHeap(), 0, Data.Key);
                }

            } while (bCond);

            if (lpAppIdName)
                HeapFree(GetProcessHeap(), 0, lpAppIdName);

            if (lpAppId != NULL)
                HeapFree(GetProcessHeap(), 0, lpAppId);

            if (lpName != NULL)
                HeapFree(GetProcessHeap(), 0, lpName);
        }
        else {
            ScanRegistry(hSubKey, OutputCallback);
        }
        RegCloseKey(hSubKey);
    }
}

/*
* EnumSubKey
*
* Purpose:
*
* Enumerate key subkeys, check elevation flag.
*
*/
VOID EnumSubKey(
    HKEY hKey,
    DWORD dwKeyIndex,
    REGCALLBACK OutputCallback
    )
{
    BOOL    bElevation = FALSE;
    LRESULT lRet;
    DWORD   dwcbName = 0, cch;
    LPTSTR  lpKeyName = NULL;

    if (OutputCallback == NULL)
        return;

    do {
        dwcbName = 32 * 1024;
        lpKeyName = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwcbName);
        if (lpKeyName == NULL)
            break;

        cch = dwcbName / sizeof(WCHAR);
        lRet = RegEnumKeyEx(hKey, dwKeyIndex,
            lpKeyName, &cch, NULL, NULL, NULL, NULL);
        if (lRet == ERROR_MORE_DATA) {
            dwcbName *= 2;
            HeapFree(GetProcessHeap(), 0, lpKeyName);
            continue;
        }
        if (lRet == ERROR_SUCCESS) {
            //skip wow64 shit
            if (_strcmpi(lpKeyName, TEXT("Wow6432Node")) == 0)
                break;

            if (_strcmpi(lpKeyName, TEXT("Elevation")) == 0)
                bElevation = TRUE;

            QuerySubKey(hKey, lpKeyName, bElevation, OutputCallback);
        }

    } while (lRet == ERROR_MORE_DATA);

    if (lpKeyName != NULL)
        HeapFree(GetProcessHeap(), 0, lpKeyName);

}

/*
* ScanRegistry
*
* Purpose:
*
* Recursively scan registry looking for autoelevated COM entries.
*
*/
VOID ScanRegistry(
    HKEY RootKey,
    REGCALLBACK OutputCallback
    )
{
    BOOL    bCond = FALSE;
    HKEY    hKey = NULL;
    LRESULT lRet;
    DWORD   dwcSubKeys = 0, i;

    if (OutputCallback == NULL)
        return;

    do {
        //open root key for enumeration
        lRet = RegOpenKeyEx(RootKey, NULL, 0, KEY_READ, &hKey);
        if ((lRet != ERROR_SUCCESS) || (hKey == NULL))
            break;

        //query subkeys count
        lRet = RegQueryInfoKey(hKey, NULL, NULL, NULL, &dwcSubKeys,
            NULL, NULL, NULL, NULL, NULL, NULL, NULL);

        if ((lRet != ERROR_SUCCESS) || (dwcSubKeys == 0))
            break;

        for (i = 0; i < dwcSubKeys; i++)
            EnumSubKey(hKey, i, OutputCallback);

    } while (bCond);

    if (hKey != NULL)
        RegCloseKey(hKey);
}
