/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2017
*
*  TITLE:       COMOBJ.C
*
*  VERSION:     1.24
*
*  DATE:        20 Mar 2017
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include <Shlwapi.h>
#include <shlobj.h>
#include <Rpc.h>
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Rpcrt4.lib")

VOID CopScanRegistry(
    _In_ HKEY RootKey,
    _In_ REGCALLBACK OutputCallback
);

/*
* CopQuerySubKey
*
* Purpose:
*
* Query subkey elevated COM object name.
*
*/
VOID CopQuerySubKey(
    _In_ HKEY RootKey,
    _In_ LPWSTR lpKeyName,
    _In_ BOOL ElevationKey,
    _In_ REGCALLBACK OutputCallback
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
                Data.DataType = UacCOMDataCommonType;
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
            CopScanRegistry(hSubKey, OutputCallback);
        }
        RegCloseKey(hSubKey);
    }
}

/*
* CopEnumSubKey
*
* Purpose:
*
* Enumerate key subkeys, check elevation flag.
*
*/
VOID CopEnumSubKey(
    _In_ HKEY hKey,
    _In_ DWORD dwKeyIndex,
    _In_ REGCALLBACK OutputCallback
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

            CopQuerySubKey(hKey, lpKeyName, bElevation, OutputCallback);
        }

    } while (lRet == ERROR_MORE_DATA);

    if (lpKeyName != NULL)
        HeapFree(GetProcessHeap(), 0, lpKeyName);

}

/*
* CopScanRegistry
*
* Purpose:
*
* Recursively scan registry looking for autoelevated COM entries.
*
*/
VOID CopScanRegistry(
    _In_ HKEY RootKey,
    _In_ REGCALLBACK OutputCallback
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
            CopEnumSubKey(hKey, i, OutputCallback);

    } while (bCond);

    if (hKey != NULL)
        RegCloseKey(hKey);
}

/*
* CopEnumInterfaces
*
* Purpose:
*
* Remember list of available interfaces, excluding IUnknown.
*
*/
BOOL CopEnumInterfaces(
    _In_ INTERFACE_INFO_LIST *InterfaceList
)
{
    BOOL        bResult = FALSE;
    HKEY        hKey = NULL;
    LRESULT     lRet;
    RPC_STATUS  RpcStatus = 0;
    LPWSTR      lpKeyName = NULL;
    SIZE_T      k;
    DWORD       i, cSubKeys = 0, cMaxLength = 0, cchKey;
    IID         iid;

    INTERFACE_INFO *infoBuffer;

    __try {

        lRet = RegOpenKeyEx(HKEY_CLASSES_ROOT, TEXT("Interface"), 0, KEY_READ, &hKey);
        if (lRet != ERROR_SUCCESS)
            __leave;

        lRet = RegQueryInfoKey(hKey, NULL, NULL, NULL, &cSubKeys, &cMaxLength, NULL,
            NULL, NULL, NULL, NULL, NULL);
        if ((lRet != ERROR_SUCCESS) || (cSubKeys == 0))
            __leave;

        infoBuffer = (INTERFACE_INFO*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cSubKeys * sizeof(INTERFACE_INFO));
        if (infoBuffer == NULL)
            __leave;

        cMaxLength = (DWORD)((cMaxLength + 1) * sizeof(WCHAR));
        lpKeyName = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cMaxLength);
        if (lpKeyName == NULL)
            __leave;

        for (k = 0, i = 0; i < cSubKeys; i++) {

            cchKey = (DWORD)(cMaxLength / sizeof(WCHAR));
            if (RegEnumKeyEx(hKey, i, lpKeyName, &cchKey, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {

                if (IIDFromString(lpKeyName, &iid) == S_OK) {

                    //skip IUnknown
                    if (UuidCompare((UUID*)&iid, (UUID*)&IID_IUnknown, &RpcStatus) == 0)
                        continue;

                    cchKey = MAX_PATH * sizeof(WCHAR);
                    infoBuffer[k].iid = iid;

                    RegGetValue(hKey, lpKeyName, TEXT(""), RRF_RT_REG_SZ, NULL,
                        (LPWSTR)&infoBuffer[k].szInterfaceName, &cchKey);

                    k++;
                }
            }
        }
        InterfaceList->cEntries = (ULONG)k;
        InterfaceList->List = infoBuffer;
        bResult = TRUE;
    }
    __finally {
        if (hKey)
            RegCloseKey(hKey);

        if (lpKeyName)
            HeapFree(GetProcessHeap(), 0, lpKeyName);
    }

    return bResult;
}

/*
* CopScanAutoApprovalList
*
* Purpose:
*
* Query list of autoapproval COM objects.
* This key was added in RS1 specially for consent.exe comfort
*
*/
VOID CopScanAutoApprovalList(
    _In_ REGCALLBACK OutputCallback
)
{
    HKEY    hKey = NULL;
    LRESULT lRet;
    SIZE_T  j;
    LPWSTR  lpValue = NULL;
    DWORD   i, cValues = 0, cMaxLength = 0, cchValue;

    UAC_INTERFACE_DATA Data;
    CLSID clsid;
    INTERFACE_INFO_LIST InterfaceList;

    IUnknown *Interface = NULL;
    IUnknown *TestObject = NULL;

    if (CoInitialize(NULL) != S_OK)
        return;

    RtlSecureZeroMemory(&InterfaceList, sizeof(InterfaceList));

    __try {

        if (!CopEnumInterfaces(&InterfaceList))
            __leave;

        lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, T_UAC_COM_AUTOAPPROVAL_LIST, 0, KEY_READ, &hKey);
        if (lRet != ERROR_SUCCESS)
            __leave;

        lRet = RegQueryInfoKey(hKey, NULL, NULL, NULL, NULL, NULL, NULL,
            &cValues, &cMaxLength, NULL, NULL, NULL);
        if ((lRet != ERROR_SUCCESS) || (cValues == 0))
            __leave;

        cMaxLength = (DWORD)((cMaxLength + 1) * sizeof(WCHAR));
        lpValue = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cMaxLength);
        if (lpValue == NULL)
            __leave;

        for (i = 0; i < cValues; i++) {
            cchValue = (DWORD)(cMaxLength / sizeof(WCHAR));
            if (RegEnumValue(hKey, i, lpValue, &cchValue, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                if (CLSIDFromString(lpValue, &clsid) == S_OK)
                    if (SUCCEEDED(CoCreateInstance(&clsid, NULL, CLSCTX_INPROC_SERVER,
                        &IID_IUnknown, (LPVOID)&Interface)))
                    {
                        for (j = 0; j < InterfaceList.cEntries; j++) {
                            Interface->lpVtbl->QueryInterface(Interface, &InterfaceList.List[j].iid, &TestObject);
                            if (TestObject != NULL) {
                                TestObject->lpVtbl->Release(TestObject);

                                RtlSecureZeroMemory(&Data, sizeof(Data));
                                Data.DataType = UacCOMDataInterfaceType;
                                Data.Name = InterfaceList.List[j].szInterfaceName;
                                Data.Clsid = clsid;
                                Data.IID = InterfaceList.List[j].iid;
                                OutputCallback((UAC_REGISTRY_DATA*)&Data);
                            }
                        }
                        Interface->lpVtbl->Release(Interface);
                    }
            }
        }
    }
    __finally {

        if (hKey)
            RegCloseKey(hKey);

        if (lpValue)
            HeapFree(GetProcessHeap(), 0, lpValue);

        if (InterfaceList.List)
            HeapFree(GetProcessHeap(), 0, InterfaceList.List);

        CoUninitialize();
    }
}

/*
* CoListInformation
*
* Purpose:
*
* Scan registry looking for autoelevated COM.
*
*/
VOID CoListInformation(
    _In_ REGCALLBACK OutputCallback
)
{
    //
    // AutoApproval COM list added since RS1.
    //
    if (g_VerboseOutput) CopScanAutoApprovalList(OutputCallback);

    CopScanRegistry(HKEY_CLASSES_ROOT, OutputCallback);
}
