/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2021
*
*  TITLE:       COMOBJ.C
*
*  VERSION:     1.51
*
*  DATE:        31 Oct 2021
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
    _In_ OUTPUTCALLBACK OutputCallback,
    _In_ INTERFACE_INFO_LIST *InterfaceList);

/*
* CopRunOutputCallbackForInterface
*
* Purpose:
*
* Output interface information.
*
*/
VOID CopRunOutputCallbackForInterface(
    _In_ ULONG DataType,
    _In_ INTERFACE_INFO *Interface,
    _In_ CLSID clsid,
    _In_ OUTPUTCALLBACK OutputCallback
)
{
    UAC_INTERFACE_DATA Data;

    RtlSecureZeroMemory(&Data, sizeof(Data));
    Data.DataType = DataType;
    Data.Name = Interface->szInterfaceName;
    Data.Clsid = clsid;
    Data.IID = Interface->iid;
    OutputCallback((PVOID)&Data);
}

/*
* CopLocateInterfaceByCLSID
*
* Purpose:
*
* Search for interface by CLSID.
*
*/
INTERFACE_INFO* CopLocateInterfaceByCLSID(
    _In_ INTERFACE_INFO_LIST *InterfaceList,
    _In_ CLSID clsid
)
{
    IUnknown *Interface = NULL;
    IUnknown *TestObject = NULL;

    ULONG i;

    INTERFACE_INFO* Result = NULL;

    if (SUCCEEDED(CoCreateInstance(&clsid, NULL, CLSCTX_INPROC_SERVER,
        &IID_IUnknown, (LPVOID)&Interface)))
    {
        for (i = 0; i < InterfaceList->cEntries; i++) {
            Interface->lpVtbl->QueryInterface(Interface, &InterfaceList->List[i].iid, &TestObject);
            if (TestObject != NULL) {
                TestObject->lpVtbl->Release(TestObject);
                Result = &InterfaceList->List[i];
                break;
            }
        }
        Interface->lpVtbl->Release(Interface);
    }

    return Result;
}

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
    _In_ OUTPUTCALLBACK OutputCallback,
    _In_ INTERFACE_INFO_LIST *InterfaceList
)
{
    LRESULT lRet;
    HKEY    hSubKey = NULL, hAppIdKey = NULL, hServerObjectsKey = NULL;
    DWORD   dwDataSize, dwEnabled = 0;
    LPWSTR  lpName = NULL, lpAppId = NULL, lpAppIdName = NULL, lpLocalizedString = NULL, t = NULL, lpValue = NULL;

    ULONG   i, cValues = 0, cMaxLength = 0, cchValue;

    CLSID   clsid;

    UAC_REGISTRY_DATA Data;
    INTERFACE_INFO *LookupInterface;

    BOOLEAN VirtualFactory = FALSE;

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

                //
                // Check virtual factory.
                //
                lRet = RegOpenKeyEx(RootKey, TEXT("VirtualServerObjects"), 0, KEY_READ, &hServerObjectsKey);
                VirtualFactory = ((lRet == ERROR_SUCCESS) && (hServerObjectsKey != NULL));

                //query object name
                lpName = supReadKeyString(RootKey, TEXT(""), &dwDataSize);

                //query localized string and convert it
                dwDataSize = 0;
                t = supReadKeyString(RootKey, TEXT("LocalizedString"), &dwDataSize);
                if (t) {
                    lpLocalizedString = (LPWSTR)supHeapAlloc((SIZE_T)MAX_PATH * 2);
                    if (lpLocalizedString) {
                        SHLoadIndirectString(t, lpLocalizedString, MAX_PATH, NULL);
                    }
                    supHeapFree(t);
                }

                //check if AppId present
                dwDataSize = 0;
                t = supReadKeyString(RootKey, TEXT("AppId"), &dwDataSize);
                if (t) {
                    lpAppId = (LPWSTR)supHeapAlloc((SIZE_T)dwDataSize + 32);
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
                    supHeapFree(t);
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

                Data.Key = (LPWSTR)supQueryKeyName(RootKey, NULL);

                if (VirtualFactory)
                    Data.DataType = UacCOMDataVirtualFactory;
                else
                    Data.DataType = UacCOMDataCommonType;

                OutputCallback((PVOID)&Data);

                if (Data.Key) {
                    supHeapFree(Data.Key);
                }

                //
                // Output virtual server objects.
                //
                if (VirtualFactory) {

                    lRet = RegQueryInfoKey(hServerObjectsKey, NULL, NULL, NULL, NULL, NULL, NULL,
                        &cValues, &cMaxLength, NULL, NULL, NULL);

                    if (lRet == ERROR_SUCCESS) {

                        cMaxLength = (DWORD)((cMaxLength + 1) * sizeof(WCHAR));
                        lpValue = (LPWSTR)supHeapAlloc(cMaxLength);
                        if (lpValue) {

                            for (i = 0; i < cValues; i++) {
                                cchValue = (DWORD)(cMaxLength / sizeof(WCHAR));
                                if (RegEnumValue(hServerObjectsKey, i, lpValue, &cchValue, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {

                                    if (CLSIDFromString(lpValue, &clsid) == S_OK) {
                                        LookupInterface = CopLocateInterfaceByCLSID(InterfaceList, clsid);
                                        if (LookupInterface) {

                                            CopRunOutputCallbackForInterface(
                                                UacCOMDataInterfaceTypeVF,
                                                LookupInterface,
                                                clsid,
                                                OutputCallback);

                                        }
                                    }
                                }
                            }

                            supHeapFree(lpValue);
                        }
                    }
                    RegCloseKey(hServerObjectsKey);
                }


            } while (FALSE);

            if (lpAppIdName)
                supHeapFree(lpAppIdName);

            if (lpAppId != NULL)
                supHeapFree(lpAppId);

            if (lpName != NULL)
                supHeapFree(lpName);
        }
        else {
            CopScanRegistry(hSubKey, OutputCallback, InterfaceList);
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
    _In_ OUTPUTCALLBACK OutputCallback,
    _In_ INTERFACE_INFO_LIST *InterfaceList
)
{
    BOOL    bElevation = FALSE;
    LRESULT lRet;
    DWORD   dwcbName = 0, cch;
    LPTSTR  lpKeyName = NULL;

    do {
        dwcbName = 32 * 1024;
        lpKeyName = (LPTSTR)supHeapAlloc(dwcbName);
        if (lpKeyName == NULL)
            break;

        cch = dwcbName / sizeof(WCHAR);
        lRet = RegEnumKeyEx(hKey, dwKeyIndex,
            lpKeyName, &cch, NULL, NULL, NULL, NULL);
        if (lRet == ERROR_MORE_DATA) {
            dwcbName *= 2;
            supHeapFree(lpKeyName);
            lpKeyName = NULL;
            continue;
        }
        if (lRet == ERROR_SUCCESS) {
            //skip wow64 shit
            if (_strcmpi(lpKeyName, TEXT("Wow6432Node")) == 0)
                break;

            if (_strcmpi(lpKeyName, TEXT("Elevation")) == 0)
                bElevation = TRUE;

            CopQuerySubKey(hKey, lpKeyName, bElevation, OutputCallback, InterfaceList);
        }

    } while (lRet == ERROR_MORE_DATA);

    if (lpKeyName != NULL)
        supHeapFree(lpKeyName);

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
    _In_ OUTPUTCALLBACK OutputCallback,
    _In_ INTERFACE_INFO_LIST *InterfaceList
)
{
    HKEY    hKey = NULL;
    LRESULT lRet;
    DWORD   dwcSubKeys = 0, i;

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
            CopEnumSubKey(hKey, i, OutputCallback, InterfaceList);

    } while (FALSE);

    if (hKey != NULL)
        RegCloseKey(hKey);
}

/*
* CoEnumInterfaces
*
* Purpose:
*
* Remember list of available interfaces, excluding IUnknown.
*
*/
BOOL CoEnumInterfaces(
    _Inout_ INTERFACE_INFO_LIST *InterfaceList
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

        infoBuffer = (INTERFACE_INFO*)supHeapAlloc(cSubKeys * sizeof(INTERFACE_INFO));
        if (infoBuffer == NULL)
            __leave;

        cMaxLength = (DWORD)((cMaxLength + 1) * sizeof(WCHAR));
        lpKeyName = (LPWSTR)supHeapAlloc(cMaxLength);
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
            supHeapFree(lpKeyName);
    }

    return bResult;
}

/*
* CoScanAutoApprovalList
*
* Purpose:
*
* Query list of autoapproval COM objects used by OOBE ICreateObject interface.
*
*/
VOID CoScanBrokerApprovalList(
    _In_ OUTPUTCALLBACK OutputCallback,
    _In_ INTERFACE_INFO_LIST *InterfaceList
)
{
    HKEY    hKey = NULL, hSubKey = NULL;
    LRESULT lRet;
    LPWSTR  lpSubKey = NULL;
    DWORD   i, cSubKeys = 0, cMaxLength = 0, cchSubKey, dwType, dwData, cbData;

    CLSID clsid;

    INTERFACE_INFO *LookupInterface;

    __try {

        lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, T_UAC_BROKER_APPROVAL_LIST, 0, KEY_READ, &hKey);
        if (lRet != ERROR_SUCCESS)
            __leave;

        lRet = RegQueryInfoKey(hKey, NULL, NULL, NULL, &cSubKeys, &cMaxLength, NULL,
            NULL, NULL, NULL, NULL, NULL);
        if ((lRet != ERROR_SUCCESS) || (cSubKeys == 0))
            __leave;

        cMaxLength = (DWORD)((cMaxLength + 1) * sizeof(WCHAR));
        lpSubKey = (LPWSTR)supHeapAlloc(cMaxLength);
        if (lpSubKey == NULL)
            __leave;

        for (i = 0; i < cSubKeys; i++) {
            cchSubKey = (DWORD)(cMaxLength / sizeof(WCHAR));
            if (RegEnumKeyEx(hKey, i, lpSubKey, &cchSubKey, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {

                //
                // Check AutoElevationAllowed
                //
                if (RegOpenKey(hKey, lpSubKey, &hSubKey) == ERROR_SUCCESS) {

                    dwType = REG_DWORD;
                    cbData = sizeof(DWORD);
                    dwData = 0;

                    if (RegQueryValueEx(hSubKey,
                        TEXT("AutoElevationAllowed"),
                        0,
                        &dwType,
                        (LPBYTE)&dwData,
                        &cbData) == ERROR_SUCCESS)
                    {
                        if ((cbData == sizeof(DWORD)) && (dwData == 1)) {

                            //
                            // Find interface and output to the callback.
                            //
                            if (CLSIDFromString(lpSubKey, &clsid) == S_OK) {
                                LookupInterface = CopLocateInterfaceByCLSID(InterfaceList, clsid);
                                if (LookupInterface) {

                                    CopRunOutputCallbackForInterface(
                                        UacCOMDataInterfaceType,
                                        LookupInterface,
                                        clsid,
                                        OutputCallback);
                                }
                            }
                        }
                    }

                    RegCloseKey(hSubKey);
                }

            }
        }

    }
    __finally {

        if (hKey)
            RegCloseKey(hKey);

        if (lpSubKey)
            supHeapFree(lpSubKey);

    }
}

/*
* CoScanAutoApprovalList
*
* Purpose:
*
* Query list of autoapproval COM objects.
* This key was added in RS1 specially for consent.exe comfort
*
*/
VOID CoScanAutoApprovalList(
    _In_ OUTPUTCALLBACK OutputCallback,
    _In_ INTERFACE_INFO_LIST *InterfaceList
)
{
    HKEY    hKey = NULL;
    LRESULT lRet;
    LPWSTR  lpValue = NULL;
    DWORD   i, cValues = 0, cMaxLength = 0, cchValue;

    CLSID clsid;

    INTERFACE_INFO *LookupInterface;

    __try {

        lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, T_UAC_COM_AUTOAPPROVAL_LIST, 0, KEY_READ, &hKey);
        if (lRet != ERROR_SUCCESS)
            __leave;

        lRet = RegQueryInfoKey(hKey, NULL, NULL, NULL, NULL, NULL, NULL,
            &cValues, &cMaxLength, NULL, NULL, NULL);
        if ((lRet != ERROR_SUCCESS) || (cValues == 0))
            __leave;

        cMaxLength = (DWORD)((cMaxLength + 1) * sizeof(WCHAR));
        lpValue = (LPWSTR)supHeapAlloc(cMaxLength);
        if (lpValue == NULL)
            __leave;

        for (i = 0; i < cValues; i++) {
            cchValue = (DWORD)(cMaxLength / sizeof(WCHAR));
            if (RegEnumValue(hKey, i, lpValue, &cchValue, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                if (CLSIDFromString(lpValue, &clsid) == S_OK) {
                    LookupInterface = CopLocateInterfaceByCLSID(InterfaceList, clsid);
                    if (LookupInterface) {

                        CopRunOutputCallbackForInterface(
                            UacCOMDataInterfaceType,
                            LookupInterface,
                            clsid,
                            OutputCallback);

                    }
                }
            }
        }
    }
    __finally {

        if (hKey)
            RegCloseKey(hKey);

        if (lpValue)
            supHeapFree(lpValue);

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
    _In_ OUTPUTCALLBACK OutputCallback,
    _In_ INTERFACE_INFO_LIST *InterfaceList
)
{
    if (OutputCallback) {
        CopScanRegistry(HKEY_CLASSES_ROOT, OutputCallback, InterfaceList);
    }
}
