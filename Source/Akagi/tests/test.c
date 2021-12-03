/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2021
*
*  TITLE:       TEST.C
*
*  VERSION:     3.55
*
*  DATE:        03 Mar 2021
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

VOID WINAPI TestEnumDB(
    _In_     PUSER_ASSOC_SIGNATURE Signature,
    _In_opt_ PVOID Context,
    _Inout_  BOOLEAN* StopEnumeration
)
{
    WCHAR szBuffer[MAX_PATH + 1];

    UNREFERENCED_PARAMETER(Context);

    _strcpy(szBuffer, TEXT("\r\nSign->NtBuildMin: "));
    ultostr(Signature->NtBuildMin, _strend(szBuffer));
    _strcat(szBuffer, TEXT("\r\n"));

    _strcat(szBuffer, TEXT("Sign->NtBuildMax: "));
    ultostr(Signature->NtBuildMax, _strend(szBuffer));
    _strcat(szBuffer, TEXT("\r\n"));

    _strcat(szBuffer, TEXT("Sign->PatternsCount: "));
    ultostr(Signature->PatternsCount, _strend(szBuffer));
    _strcat(szBuffer, TEXT("\r\n"));

    _strcat(szBuffer, TEXT("Sign->PatternsTable: 0x"));
    u64tohex((ULONG_PTR)Signature->PatternsTable, _strend(szBuffer));
    _strcat(szBuffer, TEXT("\r\n------------------"));

    OutputDebugString(szBuffer);

    *StopEnumeration = FALSE;
}

VOID TestEnumUAS()
{ 
    supEnumUserAssocSetDB((PSUP_UAS_ENUMERATION_CALLBACK_FUNCTION)TestEnumDB, NULL);
}

/*
* ucmTestRoutine
*
* Purpose:
*
* Test routine, can serve multiple purposes.
*
*/
BOOL ucmTestRoutine(
    _In_opt_ PVOID PayloadCode,
    _In_opt_ ULONG PayloadSize)
{
    UNREFERENCED_PARAMETER(PayloadCode);
    UNREFERENCED_PARAMETER(PayloadSize);

    //TestEnumUAS();
    supSetGlobalCompletionEvent();
    return TRUE;
}
