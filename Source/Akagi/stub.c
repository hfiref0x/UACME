/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2020
*
*  TITLE:       STUB.C
*
*  VERSION:     3.50
*
*  DATE:        14 Sep 2020
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

#ifdef KUMA_STUB
#ifndef COMPILE_AS_DLL

#pragma comment(linker, "/ENTRY:Stub_main")
VOID __cdecl Stub_main()
{
    ExitProcess(0);
}

#else

#pragma comment(linker, "/DLL /ENTRY:Stub_DllMain")
BOOL WINAPI Stub_DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD fdwReason,
    _In_ LPVOID lpvReserved
)
{
    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(fdwReason);
    UNREFERENCED_PARAMETER(lpvReserved);
    return TRUE;
}

#endif
#endif
