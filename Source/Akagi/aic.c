/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017
*
*  TITLE:       AIC.C
*
*  VERSION:     2.80
*
*  DATE:        04 Oct 2017
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

unsigned char LaunchAdminProcessSignature760x[] = {
    0xFF, 0xF3, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x81,
    0xEC, 0x30, 0x04, 0x00, 0x00
};

unsigned char LaunchAdminProcessSignature9200[] = {
    0x44, 0x89, 0x44, 0x24, 0x18, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56,
    0x41, 0x57, 0x48, 0x81, 0xEC, 0xF0, 0x03, 0x00, 0x00
};

unsigned char LaunchAdminProcessSignature9600[] = {
    0x44, 0x89, 0x4C, 0x24, 0x20, 0x44, 0x89, 0x44, 0x24, 0x18, 0x53, 0x56, 0x57, 0x41,
    0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x81, 0xEC, 0x00, 0x04, 0x00, 0x00
};

unsigned char LaunchAdminProcessSignature10240_10586[] = {
    0x40, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x81,
    0xEC, 0x30, 0x04, 0x00, 0x00
};

unsigned char LaunchAdminProcessSignature14393[] = {
    0x40, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x81,
    0xEC, 0x20, 0x04, 0x00, 0x00
};

unsigned char LaunchAdminProcessSignature_15063_16299[] = {
    0x40, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x81,
    0xEC, 0x20, 0x04, 0x00, 0x00
};

/*
* AipFindLaunchAdminProcess
*
* Purpose:
*
* Locate unexported AppInfo routine in memory by signature.
*
*/
ULONG_PTR AipFindLaunchAdminProcess(
    _In_ PULONG ErrorCode)
{
    ULONG_PTR Address = 0;
    PBYTE Pattern = NULL, ScanBase = NULL;
    DWORD PatternSize = 0, ScanSize = 0;
    IMAGE_NT_HEADERS *NtHeaders;
    LPWSTR ScanModule = NULL;

    switch (g_ctx.dwBuildNumber) {

    case 7600:
    case 7601:
        Pattern = LaunchAdminProcessSignature760x;
        PatternSize = sizeof(LaunchAdminProcessSignature760x);
        ScanModule = SHELL32_DLL;
        break;
    case 9200:
        Pattern = LaunchAdminProcessSignature9200;
        PatternSize = sizeof(LaunchAdminProcessSignature9200);
        ScanModule = SHELL32_DLL;
        break;
    case 9600:
        Pattern = LaunchAdminProcessSignature9600;
        PatternSize = sizeof(LaunchAdminProcessSignature9600);
        ScanModule = SHELL32_DLL;
        break;
    case 10240:
    case 10586:
        Pattern = LaunchAdminProcessSignature10240_10586;
        PatternSize = sizeof(LaunchAdminProcessSignature10240_10586);
        ScanModule = WINDOWS_STORAGE_DLL;
        break;
    case 14393:
        Pattern = LaunchAdminProcessSignature14393;
        PatternSize = sizeof(LaunchAdminProcessSignature14393);
        ScanModule = WINDOWS_STORAGE_DLL;
        break;
    case 15063:
    case 16299:
    default:
        Pattern = LaunchAdminProcessSignature_15063_16299;
        PatternSize = sizeof(LaunchAdminProcessSignature_15063_16299);
        ScanModule = WINDOWS_STORAGE_DLL;
        break;
    }
    
    ScanBase = (PBYTE)GetModuleHandle(ScanModule);
    if (ScanBase == NULL) {
        ScanBase = (PBYTE)LoadLibraryEx(ScanModule, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    }

    if ((ScanBase == NULL) || (Pattern == NULL)) {
        *ErrorCode = ERROR_INTERNAL_ERROR;
        return 0;
    }

    NtHeaders = RtlImageNtHeader(ScanBase);
    if (NtHeaders->OptionalHeader.SizeOfImage <= PatternSize) {
        *ErrorCode = ERROR_INTERNAL_ERROR;
        return 0;
    }

    ScanSize = NtHeaders->OptionalHeader.SizeOfImage - PatternSize;

    Address = (ULONG_PTR)supFindPattern(ScanBase, (SIZE_T)ScanSize, Pattern, (SIZE_T)PatternSize);
    if (Address == 0) {
        *ErrorCode = ERROR_PROC_NOT_FOUND;
        return 0;
    }

    *ErrorCode = ERROR_SUCCESS;

    return Address;
}

