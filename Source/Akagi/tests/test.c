/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017
*
*  TITLE:       TEST.C
*
*  VERSION:     2.57
*
*  DATE:        28 Feb 2017
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"


#define T_REGISTRY_USER         L"\\REGISTRY\\USER\\"
#define REGISTRY_USER_LENGTH    sizeof(T_REGISTRY_USER) - sizeof(WCHAR)

#define T_AKAGI_KEY             L"Software\\Akagi"
#define AKAGI_KEY_LENGTH        sizeof(T_AKAGI_KEY) - sizeof(WCHAR)


typedef NTSTATUS(NTAPI *PENUMOBJECTSCALLBACK)(POBJECT_DIRECTORY_INFORMATION Entry, PVOID CallbackParam);

typedef struct _OBJSCANPARAM {
    PWSTR Buffer;
    SIZE_T BufferSize;
} OBJSCANPARAM, *POBJSCANPARAM;

/*
* supEnumSystemObjects
*
* Purpose:
*
* Lookup object by name in given directory.
*
*/
NTSTATUS NTAPI supEnumSystemObjects(
    _In_opt_ LPWSTR pwszRootDirectory,
    _In_opt_ HANDLE hRootDirectory,
    _In_ PENUMOBJECTSCALLBACK CallbackProc,
    _In_opt_ PVOID CallbackParam
)
{
    BOOL                cond = TRUE;
    ULONG               ctx, rlen;
    HANDLE              hDirectory = NULL;
    NTSTATUS            status;
    NTSTATUS            CallbackStatus;
    OBJECT_ATTRIBUTES   attr;
    UNICODE_STRING      sname;

    POBJECT_DIRECTORY_INFORMATION	objinf;

    if (CallbackProc == NULL) {
        return STATUS_INVALID_PARAMETER_4;
    }

    status = STATUS_UNSUCCESSFUL;

    // We can use root directory.
    if (pwszRootDirectory != NULL) {
        RtlSecureZeroMemory(&sname, sizeof(sname));
        RtlInitUnicodeString(&sname, pwszRootDirectory);
        InitializeObjectAttributes(&attr, &sname, OBJ_CASE_INSENSITIVE, NULL, NULL);
        status = NtOpenDirectoryObject(&hDirectory, DIRECTORY_QUERY, &attr);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }
    else {
        if (hRootDirectory == NULL) {
            return STATUS_INVALID_PARAMETER_2;
        }
        hDirectory = hRootDirectory;
    }

    // Enumerate objects in directory.
    ctx = 0;
    do {

        rlen = 0;
        status = NtQueryDirectoryObject(hDirectory, NULL, 0, TRUE, FALSE, &ctx, &rlen);
        if (status != STATUS_BUFFER_TOO_SMALL)
            break;

        objinf = RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, rlen);
        if (objinf == NULL)
            break;

        status = NtQueryDirectoryObject(hDirectory, objinf, rlen, TRUE, FALSE, &ctx, &rlen);
        if (!NT_SUCCESS(status)) {
            RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, objinf);
            break;
        }

        CallbackStatus = CallbackProc(objinf, CallbackParam);

        RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, objinf);

        if (NT_SUCCESS(CallbackStatus)) {
            status = STATUS_SUCCESS;
            break;
        }

    } while (cond);

    if (hDirectory != NULL) {
        NtClose(hDirectory);
    }
    return status;
}

/*
* supDetectObjectCallback
*
* Purpose:
*
* Comparer callback routine used in objects enumeration.
*
*/
NTSTATUS NTAPI supDetectObjectCallback(
    _In_ POBJECT_DIRECTORY_INFORMATION Entry,
    _In_ PVOID CallbackParam
)
{
    SIZE_T BufferSize;
    POBJSCANPARAM Param = (POBJSCANPARAM)CallbackParam;

    if (Entry == NULL) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (CallbackParam == NULL) {
        return STATUS_INVALID_PARAMETER_2;
    }

    if (Entry->Name.Buffer) {

        BufferSize = Entry->Name.Length + sizeof(UNICODE_NULL);
        Param->Buffer = RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, BufferSize);
        if (Param->Buffer) {
            Param->BufferSize = BufferSize;
            _strncpy(
                Param->Buffer, Param->BufferSize / sizeof(WCHAR),
                Entry->Name.Buffer, Entry->Name.Length / sizeof(WCHAR)
            );
            return STATUS_SUCCESS;
        }
    }
    return STATUS_UNSUCCESSFUL;
}


VOID UACMeTest()
{
    OBJSCANPARAM Param;
    NTSTATUS status;
    LPWSTR lpszParamKey = NULL;
    SIZE_T memIO;

    ucmSetupAkagiLink();

    Param.Buffer = NULL;
    Param.BufferSize = 0;

    status = supEnumSystemObjects(L"\\Rpc Control\\Akagi", NULL,
        supDetectObjectCallback, &Param);
    if (!NT_SUCCESS(status))
        return;


    if ((Param.Buffer == NULL) || (Param.BufferSize == 0))
        return;

    memIO = MAX_PATH + Param.BufferSize + REGISTRY_USER_LENGTH + AKAGI_KEY_LENGTH;
    lpszParamKey = RtlAllocateHeap(GetProcessHeap(), HEAP_ZERO_MEMORY, memIO);
    if (lpszParamKey == NULL)
        return;

    _strcpy_w(lpszParamKey, T_REGISTRY_USER);
    _strcat_w(lpszParamKey, Param.Buffer);
    _strcat_w(lpszParamKey, L"\\");
    _strcat_w(lpszParamKey, T_AKAGI_KEY);

}
