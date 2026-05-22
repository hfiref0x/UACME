/*++

Module Name:

	utils.h

Abstract:

	This file contains definitions of support routines.

--*/

HANDLE GetExplorerHandle(
	VOID
	);

PVOID AllocAndCopyMemory(
	CONST VOID *pLocalBuffer,
	SIZE_T bufferSize,
	BOOL bExecutable
	);

WCHAR* AllocAndCopyStringW(
	CONST WCHAR *szLocalString
	);

CHAR* AllocAndCopyStringA(
	CONST CHAR *szLocalString
	);

wchar_t *_strendW(const wchar_t *s);

BOOL IsWow64(
	VOID
	);