/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2017
*
*  TITLE:       MAKECAB.C
*
*  VERSION:     2.70
*
*  DATE:        25 Mar 2017
*
*  Simplified Cabinet file support for makecab utility replacement.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "makecab.h"

#pragma comment(lib, "cabinet.lib")

/*
** CAB Callbacks START
*/

LPVOID DIAMONDAPI fnFCIALLOC(
    ULONG cb
)
{
    return supHeapAlloc((SIZE_T)cb);
}

VOID DIAMONDAPI fnFCIFREE(
    VOID HUGE *lpMem
)
{
    if (lpMem) supHeapFree((PVOID)lpMem);
}

INT_PTR DIAMONDAPI fnFCIOPEN(
    LPSTR pszFile,
    int oflag,
    int pmode,
    int FAR *err,
    void FAR *pv
)
{
    HANDLE hFile = NULL;
    DWORD dwDesiredAccess = 0;
    DWORD dwCreationDisposition = 0;

    UNREFERENCED_PARAMETER(pv);
    UNREFERENCED_PARAMETER(pmode);

    if (oflag & _O_RDWR) {
        dwDesiredAccess = GENERIC_READ | GENERIC_WRITE;
    }
    else if (oflag & _O_WRONLY) {
        dwDesiredAccess = GENERIC_WRITE;
    }
    else {
        dwDesiredAccess = GENERIC_READ;
    }

    if (oflag & _O_CREAT) {
        dwCreationDisposition = CREATE_ALWAYS;
    }
    else {
        dwCreationDisposition = OPEN_EXISTING;
    }

    hFile = CreateFileA(pszFile,
        dwDesiredAccess,
        FILE_SHARE_READ,
        NULL,
        dwCreationDisposition,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        *err = GetLastError();
    }

    return (INT_PTR)hFile;
}

UINT DIAMONDAPI fnFCIREAD(
    INT_PTR hf,
    void FAR *memory,
    UINT cb,
    int FAR *err,
    void FAR *pv
)
{
    DWORD dwBytesRead = 0;

    UNREFERENCED_PARAMETER(pv);

    if (ReadFile((HANDLE)hf, memory, cb, &dwBytesRead, NULL) == FALSE) {
        dwBytesRead = (DWORD)-1;
        if (err) {
            *err = GetLastError();
        }
    }
    return dwBytesRead;
}

UINT DIAMONDAPI fnFCIWRITE(
    INT_PTR hf,
    void FAR *memory,
    UINT cb,
    int FAR *err,
    void FAR *pv
)
{
    DWORD dwBytesWritten = 0;

    UNREFERENCED_PARAMETER(pv);

    if (WriteFile((HANDLE)hf, memory, cb, &dwBytesWritten, NULL) == FALSE) {
        dwBytesWritten = (DWORD)-1;
        if (err) {
            *err = GetLastError();
        }
    }
    return dwBytesWritten;
}

int DIAMONDAPI fnFCICLOSE(
    INT_PTR hf,
    int FAR *err,
    void FAR *pv
)
{
    INT iResult = 0;

    UNREFERENCED_PARAMETER(pv);

    if (CloseHandle((HANDLE)hf) == FALSE) {
        if (err) {
            *err = GetLastError();
        }
        iResult = -1;
    }
    return iResult;
}

long DIAMONDAPI fnFCISEEK(
    INT_PTR hf,
    long dist,
    int seektype,
    int FAR *err,
    void FAR *pv
)
{
    INT iResult = 0;
   // LARGE_INTEGER mdist, ndist;

    UNREFERENCED_PARAMETER(pv);

   /* 
    sdist.LowPart = dist;
    mdist.HighPart = 0;
    ndist.LowPart = 0;
    ndist.HighPart = 0;
    if (!SetFilePointerEx((HANDLE)hf, mdist, &ndist, seektype)) {
        if (err) *err = GetLastError();
    }
    return ndist.LowPart;
    */

    iResult = SetFilePointer((HANDLE)hf, dist, NULL, seektype);
    if (iResult == -1) {
        if (err) {
            *err = GetLastError();
        }
    }
    return iResult;
}

int DIAMONDAPI fnFCIDELETE(
    LPSTR pszFile,
    int FAR *err,
    void FAR *pv
)
{
    INT iResult = 0;

    UNREFERENCED_PARAMETER(pv);

    if (DeleteFileA(pszFile) == FALSE) {
        if (err) {
            *err = GetLastError();
        }
        iResult = -1;
    }
    return iResult;
}

long DIAMONDAPI fnFCISTATUS(
    UINT typeStatus,
    ULONG cb1,
    ULONG cb2,
    void FAR *pv
)
{
    UNREFERENCED_PARAMETER(typeStatus);
    UNREFERENCED_PARAMETER(cb1);
    UNREFERENCED_PARAMETER(cb2);
    UNREFERENCED_PARAMETER(pv);

    return 0; //not implemented
}

int DIAMONDAPI fnFCIFILEPLACED(
    PCCAB pccab,
    LPSTR pszFile,
    long cbFile,
    BOOL fContinuation,
    void FAR *pv
)
{
    UNREFERENCED_PARAMETER(pccab);
    UNREFERENCED_PARAMETER(pszFile);
    UNREFERENCED_PARAMETER(cbFile);
    UNREFERENCED_PARAMETER(fContinuation);
    UNREFERENCED_PARAMETER(pv);

    return 0; //not implemented
}

INT_PTR DIAMONDAPI fnFCIGETOPENINFO(
    LPSTR pszName,
    USHORT *pdate,
    USHORT *ptime,
    USHORT *pattribs,
    int FAR *err,
    void FAR *pv
)
{
    HANDLE hFile;
    FILETIME fileTime;
    BY_HANDLE_FILE_INFORMATION fileInfo;

    hFile = (HANDLE)fnFCIOPEN(pszName, _O_RDONLY, 0, err, pv);

    if (hFile != INVALID_HANDLE_VALUE)
    {
        if (GetFileInformationByHandle(hFile, &fileInfo)
            && FileTimeToLocalFileTime(&fileInfo.ftCreationTime, &fileTime)
            && FileTimeToDosDateTime(&fileTime, pdate, ptime))
        {
            *pattribs = (USHORT)fileInfo.dwFileAttributes;
            *pattribs &= (
                FILE_ATTRIBUTE_READONLY |
                FILE_ATTRIBUTE_HIDDEN |
                FILE_ATTRIBUTE_SYSTEM |
                FILE_ATTRIBUTE_ARCHIVE
                );
        }
        else
        {
            fnFCICLOSE((INT_PTR)hFile, err, pv);
            hFile = INVALID_HANDLE_VALUE;
        }
    }

    return (INT_PTR)hFile;
}

BOOL DIAMONDAPI fnFCIGETTEMPFILE(
    char *pszTempName,
    int cbTempName,
    void FAR *pv
)
{
    BOOL bSucceeded = FALSE;
    SIZE_T cch;
    CHAR szTempPath[MAX_PATH];
    CHAR szTempFile[MAX_PATH];

    UNREFERENCED_PARAMETER(pv);

    RtlSecureZeroMemory(szTempPath, sizeof(szTempPath));
    RtlSecureZeroMemory(szTempFile, sizeof(szTempFile));

    if (GetTempPathA(MAX_PATH, szTempPath) != 0) {
        if (GetTempFileNameA(szTempPath, "ucm", 0, szTempFile) != 0) {
            DeleteFileA(szTempFile);
            cch = (SIZE_T)(cbTempName / sizeof(CHAR));
            _strncpy_a(pszTempName, cch, szTempFile, _strlen_a(szTempFile));
            bSucceeded = TRUE;
        }
    }

    return bSucceeded;
}

BOOL DIAMONDAPI fnFCIGETNEXTCABINET(
    PCCAB  pccab,
    ULONG  cbPrevCab,
    void FAR *pv
)
{
    UNREFERENCED_PARAMETER(pccab);
    UNREFERENCED_PARAMETER(cbPrevCab);
    UNREFERENCED_PARAMETER(pv);

    return FALSE;
}

/*
** CAB Callbacks END
*/

/*
* cabCreate
*
* Purpose:
*
* Initialize cabinet class object.
*
*/
CABDATA *cabCreate(
    _In_ LPWSTR lpszCabName
)
{
    PCABDATA pCabinet;
    CHAR szCab[CB_MAX_CABINET_NAME];

    if (lpszCabName == NULL) {
        return NULL;
    }

    RtlSecureZeroMemory(szCab, sizeof(szCab));
    if (WideCharToMultiByte(CP_ACP, 0, lpszCabName, -1, szCab, CB_MAX_CABINET_NAME - 2, 0, NULL) == 0) {
        return NULL;
    }

    pCabinet = (PCABDATA)supHeapAlloc(sizeof(CABDATA));
    if (pCabinet == NULL)
        return NULL;

    _strcpy_a(pCabinet->cab.szCab, szCab); //Full name with path or only name (current folder then).

    pCabinet->cab.cb = 0x7FFFFFFF; //Maximum cabinet size in bytes.

    pCabinet->hfci = FCICreate(
        &pCabinet->erf,
        fnFCIFILEPLACED,
        fnFCIALLOC,
        fnFCIFREE,
        fnFCIOPEN,
        fnFCIREAD,
        fnFCIWRITE,
        fnFCICLOSE,
        fnFCISEEK,
        fnFCIDELETE,
        fnFCIGETTEMPFILE,
        &pCabinet->cab,
        NULL);

    if (pCabinet->hfci == NULL) {
        supHeapFree(pCabinet);
        pCabinet = NULL;
    }
    return pCabinet;
}

/*
* cabAddFile
*
* Purpose:
*
* Insert given file to the previously initialized cabinet object.
*
*/
BOOL cabAddFile(
    _In_ CABDATA *Cabinet,
    _In_ LPWSTR lpszFileName,
    _In_ LPWSTR lpszInternalName
)
{
    BOOL bResult = FALSE, cond = FALSE;
    CHAR szFileName[CB_MAX_FILENAME];
    CHAR szInternalName[CB_MAX_FILENAME];

    do {

        if (Cabinet == NULL) {
            break;
        }

        //convert filename to ansi
        RtlSecureZeroMemory(szFileName, sizeof(szFileName));
        if (WideCharToMultiByte(CP_ACP, 0, lpszFileName, -1, szFileName, CB_MAX_FILENAME - 2, 0, NULL) == 0) {
            break;
        }
        //convert internal name to ansi
        RtlSecureZeroMemory(szInternalName, sizeof(szInternalName));
        if (WideCharToMultiByte(CP_ACP, 0, lpszInternalName, -1, szInternalName, CB_MAX_FILENAME - 2, 0, NULL) == 0) {
            break;
        }

        bResult = FCIAddFile(Cabinet->hfci, (char*)szFileName, (char*)szInternalName, FALSE,
            fnFCIGETNEXTCABINET, fnFCISTATUS, fnFCIGETOPENINFO, tcompTYPE_NONE /*tcompTYPE_MSZIP*/);

    } while (cond);

    return bResult;
}

/*
* cabClose
*
* Purpose:
*
* Flush file and destroy cabinet class.
*
*/
VOID cabClose(
    _In_ CABDATA *Cabinet
)
{
    if (Cabinet == NULL) {
        return;
    }

    FCIFlushCabinet(
        Cabinet->hfci,
        FALSE,
        fnFCIGETNEXTCABINET,
        fnFCISTATUS
    );

    FCIDestroy(Cabinet->hfci);
    supHeapFree(Cabinet);
}
