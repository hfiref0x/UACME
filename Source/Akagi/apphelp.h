/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2016, translated from Microsoft Documentation
*
*  TITLE:       APPHELP.H
*
*  VERSION:     2.00
*
*  DATE:        12 Nov 2015
*
*  Application Compatibility Helper routines and definitions.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef DWORD TAGID;
typedef DWORD TAGREF;
typedef DWORD TAG;
typedef DWORD INDEXID;
typedef PVOID PDB;
typedef HANDLE HSDB;

#define TAGID_ROOT 0
#define TAGID_NULL 0

#define TAG_TYPE_NULL       0x1000
#define TAG_TYPE_BYTE       0x2000
#define TAG_TYPE_WORD       0x3000
#define TAG_TYPE_DWORD      0x4000
#define TAG_TYPE_QWORD      0x5000
#define TAG_TYPE_STRINGREF  0x6000
#define TAG_TYPE_LIST       0x7000
#define TAG_TYPE_STRING     0x8000
#define TAG_TYPE_BINARY     0x9000

#define TAG_PATCH_TAGID (0x5 | TAG_TYPE_DWORD) 
#define TAG_OS_PLATFORM (0x23 | TAG_TYPE_DWORD)  

#define TAG_PATCH_BITS (0x2 | TAG_TYPE_BINARY)
#define TAG_EXE_ID (0x4 | TAG_TYPE_BINARY)
#define TAG_DATABASE_ID (0x7 | TAG_TYPE_BINARY)  

#define TAG_DATABASE (0x1 | TAG_TYPE_LIST) 
#define TAG_LIBRARY (0x2 | TAG_TYPE_LIST) 
#define TAG_PATCH (0x5 | TAG_TYPE_LIST) 
#define TAG_EXE (0x7 | TAG_TYPE_LIST)
#define TAG_MATCHING_FILE (0x8 | TAG_TYPE_LIST)
#define TAG_SHIM_REF (0x9| TAG_TYPE_LIST)
#define TAG_PATCH_REF (0xA | TAG_TYPE_LIST)

#define TAG_NAME (0x1 | TAG_TYPE_STRINGREF) 
#define TAG_VENDOR (0x5 | TAG_TYPE_STRINGREF)
#define TAG_APP_NAME (0x6 | TAG_TYPE_STRINGREF)
#define TAG_COMMAND_LINE (0x8 | TAG_TYPE_STRINGREF)
#define TAG_COMPANY_NAME (0x9 | TAG_TYPE_STRINGREF)
#define TAG_INTERNAL_NAME (0x15 | TAG_TYPE_STRINGREF)

typedef enum _PATH_TYPE {
	DOS_PATH,
	NT_PATH
} PATH_TYPE;

#define PATCH_MATCH 0x4
#define PATCH_REPLACE 0x2
#define MAX_MODULE	32

typedef struct _PATCHBITS {
	DWORD	Opcode;
	DWORD	ActionSize;
	DWORD	PatternSize;
	DWORD	RVA;
	DWORD	Reserved;
	WCHAR	ModuleName[MAX_MODULE];
	BYTE	Pattern[1];
} PATCHBITS, *PPATCHBITS;

typedef PDB(WINAPI *pfnSdbCreateDatabase)(
	_In_  LPCWSTR pwszPath,
	_In_  PATH_TYPE eType
	);

typedef void(WINAPI *pfnSdbCloseDatabaseWrite)(
	_Inout_  PDB pdb
	);

typedef TAGID(WINAPI *pfnSdbBeginWriteListTag)(
	_In_  PDB pdb,
	_In_  TAG tTag
	);

typedef BOOL(WINAPI *pfnSdbWriteStringTag)(
	_In_  PDB pdb,
	_In_  TAG tTag,
	_In_  LPCWSTR pwszData
	);

typedef BOOL(WINAPI *pfnSdbEndWriteListTag)(
	_Inout_  PDB pdb,
	_In_     TAGID tiList
	);

typedef BOOL(WINAPI *pfnSdbWriteBinaryTag)(
	_In_  PDB pdb,
	_In_  TAG tTag,
	_In_  PBYTE pBuffer,
	_In_  DWORD dwSize
	);

typedef BOOL(WINAPI *pfnSdbWriteDWORDTag)(
	_In_  PDB pdb,
	_In_  TAG tTag,
	_In_  DWORD dwData
	);

typedef BOOL(WINAPI *pfnSdbStartIndexing)(
	_In_  PDB pdb,
	_In_  INDEXID iiWhich
	);

typedef void (WINAPI *pfnSdbStopIndexing)(
	_In_  PDB pdb,
	_In_  INDEXID iiWhich
	);

typedef BOOL(WINAPI *pfnSdbCommitIndexes)(
	_Inout_  PDB pdb
	);

typedef BOOL(WINAPI *pfnSdbDeclareIndex)(
	_In_   PDB pdb,
	_In_   TAG tWhich,
	_In_   TAG tKey,
	_In_   DWORD dwEntries,
	_In_   BOOL bUniqueKey,
	_Out_  INDEXID *piiIndex
	);
