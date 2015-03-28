/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2015, translated from Microsoft Documentation
*
*  TITLE:       APPHELP.H
*
*  VERSION:     1.10
*
*  DATE:        27 Mar 2015
*
*  Application Compatibility Helper routines and definitions.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

typedef DWORD TAGID;
typedef DWORD TAGREF;
typedef DWORD TAG;
typedef DWORD INDEXID;
typedef PVOID PDB;
typedef HANDLE HSDB;

#define TAGID_ROOT 0
#define TAGID_NULL 0

#define TAG_TYPE_NULL		0x1000
#define TAG_TYPE_BYTE		0x2000
#define TAG_TYPE_WORD		0x3000
#define TAG_TYPE_DWORD		0x4000
#define TAG_TYPE_QWORD		0x5000
#define TAG_TYPE_STRINGREF	0x6000
#define TAG_TYPE_LIST		0x7000
#define TAG_TYPE_STRING		0x8000
#define TAG_TYPE_BINARY		0x9000

#define TAG_DATABASE (0x1 | TAG_TYPE_LIST) 
#define TAG_NAME (0x1 | TAG_TYPE_STRINGREF) 
#define TAG_OS_PLATFORM (0x23 | TAG_TYPE_DWORD)  
#define TAG_DATABASE_ID (0x7 | TAG_TYPE_BINARY)  
#define TAG_LIBRARY (0x2 | TAG_TYPE_LIST) 
#define TAG_APP_NAME (0x6 | TAG_TYPE_STRINGREF)
#define TAG_EXE (0x7 | TAG_TYPE_LIST)
#define TAG_VENDOR (0x5 | TAG_TYPE_STRINGREF)
#define TAG_EXE_ID (0x4 | TAG_TYPE_BINARY)
#define TAG_MATCHING_FILE (0x8 | TAG_TYPE_LIST)
#define TAG_COMPANY_NAME (0x9 | TAG_TYPE_STRINGREF)
#define TAG_INTERNAL_NAME (0x15 | TAG_TYPE_STRINGREF)
#define TAG_SHIM_REF (0x9| TAG_TYPE_LIST)
#define TAG_COMMAND_LINE (0x8 | TAG_TYPE_STRINGREF)

typedef enum _PATH_TYPE {
	DOS_PATH,
	NT_PATH
} PATH_TYPE;

typedef PDB(WINAPI *pfnSdbCreateDatabase)(LPCWSTR pwszPath, PATH_TYPE eType);
typedef BOOL(WINAPI *pfnSdbWriteDWORDTag)(PDB pdb, TAG tTag, DWORD dwData);
typedef BOOL(WINAPI *pfnSdbWriteStringTag)(PDB pdb, TAG tTag, LPCWSTR pwszData);
typedef BOOL(WINAPI *pfnSdbWriteBinaryTag)(PDB pdb, TAG tTag, PBYTE pBuffer, DWORD dwSize);
typedef BOOL(WINAPI *pfnSdbEndWriteListTag)(PDB pdb, TAGID tiList);
typedef TAGID(WINAPI *pfnSdbBeginWriteListTag)(PDB pdb, TAG tTag);
typedef void (WINAPI *pfnSdbCloseDatabaseWrite)(PDB pdb);
