/************************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017, translated from Microsoft sources/debugger
*
*  TITLE:       LSA.H
*
*  VERSION:     1.00
*
*  DATE:        28 Aug 2017
*
*  Common header file for the LSA related API functions and definitions.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
************************************************************************************/
#pragma once

#define LSA_POLICY_VIEW_LOCAL_INFORMATION              0x00000001L
#define LSA_POLICY_VIEW_AUDIT_INFORMATION              0x00000002L
#define LSA_POLICY_GET_PRIVATE_INFORMATION             0x00000004L
#define LSA_POLICY_TRUST_ADMIN                         0x00000008L
#define LSA_POLICY_CREATE_ACCOUNT                      0x00000010L
#define LSA_POLICY_CREATE_SECRET                       0x00000020L
#define LSA_POLICY_CREATE_PRIVILEGE                    0x00000040L
#define LSA_POLICY_SET_DEFAULT_QUOTA_LIMITS            0x00000080L
#define LSA_POLICY_SET_AUDIT_REQUIREMENTS              0x00000100L
#define LSA_POLICY_AUDIT_LOG_ADMIN                     0x00000200L
#define LSA_POLICY_SERVER_ADMIN                        0x00000400L
#define LSA_POLICY_LOOKUP_NAMES                        0x00000800L
#define LSA_POLICY_NOTIFICATION                        0x00001000L

#define LSA_POLICY_ALL_ACCESS     (STANDARD_RIGHTS_REQUIRED         |\
                               LSA_POLICY_VIEW_LOCAL_INFORMATION    |\
                               LSA_POLICY_VIEW_AUDIT_INFORMATION    |\
                               LSA_POLICY_GET_PRIVATE_INFORMATION   |\
                               LSA_POLICY_TRUST_ADMIN               |\
                               LSA_POLICY_CREATE_ACCOUNT            |\
                               LSA_POLICY_CREATE_SECRET             |\
                               LSA_POLICY_CREATE_PRIVILEGE          |\
                               LSA_POLICY_SET_DEFAULT_QUOTA_LIMITS  |\
                               LSA_POLICY_SET_AUDIT_REQUIREMENTS    |\
                               LSA_POLICY_AUDIT_LOG_ADMIN           |\
                               LSA_POLICY_SERVER_ADMIN              |\
                               LSA_POLICY_LOOKUP_NAMES)


#define LSA_POLICY_READ           (STANDARD_RIGHTS_READ             |\
                               LSA_POLICY_VIEW_AUDIT_INFORMATION    |\
                               LSA_POLICY_GET_PRIVATE_INFORMATION)

#define LSA_POLICY_WRITE          (STANDARD_RIGHTS_WRITE            |\
                               LSA_POLICY_TRUST_ADMIN               |\
                               LSA_POLICY_CREATE_ACCOUNT            |\
                               LSA_POLICY_CREATE_SECRET             |\
                               LSA_POLICY_CREATE_PRIVILEGE          |\
                               LSA_POLICY_SET_DEFAULT_QUOTA_LIMITS  |\
                               LSA_POLICY_SET_AUDIT_REQUIREMENTS    |\
                               LSA_POLICY_AUDIT_LOG_ADMIN           |\
                               LSA_POLICY_SERVER_ADMIN)

#define LSA_POLICY_EXECUTE        (STANDARD_RIGHTS_EXECUTE          |\
                               LSA_POLICY_VIEW_LOCAL_INFORMATION    |\
                               LSA_POLICY_LOOKUP_NAMES)

typedef PVOID LSA_HANDLE, *PLSA_HANDLE;

//eqv to UNICODE_STRING
typedef struct _LSA_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING;

//eqv to OBJECT_ATTRIBUTES
typedef struct _LSA_OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PLSA_UNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} LSA_OBJECT_ATTRIBUTES, *PLSA_OBJECT_ATTRIBUTES;

typedef struct _LSA_TRUST_INFORMATION {
    LSA_UNICODE_STRING Name;
    PSID Sid;
} LSA_TRUST_INFORMATION, *PLSA_TRUST_INFORMATION;

typedef struct _LSA_REFERENCED_DOMAIN_LIST {
    ULONG Entries;
    PLSA_TRUST_INFORMATION Domains;
} LSA_REFERENCED_DOMAIN_LIST, *PLSA_REFERENCED_DOMAIN_LIST;

typedef struct _LSA_TRANSLATED_NAME {
    SID_NAME_USE Use;
    LSA_UNICODE_STRING Name;
    LONG DomainIndex;
} LSA_TRANSLATED_NAME, *PLSA_TRANSLATED_NAME;

NTSTATUS
NTAPI
LsaOpenPolicy(
    _In_opt_ PLSA_UNICODE_STRING SystemName,
    _In_ PLSA_OBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PLSA_HANDLE PolicyHandle);

NTSTATUS
NTAPI
LsaClose(
    _In_ LSA_HANDLE ObjectHandle);

NTSTATUS
NTAPI
LsaLookupSids(
    _In_  LSA_HANDLE                  PolicyHandle,
    _In_  ULONG                       Count,
    _In_  PSID                        *Sids,
    _Out_ PLSA_REFERENCED_DOMAIN_LIST *ReferencedDomains,
    _Out_ PLSA_TRANSLATED_NAME        *Names);

NTSTATUS 
NTAPI
LsaEnumerateAccountsWithUserRight(
    _In_  LSA_HANDLE          PolicyHandle,
    _In_  PLSA_UNICODE_STRING UserRights,
    _Out_ PVOID               *EnumerationBuffer,
    _Out_ PULONG              CountReturned);

NTSTATUS 
NTAPI 
LsaFreeMemory(
    _In_ PVOID Buffer);
