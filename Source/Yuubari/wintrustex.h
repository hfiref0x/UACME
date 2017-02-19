#pragma once

typedef enum _SIGNATURE_INFO_TYPE {
    SIT_UNKNOWN = 0x0,
    SIT_AUTHENTICODE = 0x1,
    SIT_CATALOG = 0x2
} SIGNATURE_INFO_TYPE;

typedef enum _SIGNATURE_INFO_FLAGS {
    SIF_AUTHENTICODE_SIGNED = 0x1,
    SIF_CATALOG_SIGNED = 0x2,
    SIF_VERSION_INFO = 0x4,
    SIF_CHECK_OS_BINARY = 0x800,
    SIF_BASE_VERIFICATION = 0x1000,
    SIF_CATALOG_FIRST = 0x2000,
    SIF_MOTW = 0x4000
} SIGNATURE_INFO_FLAGS;

typedef enum _SIGNATURE_STATE {
    SIGNATURE_STATE_UNSIGNED_MISSING = 0x0,
    SIGNATURE_STATE_UNSIGNED_UNSUPPORTED = 0x1,
    SIGNATURE_STATE_UNSIGNED_POLICY = 0x2,
    SIGNATURE_STATE_INVALID_CORRUPT = 0x3,
    SIGNATURE_STATE_INVALID_POLICY = 0x4,
    SIGNATURE_STATE_VALID = 0x5,
    SIGNATURE_STATE_TRUSTED = 0x6,
    SIGNATURE_STATE_UNTRUSTED = 0x7,
} SIGNATURE_STATE;

typedef struct _SIGNATURE_INFO {
    DWORD cbSize;
    SIGNATURE_STATE SignatureState;
    SIGNATURE_INFO_TYPE SignatureType;
    DWORD dwSignatureInfoAvailability;
    DWORD dwInfoAvailability;
    PWSTR pszDisplayName;
    DWORD cchDisplayName;
    PWSTR pszPublisherName;
    DWORD cchPublisherName;
    PWSTR pszMoreInfoURL;
    DWORD cchMoreInfoURL;
    LPBYTE prgbHash;
    DWORD cbHash;
    BOOL fOSBinary; //True if the item is signed as part of an operating system release
} SIGNATURE_INFO, *PSIGNATURE_INFO;

typedef LONG (WINAPI *ptrWTGetSignatureInfo)(
    LPWSTR pszFile,
    HANDLE hFile,
    SIGNATURE_INFO_FLAGS sigInfoFlags,
    SIGNATURE_INFO *siginfo,
    VOID *ppCertContext,
    VOID *phWVTStateData
);
