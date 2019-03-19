/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2019
*
*  TITLE:       SIMDA.H
*
*  VERSION:     3.17
*
*  DATE:        18 Mar 2019
*
*  Prototypes and definitions for Simda method.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

DWORD WINAPI ucmMasqueradedAlterObjectSecurityCOM(
    _In_ LPWSTR lpTargetObject,
    _In_ SECURITY_INFORMATION SecurityInformation,
    _In_ SE_OBJECT_TYPE ObjectType,
    _In_ LPWSTR NewSddl);

NTSTATUS ucmSimdaTurnOffUac(
    VOID);
