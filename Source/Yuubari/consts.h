/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2018
*
*  TITLE:       CONSTS.H
*
*  VERSION:     1.32
*
*  DATE:        25 Aug 2018
*
*  Global consts definition file.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#define YUUBARI_MIN_SUPPORTED_NT_BUILD 7600
#define YUUBARI_MAX_SUPPORTED_NT_BUILD 17713

#define T_UAC_COM_AUTOAPPROVAL_LIST    TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\UAC\\COMAutoApprovalList") //RS1+
#define T_UAC_SETTINGS_KEY             TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System")
#define T_UAC_PROMPT_BEHAVIOR          TEXT("ConsentPromptBehaviorAdmin")
#define T_UAC_SECURE_DESKTOP           TEXT("PromptOnSecureDesktop")
#define T_UAC_RESTRICTED_AUTOAPPROVE   TEXT("EnableRestrictedAutoApprove") //RS1+
#define T_UAC_AUTOAPPROVEIC            TEXT("EnableAutoApproveIntegrityContinuity") //RS2+, AipAutoApproveHardeningPolicy
#define T_UAC_AUTOAPPROVEMP            TEXT("AutoApproveMitigationPolicy") //RS2+, AipAutoApproveHardeningPolicy
#define T_UAC_AUTOAPPROVEHARDCLAIMS    TEXT("AutoApproveHardeningClaims") //RS2+, AipMarkAutoApprovedToken(TokenSecurityAttributes)
#define T_UAC_ENABLESECUREUIPATHS      TEXT("EnableSecureUIAPaths") //RS2+, Only elevate UIAccess applications that are installed in secure locations

#define T_FLAG_ELEVATION_ENABLED       TEXT("ElevationEnabled")
#define T_FLAG_VIRTUALIZATION_ENABLED  TEXT("VirtualizationEnabled")
#define T_FLAG_INSTALLERDETECT_ENABLED TEXT("InstallerDetectEnabled")

#define T_PROGRAM_NAME                 TEXT("Yuubari")
#define T_PROGRAM_TITLE                TEXT("[UacView] UAC information gathering tool, v1.3.2 (Aug 25, 2018)\n")

#define T_HELP	TEXT("Optional parameters to execute: \n\n\r\
YUUBARI [/v] \n\n\r\
  /v - produce verbose output.")
