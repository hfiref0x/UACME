/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017
*
*  TITLE:       CONSTS.H
*
*  VERSION:     1.24
*
*  DATE:        21 Mar 2017
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
#define YUUBARI_MAX_SUPPORTED_NT_BUILD 15063

#define T_UAC_COM_AUTOAPPROVAL_LIST    TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\UAC\\COMAutoApprovalList") //RS1+
#define T_UAC_SETTINGS_KEY             TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System")
#define T_UAC_PROMPT_BEHAVIOR          TEXT("ConsentPromptBehaviorAdmin")
#define T_UAC_SECURE_DESKTOP           TEXT("PromptOnSecureDesktop")
#define T_UAC_RESTRICTED_AUTOAPPROVE   TEXT("EnableRestrictedAutoApprove") //RS1+
#define T_UAC_AUTOAPPROVEIC            TEXT("EnableAutoApproveIntegrityContinuity") //RS2+

#define T_FLAG_ELEVATION_ENABLED       TEXT("ElevationEnabled")
#define T_FLAG_VIRTUALIZATION_ENABLED  TEXT("VirtualizationEnabled")
#define T_FLAG_INSTALLERDETECT_ENABLED TEXT("InstallerDetectEnabled")

#define T_PROGRAM_NAME                 TEXT("Yuubari")
#define T_PROGRAM_TITLE                TEXT("[UacView] UAC information gathering tool, v1.2.4 (21/03/2017)\n")

#define T_HELP	TEXT("Optional parameters to execute: \n\n\r\
YUUBARI [/v] \n\n\r\
  /v - produce verbose output.")
