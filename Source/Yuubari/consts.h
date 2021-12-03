/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2021
*
*  TITLE:       CONSTS.H
*
*  VERSION:     1.52
*
*  DATE:        23 Nov 2021
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

#define YUUBARI_MIN_SUPPORTED_NT_BUILD NT_WIN7_RTM
#define YUUBARI_MAX_SUPPORTED_NT_BUILD NTX_WIN11_ADB

#define T_UAC_COM_AUTOAPPROVAL_LIST    TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\UAC\\COMAutoApprovalList") //RS1+
#define T_UAC_BROKER_APPROVAL_LIST     TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CloudExperienceHost\\Broker\\ElevatedClsids")
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
#define T_PROGRAM_TITLE                TEXT("[UacView] UAC information gathering tool, v1.5.2 (Nov 23, 2021)\r\n")

#define T_HELP	TEXT("Optional parameters to execute: \r\n\n\
YUUBARI [/v] \r\n\n\
  /v - produce verbose output.")

#define T_SPLIT TEXT("===============================================================")
#define T_BASIC_HEAD TEXT("\r\n[UacView] Basic UAC settings\r\n")
#define T_COM_HEAD TEXT("\r\n[UacView] Autoelevated COM objects\r\n")
#define T_COM_APPROVE_HEAD TEXT("\r\n[UacView] COMAutoApproval list\r\n")
#define T_BROKER_APPROVE_HEAD TEXT("\r\n[UacView] Broker approval list\r\n")
#define T_WINFILES_HEAD TEXT("\r\n[UacView] Autoelevated applications in Windows directory\r\n")
#define T_PFDIRFILES_HEAD TEXT("\r\n[UacView] Autoelevated applications in Program Files directory\r\n")
#define T_APPINFO_HEAD TEXT("\r\n[UacView] Appinfo data\r\n")
