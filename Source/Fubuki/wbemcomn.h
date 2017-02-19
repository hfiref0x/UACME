/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016
*
*  TITLE:       WBEMCOMN.H
*
*  VERSION:     2.40
*
*  DATE:        20 June 2016
*
*  WBEMCOMN forwarded import.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#pragma comment(linker, " /EXPORT:?CoCreateInstance@CWbemInstallObject@@SAJAEBU_GUID@@PEAUIUnknown@@K0PEAPEAX@Z=\\\\?\\globalroot\\systemroot\\system32\\wbemcomn.?CoCreateInstance@CWbemInstallObject@@SAJAEBU_GUID@@PEAUIUnknown@@K0PEAPEAX@Z")
#pragma comment(linker, " /EXPORT:?GetPreferredLanguages@CMUILocale@@SAJPEAPEAGPEAK@Z=\\\\?\\globalroot\\systemroot\\system32\\wbemcomn.?GetPreferredLanguages@CMUILocale@@SAJPEAPEAGPEAK@Z")
#pragma comment(linker, " /EXPORT:?IsOffline@CWbemInstallObject@@SA_NXZ=\\\\?\\globalroot\\systemroot\\system32\\wbemcomn.?IsOffline@CWbemInstallObject@@SA_NXZ")
#pragma comment(linker, " /EXPORT:?WbemMemAlloc@CWin32DefaultArena@@SAPEAX_K@Z=\\\\?\\globalroot\\systemroot\\system32\\wbemcomn.?WbemMemAlloc@CWin32DefaultArena@@SAPEAX_K@Z")
#pragma comment(linker, " /EXPORT:?WbemMemFree@CWin32DefaultArena@@SAHPEAX@Z=\\\\?\\globalroot\\systemroot\\system32\\wbemcomn.?WbemMemFree@CWin32DefaultArena@@SAHPEAX@Z")
#pragma comment(linker, " /EXPORT:?Write@CMemoryLog@@QEAAXJ@Z=\\\\?\\globalroot\\systemroot\\system32\\wbemcomn.?Write@CMemoryLog@@QEAAXJ@Z")
#pragma comment(linker, " /EXPORT:?_Free@CMUILocale@@SAHPEAX@Z=\\\\?\\globalroot\\systemroot\\system32\\wbemcomn.?_Free@CMUILocale@@SAHPEAX@Z")
#pragma comment(linker, " /EXPORT:ExtractMachineName=\\\\?\\globalroot\\systemroot\\system32\\wbemcomn.ExtractMachineName")
#pragma comment(linker, " /EXPORT:GetFQDN_Ipv4=\\\\?\\globalroot\\systemroot\\system32\\wbemcomn.GetFQDN_Ipv4")
#pragma comment(linker, " /EXPORT:GetMemLogObject=\\\\?\\globalroot\\systemroot\\system32\\wbemcomn.GetMemLogObject")
#pragma comment(linker, " /EXPORT:GetQFDN_Ipv6=\\\\?\\globalroot\\systemroot\\system32\\wbemcomn.GetQFDN_Ipv6")
#pragma comment(linker, " /EXPORT:RegisterDLL=\\\\?\\globalroot\\systemroot\\system32\\wbemcomn.RegisterDLL")
#pragma comment(linker, " /EXPORT:UnRegisterDLL=\\\\?\\globalroot\\systemroot\\system32\\wbemcomn.UnRegisterDLL")
#pragma comment(linker, " /EXPORT:bAreWeLocal=\\\\?\\globalroot\\systemroot\\system32\\wbemcomn.bAreWeLocal")
#pragma comment(linker, " /EXPORT:IsLocalConnection=\\\\?\\globalroot\\systemroot\\system32\\wbemcomn.IsLocalConnection")

//6.3 and below
#pragma comment(linker, " /EXPORT:?CoCreateInstance@CWbemInstallObject@@SAJAEBU_GUID@@PEAUIUnknown@@K0PEAPEAX@Z=\\\\?\\globalroot\\systemroot\\system32\\wbemcomn.?CoCreateInstance@CWbemInstallObject@@SAJAEBU_GUID@@PEAUIUnknown@@K0PEAPEAX@Z")
#pragma comment(linker, " /EXPORT:?ExtractMachineName@@YAPEAGPEAG@Z=\\\\?\\globalroot\\systemroot\\system32\\wbemcomn.?ExtractMachineName@@YAPEAGPEAG@Z")
#pragma comment(linker, " /EXPORT:?GetFQDN_Ipv4@@YAPEAUhostent@@PEAG@Z=\\\\?\\globalroot\\systemroot\\system32\\wbemcomn.?GetFQDN_Ipv4@@YAPEAUhostent@@PEAG@Z")
#pragma comment(linker, " /EXPORT:?GetMemLogObject@@YAPEAVCMemoryLog@@XZ=\\\\?\\globalroot\\systemroot\\system32\\wbemcomn.?GetMemLogObject@@YAPEAVCMemoryLog@@XZ")
#pragma comment(linker, " /EXPORT:?GetPreferredLanguages@CMUILocale@@SAJPEAPEAGPEAK@Z=\\\\?\\globalroot\\systemroot\\system32\\wbemcomn.?GetPreferredLanguages@CMUILocale@@SAJPEAPEAGPEAK@Z")
#pragma comment(linker, " /EXPORT:?GetQFDN_Ipv6@@YAKPEAG0HH@Z=\\\\?\\globalroot\\systemroot\\system32\\wbemcomn.?GetQFDN_Ipv6@@YAKPEAG0HH@Z")
#pragma comment(linker, " /EXPORT:?IsLocalConnection@@YAHPEAUIUnknown@@@Z=\\\\?\\globalroot\\systemroot\\system32\\wbemcomn.?IsLocalConnection@@YAHPEAUIUnknown@@@Z")
#pragma comment(linker, " /EXPORT:?IsOffline@CWbemInstallObject@@SA_NXZ=\\\\?\\globalroot\\systemroot\\system32\\wbemcomn.?IsOffline@CWbemInstallObject@@SA_NXZ")
#pragma comment(linker, " /EXPORT:?RegisterDLL@@YAXPEAUHINSTANCE__@@U_GUID@@PEAG22@Z=\\\\?\\globalroot\\systemroot\\system32\\wbemcomn.?RegisterDLL@@YAXPEAUHINSTANCE__@@U_GUID@@PEAG22@Z")
#pragma comment(linker, " /EXPORT:?UnRegisterDLL@@YAXU_GUID@@PEAG@Z=\\\\?\\globalroot\\systemroot\\system32\\wbemcomn.?UnRegisterDLL@@YAXU_GUID@@PEAG@Z")
#pragma comment(linker, " /EXPORT:?WbemMemAlloc@CWin32DefaultArena@@SAPEAX_K@Z=\\\\?\\globalroot\\systemroot\\system32\\wbemcomn.?WbemMemAlloc@CWin32DefaultArena@@SAPEAX_K@Z")
#pragma comment(linker, " /EXPORT:?WbemMemFree@CWin32DefaultArena@@SAHPEAX@Z=\\\\?\\globalroot\\systemroot\\system32\\wbemcomn.?WbemMemFree@CWin32DefaultArena@@SAHPEAX@Z")
#pragma comment(linker, " /EXPORT:?Write@CMemoryLog@@QEAAXJ@Z=\\\\?\\globalroot\\systemroot\\system32\\wbemcomn.?Write@CMemoryLog@@QEAAXJ@Z")
#pragma comment(linker, " /EXPORT:?_Free@CMUILocale@@SAHPEAX@Z=\\\\?\\globalroot\\systemroot\\system32\\wbemcomn.?_Free@CMUILocale@@SAHPEAX@Z")
#pragma comment(linker, " /EXPORT:?bAreWeLocal@@YAHPEAG@Z=\\\\?\\globalroot\\systemroot\\system32\\wbemcomn.?bAreWeLocal@@YAHPEAG@Z")
