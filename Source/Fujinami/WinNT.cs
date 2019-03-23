/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2019
*
*  TITLE:       WINNT.CS
*
*  VERSION:     1.0.1.2
*
*  DATE:        20 Mar 2019
*
*  Unmanaged API definitions and prototypes.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

using System;
using System.Runtime.InteropServices;

namespace Fujinami
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SHARED_PARAMS
    {
        public uint Crc32;
        public uint SessionId;
        public uint AkagiFlag;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 261)]
        public string szParameter;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 261)]
        public string szDesktop;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 261)]
        public string szWinstation;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 261)]
        public string szSignalObject;
    }

    public enum WELL_KNOWN_SID_TYPE
    {
        WinWorldSid = 1
    }

    public enum NtStatus : int
    {
        Success = 0,
        Informational = 1073741824,
        Error = -1073741824
    }

    [Flags]
    public enum ObjectFlags : uint
    {
        Inherit = 0x2,
        Permanent = 0x10,
        Exclusive = 0x20,
        CaseInsensitive = 0x40,
        OpenIf = 0x80,
        OpenLink = 0x100,
        KernelHandle = 0x200,
        ForceAccessCheck = 0x400,
        ValidAttributes = 0x7f2
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING : IDisposable
    {
        public ushort Length;
        public ushort MaximumLength;
        private IntPtr buffer;

        public UNICODE_STRING(string s)
        {
            Length = (ushort)(s.Length * 2);
            MaximumLength = (ushort)(Length + 2);
            buffer = Marshal.StringToHGlobalUni(s);
        }

        public void Dispose()
        {
            Marshal.FreeHGlobal(buffer);
            buffer = IntPtr.Zero;
        }

        public override string ToString()
        {
            return Marshal.PtrToStringUni(buffer);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_ATTRIBUTES : IDisposable
    {
        public int Length;
        public IntPtr RootDirectory;
        private IntPtr objectName;
        public ObjectFlags Attributes;
        private IntPtr SecurityDescriptor;
        private IntPtr SecurityQualityOfService;

        public OBJECT_ATTRIBUTES(string name, ObjectFlags attrs, IntPtr root)
        {
            Length = 0;
            RootDirectory = root;
            objectName = IntPtr.Zero;
            Attributes = attrs;
            SecurityDescriptor = IntPtr.Zero;
            SecurityQualityOfService = IntPtr.Zero;

            Length = Marshal.SizeOf(this);
            ObjectName = new UNICODE_STRING(name);
        }

        public UNICODE_STRING ObjectName
        {
            get
            {
                return (UNICODE_STRING)Marshal.PtrToStructure(
                 objectName, typeof(UNICODE_STRING));
            }

            set
            {
                bool fDeleteOld = objectName != IntPtr.Zero;
                if (!fDeleteOld)
                    objectName = Marshal.AllocHGlobal(Marshal.SizeOf(value));
                Marshal.StructureToPtr(value, objectName, fDeleteOld);
            }
        }

        public void Dispose()
        {
            if (objectName != IntPtr.Zero)
            {
                Marshal.DestroyStructure(objectName, typeof(UNICODE_STRING));
                Marshal.FreeHGlobal(objectName);
                objectName = IntPtr.Zero;
            }
        }
    }

    [Flags]
    public enum StandardRights : uint
    {
        Delete = 0x00010000,
        ReadControl = 0x00020000,
        WriteDac = 0x00040000,
        WriteOwner = 0x00080000,
        Synchronize = 0x00100000,
        Required = 0x000f0000,
        Read = ReadControl,
        Write = ReadControl,
        Execute = ReadControl,
        All = 0x001f0000,

        SpecificRightsAll = 0x0000ffff,
        AccessSystemSecurity = 0x01000000,
        MaximumAllowed = 0x02000000,
        GenericRead = 0x80000000,
        GenericWrite = 0x40000000,
        GenericExecute = 0x20000000,
        GenericAll = 0x10000000
    }

    [Flags]
    public enum SectionAccess : uint
    {
        Query = 0x0001,
        MapWrite = 0x0002,
        MapRead = 0x0004,
        MapExecute = 0x0008,
        ExtendSize = 0x0010,
        MapExecuteExplicit = 0x0020,
        AllAccess = StandardRights.Required | Query | MapWrite | MapRead | MapExecute | ExtendSize
    }

    public enum SectionInherit : int
    {
        ViewShare = 1,
        ViewUnmap = 2
    }

    [Flags]
    public enum MemoryFlags : uint
    {
        Commit = 0x1000,
        Reserve = 0x2000,
        Decommit = 0x4000,
        Release = 0x8000,
        Free = 0x10000,
        Private = 0x20000,
        Mapped = 0x40000,
        Reset = 0x80000,
        TopDown = 0x100000,
        WriteWatch = 0x200000,
        Physical = 0x400000,
        LargePages = 0x20000000,
        DosLimit = 0x40000000,
        FourMbPages = 0x80000000
    }

    [Flags]
    public enum MemoryProtection : uint
    {
        AccessDenied = 0x0,
        Execute = 0x10,
        ExecuteRead = 0x20,
        ExecuteReadWrite = 0x40,
        ExecuteWriteCopy = 0x80,
        Guard = 0x100,
        NoCache = 0x200,
        WriteCombine = 0x400,
        NoAccess = 0x01,
        ReadOnly = 0x02,
        ReadWrite = 0x04,
        WriteCopy = 0x08
    }

    [Flags]
    public enum EventAccess : uint
    {
        QueryState = 0x1,
        ModifyState = 0x2,
        AllAccess = StandardRights.Required | StandardRights.Synchronize |
            QueryState | ModifyState
    }

    public static partial class NativeMethods
    {

        public static bool IsSuccess(NtStatus status) => status >= NtStatus.Success && status < NtStatus.Informational;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenPrivateNamespaceW(
            [In] IntPtr lpBoundaryDescriptor,
            [In] [MarshalAs(UnmanagedType.LPWStr)] string lpAliasPrefix);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ClosePrivateNamespace(
            [In] IntPtr Handle,
            [In] uint Flags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr CreateBoundaryDescriptorW(
            [In] [MarshalAs(UnmanagedType.LPWStr)] string Name,
            [In] uint Flags);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern void DeleteBoundaryDescriptor(
            [In] IntPtr BoundaryDescriptor);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CreateWellKnownSid(
            [In] WELL_KNOWN_SID_TYPE WellKnownSidType,
            [In] IntPtr DomainSid,
            [In] IntPtr pSid,
            ref uint cbSid);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool AddSIDToBoundaryDescriptor(
            ref IntPtr BoundaryDescriptor,
            [In] IntPtr RequiredSid);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtClose(
            [In] IntPtr hObject);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenSection(
            [Out] out IntPtr SectionHandle,
            [In] SectionAccess DesiredAccess,
            [In] ref OBJECT_ATTRIBUTES ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtMapViewOfSection(
            [In] IntPtr SectionHandle,
            [In] IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            [In] IntPtr ZeroBits,
            [In] IntPtr CommitSize,
            [Optional] ref long SectionOffset,
            ref IntPtr ViewSize,
            [In] SectionInherit InheritDisposition,
            [In] MemoryFlags AllocationType,
            [In] MemoryProtection Win32Protect);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtUnmapViewOfSection(
            [In] IntPtr ProcessHandle,
            [In] IntPtr BaseAddress);

        [DllImport("ntdll.dll")]
        public static extern uint RtlComputeCrc32(
            [In] uint PartialCrc,
            [In] IntPtr Buffer,
            [In] uint Length);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenEvent(
            [Out] out IntPtr EventHandle,
            [In] EventAccess DesiredAccess,
            [In] ref OBJECT_ATTRIBUTES ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetEvent(
            [In] IntPtr EventHandle,
            [Out] [Optional] out int PreviousState);

    }
}
