

/* this ALWAYS GENERATED file contains the RPC client stubs */


 /* File created by MIDL compiler version 8.01.0622 */
/* at Mon Jan 18 19:14:07 2038
 */
/* Compiler settings for appinfo.idl:
    Oicf, W1, Zp8, env=Win64 (32b run), target_arch=AMD64 8.01.0622 
    protocol : dce , ms_ext, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
/* @@MIDL_FILE_HEADING(  ) */

#if defined(_M_AMD64)


#pragma warning( disable: 4049 )  /* more than 64k source lines */
#if _MSC_VER >= 1200
#pragma warning(push)
#endif

#pragma warning( disable: 4211 )  /* redefine extern to static */
#pragma warning( disable: 4232 )  /* dllimport identity*/
#pragma warning( disable: 4024 )  /* array to pointer mapping*/

#include "appinfo64.h"

#define TYPE_FORMAT_STRING_SIZE   75                                
#define PROC_FORMAT_STRING_SIZE   103                               
#define EXPR_FORMAT_STRING_SIZE   1                                 
#define TRANSMIT_AS_TABLE_SIZE    0            
#define WIRE_MARSHAL_TABLE_SIZE   0            

typedef struct _appinfo_MIDL_TYPE_FORMAT_STRING
    {
    short          Pad;
    unsigned char  Format[ TYPE_FORMAT_STRING_SIZE ];
    } appinfo_MIDL_TYPE_FORMAT_STRING;

typedef struct _appinfo_MIDL_PROC_FORMAT_STRING
    {
    short          Pad;
    unsigned char  Format[ PROC_FORMAT_STRING_SIZE ];
    } appinfo_MIDL_PROC_FORMAT_STRING;

typedef struct _appinfo_MIDL_EXPR_FORMAT_STRING
    {
    long          Pad;
    unsigned char  Format[ EXPR_FORMAT_STRING_SIZE ];
    } appinfo_MIDL_EXPR_FORMAT_STRING;


static const RPC_SYNTAX_IDENTIFIER  _RpcTransferSyntax = 
{{0x8A885D04,0x1CEB,0x11C9,{0x9F,0xE8,0x08,0x00,0x2B,0x10,0x48,0x60}},{2,0}};


extern const appinfo_MIDL_TYPE_FORMAT_STRING appinfo__MIDL_TypeFormatString;
extern const appinfo_MIDL_PROC_FORMAT_STRING appinfo__MIDL_ProcFormatString;
extern const appinfo_MIDL_EXPR_FORMAT_STRING appinfo__MIDL_ExprFormatString;

#define GENERIC_BINDING_TABLE_SIZE   0            


/* Standard interface: LaunchAdminProcess, ver. 1.0,
   GUID={0x201ef99a,0x7fa0,0x444c,{0x93,0x99,0x19,0xba,0x84,0xf1,0x2a,0x1a}} */



static const RPC_CLIENT_INTERFACE LaunchAdminProcess___RpcClientInterface =
    {
    sizeof(RPC_CLIENT_INTERFACE),
    {{0x201ef99a,0x7fa0,0x444c,{0x93,0x99,0x19,0xba,0x84,0xf1,0x2a,0x1a}},{1,0}},
    {{0x8A885D04,0x1CEB,0x11C9,{0x9F,0xE8,0x08,0x00,0x2B,0x10,0x48,0x60}},{2,0}},
    0,
    0,
    0,
    0,
    0,
    0x00000000
    };
RPC_IF_HANDLE LaunchAdminProcess_v1_0_c_ifspec = (RPC_IF_HANDLE)& LaunchAdminProcess___RpcClientInterface;

extern const MIDL_STUB_DESC LaunchAdminProcess_StubDesc;

static RPC_BINDING_HANDLE LaunchAdminProcess__MIDL_AutoBindHandle;


/* [async] */ void  RAiLaunchAdminProcess( 
    /* [in] */ PRPC_ASYNC_STATE RAiLaunchAdminProcess_AsyncHandle,
    handle_t hBinding,
    /* [string][unique][in] */ wchar_t *ExecutablePath,
    /* [string][unique][in] */ wchar_t *CommandLine,
    /* [in] */ long StartFlags,
    /* [in] */ long CreationFlags,
    /* [string][in] */ wchar_t *CurrentDirectory,
    /* [string][in] */ wchar_t *WindowStation,
    /* [in] */ struct _APP_STARTUP_INFO *StartupInfo,
    /* [in] */ unsigned __int3264 hWnd,
    /* [in] */ long Timeout,
    /* [out] */ struct _APP_PROCESS_INFORMATION *ProcessInformation,
    /* [out] */ long *ElevationType)
{

    NdrAsyncClientCall(
                      ( PMIDL_STUB_DESC  )&LaunchAdminProcess_StubDesc,
                      (PFORMAT_STRING) &appinfo__MIDL_ProcFormatString.Format[0],
                      RAiLaunchAdminProcess_AsyncHandle,
                      hBinding,
                      ExecutablePath,
                      CommandLine,
                      StartFlags,
                      CreationFlags,
                      CurrentDirectory,
                      WindowStation,
                      StartupInfo,
                      hWnd,
                      Timeout,
                      ProcessInformation,
                      ElevationType);
    
}


#if !defined(__RPC_WIN64__)
#error  Invalid build platform for this stub.
#endif

static const appinfo_MIDL_PROC_FORMAT_STRING appinfo__MIDL_ProcFormatString =
    {
        0,
        {

	/* Procedure RAiLaunchAdminProcess */

			0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/*  2 */	NdrFcLong( 0x0 ),	/* 0 */
/*  6 */	NdrFcShort( 0x0 ),	/* 0 */
/*  8 */	NdrFcShort( 0x70 ),	/* X64 Stack size/offset = 112 */
/* 10 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 12 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 14 */	NdrFcShort( 0x20 ),	/* 32 */
/* 16 */	NdrFcShort( 0x24 ),	/* 36 */
/* 18 */	0xc7,		/* Oi2 Flags:  srv must size, clt must size, has return, has ext, has async handle */
			0xc,		/* 12 */
/* 20 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 22 */	NdrFcShort( 0x0 ),	/* 0 */
/* 24 */	NdrFcShort( 0x0 ),	/* 0 */
/* 26 */	NdrFcShort( 0x0 ),	/* 0 */
/* 28 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Parameter ExecutablePath */

/* 30 */	NdrFcShort( 0xb ),	/* Flags:  must size, must free, in, */
/* 32 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 34 */	NdrFcShort( 0x2 ),	/* Type Offset=2 */

	/* Parameter CommandLine */

/* 36 */	NdrFcShort( 0xb ),	/* Flags:  must size, must free, in, */
/* 38 */	NdrFcShort( 0x18 ),	/* X64 Stack size/offset = 24 */
/* 40 */	NdrFcShort( 0x2 ),	/* Type Offset=2 */

	/* Parameter StartFlags */

/* 42 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 44 */	NdrFcShort( 0x20 ),	/* X64 Stack size/offset = 32 */
/* 46 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Parameter CreationFlags */

/* 48 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 50 */	NdrFcShort( 0x28 ),	/* X64 Stack size/offset = 40 */
/* 52 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Parameter CurrentDirectory */

/* 54 */	NdrFcShort( 0x10b ),	/* Flags:  must size, must free, in, simple ref, */
/* 56 */	NdrFcShort( 0x30 ),	/* X64 Stack size/offset = 48 */
/* 58 */	NdrFcShort( 0x8 ),	/* Type Offset=8 */

	/* Parameter WindowStation */

/* 60 */	NdrFcShort( 0x10b ),	/* Flags:  must size, must free, in, simple ref, */
/* 62 */	NdrFcShort( 0x38 ),	/* X64 Stack size/offset = 56 */
/* 64 */	NdrFcShort( 0x8 ),	/* Type Offset=8 */

	/* Parameter StartupInfo */

/* 66 */	NdrFcShort( 0x10b ),	/* Flags:  must size, must free, in, simple ref, */
/* 68 */	NdrFcShort( 0x40 ),	/* X64 Stack size/offset = 64 */
/* 70 */	NdrFcShort( 0x16 ),	/* Type Offset=22 */

	/* Parameter hWnd */

/* 72 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 74 */	NdrFcShort( 0x48 ),	/* X64 Stack size/offset = 72 */
/* 76 */	0xb9,		/* FC_UINT3264 */
			0x0,		/* 0 */

	/* Parameter Timeout */

/* 78 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 80 */	NdrFcShort( 0x50 ),	/* X64 Stack size/offset = 80 */
/* 82 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Parameter ProcessInformation */

/* 84 */	NdrFcShort( 0x6113 ),	/* Flags:  must size, must free, out, simple ref, srv alloc size=24 */
/* 86 */	NdrFcShort( 0x58 ),	/* X64 Stack size/offset = 88 */
/* 88 */	NdrFcShort( 0x38 ),	/* Type Offset=56 */

	/* Parameter ElevationType */

/* 90 */	NdrFcShort( 0x2150 ),	/* Flags:  out, base type, simple ref, srv alloc size=8 */
/* 92 */	NdrFcShort( 0x60 ),	/* X64 Stack size/offset = 96 */
/* 94 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Return value */

/* 96 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 98 */	NdrFcShort( 0x68 ),	/* X64 Stack size/offset = 104 */
/* 100 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

			0x0
        }
    };

static const appinfo_MIDL_TYPE_FORMAT_STRING appinfo__MIDL_TypeFormatString =
    {
        0,
        {
			NdrFcShort( 0x0 ),	/* 0 */
/*  2 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/*  4 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/*  6 */	
			0x11, 0x8,	/* FC_RP [simple_pointer] */
/*  8 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 10 */	
			0x11, 0x0,	/* FC_RP */
/* 12 */	NdrFcShort( 0xa ),	/* Offset= 10 (22) */
/* 14 */	
			0x15,		/* FC_STRUCT */
			0x3,		/* 3 */
/* 16 */	NdrFcShort( 0x8 ),	/* 8 */
/* 18 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 20 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 22 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 24 */	NdrFcShort( 0x38 ),	/* 56 */
/* 26 */	NdrFcShort( 0x0 ),	/* 0 */
/* 28 */	NdrFcShort( 0x14 ),	/* Offset= 20 (48) */
/* 30 */	0x36,		/* FC_POINTER */
			0x8,		/* FC_LONG */
/* 32 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 34 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 36 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 38 */	0x8,		/* FC_LONG */
			0x6,		/* FC_SHORT */
/* 40 */	0x3e,		/* FC_STRUCTPAD2 */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 42 */	0x0,		/* 0 */
			NdrFcShort( 0xffe3 ),	/* Offset= -29 (14) */
			0x40,		/* FC_STRUCTPAD4 */
/* 46 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 48 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 50 */	0x5,		/* FC_WCHAR */
			0x5c,		/* FC_PAD */
/* 52 */	
			0x11, 0x4,	/* FC_RP [alloced_on_stack] */
/* 54 */	NdrFcShort( 0x2 ),	/* Offset= 2 (56) */
/* 56 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 58 */	NdrFcShort( 0x18 ),	/* 24 */
/* 60 */	NdrFcShort( 0x0 ),	/* 0 */
/* 62 */	NdrFcShort( 0x0 ),	/* Offset= 0 (62) */
/* 64 */	0xb9,		/* FC_UINT3264 */
			0xb9,		/* FC_UINT3264 */
/* 66 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 68 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 70 */	
			0x11, 0xc,	/* FC_RP [alloced_on_stack] [simple_pointer] */
/* 72 */	0x8,		/* FC_LONG */
			0x5c,		/* FC_PAD */

			0x0
        }
    };

static const unsigned short LaunchAdminProcess_FormatStringOffsetTable[] =
    {
    0
    };


static const MIDL_STUB_DESC LaunchAdminProcess_StubDesc = 
    {
    (void *)& LaunchAdminProcess___RpcClientInterface,
    MIDL_user_allocate,
    MIDL_user_free,
    &LaunchAdminProcess__MIDL_AutoBindHandle,
    0,
    0,
    0,
    0,
    appinfo__MIDL_TypeFormatString.Format,
    1, /* -error bounds_check flag */
    0x50002, /* Ndr library version */
    0,
    0x801026e, /* MIDL Version 8.1.622 */
    0,
    0,
    0,  /* notify & notify_flag routine table */
    0x1, /* MIDL flag */
    0, /* cs routines */
    0,   /* proxy/server info */
    0
    };
#if _MSC_VER >= 1200
#pragma warning(pop)
#endif
#else
#pragma warning(disable: 4206)
#endif /* defined(_M_AMD64)*/
