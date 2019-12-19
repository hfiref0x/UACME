

/* this ALWAYS GENERATED file contains the RPC client stubs */


 /* File created by MIDL compiler version 8.01.0622 */
/* at Mon Jan 18 19:14:07 2038
 */
/* Compiler settings for appinfo.idl:
    Oicf, W1, Zp8, env=Win32 (32b run), target_arch=X86 8.01.0622 
    protocol : dce , ms_ext, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
/* @@MIDL_FILE_HEADING(  ) */

#if !defined(_M_IA64) && !defined(_M_AMD64) && !defined(_ARM_)


#pragma warning( disable: 4049 )  /* more than 64k source lines */
#if _MSC_VER >= 1200
#pragma warning(push)
#endif

#pragma warning( disable: 4211 )  /* redefine extern to static */
#pragma warning( disable: 4232 )  /* dllimport identity*/
#pragma warning( disable: 4024 )  /* array to pointer mapping*/
#pragma warning( disable: 4100 ) /* unreferenced arguments in x86 call */

#pragma optimize("", off ) 

#include "appinfo32.h"

#define TYPE_FORMAT_STRING_SIZE   75                                
#define PROC_FORMAT_STRING_SIZE   101                               
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
                      ( unsigned char * )&RAiLaunchAdminProcess_AsyncHandle);
    
}


#if !defined(__RPC_WIN32__)
#error  Invalid build platform for this stub.
#endif

#if !(TARGET_IS_NT50_OR_LATER)
#error You need Windows 2000 or later to run this stub because it uses these features:
#error   [async] attribute, /robust command line switch.
#error However, your C/C++ compilation flags indicate you intend to run this app on earlier systems.
#error This app will fail with the RPC_X_WRONG_STUB_VERSION error.
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
/*  8 */	NdrFcShort( 0x38 ),	/* x86 Stack size/offset = 56 */
/* 10 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 12 */	NdrFcShort( 0x4 ),	/* x86 Stack size/offset = 4 */
/* 14 */	NdrFcShort( 0x9a ),	/* 154 */
/* 16 */	NdrFcShort( 0x58 ),	/* 88 */
/* 18 */	0xc6,		/* Oi2 Flags:  clt must size, has return, has ext, has async handle */
			0xc,		/* 12 */
/* 20 */	0x8,		/* 8 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 22 */	NdrFcShort( 0x0 ),	/* 0 */
/* 24 */	NdrFcShort( 0x0 ),	/* 0 */
/* 26 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Parameter ExecutablePath */

/* 28 */	NdrFcShort( 0xb ),	/* Flags:  must size, must free, in, */
/* 30 */	NdrFcShort( 0x8 ),	/* x86 Stack size/offset = 8 */
/* 32 */	NdrFcShort( 0x2 ),	/* Type Offset=2 */

	/* Parameter CommandLine */

/* 34 */	NdrFcShort( 0xb ),	/* Flags:  must size, must free, in, */
/* 36 */	NdrFcShort( 0xc ),	/* x86 Stack size/offset = 12 */
/* 38 */	NdrFcShort( 0x2 ),	/* Type Offset=2 */

	/* Parameter StartFlags */

/* 40 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 42 */	NdrFcShort( 0x10 ),	/* x86 Stack size/offset = 16 */
/* 44 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Parameter CreationFlags */

/* 46 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 48 */	NdrFcShort( 0x14 ),	/* x86 Stack size/offset = 20 */
/* 50 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Parameter CurrentDirectory */

/* 52 */	NdrFcShort( 0x10b ),	/* Flags:  must size, must free, in, simple ref, */
/* 54 */	NdrFcShort( 0x18 ),	/* x86 Stack size/offset = 24 */
/* 56 */	NdrFcShort( 0x8 ),	/* Type Offset=8 */

	/* Parameter WindowStation */

/* 58 */	NdrFcShort( 0x10b ),	/* Flags:  must size, must free, in, simple ref, */
/* 60 */	NdrFcShort( 0x1c ),	/* x86 Stack size/offset = 28 */
/* 62 */	NdrFcShort( 0x8 ),	/* Type Offset=8 */

	/* Parameter StartupInfo */

/* 64 */	NdrFcShort( 0x10a ),	/* Flags:  must free, in, simple ref, */
/* 66 */	NdrFcShort( 0x20 ),	/* x86 Stack size/offset = 32 */
/* 68 */	NdrFcShort( 0x16 ),	/* Type Offset=22 */

	/* Parameter hWnd */

/* 70 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 72 */	NdrFcShort( 0x24 ),	/* x86 Stack size/offset = 36 */
/* 74 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Parameter Timeout */

/* 76 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 78 */	NdrFcShort( 0x28 ),	/* x86 Stack size/offset = 40 */
/* 80 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Parameter ProcessInformation */

/* 82 */	NdrFcShort( 0x4112 ),	/* Flags:  must free, out, simple ref, srv alloc size=16 */
/* 84 */	NdrFcShort( 0x2c ),	/* x86 Stack size/offset = 44 */
/* 86 */	NdrFcShort( 0x3c ),	/* Type Offset=60 */

	/* Parameter ElevationType */

/* 88 */	NdrFcShort( 0x2150 ),	/* Flags:  out, base type, simple ref, srv alloc size=8 */
/* 90 */	NdrFcShort( 0x30 ),	/* x86 Stack size/offset = 48 */
/* 92 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Return value */

/* 94 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 96 */	NdrFcShort( 0x34 ),	/* x86 Stack size/offset = 52 */
/* 98 */	0x8,		/* FC_LONG */
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
			0x16,		/* FC_PSTRUCT */
			0x3,		/* 3 */
/* 24 */	NdrFcShort( 0x30 ),	/* 48 */
/* 26 */	
			0x4b,		/* FC_PP */
			0x5c,		/* FC_PAD */
/* 28 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 30 */	NdrFcShort( 0x0 ),	/* 0 */
/* 32 */	NdrFcShort( 0x0 ),	/* 0 */
/* 34 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 36 */	0x5,		/* FC_WCHAR */
			0x5c,		/* FC_PAD */
/* 38 */	
			0x5b,		/* FC_END */

			0x8,		/* FC_LONG */
/* 40 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 42 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 44 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 46 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 48 */	0x6,		/* FC_SHORT */
			0x3e,		/* FC_STRUCTPAD2 */
/* 50 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 52 */	NdrFcShort( 0xffda ),	/* Offset= -38 (14) */
/* 54 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 56 */	
			0x11, 0x4,	/* FC_RP [alloced_on_stack] */
/* 58 */	NdrFcShort( 0x2 ),	/* Offset= 2 (60) */
/* 60 */	
			0x15,		/* FC_STRUCT */
			0x3,		/* 3 */
/* 62 */	NdrFcShort( 0x10 ),	/* 16 */
/* 64 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
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
#pragma warning(disable:4206)
#endif /* !defined(_M_IA64) && !defined(_M_AMD64) && !defined(_ARM_) */

