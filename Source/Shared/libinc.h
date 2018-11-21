/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018
*
*  TITLE:       LIBINC.H
*
*  VERSION:     1.0.02
*
*  DATE:        18 Nov 2018
*
*  Master header file for C Runtime libraries include.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#if defined (_MSC_VER)
    #if (_MSC_VER >= 1900) //VS15, 17 etc
        #ifdef _DEBUG
            #pragma comment(lib, "vcruntimed.lib")
            #pragma comment(lib, "ucrtd.lib")
        #else
            #pragma comment(lib, "libucrt.lib")
            #pragma comment(lib, "libvcruntime.lib")
        #endif
    #endif
#endif
