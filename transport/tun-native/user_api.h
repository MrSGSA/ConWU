#pragma once
#include <windows.h>
#include "../../drivers/StreamLink.Tun/abi.h"
#ifdef SLT_BUILD_DLL
#define SLT_API extern "C" __declspec(dllexport)
#else
#define SLT_API extern "C" __declspec(dllimport)
#endif
typedef unsigned long long SLT_HANDLE;
SLT_API unsigned __cdecl SLT_UserAbi();
SLT_API SLT_HANDLE __cdecl SLT_Open(unsigned interfaceIndex);
SLT_API BOOL __cdecl SLT_Info(SLT_HANDLE,SLT_INFO *);
SLT_API BOOL __cdecl SLT_Stats(SLT_HANDLE,SLT_STATS *);
SLT_API BOOL __cdecl SLT_ConfigureIpv4(SLT_HANDLE,const unsigned char *address);
SLT_API int __cdecl SLT_Read(SLT_HANDLE,void *,unsigned);
SLT_API BOOL __cdecl SLT_Write(SLT_HANDLE,const void *,unsigned);
SLT_API BOOL __cdecl SLT_Stop(SLT_HANDLE);
SLT_API BOOL __cdecl SLT_Close(SLT_HANDLE);
