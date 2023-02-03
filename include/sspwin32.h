/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * AUTHOR: Guido Serassio <serassio@squid-cache.org>
 * Based on previous work of Francesco Chemolli, Robert Collins and Andrew Doran
 */

#ifndef _LIBSSPWIN32_H_
#define _LIBSSPWIN32_H_

#if _SQUID_WINDOWS_

#if defined(__cplusplus)
extern "C" {
#endif

#define SECURITY_WIN32
#define NTLM_PACKAGE_NAME "NTLM"
#define NEGOTIATE_PACKAGE_NAME "Negotiate"

#if _SQUID_CYGWIN_
#include <wchar.h>
#define _T(x) TEXT(x)
#else
#include <tchar.h>
#endif
#include <windows.h>
#include <ntsecapi.h>
#include <security.h>
#include <sspi.h>

typedef char * SSP_blobP;

#define WINNT_SECURITY_DLL "security.dll"
#define WIN2K_SECURITY_DLL "secur32.dll"

#define SSP_BASIC 1
#define SSP_NTLM 2

#define SSP_MAX_CRED_LEN 848

#define SSP_DEBUG 0

#define SSP_OK 1
#define SSP_ERROR 2

HMODULE LoadSecurityDll(int, const char *);
void UnloadSecurityDll(void);
BOOL WINAPI SSP_LogonUser(PTSTR, PTSTR, PTSTR);
BOOL WINAPI SSP_ValidateNTLMCredentials(PVOID, int, char *);
const char * WINAPI SSP_ValidateNegotiateCredentials(PVOID, int, PBOOL, int *, char *);
const char * WINAPI SSP_MakeChallenge(PVOID, int);
const char * WINAPI SSP_MakeNegotiateBlob(PVOID, int, PBOOL, int *, char *);

extern BOOL Use_Unicode;
extern BOOL NTLM_LocalCall;

#if defined(__cplusplus)
}
#endif

#endif /* _SQUID_WINDOWS_ */
#endif /* LIBSSPWIN32_H_ */

