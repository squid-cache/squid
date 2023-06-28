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

#if HAVE_WINDOWS_H && HAVE_SSPI_H

#define SECURITY_WIN32
#define NTLM_PACKAGE_NAME "NTLM"
#define NEGOTIATE_PACKAGE_NAME "Negotiate"

#if HAVE_TCHAR_H
#include <tchar.h>
#endif
#if HAVE_WINDOWS_H
#include <windows.h>
#endif
#if HAVE_NTSECAPI_H
#include <ntsecapi.h>
#endif
#if HAVE_SECURITY_H
#include <security.h>
#endif
#if HAVE_SSPI_H
#include <sspi.h>
#endif

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

#if HAVE_AUTH_MODULE_BASIC
BOOL WINAPI SSP_LogonUser(PTSTR, PTSTR, PTSTR);
#endif

#if HAVE_AUTH_MODULE_NTLM
const char * WINAPI SSP_MakeChallenge(PVOID, int);
BOOL WINAPI SSP_ValidateNTLMCredentials(PVOID, int, char *);
extern BOOL NTLM_LocalCall;
#endif

#if HAVE_AUTH_MODULE_NEGOTIATE
const char * WINAPI SSP_MakeNegotiateBlob(PVOID, int, PBOOL, int *, char *);
const char * WINAPI SSP_ValidateNegotiateCredentials(PVOID, int, PBOOL, int *, char *);
#endif

#endif /* HAVE_WINDOWS_H && HAVE_SSPI_H */
#endif /* LIBSSPWIN32_H_ */

