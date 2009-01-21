
/*
 * $Id$
 *
 * AUTHOR: Guido Serassio <serassio@squid-cache.org>
 * inspired by previous work by Robert Collins, Francesco Chemolli.
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "util.h"

#include "ntlmauth.h"
#include "sspwin32.h"

typedef struct _AUTH_SEQ {
    BOOL fInitialized;
    BOOL fHaveCredHandle;
    BOOL fHaveCtxtHandle;
    CredHandle hcred;
    TimeStamp hcredLifeTime;
    struct _SecHandle hctxt;
    TimeStamp hctxtLifeTime;
} AUTH_SEQ, *PAUTH_SEQ;

BOOL GenClientContext(PAUTH_SEQ, PSEC_WINNT_AUTH_IDENTITY, PVOID, DWORD, PVOID, PDWORD, PBOOL);
BOOL GenServerContext(PAUTH_SEQ, PVOID, DWORD, PVOID, PDWORD, PBOOL, char *);

static HMODULE hModule;
static int NTLM_mode = SSP_BASIC;
static char * SSP_Package_InUse;
SECURITY_STATUS SecurityStatus = SEC_E_OK;

static DWORD cbMaxToken = 0;
static PVOID pClientBuf = NULL;
static PVOID pServerBuf = NULL;

static AUTH_SEQ NTLM_asServer = {0};

BOOL Use_Unicode = FALSE;
BOOL NTLM_LocalCall = FALSE;

/* Function pointers */
ACCEPT_SECURITY_CONTEXT_FN _AcceptSecurityContext = NULL;
ACQUIRE_CREDENTIALS_HANDLE_FN _AcquireCredentialsHandle = NULL;
COMPLETE_AUTH_TOKEN_FN _CompleteAuthToken = NULL;
DELETE_SECURITY_CONTEXT_FN _DeleteSecurityContext = NULL;
FREE_CONTEXT_BUFFER_FN _FreeContextBuffer = NULL;
FREE_CREDENTIALS_HANDLE_FN _FreeCredentialsHandle = NULL;
INITIALIZE_SECURITY_CONTEXT_FN _InitializeSecurityContext = NULL;
QUERY_SECURITY_PACKAGE_INFO_FN _QuerySecurityPackageInfo = NULL;
#ifdef UNICODE
QUERY_CONTEXT_ATTRIBUTES_FN_W _QueryContextAttributes = NULL;
#else
QUERY_CONTEXT_ATTRIBUTES_FN_A _QueryContextAttributes = NULL;
#endif

void UnloadSecurityDll(void)
{
    if (NTLM_asServer.fHaveCtxtHandle)
        _DeleteSecurityContext(&NTLM_asServer.hctxt);
    if (NTLM_asServer.fHaveCredHandle)
        _FreeCredentialsHandle(&NTLM_asServer.hcred);

    if (hModule)
        FreeLibrary(hModule);

    xfree(SSP_Package_InUse);
    xfree(pClientBuf);
    xfree(pServerBuf);

    _AcceptSecurityContext      = NULL;
    _AcquireCredentialsHandle   = NULL;
    _CompleteAuthToken          = NULL;
    _DeleteSecurityContext      = NULL;
    _FreeContextBuffer          = NULL;
    _FreeCredentialsHandle      = NULL;
    _InitializeSecurityContext  = NULL;
    _QuerySecurityPackageInfo   = NULL;
    _QueryContextAttributes     = NULL;

    hModule = NULL;
}


HMODULE LoadSecurityDll(int mode, char * SSP_Package)
{
    TCHAR lpszDLL[MAX_PATH];
    OSVERSIONINFO VerInfo;
    PSecPkgInfo pSPI       = NULL;

    /*
    *  Find out which security DLL to use, depending on
    *  whether we are on NT or 2000 or XP or 2003 Server
    *  We have to use security.dll on Windows NT 4.0.
    *  All other operating systems, we have to use Secur32.dll
    */
    hModule = NULL;
    if ((mode != SSP_BASIC) && (mode != SSP_NTLM))
        return hModule;
    NTLM_mode = mode;
    VerInfo.dwOSVersionInfoSize = sizeof (OSVERSIONINFO);
    if (!GetVersionEx (&VerInfo)) {   /* If this fails, something has gone wrong */
        return hModule;
    }
    if (VerInfo.dwPlatformId == VER_PLATFORM_WIN32_NT &&
            VerInfo.dwMajorVersion == 4 &&
            VerInfo.dwMinorVersion == 0) {
        lstrcpy (lpszDLL, _T(WINNT_SECURITY_DLL));
    } else {
        lstrcpy (lpszDLL, _T(WIN2K_SECURITY_DLL));
    }
    hModule = LoadLibrary(lpszDLL);
    if (!hModule)
        return hModule;
    _AcceptSecurityContext = (ACCEPT_SECURITY_CONTEXT_FN)
                             GetProcAddress(hModule, "AcceptSecurityContext");
    if (!_AcceptSecurityContext) {
        UnloadSecurityDll();
        hModule = NULL;
        return hModule;
    }
#ifdef UNICODE
    _AcquireCredentialsHandle = (ACQUIRE_CREDENTIALS_HANDLE_FN)
                                GetProcAddress(hModule, "AcquireCredentialsHandleW");
#else
    _AcquireCredentialsHandle = (ACQUIRE_CREDENTIALS_HANDLE_FN)
                                GetProcAddress(hModule, "AcquireCredentialsHandleA");
#endif
    if (!_AcquireCredentialsHandle) {
        UnloadSecurityDll();
        hModule = NULL;
        return hModule;
    }
    _CompleteAuthToken = (COMPLETE_AUTH_TOKEN_FN)
                         GetProcAddress(hModule, "CompleteAuthToken");
    if (!_CompleteAuthToken) {
        UnloadSecurityDll();
        hModule = NULL;
        return hModule;
    }
    _DeleteSecurityContext = (DELETE_SECURITY_CONTEXT_FN)
                             GetProcAddress(hModule, "DeleteSecurityContext");
    if (!_DeleteSecurityContext) {
        UnloadSecurityDll();
        hModule = NULL;
        return hModule;
    }
    _FreeContextBuffer = (FREE_CONTEXT_BUFFER_FN)
                         GetProcAddress(hModule, "FreeContextBuffer");
    if (!_FreeContextBuffer) {
        UnloadSecurityDll();
        hModule = NULL;
        return hModule;
    }
    _FreeCredentialsHandle = (FREE_CREDENTIALS_HANDLE_FN)
                             GetProcAddress(hModule, "FreeCredentialsHandle");
    if (!_FreeCredentialsHandle) {
        UnloadSecurityDll();
        hModule = NULL;
        return hModule;
    }
#ifdef UNICODE
    _InitializeSecurityContext = (INITIALIZE_SECURITY_CONTEXT_FN)
                                 GetProcAddress(hModule, "InitializeSecurityContextW");
#else
    _InitializeSecurityContext = (INITIALIZE_SECURITY_CONTEXT_FN)
                                 GetProcAddress(hModule, "InitializeSecurityContextA");
#endif
    if (!_InitializeSecurityContext) {
        UnloadSecurityDll();
        hModule = NULL;
        return hModule;
    }
#ifdef UNICODE
    _QuerySecurityPackageInfo = (QUERY_SECURITY_PACKAGE_INFO_FN)
                                GetProcAddress(hModule, "QuerySecurityPackageInfoW");
#else
    _QuerySecurityPackageInfo = (QUERY_SECURITY_PACKAGE_INFO_FN)
                                GetProcAddress(hModule, "QuerySecurityPackageInfoA");
#endif
    if (!_QuerySecurityPackageInfo) {
        UnloadSecurityDll();
        hModule = NULL;
    }

#ifdef UNICODE
    _QueryContextAttributes = (QUERY_CONTEXT_ATTRIBUTES_FN_W)
                              GetProcAddress(hModule, "QueryContextAttributesW");
#else
    _QueryContextAttributes = (QUERY_CONTEXT_ATTRIBUTES_FN_A)
                              GetProcAddress(hModule, "QueryContextAttributesA");
#endif
    if (!_QueryContextAttributes) {
        UnloadSecurityDll();
        hModule = NULL;
    }

    /* Get max token size */
    _QuerySecurityPackageInfo((SEC_CHAR*)_T(SSP_Package), &pSPI);
    cbMaxToken = pSPI->cbMaxToken;
    _FreeContextBuffer(pSPI);

    /* Allocate buffers for client and server messages */
    pClientBuf = xcalloc(cbMaxToken, sizeof(char));
    pServerBuf = xcalloc(cbMaxToken, sizeof(char));
    SSP_Package_InUse = xstrdup(SSP_Package);

    return hModule;
}


BOOL GenClientContext(PAUTH_SEQ pAS, PSEC_WINNT_AUTH_IDENTITY pAuthIdentity,
                      PVOID pIn, DWORD cbIn, PVOID pOut, PDWORD pcbOut, PBOOL pfDone)
{
    /*
     *  Routine Description:
     *
     *  Optionally takes an input buffer coming from the server and returns
     *  a buffer of information to send back to the server. Also returns
     *  an indication of whether or not the context is complete.
     *
     *  Return Value:
     *  Returns TRUE if successful; otherwise FALSE.
     */
    TimeStamp       tsExpiry;
    SecBufferDesc   sbdOut;
    SecBuffer       sbOut;
    SecBufferDesc   sbdIn;
    SecBuffer       sbIn;
    ULONG           fContextAttr;

    if (!pAS->fInitialized) {
        SecurityStatus = _AcquireCredentialsHandle(NULL, (SEC_CHAR*) _T(SSP_Package_InUse),
                         SECPKG_CRED_OUTBOUND, NULL, (NTLM_mode == SSP_NTLM) ? NULL : pAuthIdentity, NULL, NULL,
                         &pAS->hcred, &tsExpiry);
        if (SecurityStatus < 0)
            return FALSE;
        pAS->fHaveCredHandle = TRUE;
    }

    /* Prepare output buffer */
    sbdOut.ulVersion = 0;
    sbdOut.cBuffers = 1;
    sbdOut.pBuffers = &sbOut;
    sbOut.cbBuffer = *pcbOut;
    sbOut.BufferType = SECBUFFER_TOKEN;
    sbOut.pvBuffer = pOut;

    /* Prepare input buffer */
    if (pAS->fInitialized)  {
        sbdIn.ulVersion = 0;
        sbdIn.cBuffers = 1;
        sbdIn.pBuffers = &sbIn;
        sbIn.cbBuffer = cbIn;
        sbIn.BufferType = SECBUFFER_TOKEN;
        sbIn.pvBuffer = pIn;
    }
    SecurityStatus = _InitializeSecurityContext(&pAS->hcred,
                     pAS->fInitialized ? &pAS->hctxt : NULL, NULL, 0, 0,
                     SECURITY_NATIVE_DREP, pAS->fInitialized ? &sbdIn : NULL,
                     0, &pAS->hctxt, &sbdOut, &fContextAttr, &tsExpiry);
    if (SecurityStatus < 0)
        return FALSE;
    pAS->fHaveCtxtHandle = TRUE;

    /* If necessary, complete token */
    if (SecurityStatus == SEC_I_COMPLETE_NEEDED || SecurityStatus == SEC_I_COMPLETE_AND_CONTINUE) {
        SecurityStatus = _CompleteAuthToken(&pAS->hctxt, &sbdOut);
        if (SecurityStatus < 0)
            return FALSE;
    }
    *pcbOut = sbOut.cbBuffer;
    if (!pAS->fInitialized)
        pAS->fInitialized = TRUE;
    *pfDone = !(SecurityStatus == SEC_I_CONTINUE_NEEDED
                || SecurityStatus == SEC_I_COMPLETE_AND_CONTINUE );
    return TRUE;
}


BOOL GenServerContext(PAUTH_SEQ pAS, PVOID pIn, DWORD cbIn, PVOID pOut,
                      PDWORD pcbOut, PBOOL pfDone, char * credentials)
{
    /*
     *   Routine Description:
     *
     *   Takes an input buffer coming from the client and returns a buffer
     *   to be sent to the client.  Also returns an indication of whether or
     *   not the context is complete.
     *
     *   Return Value:
     *
     *   Returns TRUE if successful; otherwise FALSE.
     */

    SecBufferDesc   sbdOut;
    SecBuffer       sbOut;
    SecBufferDesc   sbdIn;
    SecBuffer       sbIn;
    ULONG           fContextAttr;
    SecPkgContext_Names namebuffer;

    if (!pAS->fInitialized)  {
        SecurityStatus = _AcquireCredentialsHandle(NULL, (SEC_CHAR*) _T(SSP_Package_InUse),
                         SECPKG_CRED_INBOUND, NULL, NULL, NULL, NULL, &pAS->hcred,
                         &pAS->hcredLifeTime);
#if SSP_DEBUG
        fprintf(stderr, "AcquireCredentialsHandle returned: %x\n", SecurityStatus);
#endif
        if (SecurityStatus < 0) {
#if SSP_DEBUG
            fprintf(stderr, "AcquireCredentialsHandle failed: %x\n", SecurityStatus);
#endif
            return FALSE;
        }
        pAS->fHaveCredHandle = TRUE;
    }

    /* Prepare output buffer */
    sbdOut.ulVersion = 0;
    sbdOut.cBuffers = 1;
    sbdOut.pBuffers = &sbOut;
    sbOut.cbBuffer = *pcbOut;
    sbOut.BufferType = SECBUFFER_TOKEN;
    sbOut.pvBuffer = pOut;

    /* Prepare input buffer */
    sbdIn.ulVersion = 0;
    sbdIn.cBuffers = 1;
    sbdIn.pBuffers = &sbIn;
    sbIn.cbBuffer = cbIn;
    sbIn.BufferType = SECBUFFER_TOKEN;
    sbIn.pvBuffer = pIn;
    SecurityStatus = _AcceptSecurityContext(&pAS->hcred,
                                            pAS->fInitialized ? &pAS->hctxt : NULL, &sbdIn, (NTLM_mode == SSP_NTLM) ? ASC_REQ_DELEGATE : 0,
                                            SECURITY_NATIVE_DREP, &pAS->hctxt, &sbdOut, &fContextAttr,
                                            &pAS->hctxtLifeTime);
#if SSP_DEBUG
    fprintf(stderr, "AcceptSecurityContext returned: %x\n", SecurityStatus);
#endif
    if (SecurityStatus < 0) {
#if SSP_DEBUG
        fprintf(stderr, "AcceptSecurityContext failed: %x\n", SecurityStatus);
#endif
        return FALSE;
    }
    pAS->fHaveCtxtHandle = TRUE;

    /* If necessary, complete token */
    if (SecurityStatus == SEC_I_COMPLETE_NEEDED || SecurityStatus == SEC_I_COMPLETE_AND_CONTINUE) {
        SecurityStatus = _CompleteAuthToken(&pAS->hctxt, &sbdOut);
#if SSP_DEBUG
        fprintf(stderr, "CompleteAuthToken returned: %x\n", SecurityStatus);
#endif
        if (SecurityStatus < 0) {
#if SSP_DEBUG
            fprintf(stderr, "CompleteAuthToken failed: %x\n", SecurityStatus);
#endif
            return FALSE;
        }
    }

    if ((credentials != NULL) &&
            !(SecurityStatus == SEC_I_CONTINUE_NEEDED || SecurityStatus == SEC_I_COMPLETE_AND_CONTINUE)) {
        SecurityStatus = _QueryContextAttributes(&pAS->hctxt, SECPKG_ATTR_NAMES, &namebuffer);
#if SSP_DEBUG
        fprintf(stderr, "QueryContextAttributes returned: %x\n", SecurityStatus);
#endif
        if (SecurityStatus < 0) {
#if SSP_DEBUG
            fprintf(stderr, "QueryContextAttributes failed: %x\n", SecurityStatus);
#endif
            return FALSE;
        }
        strncpy(credentials, namebuffer.sUserName, SSP_MAX_CRED_LEN);
    }

    *pcbOut = sbOut.cbBuffer;
    if (!pAS->fInitialized)
        pAS->fInitialized = TRUE;
    *pfDone = !(SecurityStatus == SEC_I_CONTINUE_NEEDED
                || SecurityStatus == SEC_I_COMPLETE_AND_CONTINUE);
    return TRUE;
}


BOOL WINAPI SSP_LogonUser(PTSTR szUser, PTSTR szPassword, PTSTR szDomain)
{
    AUTH_SEQ    asServer   = {0};
    AUTH_SEQ    asClient   = {0};
    BOOL        fDone      = FALSE;
    BOOL        fResult    = FALSE;
    DWORD       cbOut      = 0;
    DWORD       cbIn       = 0;

    SEC_WINNT_AUTH_IDENTITY ai;

    do {
        if (!hModule)
            break;

        /* Initialize auth identity structure */
        ZeroMemory(&ai, sizeof(ai));
        ai.Domain = (void *)szDomain;
        ai.DomainLength = lstrlen(szDomain);
        ai.User = (void *)szUser;
        ai.UserLength = lstrlen(szUser);
        ai.Password = (void *)szPassword;
        ai.PasswordLength = lstrlen(szPassword);
#if defined(UNICODE) || defined(_UNICODE)
        ai.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
#else
        ai.Flags = SEC_WINNT_AUTH_IDENTITY_ANSI;
#endif

        /* Prepare client message (negotiate) */
        cbOut = cbMaxToken;
        if (!GenClientContext(&asClient, &ai, NULL, 0, pClientBuf, &cbOut, &fDone))
            break;

        /* Prepare server message (challenge) */
        cbIn = cbOut;
        cbOut = cbMaxToken;
        if (!GenServerContext(&asServer, pClientBuf, cbIn, pServerBuf, &cbOut,
                              &fDone, NULL))
            break;
        /* Most likely failure: AcceptServerContext fails with SEC_E_LOGON_DENIED
         * in the case of bad szUser or szPassword.
         * Unexpected Result: Logon will succeed if you pass in a bad szUser and
         * the guest account is enabled in the specified domain.
         */

        /* Prepare client message (authenticate) */
        cbIn = cbOut;
        cbOut = cbMaxToken;
        if (!GenClientContext(&asClient, &ai, pServerBuf, cbIn, pClientBuf, &cbOut,
                              &fDone))
            break;

        /* Prepare server message (authentication) */
        cbIn = cbOut;
        cbOut = cbMaxToken;
        if (!GenServerContext(&asServer, pClientBuf, cbIn, pServerBuf, &cbOut,
                              &fDone, NULL))
            break;
        fResult = TRUE;
    } while (0);

    /* Clean up resources */
    if (asClient.fHaveCtxtHandle)
        _DeleteSecurityContext(&asClient.hctxt);
    if (asClient.fHaveCredHandle)
        _FreeCredentialsHandle(&asClient.hcred);
    if (asServer.fHaveCtxtHandle)
        _DeleteSecurityContext(&asServer.hctxt);
    if (asServer.fHaveCredHandle)
        _FreeCredentialsHandle(&asServer.hcred);

    return fResult;
}


const char * WINAPI SSP_MakeChallenge(PVOID PNegotiateBuf, int NegotiateLen)
{
    BOOL        fDone      = FALSE;
    PVOID       fResult    = NULL;
    DWORD       cbOut      = 0;
    DWORD       cbIn       = 0;
    ntlm_challenge * challenge;
    const char * encoded = NULL;

    if (NTLM_asServer.fHaveCtxtHandle)
        _DeleteSecurityContext(&NTLM_asServer.hctxt);
    if (NTLM_asServer.fHaveCredHandle)
        _FreeCredentialsHandle(&NTLM_asServer.hcred);

    NTLM_LocalCall = FALSE;
    Use_Unicode = FALSE;
    memcpy(pClientBuf, PNegotiateBuf, NegotiateLen);
    ZeroMemory(pServerBuf, cbMaxToken);
    ZeroMemory(&NTLM_asServer, sizeof(NTLM_asServer));
    do {
        if (!hModule)
            break;

        /* Prepare server message (challenge) */
        cbIn = NegotiateLen;
        cbOut = cbMaxToken;
        if (!GenServerContext(&NTLM_asServer, pClientBuf, cbIn, pServerBuf, &cbOut,
                              &fDone, NULL))
            break;
        fResult = pServerBuf;
    } while (0);
    if (fResult != NULL) {
        challenge = (ntlm_challenge *) fResult;
        Use_Unicode = NEGOTIATE_UNICODE & challenge->flags;
        NTLM_LocalCall = NEGOTIATE_THIS_IS_LOCAL_CALL & challenge->flags;
        encoded = base64_encode_bin((char *) fResult, cbOut);
    }
    return encoded;
}


BOOL WINAPI SSP_ValidateNTLMCredentials(PVOID PAutenticateBuf, int AutenticateLen, char * credentials)
{
    BOOL        fDone      = FALSE;
    BOOL        fResult    = FALSE;
    DWORD       cbOut      = 0;
    DWORD       cbIn       = 0;

    memcpy(pClientBuf, PAutenticateBuf, AutenticateLen);
    ZeroMemory(pServerBuf, cbMaxToken);
    do {
        if (!hModule)
            break;

        /* Prepare server message (authentication) */
        cbIn = AutenticateLen;
        cbOut = cbMaxToken;
        if (!GenServerContext(&NTLM_asServer, pClientBuf, cbIn, pServerBuf, &cbOut,
                              &fDone, credentials))
            break;
        fResult = TRUE;
    } while (0);

    return fResult;
}


const char * WINAPI SSP_MakeNegotiateBlob(PVOID PNegotiateBuf, int NegotiateLen, PBOOL fDone, int * Status, char * credentials)
{
    DWORD       cbOut      = 0;
    DWORD       cbIn       = 0;
    const char * encoded = NULL;

    if (NTLM_asServer.fHaveCtxtHandle)
        _DeleteSecurityContext(&NTLM_asServer.hctxt);
    if (NTLM_asServer.fHaveCredHandle)
        _FreeCredentialsHandle(&NTLM_asServer.hcred);

    memcpy(pClientBuf, PNegotiateBuf, NegotiateLen);
    ZeroMemory(pServerBuf, cbMaxToken);
    ZeroMemory(&NTLM_asServer, sizeof(NTLM_asServer));
    do {
        if (!hModule)
            break;

        /* Prepare server message (challenge) */
        cbIn = NegotiateLen;
        cbOut = cbMaxToken;
        if (!GenServerContext(&NTLM_asServer, pClientBuf, cbIn, pServerBuf, &cbOut,
                              fDone, credentials)) {
            *Status = SSP_ERROR;
            break;
        }
        *Status = SSP_OK;
    } while (0);
    if (pServerBuf != NULL && cbOut > 0)
        encoded = base64_encode_bin((char *) pServerBuf, cbOut);
    return encoded;
}


const char * WINAPI SSP_ValidateNegotiateCredentials(PVOID PAutenticateBuf, int AutenticateLen, PBOOL fDone, int * Status, char * credentials)
{
    DWORD       cbOut      = 0;
    DWORD       cbIn       = 0;
    const char * encoded = NULL;

    memcpy(pClientBuf, PAutenticateBuf, AutenticateLen);
    ZeroMemory(pServerBuf, cbMaxToken);
    do {
        if (!hModule)
            break;

        /* Prepare server message (authentication) */
        cbIn = AutenticateLen;
        cbOut = cbMaxToken;
        if (!GenServerContext(&NTLM_asServer, pClientBuf, cbIn, pServerBuf, &cbOut,
                              fDone, credentials)) {
            *Status = SSP_ERROR;
            break;
        }
        *Status = SSP_OK;
    } while (0);
    if (pServerBuf != NULL && cbOut > 0)
        encoded = base64_encode_bin((char *) pServerBuf, cbOut);
    return encoded;
}
