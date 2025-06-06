/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base64.h"
#if HAVE_AUTH_MODULE_NTLM
#include "ntlmauth/ntlmauth.h"
#endif
#include "sspi/sspwin32.h"
#include "util.h"

// FARPROC is an exception on Windows to the -Wcast-function-type sanity check.
// suppress the warning only when casting FARPROC
template <typename T>
T
farproc_cast(FARPROC in)
{
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-function-type"
    return reinterpret_cast<T>(in);
#pragma GCC diagnostic pop
#else
    return reinterpret_cast<T>(in);
#endif
}

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
static uint8_t * pClientBuf = nullptr;
static uint8_t * pServerBuf = nullptr;

static AUTH_SEQ NTLM_asServer = {};

BOOL Use_Unicode = FALSE;
#if HAVE_AUTH_MODULE_NTLM
BOOL NTLM_LocalCall = FALSE;
#endif

/* Function pointers */
ACCEPT_SECURITY_CONTEXT_FN _AcceptSecurityContext = nullptr;
ACQUIRE_CREDENTIALS_HANDLE_FN _AcquireCredentialsHandle = nullptr;
COMPLETE_AUTH_TOKEN_FN _CompleteAuthToken = nullptr;
DELETE_SECURITY_CONTEXT_FN _DeleteSecurityContext = nullptr;
FREE_CONTEXT_BUFFER_FN _FreeContextBuffer = nullptr;
FREE_CREDENTIALS_HANDLE_FN _FreeCredentialsHandle = nullptr;
INITIALIZE_SECURITY_CONTEXT_FN _InitializeSecurityContext = nullptr;
QUERY_SECURITY_PACKAGE_INFO_FN _QuerySecurityPackageInfo = nullptr;
#ifdef UNICODE
QUERY_CONTEXT_ATTRIBUTES_FN_W _QueryContextAttributes = nullptr;
#else
QUERY_CONTEXT_ATTRIBUTES_FN_A _QueryContextAttributes = nullptr;
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

    _AcceptSecurityContext      = nullptr;
    _AcquireCredentialsHandle   = nullptr;
    _CompleteAuthToken          = nullptr;
    _DeleteSecurityContext      = nullptr;
    _FreeContextBuffer          = nullptr;
    _FreeCredentialsHandle      = nullptr;
    _InitializeSecurityContext  = nullptr;
    _QuerySecurityPackageInfo   = nullptr;
    _QueryContextAttributes     = nullptr;

    hModule = nullptr;
}

HMODULE LoadSecurityDll(int mode, const char * SSP_Package)
{
    TCHAR lpszDLL[MAX_PATH];
    OSVERSIONINFO VerInfo;
    PSecPkgInfo pSPI       = nullptr;

    /*
    *  Find out which security DLL to use, depending on
    *  whether we are on NT or 2000 or XP or 2003 Server
    *  We have to use security.dll on Windows NT 4.0.
    *  All other operating systems, we have to use Secur32.dll
    */
    hModule = nullptr;
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
    _AcceptSecurityContext = farproc_cast<ACCEPT_SECURITY_CONTEXT_FN>(GetProcAddress(hModule, "AcceptSecurityContext"));
    if (!_AcceptSecurityContext) {
        UnloadSecurityDll();
        hModule = nullptr;
        return hModule;
    }
#ifdef UNICODE
    _AcquireCredentialsHandle = farproc_cast<ACQUIRE_CREDENTIALS_HANDLE_FN>(GetProcAddress(hModule, "AcquireCredentialsHandleW"));
#else
    _AcquireCredentialsHandle = farproc_cast<ACQUIRE_CREDENTIALS_HANDLE_FN>(GetProcAddress(hModule, "AcquireCredentialsHandleA"));
#endif
    if (!_AcquireCredentialsHandle) {
        UnloadSecurityDll();
        hModule = nullptr;
        return hModule;
    }
    _CompleteAuthToken = farproc_cast<COMPLETE_AUTH_TOKEN_FN>(GetProcAddress(hModule, "CompleteAuthToken"));
    if (!_CompleteAuthToken) {
        UnloadSecurityDll();
        hModule = nullptr;
        return hModule;
    }
    _DeleteSecurityContext = farproc_cast<DELETE_SECURITY_CONTEXT_FN>(GetProcAddress(hModule, "DeleteSecurityContext"));
    if (!_DeleteSecurityContext) {
        UnloadSecurityDll();
        hModule = nullptr;
        return hModule;
    }
    _FreeContextBuffer = farproc_cast<FREE_CONTEXT_BUFFER_FN>(GetProcAddress(hModule, "FreeContextBuffer"));
    if (!_FreeContextBuffer) {
        UnloadSecurityDll();
        hModule = nullptr;
        return hModule;
    }
    _FreeCredentialsHandle = farproc_cast<FREE_CREDENTIALS_HANDLE_FN>(GetProcAddress(hModule, "FreeCredentialsHandle"));
    if (!_FreeCredentialsHandle) {
        UnloadSecurityDll();
        hModule = nullptr;
        return hModule;
    }
#ifdef UNICODE
    _InitializeSecurityContext = farproc_cast<INITIALIZE_SECURITY_CONTEXT_FN>(GetProcAddress(hModule, "InitializeSecurityContextW"));
#else
    _InitializeSecurityContext = farproc_cast<INITIALIZE_SECURITY_CONTEXT_FN>(GetProcAddress(hModule, "InitializeSecurityContextA"));
#endif
    if (!_InitializeSecurityContext) {
        UnloadSecurityDll();
        hModule = nullptr;
        return hModule;
    }
#ifdef UNICODE
    _QuerySecurityPackageInfo = farproc_cast<QUERY_SECURITY_PACKAGE_INFO_FN>(GetProcAddress(hModule, "QuerySecurityPackageInfoW"));
#else
    _QuerySecurityPackageInfo = farproc_cast<QUERY_SECURITY_PACKAGE_INFO_FN>(GetProcAddress(hModule, "QuerySecurityPackageInfoA"));
#endif
    if (!_QuerySecurityPackageInfo) {
        UnloadSecurityDll();
        hModule = nullptr;
    }

#ifdef UNICODE
    _QueryContextAttributes = farproc_cast<QUERY_CONTEXT_ATTRIBUTES_FN_W>(GetProcAddress(hModule, "QueryContextAttributesW"));
#else
    _QueryContextAttributes = farproc_cast<QUERY_CONTEXT_ATTRIBUTES_FN_A>(GetProcAddress(hModule, "QueryContextAttributesA"));
#endif
    if (!_QueryContextAttributes) {
        UnloadSecurityDll();
        hModule = nullptr;
    }

    /* Get max token size */
    _QuerySecurityPackageInfo((SEC_CHAR*)_T(SSP_Package), &pSPI);
    cbMaxToken = pSPI->cbMaxToken;
    _FreeContextBuffer(pSPI);

    /* Allocate buffers for client and server messages */
    pClientBuf = static_cast<uint8_t *>(xcalloc(cbMaxToken, sizeof(char)));
    pServerBuf = static_cast<uint8_t *>(xcalloc(cbMaxToken, sizeof(char)));
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
        SecurityStatus = _AcquireCredentialsHandle(nullptr, (SEC_CHAR*) _T(SSP_Package_InUse),
                         SECPKG_CRED_OUTBOUND, nullptr, (NTLM_mode == SSP_NTLM) ? NULL : pAuthIdentity, nullptr, nullptr,
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
                     pAS->fInitialized ? &pAS->hctxt : NULL, nullptr, 0, 0,
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
        SecurityStatus = _AcquireCredentialsHandle(nullptr, (SEC_CHAR*) _T(SSP_Package_InUse),
                         SECPKG_CRED_INBOUND, nullptr, nullptr, nullptr, nullptr, &pAS->hcred,
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
    AUTH_SEQ    asServer   = {};
    AUTH_SEQ    asClient   = {};
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
        ai.Domain = (unsigned char *)szDomain;
        ai.DomainLength = lstrlen(szDomain);
        ai.User = (unsigned char *)szUser;
        ai.UserLength = lstrlen(szUser);
        ai.Password = (unsigned char *)szPassword;
        ai.PasswordLength = lstrlen(szPassword);
#if defined(UNICODE) || defined(_UNICODE)
        ai.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
#else
        ai.Flags = SEC_WINNT_AUTH_IDENTITY_ANSI;
#endif

        /* Prepare client message (negotiate) */
        cbOut = cbMaxToken;
        if (!GenClientContext(&asClient, &ai, nullptr, 0, pClientBuf, &cbOut, &fDone))
            break;

        /* Prepare server message (challenge) */
        cbIn = cbOut;
        cbOut = cbMaxToken;
        if (!GenServerContext(&asServer, pClientBuf, cbIn, pServerBuf, &cbOut,
                              &fDone, nullptr))
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
                              &fDone, nullptr))
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

#if HAVE_AUTH_MODULE_NTLM
const char * WINAPI SSP_MakeChallenge(PVOID PNegotiateBuf, int NegotiateLen)
{
    BOOL        fDone      = FALSE;
    uint8_t  * fResult = nullptr;
    DWORD       cbOut      = 0;
    DWORD       cbIn       = 0;
    ntlm_challenge * challenge;

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
                              &fDone, nullptr))
            break;
        fResult = pServerBuf;
    } while (0);
    if (fResult != NULL) {
        challenge = (ntlm_challenge *) fResult;
        Use_Unicode = NTLM_NEGOTIATE_UNICODE & challenge->flags;
        NTLM_LocalCall = NTLM_NEGOTIATE_THIS_IS_LOCAL_CALL & challenge->flags;
        struct base64_encode_ctx ctx;
        base64_encode_init(&ctx);
        static char encoded[8192];
        size_t dstLen = base64_encode_update(&ctx, encoded, cbOut, reinterpret_cast<const uint8_t*>(fResult));
        assert(dstLen < sizeof(encoded));
        dstLen += base64_encode_final(&ctx, encoded+dstLen);
        assert(dstLen < sizeof(encoded));
        encoded[dstLen] = '\0';
        return encoded;
    }
    return nullptr;
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
#endif /* HAVE_AUTH_MODULE_NTLM */

#if HAVE_AUTH_MODULE_NEGOTIATE
const char * WINAPI SSP_MakeNegotiateBlob(PVOID PNegotiateBuf, int NegotiateLen, PBOOL fDone, int * Status, char * credentials)
{
    DWORD       cbOut      = 0;
    DWORD       cbIn       = 0;

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
    if (pServerBuf != NULL && cbOut > 0) {
        struct base64_encode_ctx ctx;
        base64_encode_init(&ctx);
        static char encoded[8192];
        size_t dstLen = base64_encode_update(&ctx, encoded, cbOut, reinterpret_cast<const uint8_t*>(pServerBuf));
        assert(dstLen < sizeof(encoded));
        dstLen += base64_encode_final(&ctx, encoded+dstLen);
        assert(dstLen < sizeof(encoded));
        encoded[dstLen] = '\0';
        return encoded;
    }
    return nullptr;
}

const char * WINAPI SSP_ValidateNegotiateCredentials(PVOID PAutenticateBuf, int AutenticateLen, PBOOL fDone, int * Status, char * credentials)
{
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
                              fDone, credentials)) {
            *Status = SSP_ERROR;
            break;
        }
        *Status = SSP_OK;
    } while (0);
    if (pServerBuf != NULL && cbOut > 0) {
        struct base64_encode_ctx ctx;
        base64_encode_init(&ctx);
        static char encoded[8192];
        size_t dstLen = base64_encode_update(&ctx, encoded, cbOut, reinterpret_cast<const uint8_t*>(pServerBuf));
        assert(dstLen < sizeof(encoded));
        dstLen += base64_encode_final(&ctx, encoded+dstLen);
        assert(dstLen < sizeof(encoded));
        encoded[dstLen] = '\0';
        return encoded;
    }
    return nullptr;
}
#endif /* HAVE_AUTH_MODULE_NEGOTIATE */
