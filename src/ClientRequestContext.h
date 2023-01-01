/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_CLIENTREQUESTCONTEXT_H
#define SQUID_CLIENTREQUESTCONTEXT_H

#include "base/RefCount.h"
#include "cbdata.h"
#include "dns/forward.h"
#include "helper/forward.h"
#include "ipcache.h"

#if USE_ADAPTATION
#include "adaptation/forward.h"
#endif

class ACLChecklist;
class ClientHttpRequest;
class ErrorState;

class ClientRequestContext : public RefCountable
{
    CBDATA_CLASS(ClientRequestContext);

public:
    ClientRequestContext(ClientHttpRequest *);
    ~ClientRequestContext() override;

    bool httpStateIsValid();
    void hostHeaderVerify();
    void hostHeaderIpVerify(const ipcache_addrs *, const Dns::LookupDetails &);
    void hostHeaderVerifyFailed(const char *A, const char *B);
    void clientAccessCheck();
    void clientAccessCheck2();
    void clientAccessCheckDone(const Acl::Answer &);
    void clientRedirectStart();
    void clientRedirectDone(const Helper::Reply &);
    void clientStoreIdStart();
    void clientStoreIdDone(const Helper::Reply &);
    void checkNoCache();
    void checkNoCacheDone(const Acl::Answer &);
#if USE_ADAPTATION
    void adaptationAccessCheck();
#endif
#if USE_OPENSSL
    /**
     * Initiates and start the acl checklist to check if the CONNECT
     * request must be bumped.
     * \retval true if the acl check scheduled
     * \retval false if no ssl-bump required
     */
    bool sslBumpAccessCheck();
    /// The callback function for ssl-bump access check list
    void sslBumpAccessCheckDone(const Acl::Answer &answer);
#endif

    ClientHttpRequest *http;
    ACLChecklist *acl_checklist = nullptr; ///< need ptr back so we can unregister if needed
    int redirect_state = REDIRECT_NONE;
    int store_id_state = REDIRECT_NONE;

    bool host_header_verify_done = false;
    bool http_access_done = false;
    bool adapted_http_access_done = false;
#if USE_ADAPTATION
    bool adaptation_acl_check_done = false;
#endif
    bool redirect_done = false;
    bool store_id_done = false;
    bool no_cache_done = false;
    bool interpreted_req_hdrs = false;
    bool toClientMarkingDone = false;
#if USE_OPENSSL
    bool sslBumpCheckDone = false;
#endif
    ErrorState *error = nullptr; ///< saved error page for centralized/delayed processing
    bool readNextRequest = false; ///< whether Squid should read after error handling
};

#endif /* SQUID_CLIENTREQUESTCONTEXT_H */

