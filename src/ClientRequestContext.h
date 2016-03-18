/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
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
    ~ClientRequestContext();

    bool httpStateIsValid();
    void hostHeaderVerify();
    void hostHeaderIpVerify(const ipcache_addrs* ia, const Dns::LookupDetails &dns);
    void hostHeaderVerifyFailed(const char *A, const char *B);
    void clientAccessCheck();
    void clientAccessCheck2();
    void clientAccessCheckDone(const allow_t &answer);
    void clientRedirectStart();
    void clientRedirectDone(const Helper::Reply &reply);
    void clientStoreIdStart();
    void clientStoreIdDone(const Helper::Reply &reply);
    void checkNoCache();
    void checkNoCacheDone(const allow_t &answer);
#if USE_ADAPTATION

    void adaptationAccessCheck();
#endif
#if USE_OPENSSL
    /**
     * Initiates and start the acl checklist to check if the a CONNECT
     * request must be bumped.
     \retval true if the acl check scheduled, false if no ssl-bump required
     */
    bool sslBumpAccessCheck();
    /// The callback function for ssl-bump access check list
    void sslBumpAccessCheckDone(const allow_t &answer);
#endif

    ClientHttpRequest *http;
    ACLChecklist *acl_checklist;        /* need ptr back so we can unreg if needed */
    int redirect_state;
    int store_id_state;

    bool host_header_verify_done;
    bool http_access_done;
    bool adapted_http_access_done;
#if USE_ADAPTATION
    bool adaptation_acl_check_done;
#endif
    bool redirect_done;
    bool store_id_done;
    bool no_cache_done;
    bool interpreted_req_hdrs;
    bool tosToClientDone;
    bool nfmarkToClientDone;
#if USE_OPENSSL
    bool sslBumpCheckDone;
#endif
    ErrorState *error; ///< saved error page for centralized/delayed processing
    bool readNextRequest; ///< whether Squid should read after error handling
};

#endif /* SQUID_CLIENTREQUESTCONTEXT_H */

