/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 33    Client-side Routines */

#include "squid.h"
#include "anyp/Uri.h"
#include "client_side.h"
#include "FwdState.h"
#include "http/Stream.h"
#include "ssl/ServerBump.h"
#include "Store.h"
#include "StoreClient.h"

CBDATA_NAMESPACED_CLASS_INIT(Ssl, ServerBump);

Ssl::ServerBump::ServerBump(HttpRequest *fakeRequest, StoreEntry *e, Ssl::BumpMode md):
    request(fakeRequest),
    step(bumpStep1)
{
    debugs(33, 4, "will peek at " << request->url.authority(true));
    act.step1 = md;
    act.step2 = act.step3 = Ssl::bumpNone;

    if (e) {
        entry = e;
        entry->lock("Ssl::ServerBump");
    } else {
        // XXX: Performance regression. c_str() reallocates
        SBuf uriBuf(request->effectiveRequestUri());
        const char *uri = uriBuf.c_str();
        entry = storeCreateEntry(uri, uri, request->flags, request->method);
    }
    // We do not need to be a client because the error contents will be used
    // later, but an entry without any client will trim all its contents away.
    sc = storeClientListAdd(entry, this);
}

Ssl::ServerBump::~ServerBump()
{
    debugs(33, 4, HERE << "destroying");
    if (entry) {
        debugs(33, 4, HERE << *entry);
        storeUnregister(sc, entry, this);
        entry->unlock("Ssl::ServerBump");
    }
}

void
Ssl::ServerBump::attachServerSession(const Security::SessionPointer &s)
{
    if (serverSession)
        return;

    serverSession = s;
}

const Security::CertErrors *
Ssl::ServerBump::sslErrors() const
{
    if (!serverSession)
        return NULL;

    const Security::CertErrors *errs = static_cast<const Security::CertErrors*>(SSL_get_ex_data(serverSession.get(), ssl_ex_index_ssl_errors));
    return errs;
}

