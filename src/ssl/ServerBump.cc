/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 33    Client-side Routines */

#include "squid.h"

#include "client_side.h"
#include "FwdState.h"
#include "globals.h"
#include "ssl/ServerBump.h"
#include "Store.h"
#include "StoreClient.h"
#include "URL.h"

CBDATA_NAMESPACED_CLASS_INIT(Ssl, ServerBump);

Ssl::ServerBump::ServerBump(HttpRequest *fakeRequest, StoreEntry *e, Ssl::BumpMode md):
    request(fakeRequest),
    step(bumpStep1)
{
    debugs(33, 4, HERE << "will peek at " << request->GetHost() << ':' << request->port);
    act.step1 = md;
    act.step2 = act.step3 = Ssl::bumpNone;

    const char *uri = urlCanonical(request.getRaw());
    if (e) {
        entry = e;
        entry->lock("Ssl::ServerBump");
    } else
        entry = storeCreateEntry(uri, uri, request->flags, request->method);
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
Ssl::ServerBump::attachServerSSL(SSL *ssl)
{
    if (serverSSL.get())
        return;

    serverSSL.resetAndLock(ssl);
}

const Ssl::CertErrors *
Ssl::ServerBump::sslErrors() const
{
    if (!serverSSL.get())
        return NULL;

    const Ssl::CertErrors *errs = static_cast<const Ssl::CertErrors*>(SSL_get_ex_data(serverSSL.get(), ssl_ex_index_ssl_errors));
    return errs;
}

