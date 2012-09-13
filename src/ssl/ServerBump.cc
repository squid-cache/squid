/*
 * DEBUG: section 33    Client-side Routines
 *
 */

#include "squid.h"

#include "client_side.h"
#include "forward.h"
#include "ssl/ServerBump.h"
#include "Store.h"
#include "StoreClient.h"
#include "URL.h"

CBDATA_NAMESPACED_CLASS_INIT(Ssl, ServerBump);

Ssl::ServerBump::ServerBump(HttpRequest *fakeRequest, StoreEntry *e):
        request(fakeRequest),
        sslErrors(NULL)
{
    debugs(33, 4, HERE << "will peek at " << request->GetHost() << ':' << request->port);
    const char *uri = urlCanonical(request);
    if (e) {
        entry = e;
        entry->lock();
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
        entry->unlock();
    }
    cbdataReferenceDone(sslErrors);
}

