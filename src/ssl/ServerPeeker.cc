/*
 * $Id$
 *
 * DEBUG: section 33    Client-side Routines
 *
 */

#include "squid.h"

#include "client_side.h"
#include "forward.h"
#include "ssl/ServerPeeker.h"
#include "Store.h"


CBDATA_NAMESPACED_CLASS_INIT(Ssl, ServerPeeker);


Ssl::ServerPeeker::ServerPeeker(ConnStateData *anInitiator,
    const char *host, const int port):
    AsyncJob("Ssl::ServerPeeker"),
    initiator(anInitiator),
    clientConnection(anInitiator->clientConnection),
    request(new HttpRequest),
    entry(NULL),
    sc(NULL)
{
    debugs(33, 4, HERE << "will peek at " << host << ':' << port);
    request->flags.sslPeek = 1;
    request->SetHost(host);
    request->port = port;
    request->protocol = AnyP::PROTO_HTTPS;
    request->clientConnectionManager = initiator;
    const char *uri = urlCanonical(request);
    entry = storeCreateEntry(uri, uri, request->flags, request->method);
    // We do not need to be a client because the error contents will be used
    // later, but an entry without any client will trim all its contents away.
    sc = storeClientListAdd(entry, this);
}

Ssl::ServerPeeker::~ServerPeeker()
{
    if (entry) {
        debugs(33, 4, HERE << "stopped peeking via " << *entry);
        storeUnregister(sc, entry, this);
        entry->unlock();
    }
}

void
Ssl::ServerPeeker::start()
{
    FwdState::fwdStart(clientConnection, entry, request);
}

void Ssl::ServerPeeker::noteHttpsPeeked(Comm::ConnectionPointer &serverConnection)
{
    assert(initiator.raw());
    initiator.clear(); // will trigger the end of the job
}

bool
Ssl::ServerPeeker::doneAll() const
{
    return !initiator.valid() && AsyncJob::doneAll();
}

void
Ssl::ServerPeeker::swanSong()
{
}
