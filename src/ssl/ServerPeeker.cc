/*
 * $Id$
 *
 * DEBUG: section 33    Client-side Routines
 *
 */

#include "config.h"

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
    entry(NULL)
{
    debugs(33, 4, HERE << "will peek at " << host << ':' << port);

    request->SetHost(host);
    request->port = port;
    request->protocol = AnyP::PROTO_SSL_PEEK;
    request->clientConnectionManager = initiator;
}

void
Ssl::ServerPeeker::start()
{
    const char *uri = urlCanonical(request);
    entry = storeCreateEntry(uri, uri, request->flags, request->method);

    FwdState::fwdStart(clientConnection, entry, request);

    // XXX: wait for FwdState to tell us the connection is ready

    // TODO: send our answer to the initiator
    // CallJobHere(33, 4, initiator, ConnStateData, ConnStateData::httpsPeeked);
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
