#include "squid.h"
#include "ICAPModXact.h"
#include "ICAPClient.h"
#include "http.h"

void ICAPInitModule()
{
    /*
     * ICAP's MsgPipe buffer needs to be at least as large
     * as the HTTP read buffer.  Otherwise HTTP may take
     * data from the network that won't fit into the MsgPipe,
     * which leads to a runtime assertion.
     */
    assert(ICAP::MsgPipeBufSizeMax >= SQUID_TCP_SO_RCVBUF);
}

void ICAPCleanModule()
{}

// initialize ICAP-specific ends of message pipes
void ICAPInitXaction(ICAPServiceRep::Pointer service, MsgPipe::Pointer virgin, MsgPipe::Pointer adapted)
{
    ICAPModXact::Pointer x = new ICAPModXact;
    debugs(93,5, "ICAPInitXaction: " << x.getRaw());
    x->init(service, virgin, adapted, x);
    // if we want to do something to the transaction after it is done,
    // we need to keep a pointer to it
}

// declared in ICAPModXact.h (ick?)
void ICAPNoteXactionDone(ICAPModXact::Pointer x)
{
    // nothing to be done here?
    // refcounting will delete the transaction
    // as soon as the last pointer to it is gone
    debugs(93,5, "ICAPNoteXactionDone: " << x.getRaw());
}
