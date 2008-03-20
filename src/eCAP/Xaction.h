
/*
 * $Id$
 *
 */

#ifndef SQUID_ECAP_XACTION_H
#define SQUID_ECAP_XACTION_H

#include "MemBuf.h"
#include "eCAP/ServiceRep.h"
#include "ICAP/ICAPInitiate.h"
#include "ICAP/ICAPInOut.h"

class HttpMsg;

#if USE_ECAP_AS_ICAP_HACK
#define EcapXaction ICAPXaction
#endif


class EcapXaction: public ICAPInitiate
{

public:
    EcapXaction(const char *aTypeName, ICAPInitiator *anInitiator, ICAPServiceRep::Pointer &aService);
    virtual ~EcapXaction();

public:
    ICAPInOut virgin;
    ICAPInOut adapted;

protected:
    virtual void start();
    virtual void noteInitiatorAborted(); // TODO: move to ICAPInitiate

    void updateTimeout();

    virtual bool doneAll() const;

    // called just before the 'done' transaction is deleted
    virtual void swanSong(); 

    // returns a temporary string depicting transaction status, for debugging
    virtual const char *status() const;
    virtual void fillPendingStatus(MemBuf &buf) const;
    virtual void fillDoneStatus(MemBuf &buf) const;

    // useful for debugging
    virtual bool fillVirginHttpHeader(MemBuf&) const;

    // custom end-of-call checks
    virtual void callEnd();

protected:
    const int id; // transaction ID for debugging, unique across ICAP xactions

    const char *stopReason;

private:
    static int TheLastId;

    CBDATA_CLASS2(EcapXaction);
};

// call guards for all "asynchronous" note*() methods
// If we move EcapXaction_* macros to core, they can use these generic names:
#define EcapXaction_Enter(method) AsyncCallEnter(method)
#define EcapXaction_Exit() AsyncCallExit()

#if USE_ECAP_AS_ICAP_HACK

// An ICAPLauncher that stores ICAPModXact construction info and 
// creates ICAPModXact when needed
class ICAPModXactLauncher: public ICAPXaction
{
public:
    ICAPModXactLauncher(ICAPInitiator *anInitiator, HttpMsg *virginHeader, HttpRequest *virginCause, ICAPServiceRep::Pointer &s);
};

#endif /* USE_ECAP_AS_ICAP_HACK */


#endif /* SQUID_ECAP_XACTION_H */
