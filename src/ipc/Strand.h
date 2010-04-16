/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */

#ifndef SQUID_IPC_STRAND_H
#define SQUID_IPC_STRAND_H


#include "SquidString.h"
#include "ipc/Port.h"


namespace Ipc
{


/**
  Strand implement functionality of Coordinator's client and
  send registration query to Coordinator with it KidIdentifier.
*/
class Strand: public Port, public RefCountable
{
private:
    typedef void (Strand::*TimeoutHandler)(const CommTimeoutCbParams&);

private:
    Strand(const Strand&); // not implemented
    Strand& operator =(const Strand&); // not implemented

public:
    Strand();

public:
    virtual void start();
    /// send register query
    void enroll();
    bool registered() const;

private:
    virtual void handleRead(const Message& message);
    void handleRegistrationResponse(const StrandData& strand);
    void setListenTimeout(TimeoutHandler timeoutHandler, int timeout);
    void noteRegistrationTimeout(const CommTimeoutCbParams& params);

private:
    bool isRegistered;

    CBDATA_CLASS2(Strand);
};


}


#endif /* SQUID_IPC_STRAND_H */
