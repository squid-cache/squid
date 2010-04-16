/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */

#ifndef SQUID_IPC_COORDINATOR_H
#define SQUID_IPC_COORDINATOR_H


#include "Array.h"
#include "SquidString.h"
#include "ipc/Port.h"


namespace Ipc
{


/**
  Coordinator processes incoming queries about registration of running squid instances
  and store it KidIndentiers.
*/
class Coordinator: public Port, public RefCountable
{
private:
    Coordinator(const Coordinator&); // not implemented
    Coordinator& operator =(const Coordinator&); // not implemented

public:
    Coordinator();

public:
    virtual void start();

private:
    virtual void handleRead(const Message& message);
    StrandData* findStrand(int kidId);
    void enrollStrand(const StrandData& strand);
    void handleRegistrationRequest(const StrandData& strand);

private:
    Vector<StrandData> strands;

    CBDATA_CLASS2(Coordinator);
};


}

#endif /* SQUID_IPC_COORDINATOR_H */
