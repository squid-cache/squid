/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */

#ifndef SQUID_IPC_STRAND_H
#define SQUID_IPC_STRAND_H

#include "ipc/Port.h"


namespace Ipc
{

class StrandCoord;
class Descriptor;

/// Receives coordination messages on behalf of its process or thread
class Strand: public Port
{
public:
    Strand();

    virtual void start(); // Port (AsyncJob) API

protected:
    virtual void timedout(); // Port (UsdOp) API
    virtual void receive(const TypedMsgHdr &message); // Port API

private:
    void registerSelf(); /// let Coordinator know this strand exists
    void handleRegistrationResponse(const StrandCoord &strand);
    void putDescriptor(const Descriptor &message);

private:
    bool isRegistered; ///< whether Coordinator ACKed registration (unused)

    CBDATA_CLASS2(Strand);

private:
    Strand(const Strand&); // not implemented
    Strand& operator =(const Strand&); // not implemented
};


}


#endif /* SQUID_IPC_STRAND_H */
