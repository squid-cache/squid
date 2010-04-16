/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */

#ifndef SQUID_IPC_PORT_H
#define SQUID_IPC_PORT_H


#include "SquidString.h"
#include "ipc/UdsOp.h"


namespace Ipc
{


/**
   Base class implements functionality of local endpoint
   is listening incoming connections
*/
class Port: public UdsOp
{
public:
    Port(const String& aListenAddr);

public:
    /// start listening of incoming connections
    void listen();
    String makeAddr(const char* pathAddr, int id) const;

protected:
    virtual void handleRead(const Message& message) = 0;

private:
    void noteRead(const CommIoCbParams& params);

private:
    String listenAddr;
    Message message;
};


extern const char coordinatorPathAddr[];
extern const char strandPathAddr[];


}


#endif /* SQUID_IPC_PORT_H */
