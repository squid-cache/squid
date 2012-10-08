/*
 * DEBUG: section 54    Interprocess Communication
 *
 */

#ifndef SQUID_IPC_PORT_H
#define SQUID_IPC_PORT_H

#include "SquidString.h"
#include "ipc/UdsOp.h"

namespace Ipc
{

/// Waits for and receives incoming IPC messages; kids handle the messages
class Port: public UdsOp
{
public:
    Port(const String &aListenAddr);
    /// calculates IPC message address for strand #id at path
    static String MakeAddr(const char *path, int id);

protected:
    virtual void start() = 0; // UdsOp (AsyncJob) API; has body
    virtual bool doneAll() const; // UdsOp (AsyncJob) API

    /// read the next incoming message
    void doListen();

    /// handle IPC message just read
    virtual void receive(const TypedMsgHdr& message) = 0;

private:
    void noteRead(const CommIoCbParams &params); // Comm callback API

private:
    TypedMsgHdr buf; ///< msghdr struct filled by Comm
};

extern const char coordinatorAddr[]; ///< where coordinator listens
extern const char strandAddrPfx[]; ///< strand's listening address prefix

} // namespace Ipc

#endif /* SQUID_IPC_PORT_H */
