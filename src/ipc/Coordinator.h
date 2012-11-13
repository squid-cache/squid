/*
 * DEBUG: section 54    Interprocess Communication
 *
 */

#ifndef SQUID_IPC_COORDINATOR_H
#define SQUID_IPC_COORDINATOR_H

#include "Array.h"
#include "ipc/Messages.h"
#include "ipc/Port.h"
#include "ipc/SharedListen.h"
#include "ipc/StrandCoords.h"
#include "ipc/StrandSearch.h"
#include "mgr/forward.h"
#if SQUID_SNMP
#include "snmp/forward.h"
#endif
#include <list>
#include <map>

namespace Ipc
{

///  Coordinates shared activities of Strands (Squid processes or threads)
class Coordinator: public Port
{
public:
    static Coordinator* Instance();

public:
    Coordinator();

    void broadcastSignal(int sig) const; ///< send sig to registered strands

    const StrandCoords &strands() const; ///< currently registered strands

protected:
    virtual void start(); // Port (AsyncJob) API
    virtual void receive(const TypedMsgHdr& message); // Port API

    StrandCoord* findStrand(int kidId); ///< registered strand or NULL
    void registerStrand(const StrandCoord &); ///< adds or updates existing
    void handleRegistrationRequest(const HereIamMessage &); ///< register,ACK

    /// answer the waiting search request
    void notifySearcher(const StrandSearchRequest &request, const StrandCoord&);
    /// answers or queues the request if the answer is not yet known
    void handleSearchRequest(const StrandSearchRequest &request);

    /// returns cached socket or calls openListenSocket()
    void handleSharedListenRequest(const SharedListenRequest& request);
    void handleCacheMgrRequest(const Mgr::Request& request);
    void handleCacheMgrResponse(const Mgr::Response& response);
#if SQUID_SNMP
    void handleSnmpRequest(const Snmp::Request& request);
    void handleSnmpResponse(const Snmp::Response& response);
#endif
    /// calls comm_open_listener()
    Comm::ConnectionPointer openListenSocket(const SharedListenRequest& request, int &errNo);

private:
    StrandCoords strands_; ///< registered processes and threads

    typedef std::list<StrandSearchRequest> Searchers; ///< search requests
    Searchers searchers; ///< yet unanswered search requests in arrival order

    typedef std::map<OpenListenerParams, Comm::ConnectionPointer> Listeners; ///< params:connection map
    Listeners listeners; ///< cached comm_open_listener() results

    static Coordinator* TheInstance; ///< the only class instance in existence

private:
    Coordinator(const Coordinator&); // not implemented
    Coordinator& operator =(const Coordinator&); // not implemented

    CBDATA_CLASS2(Coordinator);
};

} // namespace Ipc

#endif /* SQUID_IPC_COORDINATOR_H */
