/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#ifndef SQUID_IPC_COORDINATOR_H
#define SQUID_IPC_COORDINATOR_H

#include "ipc/Messages.h"
#include "ipc/QuestionerId.h"
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
#include <vector>

namespace Ipc
{

///  Coordinates shared activities of Strands (Squid processes or threads)
class Coordinator: public Port
{
    CBDATA_CLASS(Coordinator);

public:
    static Coordinator* Instance();

public:
    Coordinator();

    const StrandCoords &strands() const; ///< currently registered strands

protected:
    virtual void start(); // Port (AsyncJob) API
    virtual void receive(const TypedMsgHdr& message); // Port API

    StrandCoord* findStrand(int kidId); ///< registered strand or NULL
    void registerStrand(const StrandMessage &); ///< adds or updates existing
    void handleRegistrationRequest(const StrandMessage &); ///< register,ACK
    /// notifies waiting searches of a not yet ready strand
    void handleForegroundRebuildMessage(const StrandMessage &);
    /// notifies all strands of an indexed strand
    void handleRebuildFinishedMessage(const StrandMessage &);

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
    /// questioner ids for each of StrandCoord in strands_,
    /// i.e., questioners_[i] is the questioner id for strands_[i]
    std::vector<QuestionerId> questioners_;

    typedef std::list<StrandSearchRequest> Searchers; ///< search requests
    Searchers searchers; ///< yet unanswered search requests in arrival order

    typedef std::map<OpenListenerParams, Comm::ConnectionPointer> Listeners; ///< params:connection map
    Listeners listeners; ///< cached comm_open_listener() results

    StrandCoords rebuildFinishedStrands_; ///< disker processes, completed their indexing

    static Coordinator* TheInstance; ///< the only class instance in existence

private:
    Coordinator(const Coordinator&); // not implemented
    Coordinator& operator =(const Coordinator&); // not implemented
};

} // namespace Ipc

#endif /* SQUID_IPC_COORDINATOR_H */

